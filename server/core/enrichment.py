"""
Vulnerability enrichment — fetches CVE data from NVD and OSV,
then attaches EPSS scores from FIRST.org.

Key design decisions:
  - All external API calls are async (httpx).
  - NVD responses are cached in PostgreSQL (Vulnerability table) with a
    configurable TTL to avoid hammering the API on re-scans.
  - Rate limiting is applied per the NVD guidelines (50 req/30 s with key).
  - OSV is queried by package name + ecosystem for package-based findings.
  - EPSS scores are bulk-fetched for a batch of CVE IDs.
"""

from __future__ import annotations

import asyncio
import logging
import math
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from server.config import settings
from server.db.models import EPSSScore, Severity, Vulnerability, VulnSource

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CVSS v3 base-score calculator (no external library required)
# ---------------------------------------------------------------------------

def _cvss3_score_from_vector(vector: str) -> Optional[float]:
    """
    Calculate the CVSS v3 numerical base score from a vector string such as
    ``CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H``.
    Returns None if the vector cannot be parsed.
    """
    if not vector or not vector.startswith("CVSS:3"):
        return None
    try:
        parts = dict(item.split(":") for item in vector.split("/")[1:])

        av  = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}[parts["AV"]]
        ac  = {"L": 0.77, "H": 0.44}[parts["AC"]]
        ui  = {"N": 0.85, "R": 0.62}[parts["UI"]]
        s   = parts["S"]
        # Privileges Required has different weights when scope changes
        pr_map = (
            {"N": 0.85, "L": 0.68, "H": 0.50} if s == "C"
            else {"N": 0.85, "L": 0.62, "H": 0.27}
        )
        pr  = pr_map[parts["PR"]]
        ci  = {"N": 0.00, "L": 0.22, "H": 0.56}[parts["C"]]
        ii  = {"N": 0.00, "L": 0.22, "H": 0.56}[parts["I"]]
        ai  = {"N": 0.00, "L": 0.22, "H": 0.56}[parts["A"]]

        isc_base = 1.0 - (1.0 - ci) * (1.0 - ii) * (1.0 - ai)
        if s == "U":
            iss = 6.42 * isc_base
        else:
            iss = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15

        if iss <= 0:
            return 0.0

        exploit = 8.22 * av * ac * pr * ui
        raw = min(iss + exploit, 10.0) if s == "U" else min(1.08 * (iss + exploit), 10.0)
        # Roundup: ceiling to nearest tenth
        return math.ceil(raw * 10) / 10
    except (KeyError, ValueError, ZeroDivisionError):
        return None

# ---------------------------------------------------------------------------
# Severity mapping helpers
# ---------------------------------------------------------------------------

def _cvss3_to_severity(score: Optional[float]) -> Severity:
    if score is None:
        return Severity.unknown
    if score >= 9.0:
        return Severity.critical
    if score >= 7.0:
        return Severity.high
    if score >= 4.0:
        return Severity.medium
    if score > 0.0:
        return Severity.low
    return Severity.none


def _nvd_severity_str(s: str) -> Severity:
    mapping = {
        "CRITICAL": Severity.critical,
        "HIGH":     Severity.high,
        "MEDIUM":   Severity.medium,
        "LOW":      Severity.low,
        "NONE":     Severity.none,
    }
    return mapping.get(s.upper(), Severity.unknown)


# ---------------------------------------------------------------------------
# Rate limiter (token bucket)
# ---------------------------------------------------------------------------

class _RateLimiter:
    def __init__(self, rate: int, window: float) -> None:
        self._rate = rate
        self._window = window
        self._tokens = float(rate)
        self._last_refill = asyncio.get_event_loop().time() if asyncio.get_event_loop().is_running() else 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = asyncio.get_event_loop().time()
            elapsed = now - self._last_refill
            self._tokens = min(
                float(self._rate),
                self._tokens + elapsed * (self._rate / self._window),
            )
            self._last_refill = now
            if self._tokens < 1:
                wait = (1 - self._tokens) * (self._window / self._rate)
                await asyncio.sleep(wait)
                self._tokens = 0
            else:
                self._tokens -= 1


# ---------------------------------------------------------------------------
# NVD Client
# ---------------------------------------------------------------------------

class NVDClient:
    """
    Client for the NVD 2.0 REST API.
    Docs: https://nvd.nist.gov/developers/vulnerabilities
    """

    def __init__(self) -> None:
        headers: dict[str, str] = {}
        if settings.NVD_API_KEY:
            headers["apiKey"] = settings.NVD_API_KEY
        self._client = httpx.AsyncClient(
            base_url=settings.NVD_API_BASE_URL,
            headers=headers,
            timeout=30.0,
        )
        # NVD allows 50 req/30 s with an API key, only 5 req/30 s without.
        # Respect the lower limit to avoid 403/429 responses.
        rate = settings.NVD_RATE_LIMIT_REQUESTS if settings.NVD_API_KEY else 5
        self._rate_limiter = _RateLimiter(
            rate=rate,
            window=settings.NVD_RATE_LIMIT_WINDOW,
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def fetch_cve(self, cve_id: str) -> Optional[dict[str, Any]]:
        """Fetch a single CVE record by ID."""
        await self._rate_limiter.acquire()
        try:
            resp = await self._client.get("", params={"cveId": cve_id})
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            return vulns[0]["cve"] if vulns else None
        except httpx.HTTPStatusError as exc:
            logger.warning("NVD fetch failed for %s: %s", cve_id, exc)
            return None
        except Exception as exc:
            logger.error("Unexpected NVD error for %s: %s", cve_id, exc)
            return None

    async def search_by_cpe(self, cpe: str, results_per_page: int = 100) -> list[dict[str, Any]]:
        """Search CVEs matching a CPE string."""
        await self._rate_limiter.acquire()
        results: list[dict[str, Any]] = []
        start_index = 0
        while True:
            try:
                resp = await self._client.get("", params={
                    "cpeName": cpe,
                    "resultsPerPage": results_per_page,
                    "startIndex": start_index,
                })
                resp.raise_for_status()
                data = resp.json()
                batch = [v["cve"] for v in data.get("vulnerabilities", [])]
                results.extend(batch)
                if start_index + results_per_page >= data.get("totalResults", 0):
                    break
                start_index += results_per_page
                await self._rate_limiter.acquire()
            except httpx.HTTPStatusError as exc:
                logger.warning("NVD CPE search failed for %s: %s", cpe, exc)
                break
        return results

    def parse_cve(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Normalise a raw NVD CVE object into our internal schema."""
        cve_id = raw.get("id", "")
        descriptions = raw.get("descriptions", [])
        desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), None)

        metrics = raw.get("metrics", {})
        cvss_v3 = None
        cvss_v3_vec = None
        cvss_v3_src = None
        for key in ("cvssMetricV31", "cvssMetricV30"):
            if key in metrics and metrics[key]:
                m = metrics[key][0]
                cvss_v3 = m.get("cvssData", {}).get("baseScore")
                cvss_v3_vec = m.get("cvssData", {}).get("vectorString")
                cvss_v3_src = m.get("source")
                break

        cvss_v2 = None
        cvss_v2_vec = None
        if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            m = metrics["cvssMetricV2"][0]
            cvss_v2 = m.get("cvssData", {}).get("baseScore")
            cvss_v2_vec = m.get("cvssData", {}).get("vectorString")

        vuln_status = raw.get("vulnStatus", "")
        base_severity = (
            raw.get("metrics", {})
               .get("cvssMetricV31", [{}])[0]
               .get("cvssData", {})
               .get("baseSeverity")
            or raw.get("metrics", {})
               .get("cvssMetricV30", [{}])[0]
               .get("cvssData", {})
               .get("baseSeverity")
        )
        severity = (
            _nvd_severity_str(base_severity) if base_severity
            else _cvss3_to_severity(cvss_v3)
        )

        cwe_ids = []
        for weakness in raw.get("weaknesses", []):
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en":
                    cwe_ids.append(desc["value"])

        affected_cpes = []
        for config in raw.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable"):
                        affected_cpes.append(cpe_match.get("criteria", ""))

        references = [
            {"url": r.get("url"), "source": r.get("source"), "tags": r.get("tags", [])}
            for r in raw.get("references", [])
        ]

        published = raw.get("published")
        modified = raw.get("lastModified")

        return {
            "id": cve_id,
            "source": VulnSource.nvd,
            "title": cve_id,
            "description": desc_en,
            "severity": severity,
            "cvss_v3_score": cvss_v3,
            "cvss_v3_vector": cvss_v3_vec,
            "cvss_v3_source": cvss_v3_src,
            "cvss_v2_score": cvss_v2,
            "cvss_v2_vector": cvss_v2_vec,
            "cwe_ids": list(set(cwe_ids)),
            "affected_cpes": affected_cpes,
            "affected_packages": [],
            "references": references,
            "published_at": datetime.fromisoformat(published.replace("Z", "+00:00")) if published else None,
            "modified_at": datetime.fromisoformat(modified.replace("Z", "+00:00")) if modified else None,
        }


# ---------------------------------------------------------------------------
# OSV Client
# ---------------------------------------------------------------------------

class OSVClient:
    """
    Client for the OSV.dev API.
    Docs: https://google.github.io/osv.dev/api/
    """

    ECOSYSTEM_MAP = {
        "dpkg":    "Debian",
        "rpm":     "AlmaLinux",  # Also covers RHEL/CentOS via multiple ecosystems
        "apk":     "Alpine",
        "pip":     "PyPI",
        "npm":     "npm",
        "gem":     "RubyGems",
        "cargo":   "crates.io",
        "go":      "Go",
        "maven":   "Maven",
        "nuget":   "NuGet",
        "brew":    "Homebrew",
        "msi":     "NuGet",
        "winget":  "NuGet",
    }

    def __init__(self) -> None:
        self._client = httpx.AsyncClient(
            base_url=settings.OSV_API_BASE_URL,
            timeout=30.0,
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def query_package(
        self,
        package_name: str,
        version: str,
        package_manager: str,
    ) -> list[dict[str, Any]]:
        """Find OSV vulnerabilities affecting a specific package version."""
        ecosystem = self.ECOSYSTEM_MAP.get(package_manager.lower(), "")
        payload: dict[str, Any] = {
            "package": {"name": package_name, "ecosystem": ecosystem},
            "version": version,
        }
        try:
            resp = await self._client.post("/query", json=payload)
            resp.raise_for_status()
            return resp.json().get("vulns", [])
        except httpx.HTTPStatusError as exc:
            logger.warning("OSV query failed for %s@%s: %s", package_name, version, exc)
            return []

    async def fetch_vuln(self, osv_id: str) -> Optional[dict[str, Any]]:
        """Fetch a full OSV record by ID."""
        try:
            resp = await self._client.get(f"/vulns/{osv_id}")
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError:
            return None

    def parse_osv(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Normalise an OSV record into our internal schema."""
        osv_id = raw.get("id", "")
        aliases = raw.get("aliases", [])
        # Prefer the CVE alias as our canonical ID
        cve_alias = next((a for a in aliases if a.startswith("CVE-")), None)
        canonical_id = cve_alias or osv_id

        severity_entries = raw.get("severity", [])
        cvss_v3_score = None
        cvss_v3_vec = None
        for s in severity_entries:
            if s.get("type") in ("CVSS_V3", "CVSS_V31"):
                vec = s.get("score", "")
                if re.search(r"/AV:", vec):
                    cvss_v3_vec = vec
                    cvss_v3_score = _cvss3_score_from_vector(vec)
                break

        affected_packages = []
        for aff in raw.get("affected", []):
            pkg = aff.get("package", {})
            affected_packages.append({
                "name": pkg.get("name"),
                "ecosystem": pkg.get("ecosystem"),
                "ranges": aff.get("ranges", []),
                "versions": aff.get("versions", []),
            })

        references = [
            {"url": r.get("url"), "type": r.get("type")}
            for r in raw.get("references", [])
        ]

        published = raw.get("published")
        modified = raw.get("modified")

        return {
            "id": canonical_id,
            "source": VulnSource.osv,
            "title": raw.get("summary", canonical_id),
            "description": raw.get("details"),
            "severity": _cvss3_to_severity(cvss_v3_score),
            "cvss_v3_score": cvss_v3_score,
            "cvss_v3_vector": cvss_v3_vec,
            "cvss_v3_source": None,
            "cvss_v2_score": None,
            "cvss_v2_vector": None,
            "cwe_ids": [],
            "affected_cpes": [],
            "affected_packages": affected_packages,
            "references": references,
            "published_at": datetime.fromisoformat(published.replace("Z", "+00:00")) if published else None,
            "modified_at": datetime.fromisoformat(modified.replace("Z", "+00:00")) if modified else None,
        }


# ---------------------------------------------------------------------------
# EPSS Client
# ---------------------------------------------------------------------------

class EPSSClient:
    """
    Client for the FIRST.org EPSS API.
    Docs: https://www.first.org/epss/api
    """

    def __init__(self) -> None:
        self._client = httpx.AsyncClient(
            base_url=settings.EPSS_API_BASE_URL,
            timeout=30.0,
            headers={"User-Agent": "claude-scanner/0.1 (security research; httpx)"},
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def fetch_scores(self, cve_ids: list[str]) -> dict[str, dict[str, Any]]:
        """
        Fetch EPSS scores for a batch of CVE IDs.
        Returns a dict mapping CVE ID → {"epss": float, "percentile": float, "date": str}.
        """
        if not cve_ids:
            return {}

        results: dict[str, dict[str, Any]] = {}
        chunk_size = 100
        for i in range(0, len(cve_ids), chunk_size):
            chunk = cve_ids[i : i + chunk_size]
            try:
                resp = await self._client.get(
                    "/epss",
                    params={"cve": ",".join(chunk)},
                )
                resp.raise_for_status()
                data = resp.json()
                entries = data.get("data", [])
                logger.info(
                    "EPSS API returned %d scores for %d CVEs requested",
                    len(entries), len(chunk),
                )
                for entry in entries:
                    cve = entry.get("cve", "")
                    if cve:
                        results[cve] = {
                            "epss": float(entry.get("epss") or 0),
                            "percentile": float(entry.get("percentile") or 0),
                            "date": entry.get("date"),
                            "model_version": data.get("version"),
                        }
            except httpx.HTTPStatusError as exc:
                logger.warning("EPSS fetch HTTP error for chunk starting %s: %s", chunk[0], exc)
            except Exception as exc:
                logger.warning("EPSS fetch failed for chunk starting %s: %s", chunk[0], exc)
        return results


# ---------------------------------------------------------------------------
# VulnerabilityEnrichmentService
# ---------------------------------------------------------------------------

class VulnerabilityEnrichmentService:
    """
    Orchestrates NVD + OSV lookups and EPSS scoring.
    Caches results in the database to minimise API calls.
    """

    def __init__(self) -> None:
        self.nvd = NVDClient()
        self.osv = OSVClient()
        self.epss = EPSSClient()

    async def close(self) -> None:
        await asyncio.gather(self.nvd.close(), self.osv.close(), self.epss.close())

    async def get_or_fetch_cve(
        self,
        db: AsyncSession,
        cve_id: str,
        force_refresh: bool = False,
    ) -> Optional[Vulnerability]:
        """
        Return a Vulnerability record for cve_id, fetching from NVD if not
        cached or if the cache is stale (older than VULN_CACHE_TTL_HOURS).
        """
        result = await db.execute(select(Vulnerability).where(Vulnerability.id == cve_id))
        vuln = result.scalar_one_or_none()

        ttl = timedelta(hours=settings.VULN_CACHE_TTL_HOURS)
        is_stale = (
            vuln is None
            or force_refresh
            or (datetime.now(timezone.utc) - vuln.last_fetched_at.replace(tzinfo=timezone.utc) > ttl)
        )

        if not is_stale:
            return vuln

        # Fetch fresh data from NVD
        raw = await self.nvd.fetch_cve(cve_id)
        if raw is None:
            # Record the attempt so the TTL prevents repeated NVD queries for
            # CVEs that genuinely have no NVD entry.
            if vuln is not None:
                vuln.last_fetched_at = datetime.utcnow()
                await db.flush()
            return vuln

        parsed = self.nvd.parse_cve(raw)

        if vuln is None:
            vuln = Vulnerability(**parsed)
            db.add(vuln)
        else:
            for k, v in parsed.items():
                if hasattr(vuln, k):
                    setattr(vuln, k, v)
            vuln.last_fetched_at = datetime.utcnow()

        await db.flush()
        return vuln

    async def enrich_packages(
        self,
        db: AsyncSession,
        packages: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        For each package, query OSV for known vulnerabilities.
        Returns list of finding dicts: {cve_id, package_name, version, source}.
        """
        findings: list[dict[str, Any]] = []
        tasks = []
        for pkg in packages:
            tasks.append(
                self.osv.query_package(
                    pkg["name"],
                    pkg["version"],
                    pkg.get("package_manager", ""),
                )
            )
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for pkg, osv_results in zip(packages, results):
            if isinstance(osv_results, Exception):
                logger.warning("OSV query failed for %s: %s", pkg["name"], osv_results)
                continue
            for osv_vuln in osv_results:
                # Prefer CVE alias; fall back to OSV ID
                osv_id = osv_vuln.get("id", "")
                aliases = osv_vuln.get("aliases", [])
                cve_id = next((a for a in aliases if a.startswith("CVE-")), osv_id)

                # Upsert the vulnerability record
                parsed = self.osv.parse_osv(osv_vuln)
                parsed["id"] = cve_id

                result = await db.execute(select(Vulnerability).where(Vulnerability.id == cve_id))
                existing = result.scalar_one_or_none()
                if existing is None:
                    db.add(Vulnerability(**parsed))
                    await db.flush()

                # If it's a CVE, also enrich from NVD for CVSS scores.
                # Force refresh for newly created records — they were just added
                # from OSV data which never carries a numerical CVSS score, so
                # the stale-time check would incorrectly skip the NVD fetch.
                if cve_id.startswith("CVE-"):
                    await self.get_or_fetch_cve(
                        db, cve_id, force_refresh=(existing is None)
                    )

                findings.append({
                    "vulnerability_id": cve_id,
                    "package_name": pkg["name"],
                    "version": pkg["version"],
                    "source": "osv",
                    "finding_type": "package",
                })

        return findings

    async def enrich_cpes(
        self,
        db: AsyncSession,
        cpes: list[str],
    ) -> list[dict[str, Any]]:
        """
        For a list of CPE strings (from network service detection),
        query NVD for matching CVEs.
        """
        findings: list[dict[str, Any]] = []
        for cpe in cpes:
            cves = await self.nvd.search_by_cpe(cpe)
            for raw in cves:
                parsed = self.nvd.parse_cve(raw)
                cve_id = parsed["id"]
                result = await db.execute(select(Vulnerability).where(Vulnerability.id == cve_id))
                existing = result.scalar_one_or_none()
                if existing is None:
                    db.add(Vulnerability(**parsed))
                    await db.flush()
                findings.append({
                    "vulnerability_id": cve_id,
                    "cpe": cpe,
                    "source": "nvd",
                    "finding_type": "network",
                })
        return findings

    async def attach_epss_scores(
        self,
        db: AsyncSession,
        cve_ids: list[str],
    ) -> dict[str, tuple[float, float]]:
        """
        Bulk-fetch EPSS scores for a list of CVE IDs, upsert EPSSScore records,
        and return a mapping of {cve_id: (epss_score, percentile)} so callers
        can use the scores immediately without a second DB query.
        """
        # Deduplicate and filter to real CVE IDs only
        cve_only = list({c for c in cve_ids if c.startswith("CVE-")})
        if not cve_only:
            logger.info("EPSS: no CVE-prefixed IDs in batch of %d — skipping", len(cve_ids))
            return {}

        logger.info("EPSS: fetching scores for %d unique CVE IDs", len(cve_only))
        scores = await self.epss.fetch_scores(cve_only)
        logger.info("EPSS: received scores for %d / %d CVEs", len(scores), len(cve_only))

        live_scores: dict[str, tuple[float, float]] = {}

        for cve_id, score_data in scores.items():
            epss_val = score_data["epss"]
            pct_val = score_data["percentile"]
            live_scores[cve_id] = (epss_val, pct_val)

            scored_at_str = score_data.get("date")
            scored_at = (
                datetime.fromisoformat(scored_at_str) if scored_at_str
                else datetime.utcnow()
            )

            try:
                result = await db.execute(select(EPSSScore).where(EPSSScore.cve_id == cve_id))
                existing = result.scalar_one_or_none()
                if existing is None:
                    db.add(EPSSScore(
                        cve_id=cve_id,
                        epss_score=epss_val,
                        percentile=pct_val,
                        model_version=score_data.get("model_version"),
                        scored_at=scored_at,
                    ))
                else:
                    existing.epss_score = epss_val
                    existing.percentile = pct_val
                    existing.scored_at = scored_at
                    existing.fetched_at = datetime.utcnow()
            except Exception as exc:
                logger.warning("EPSS: failed to upsert score for %s: %s", cve_id, exc)

        if live_scores:
            try:
                await db.flush()
            except Exception as exc:
                logger.warning("EPSS: flush failed, scores held in memory only: %s", exc)

        return live_scores
