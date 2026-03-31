"""
IBM i (AS/400) parser — connects via SSH to the PASE environment.

IBM i exposes a PASE (Portable App Solutions Environment) Unix-like shell
over SSH.  Most standard Unix commands work; IBM i-specific inventory is
queried via the PASE `db2` CLI which can reach the system catalog in QSYS2.

Key differences from Linux:
  - `uname -s` returns "OS400"
  - Licensed programs are enumerated from QSYS2.PRODUCT_INFO
  - PTFs (security patches) are enumerated from QSYS2.PTF_INFO
  - No package manager (dpkg/rpm/etc.); each licensed program is treated
    as a "package" with its release level as the version.
"""

from __future__ import annotations

import re
from typing import Optional

from server.core.parsers.base import BaseParser, ParsedOSInfo, ParsedPackage


class IBMiParser(BaseParser):
    @property
    def os_type(self) -> str:
        return "ibmi"

    def os_info_commands(self) -> list[str]:
        return [
            "uname -s",                                             # OS400
            "uname -r",                                             # release e.g. 7.5
            "uname -m",                                             # machine type
            "hostname",
            # IBM i release from system value (PASE system command)
            "system 'DSPSYSVAL SYSVAL(QRLRLS)' 2>/dev/null | head -5",
        ]

    def package_commands(self) -> list[str]:
        return [
            # Licensed programs — treated as "packages"
            (
                "db2 \"SELECT TRIM(PRODUCT_ID), TRIM(PRODUCT_OPTION), "
                "TRIM(RELEASE_LEVEL), TRIM(DESCRIPTION) "
                "FROM QSYS2.PRODUCT_INFO "
                "FETCH FIRST 1000 ROWS ONLY\" 2>/dev/null"
            ),
            # PTFs — security patches; used for CVE correlation
            (
                "db2 \"SELECT TRIM(PTF_IDENTIFIER), TRIM(PTF_PRODUCT_ID), "
                "TRIM(PTF_PRODUCT_RELEASE_LEVEL), PTF_STATUS "
                "FROM QSYS2.PTF_INFO "
                "FETCH FIRST 2000 ROWS ONLY\" 2>/dev/null"
            ),
            # Open-source packages installed under /QOpenSys (yum/dnf on IBM i)
            "rpm -qa --queryformat '%{NAME}\\t%{VERSION}\\t%{ARCH}\\n' 2>/dev/null",
        ]

    def parse_os_info(self, outputs: dict[str, str]) -> ParsedOSInfo:
        uname_s = ""
        uname_r = ""
        uname_m = ""
        hostname = ""

        for cmd, out in outputs.items():
            stripped = out.strip()
            if "uname -s" in cmd:
                uname_s = stripped
            elif "uname -r" in cmd:
                uname_r = stripped
            elif "uname -m" in cmd:
                uname_m = stripped
            elif "hostname" in cmd and "DSPSYSVAL" not in cmd:
                hostname = stripped.split("\n")[0].strip()

        return ParsedOSInfo(
            os_type="ibmi",
            os_name=f"IBM i {uname_r}".strip() if uname_r else "IBM i",
            os_version=uname_r,
            architecture=uname_m or "unknown",
            hostname=hostname,
        )

    def parse_packages(self, outputs: dict[str, str]) -> list[ParsedPackage]:
        packages: list[ParsedPackage] = []

        for cmd, out in outputs.items():
            if not out.strip():
                continue

            if "QSYS2.PRODUCT_INFO" in cmd:
                packages.extend(self._parse_licensed_programs(out))
            elif "QSYS2.PTF_INFO" in cmd:
                packages.extend(self._parse_ptfs(out))
            elif "rpm -qa" in cmd:
                packages.extend(self._parse_rpm(out))

        return packages

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_licensed_programs(self, output: str) -> list[ParsedPackage]:
        """Parse db2 SELECT output from QSYS2.PRODUCT_INFO."""
        pkgs: list[ParsedPackage] = []
        for line in output.splitlines():
            # db2 output rows are separated by whitespace columns; typical format:
            # 5770SS1   *BASE   V7R5M0   IBM i Operating System
            parts = line.split(None, 3)
            if len(parts) < 3:
                continue
            product_id, option, release, *rest = parts
            # Skip header/separator lines
            if product_id in ("-", "PRODUCT_ID", "") or "---" in product_id:
                continue
            description = rest[0].strip() if rest else ""
            pkgs.append(ParsedPackage(
                name=f"{product_id}-{option}" if option != "*BASE" else product_id,
                version=release,
                package_manager="ibmi-licensed",
                vendor="IBM",
                cpe=f"cpe:2.3:a:ibm:{product_id.lower()}:{release}:*:*:*:*:ibmi:*:*",
            ))
        return pkgs

    def _parse_ptfs(self, output: str) -> list[ParsedPackage]:
        """Parse db2 SELECT output from QSYS2.PTF_INFO."""
        pkgs: list[ParsedPackage] = []
        for line in output.splitlines():
            parts = line.split(None, 3)
            if len(parts) < 3:
                continue
            ptf_id, product_id, release, *rest = parts
            if ptf_id in ("-", "PTF_IDENTIFIER", "") or "---" in ptf_id:
                continue
            ptf_status = rest[0].strip() if rest else ""
            # Only report applied PTFs as installed packages
            if ptf_status and ptf_status not in ("APPLIED", "PERMANENTLY APPLIED", ""):
                continue
            pkgs.append(ParsedPackage(
                name=ptf_id,
                version=release,
                package_manager="ibmi-ptf",
                vendor="IBM",
            ))
        return pkgs

    def _parse_rpm(self, output: str) -> list[ParsedPackage]:
        """Parse rpm -qa output (open-source packages installed under /QOpenSys)."""
        pkgs: list[ParsedPackage] = []
        for line in output.splitlines():
            parts = line.strip().split("\t")
            if len(parts) < 2:
                continue
            name, version, *arch_parts = parts
            pkgs.append(ParsedPackage(
                name=name,
                version=version,
                arch=arch_parts[0] if arch_parts else "",
                package_manager="rpm",
            ))
        return pkgs
