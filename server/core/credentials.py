"""
Credential manager — retrieves device credentials from 1Password Connect Server
with a fallback to interactive prompting or environment variables.

Usage:
    manager = CredentialManager()
    creds = await manager.get_credentials(device)
    # creds.username, creds.password, creds.ssh_key, creds.ssh_key_passphrase
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Optional

import httpx

from server.config import settings

logger = logging.getLogger(__name__)


@dataclass
class DeviceCredentials:
    """Resolved credentials for connecting to a target device."""
    username: str
    password: Optional[str] = None
    ssh_key: Optional[str] = None            # PEM-encoded private key
    ssh_key_passphrase: Optional[str] = None
    winrm_auth_type: str = "ntlm"            # ntlm / kerberos / basic
    source: str = "unknown"                  # where these creds came from


@dataclass
class _OPItem:
    """Parsed relevant fields from a 1Password item."""
    username: str = ""
    password: str = ""
    ssh_private_key: str = ""
    ssh_passphrase: str = ""
    notes: str = ""
    extra: dict = field(default_factory=dict)


class CredentialManager:
    """
    Fetches device credentials from 1Password Connect Server.

    Resolution order for a given device:
      1. Look up by credential_ref (item UUID or "vault/item-title") in 1Password.
      2. Fall back to a generic lookup by device hostname in 1Password.
      3. Fall back to environment variables  SCANNER_DEFAULT_USER / SCANNER_DEFAULT_PASS.
      4. If still unresolved, raise CredentialNotFoundError (caller should prompt).
    """

    # 1Password item field labels we recognise
    _USERNAME_LABELS = {"username", "user", "login"}
    _PASSWORD_LABELS = {"password", "pass", "secret"}
    _SSH_KEY_LABELS  = {"private key", "ssh key", "ssh private key", "key"}
    _SSH_PASS_LABELS = {"passphrase", "key passphrase", "ssh passphrase"}

    def __init__(self) -> None:
        self._client: Optional[httpx.AsyncClient] = None
        self._connected = False

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=settings.OP_CONNECT_HOST.rstrip("/"),
                headers={
                    "Authorization": f"Bearer {settings.OP_CONNECT_TOKEN}",
                    "Content-Type": "application/json",
                },
                timeout=10.0,
            )
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def _fetch_item_by_id(self, item_id: str, vault_id: str) -> Optional[_OPItem]:
        """Fetch a specific 1Password item by vault + item UUID."""
        client = await self._get_client()
        try:
            resp = await client.get(f"/v1/vaults/{vault_id}/items/{item_id}")
            resp.raise_for_status()
            return self._parse_op_item(resp.json())
        except httpx.HTTPStatusError as exc:
            logger.warning("1Password item fetch failed: %s", exc)
            return None

    async def _search_items(self, query: str, vault_id: str = "") -> list[dict]:
        """Search 1Password items by title."""
        client = await self._get_client()
        vaults_to_search = [vault_id] if vault_id else await self._list_vault_ids()
        results = []
        for vid in vaults_to_search:
            try:
                resp = await client.get(
                    f"/v1/vaults/{vid}/items",
                    params={"filter": f"title eq \"{query}\""},
                )
                resp.raise_for_status()
                results.extend(resp.json())
            except httpx.HTTPStatusError as exc:
                logger.debug("Search in vault %s failed: %s", vid, exc)
        return results

    async def _list_vault_ids(self) -> list[str]:
        """Return all accessible vault UUIDs."""
        if settings.OP_VAULT_ID:
            return [settings.OP_VAULT_ID]
        client = await self._get_client()
        try:
            resp = await client.get("/v1/vaults")
            resp.raise_for_status()
            return [v["id"] for v in resp.json()]
        except httpx.HTTPStatusError as exc:
            logger.warning("Could not list 1Password vaults: %s", exc)
            return []

    def _parse_op_item(self, item: dict) -> _OPItem:
        """Extract credential fields from a raw 1Password item response."""
        parsed = _OPItem()
        for field_obj in item.get("fields", []):
            label = field_obj.get("label", "").lower()
            value = field_obj.get("value", "") or ""
            if label in self._USERNAME_LABELS:
                parsed.username = value
            elif label in self._PASSWORD_LABELS:
                parsed.password = value
            elif label in self._SSH_KEY_LABELS:
                parsed.ssh_private_key = value
            elif label in self._SSH_PASS_LABELS:
                parsed.ssh_passphrase = value
        return parsed

    async def _resolve_from_op(
        self,
        credential_ref: Optional[str],
        hostname: str,
    ) -> Optional[_OPItem]:
        """
        Try to resolve credentials from 1Password.
        credential_ref format:
          - "<vault_uuid>/<item_uuid>"  → direct lookup
          - "<item_uuid>"               → lookup in default/all vaults
          - None                        → search by hostname
        """
        if not settings.OP_CONNECT_TOKEN:
            logger.debug("1Password Connect token not configured, skipping")
            return None

        vault_id = settings.OP_VAULT_ID

        if credential_ref:
            parts = credential_ref.split("/", 1)
            if len(parts) == 2:
                vault_id, item_id = parts
                return await self._fetch_item_by_id(item_id, vault_id)
            else:
                item_id = parts[0]
                vaults = [vault_id] if vault_id else await self._list_vault_ids()
                for vid in vaults:
                    result = await self._fetch_item_by_id(item_id, vid)
                    if result:
                        return result

        # Fall back to searching by hostname
        logger.debug("Searching 1Password for credentials matching hostname: %s", hostname)
        items = await self._search_items(hostname, vault_id)
        if not items:
            # Try just the short hostname
            short = hostname.split(".")[0]
            items = await self._search_items(short, vault_id)

        if items:
            # Pick best match — prefer exact hostname match
            best = next((i for i in items if i.get("title", "").lower() == hostname.lower()), items[0])
            vids = [vault_id] if vault_id else await self._list_vault_ids()
            for vid in vids:
                result = await self._fetch_item_by_id(best["id"], vid)
                if result:
                    return result

        return None

    async def get_credentials(
        self,
        hostname: str,
        ip_address: str,
        credential_ref: Optional[str] = None,
        os_type: str = "linux",
        override_username: Optional[str] = None,
        override_password: Optional[str] = None,
    ) -> DeviceCredentials:
        """
        Resolve credentials for a target device.

        Parameters
        ----------
        hostname        : Device hostname (used for 1Password search fallback)
        ip_address      : Device IP (used as additional search term)
        credential_ref  : 1Password vault/item reference stored on the Device record
        os_type         : Affects default port/auth type guesses
        override_*      : Explicit credentials (e.g. from CLI prompt)
        """
        # 1. Explicit override (single-host CLI scans)
        if override_username:
            logger.info("Using provided credentials for %s", hostname)
            return DeviceCredentials(
                username=override_username,
                password=override_password,
                source="manual",
            )

        # 2. 1Password Connect
        try:
            op_item = await self._resolve_from_op(credential_ref, hostname)
            if op_item and op_item.username:
                logger.info("Resolved credentials from 1Password for %s", hostname)
                return DeviceCredentials(
                    username=op_item.username,
                    password=op_item.password or None,
                    ssh_key=op_item.ssh_private_key or None,
                    ssh_key_passphrase=op_item.ssh_passphrase or None,
                    winrm_auth_type="ntlm" if os_type == "windows" else "ntlm",
                    source="1password",
                )
        except Exception as exc:
            logger.warning("1Password lookup failed for %s: %s", hostname, exc)

        # 3. Environment variable fallback
        env_user = os.getenv("SCANNER_DEFAULT_USER")
        env_pass = os.getenv("SCANNER_DEFAULT_PASS")
        if env_user:
            logger.info("Using env-var fallback credentials for %s", hostname)
            return DeviceCredentials(
                username=env_user,
                password=env_pass,
                source="env",
            )

        # 4. Cannot resolve
        raise CredentialNotFoundError(
            f"No credentials found for {hostname} ({ip_address}). "
            "Add a 1Password item referencing this host, set the device's "
            "credential_ref field, or set SCANNER_DEFAULT_USER/SCANNER_DEFAULT_PASS "
            "environment variables."
        )

    async def store_credential_ref(self, hostname: str, item_uuid: str, vault_id: str = "") -> str:
        """Return a credential_ref string to store on a Device record."""
        if vault_id:
            return f"{vault_id}/{item_uuid}"
        return item_uuid


class CredentialNotFoundError(Exception):
    """Raised when no credentials can be resolved for a device."""
