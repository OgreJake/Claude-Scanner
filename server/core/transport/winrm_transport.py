"""
WinRM transport for Windows hosts.

Runs PowerShell commands over WinRM (HTTP/HTTPS).
Auth: NTLM (default), Kerberos, or Basic.
"""

from __future__ import annotations

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

import winrm
from winrm.exceptions import AuthenticationError, WinRMError, WinRMTransportError

from server.core.transport.base import BaseTransport, CommandResult, TransportError

logger = logging.getLogger(__name__)

# WinRM is synchronous; we run it in a thread pool to avoid blocking asyncio.
_executor = ThreadPoolExecutor(max_workers=50, thread_name_prefix="winrm")


class WinRMTransport(BaseTransport):
    def __init__(
        self,
        host: str,
        port: int = 5985,
        username: str = "",
        password: str = "",
        use_ssl: bool = False,
        auth_method: str = "ntlm",   # ntlm | kerberos | basic
        connect_timeout: int = 30,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self.auth_method = auth_method
        self.connect_timeout = connect_timeout
        self._session: Optional[winrm.Session] = None

    async def connect(self) -> None:
        """Build WinRM session (lazy — actual connection happens on first command)."""
        protocol = "https" if self.use_ssl else "http"
        endpoint = f"{protocol}://{self.host}:{self.port}/wsman"
        try:
            self._session = winrm.Session(
                endpoint,
                auth=(self.username, self.password),
                transport=self.auth_method,
                read_timeout_sec=self.connect_timeout + 30,
                operation_timeout_sec=self.connect_timeout,
            )
            logger.debug("WinRM session created for %s:%d (%s)", self.host, self.port, self.auth_method)
        except Exception as exc:
            raise TransportError(f"WinRM session setup failed for {self.host}: {exc}") from exc

    async def run(self, command: str, timeout: int = 60) -> CommandResult:
        """Execute a PowerShell command."""
        if self._session is None:
            raise TransportError("Not connected. Call connect() first.")

        def _run_sync():
            try:
                # Use PowerShell for all commands
                result = self._session.run_ps(command)
                return CommandResult(
                    stdout=result.std_out.decode("utf-8", errors="replace"),
                    stderr=result.std_err.decode("utf-8", errors="replace"),
                    exit_code=result.status_code,
                )
            except AuthenticationError as exc:
                raise TransportError(f"WinRM authentication failed for {self.host}: {exc}") from exc
            except WinRMTransportError as exc:
                raise TransportError(f"WinRM transport error on {self.host}: {exc}") from exc
            except WinRMError as exc:
                raise TransportError(f"WinRM error on {self.host}: {exc}") from exc

        loop = asyncio.get_event_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(_executor, _run_sync),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            raise TransportError(f"WinRM command timed out on {self.host}: {command!r}")

    async def run_cmd(self, command: str, timeout: int = 60) -> CommandResult:
        """Execute a cmd.exe command (non-PowerShell)."""
        if self._session is None:
            raise TransportError("Not connected.")

        def _run_sync():
            try:
                result = self._session.run_cmd(command)
                return CommandResult(
                    stdout=result.std_out.decode("utf-8", errors="replace"),
                    stderr=result.std_err.decode("utf-8", errors="replace"),
                    exit_code=result.status_code,
                )
            except WinRMError as exc:
                raise TransportError(f"WinRM cmd error: {exc}") from exc

        loop = asyncio.get_event_loop()
        return await asyncio.wait_for(
            loop.run_in_executor(_executor, _run_sync),
            timeout=timeout,
        )

    async def read_file(self, path: str) -> bytes:
        """Read a remote file via PowerShell Get-Content -Encoding Byte."""
        result = await self.run(
            f"[System.IO.File]::ReadAllBytes('{path}') | "
            f"ForEach-Object {{ $_.ToString('X2') }} | "
            f"Write-Output"
        )
        if not result.succeeded:
            raise TransportError(f"Failed to read {path} on {self.host}: {result.stderr}")
        hex_str = result.stdout.replace("\r\n", "").replace("\n", "").strip()
        return bytes.fromhex(hex_str)

    async def close(self) -> None:
        self._session = None
        logger.debug("WinRM session closed for %s", self.host)
