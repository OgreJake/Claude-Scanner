"""
Async SSH transport using asyncssh.

Supports:
  - Password authentication
  - Private key authentication (PEM from 1Password)
  - Known-hosts validation (optional, configurable per deployment)
  - Command execution with timeout
  - File download via SFTP
"""

from __future__ import annotations

import logging
from io import BytesIO
from typing import Optional

import asyncssh

from server.core.transport.base import BaseTransport, CommandResult, TransportError
from server.config import settings

logger = logging.getLogger(__name__)


class SSHTransport(BaseTransport):
    def __init__(
        self,
        host: str,
        port: int = 22,
        username: str = "root",
        password: Optional[str] = None,
        private_key: Optional[str] = None,     # PEM string
        key_passphrase: Optional[str] = None,
        known_hosts: Optional[str] = None,      # path or None to disable checking
        connect_timeout: int = 30,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.private_key_pem = private_key
        self.key_passphrase = key_passphrase
        self.known_hosts = known_hosts
        self.connect_timeout = connect_timeout
        self._conn: Optional[asyncssh.SSHClientConnection] = None

    async def connect(self) -> None:
        kwargs: dict = {
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "connect_timeout": self.connect_timeout,
            "known_hosts": self.known_hosts,  # None = disable host key checking
        }

        if self.private_key_pem:
            try:
                key = asyncssh.import_private_key(
                    self.private_key_pem,
                    passphrase=self.key_passphrase,
                )
                kwargs["client_keys"] = [key]
                kwargs["preferred_auth"] = "publickey"
            except (asyncssh.KeyImportError, ValueError) as exc:
                raise TransportError(f"Failed to import SSH private key for {self.host}: {exc}") from exc
        elif self.password:
            kwargs["password"] = self.password
            kwargs["preferred_auth"] = "password,keyboard-interactive"
        else:
            raise TransportError(f"No authentication credentials provided for {self.host}")

        try:
            self._conn = await asyncssh.connect(**kwargs)
            logger.debug("SSH connected to %s:%d as %s", self.host, self.port, self.username)
        except asyncssh.DisconnectError as exc:
            raise TransportError(f"SSH connection refused by {self.host}: {exc}") from exc
        except asyncssh.PermissionDenied as exc:
            raise TransportError(f"SSH authentication failed for {self.host}: {exc}") from exc
        except TimeoutError as exc:
            raise TransportError(f"SSH connection timed out to {self.host}") from exc
        except Exception as exc:
            raise TransportError(f"SSH connection failed to {self.host}: {exc}") from exc

    async def run(self, command: str, timeout: int = 60) -> CommandResult:
        if self._conn is None:
            raise TransportError("Not connected. Call connect() first.")
        try:
            result = await self._conn.run(command, timeout=timeout, check=False)
            return CommandResult(
                stdout=result.stdout or "",
                stderr=result.stderr or "",
                exit_code=result.exit_status or 0,
            )
        except asyncssh.TimeoutError:
            raise TransportError(f"Command timed out on {self.host}: {command!r}")
        except asyncssh.ChannelOpenError as exc:
            raise TransportError(f"SSH channel error on {self.host}: {exc}") from exc

    async def run_sudo(self, command: str, timeout: int = 60) -> CommandResult:
        """Run a command with sudo (password-less sudo expected)."""
        return await self.run(f"sudo -n {command}", timeout=timeout)

    async def read_file(self, path: str) -> bytes:
        if self._conn is None:
            raise TransportError("Not connected.")
        try:
            async with self._conn.start_sftp_client() as sftp:
                buf = BytesIO()
                await sftp.getfo(path, buf)
                return buf.getvalue()
        except asyncssh.SFTPError as exc:
            raise TransportError(f"SFTP read failed for {path} on {self.host}: {exc}") from exc

    async def close(self) -> None:
        if self._conn:
            self._conn.close()
            await self._conn.wait_closed()
            self._conn = None
            logger.debug("SSH disconnected from %s", self.host)
