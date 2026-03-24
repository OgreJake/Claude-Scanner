"""Abstract base class for host transports (SSH, WinRM, Agent)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class CommandResult:
    stdout: str
    stderr: str
    exit_code: int

    @property
    def succeeded(self) -> bool:
        return self.exit_code == 0


class TransportError(Exception):
    """Raised when a transport-level operation fails."""


class BaseTransport(ABC):
    @abstractmethod
    async def connect(self) -> None:
        """Establish connection to the target host."""

    @abstractmethod
    async def run(self, command: str, timeout: int = 60) -> CommandResult:
        """Execute a command and return stdout/stderr/exit_code."""

    @abstractmethod
    async def read_file(self, path: str) -> bytes:
        """Read a remote file and return its raw contents."""

    @abstractmethod
    async def close(self) -> None:
        """Clean up the connection."""

    async def __aenter__(self) -> "BaseTransport":
        await self.connect()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()
