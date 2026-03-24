"""Base classes for OS-specific package and system info parsers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ParsedPackage:
    name: str
    version: str
    arch: str = ""
    package_manager: str = ""
    vendor: str = ""
    cpe: str = ""
    install_date: Optional[str] = None  # ISO8601 string if available


@dataclass
class ParsedOSInfo:
    os_type: str = "unknown"      # linux | windows | darwin | unix
    os_name: str = ""             # "Ubuntu 22.04 LTS"
    os_version: str = ""          # "22.04"
    os_build: str = ""            # Windows build number etc.
    architecture: str = ""        # x86_64 | arm64
    kernel_version: str = ""
    hostname: str = ""


class BaseParser(ABC):
    """
    Parses raw command output collected from a remote host.
    Each OS subclass implements the commands to run and how to parse their output.
    """

    @property
    @abstractmethod
    def os_type(self) -> str:
        """Return the OS type string: linux | windows | darwin | unix."""

    @abstractmethod
    def os_info_commands(self) -> list[str]:
        """Return list of commands to collect OS info."""

    @abstractmethod
    def package_commands(self) -> list[str]:
        """Return list of commands to enumerate installed packages."""

    @abstractmethod
    def parse_os_info(self, outputs: dict[str, str]) -> ParsedOSInfo:
        """Parse OS info from command outputs. Key = command, value = stdout."""

    @abstractmethod
    def parse_packages(self, outputs: dict[str, str]) -> list[ParsedPackage]:
        """Parse installed packages from command outputs."""
