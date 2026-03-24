"""
Linux package and OS info parser.

Supports:
  - dpkg  (Debian, Ubuntu, Raspberry Pi OS)
  - rpm   (RHEL, CentOS, AlmaLinux, Rocky, Fedora, SUSE)
  - apk   (Alpine Linux)
  - pacman (Arch Linux)
  - snap  (supplementary)
  - flatpak (supplementary)
"""

from __future__ import annotations

import re
from typing import Optional

from server.core.parsers.base import BaseParser, ParsedOSInfo, ParsedPackage


class LinuxParser(BaseParser):
    @property
    def os_type(self) -> str:
        return "linux"

    def os_info_commands(self) -> list[str]:
        return [
            "cat /etc/os-release 2>/dev/null || cat /etc/lsb-release 2>/dev/null",
            "uname -r",
            "uname -m",
            "hostname -f 2>/dev/null || hostname",
        ]

    def package_commands(self) -> list[str]:
        return [
            # dpkg — Debian/Ubuntu
            "dpkg-query -W -f='${Package}\\t${Version}\\t${Architecture}\\t${Status}\\n' 2>/dev/null",
            # rpm — RHEL/CentOS/Fedora/SUSE
            "rpm -qa --queryformat '%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\t%{VENDOR}\\t%{INSTALLTIME:date}\\n' 2>/dev/null",
            # apk — Alpine
            "apk info -v 2>/dev/null",
            # pacman — Arch
            "pacman -Q 2>/dev/null",
            # snap
            "snap list 2>/dev/null",
            # flatpak
            "flatpak list --columns=application,version 2>/dev/null",
        ]

    def parse_os_info(self, outputs: dict[str, str]) -> ParsedOSInfo:
        info = ParsedOSInfo(os_type="linux")

        # /etc/os-release
        os_release_raw = next(
            (v for k, v in outputs.items() if "os-release" in k or "lsb-release" in k),
            ""
        )
        os_data: dict[str, str] = {}
        for line in os_release_raw.splitlines():
            if "=" in line:
                key, _, value = line.partition("=")
                os_data[key.strip()] = value.strip().strip('"')

        info.os_name = os_data.get("PRETTY_NAME") or os_data.get("NAME", "Linux")
        info.os_version = os_data.get("VERSION_ID") or os_data.get("DISTRIB_RELEASE", "")

        # uname -r
        for cmd, out in outputs.items():
            if "uname -r" in cmd:
                info.kernel_version = out.strip()
            elif "uname -m" in cmd:
                info.architecture = out.strip()
            elif "hostname" in cmd:
                info.hostname = out.strip().split("\n")[0]

        return info

    def parse_packages(self, outputs: dict[str, str]) -> list[ParsedPackage]:
        packages: list[ParsedPackage] = []
        seen: set[tuple[str, str]] = set()

        for cmd, output in outputs.items():
            if not output.strip():
                continue

            if "dpkg-query" in cmd:
                packages.extend(self._parse_dpkg(output, seen))
            elif "rpm -qa" in cmd:
                packages.extend(self._parse_rpm(output, seen))
            elif "apk info" in cmd:
                packages.extend(self._parse_apk(output, seen))
            elif "pacman -Q" in cmd:
                packages.extend(self._parse_pacman(output, seen))
            elif "snap list" in cmd:
                packages.extend(self._parse_snap(output, seen))
            elif "flatpak list" in cmd:
                packages.extend(self._parse_flatpak(output, seen))

        return packages

    def _parse_dpkg(self, output: str, seen: set) -> list[ParsedPackage]:
        pkgs = []
        for line in output.splitlines():
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            name, version, arch = parts[0], parts[1], parts[2]
            status = parts[3] if len(parts) > 3 else ""
            # Only include installed packages
            if "install ok installed" not in status and status:
                continue
            key = (name, version)
            if key in seen:
                continue
            seen.add(key)
            pkgs.append(ParsedPackage(
                name=name,
                version=version,
                arch=arch,
                package_manager="dpkg",
            ))
        return pkgs

    def _parse_rpm(self, output: str, seen: set) -> list[ParsedPackage]:
        pkgs = []
        for line in output.splitlines():
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            name = parts[0]
            version = parts[1] if len(parts) > 1 else ""
            arch = parts[2] if len(parts) > 2 else ""
            vendor = parts[3] if len(parts) > 3 else ""
            key = (name, version)
            if key in seen:
                continue
            seen.add(key)
            pkgs.append(ParsedPackage(
                name=name,
                version=version,
                arch=arch,
                vendor=vendor,
                package_manager="rpm",
            ))
        return pkgs

    def _parse_apk(self, output: str, seen: set) -> list[ParsedPackage]:
        pkgs = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            # Format: "name-version" e.g. "musl-1.2.4-r2"
            # Find last occurrence of "-" followed by a digit
            m = re.match(r"^(.+)-(\d[\w.\-+]*)$", line)
            if m:
                name, version = m.group(1), m.group(2)
            else:
                name, version = line, ""
            key = (name, version)
            if key in seen:
                continue
            seen.add(key)
            pkgs.append(ParsedPackage(name=name, version=version, package_manager="apk"))
        return pkgs

    def _parse_pacman(self, output: str, seen: set) -> list[ParsedPackage]:
        pkgs = []
        for line in output.splitlines():
            parts = line.split()
            if len(parts) != 2:
                continue
            name, version = parts
            key = (name, version)
            if key in seen:
                continue
            seen.add(key)
            pkgs.append(ParsedPackage(name=name, version=version, package_manager="pacman"))
        return pkgs

    def _parse_snap(self, output: str, seen: set) -> list[ParsedPackage]:
        pkgs = []
        lines = output.splitlines()
        for line in lines[1:]:  # skip header
            parts = line.split()
            if len(parts) < 2:
                continue
            name, version = parts[0], parts[1]
            key = (name, version)
            if key in seen:
                continue
            seen.add(key)
            pkgs.append(ParsedPackage(name=name, version=version, package_manager="snap"))
        return pkgs

    def _parse_flatpak(self, output: str, seen: set) -> list[ParsedPackage]:
        pkgs = []
        for line in output.splitlines():
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            name, version = parts[0].strip(), parts[1].strip()
            key = (name, version)
            if key in seen:
                continue
            seen.add(key)
            pkgs.append(ParsedPackage(name=name, version=version, package_manager="flatpak"))
        return pkgs
