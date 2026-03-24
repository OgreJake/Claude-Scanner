"""
Generic Unix (FreeBSD, OpenBSD, NetBSD, Solaris/Illumos) parser.

Package managers covered:
  - pkg (FreeBSD pkg-ng)
  - pkg_info (FreeBSD legacy / OpenBSD / NetBSD)
  - pkgin (NetBSD binary packages)
  - IPS pkg (Oracle Solaris / OmniOS)
"""

from __future__ import annotations

import re

from server.core.parsers.base import BaseParser, ParsedOSInfo, ParsedPackage


class UnixParser(BaseParser):
    @property
    def os_type(self) -> str:
        return "unix"

    def os_info_commands(self) -> list[str]:
        return [
            "uname -a",
            "uname -m",
            "hostname",
            # FreeBSD
            "freebsd-version 2>/dev/null",
            # Solaris
            "cat /etc/release 2>/dev/null",
            # Generic
            "cat /etc/os-release 2>/dev/null",
        ]

    def package_commands(self) -> list[str]:
        return [
            # FreeBSD pkg-ng
            "pkg info -a --raw 2>/dev/null | awk '/^name:/{name=$2} /^version:/{print name\"\\t\"$2}' 2>/dev/null",
            # Legacy pkg_info (OpenBSD / old FreeBSD)
            "pkg_info 2>/dev/null",
            # pkgin (NetBSD)
            "pkgin list 2>/dev/null",
            # Solaris IPS
            "pkg list -H 2>/dev/null",
        ]

    def parse_os_info(self, outputs: dict[str, str]) -> ParsedOSInfo:
        info = ParsedOSInfo(os_type="unix")
        for cmd, output in outputs.items():
            output = output.strip()
            if not output:
                continue
            if "uname -a" in cmd:
                parts = output.split()
                if parts:
                    info.hostname = parts[1] if len(parts) > 1 else ""
                    info.kernel_version = parts[2] if len(parts) > 2 else ""
                    # Detect OS from uname
                    sysname = parts[0] if parts else ""
                    if "FreeBSD" in sysname:
                        info.os_name = f"FreeBSD {parts[2]}" if len(parts) > 2 else "FreeBSD"
                    elif "OpenBSD" in sysname:
                        info.os_name = f"OpenBSD {parts[2]}" if len(parts) > 2 else "OpenBSD"
                    elif "NetBSD" in sysname:
                        info.os_name = f"NetBSD {parts[2]}" if len(parts) > 2 else "NetBSD"
                    elif "SunOS" in sysname:
                        info.os_name = "Solaris/Illumos"
            elif "uname -m" in cmd:
                info.architecture = output
            elif "freebsd-version" in cmd and output:
                info.os_version = output
            elif "cat /etc/release" in cmd and "Oracle Solaris" in output:
                info.os_name = output.splitlines()[0].strip() if output else info.os_name
        return info

    def parse_packages(self, outputs: dict[str, str]) -> list[ParsedPackage]:
        packages: list[ParsedPackage] = []
        seen: set[tuple[str, str]] = set()

        for cmd, output in outputs.items():
            if not output.strip():
                continue
            if "pkg info" in cmd and "--raw" in cmd:
                packages.extend(self._parse_freebsd_pkg(output, seen))
            elif "pkg_info" in cmd:
                packages.extend(self._parse_pkg_info(output, seen))
            elif "pkgin list" in cmd:
                packages.extend(self._parse_pkgin(output, seen))
            elif "pkg list" in cmd:
                packages.extend(self._parse_solaris_ips(output, seen))

        return packages

    def _parse_freebsd_pkg(self, output: str, seen: set) -> list[ParsedPackage]:
        pkgs = []
        for line in output.splitlines():
            parts = line.split("\t")
            if len(parts) != 2:
                continue
            name, version = parts[0].strip(), parts[1].strip()
            key = (name, version)
            if key in seen:
                continue
            seen.add(key)
            pkgs.append(ParsedPackage(name=name, version=version, package_manager="pkg"))
        return pkgs

    def _parse_pkg_info(self, output: str, seen: set) -> list[ParsedPackage]:
        pkgs = []
        for line in output.splitlines():
            # Format: "name-version  description"
            m = re.match(r"^([a-zA-Z0-9_\-+.]+)-(\d[\w.+_\-]*)(?:\s|$)", line)
            if m:
                name, version = m.group(1), m.group(2)
                key = (name, version)
                if key in seen:
                    continue
                seen.add(key)
                pkgs.append(ParsedPackage(name=name, version=version, package_manager="pkg_info"))
        return pkgs

    def _parse_pkgin(self, output: str, seen: set) -> list[ParsedPackage]:
        pkgs = []
        for line in output.splitlines():
            m = re.match(r"^([a-zA-Z0-9_\-+.]+)-(\d[\w.+_\-]*)(?:\s|$)", line)
            if m:
                name, version = m.group(1), m.group(2)
                key = (name, version)
                if key in seen:
                    continue
                seen.add(key)
                pkgs.append(ParsedPackage(name=name, version=version, package_manager="pkgin"))
        return pkgs

    def _parse_solaris_ips(self, output: str, seen: set) -> list[ParsedPackage]:
        pkgs = []
        for line in output.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            # Format: "pkg:/name@version,5.11-0.175.3.0.0.30.1:20151201T164048Z i--"
            pkg_str = parts[0]
            m = re.match(r"(?:pkg:/)?([^@]+)@([\d.\-,]+)", pkg_str)
            if m:
                name = m.group(1).split("/")[-1]  # strip category prefix
                version = m.group(2).split(",")[0]  # strip build tag
                key = (name, version)
                if key in seen:
                    continue
                seen.add(key)
                pkgs.append(ParsedPackage(name=name, version=version, package_manager="ips"))
        return pkgs
