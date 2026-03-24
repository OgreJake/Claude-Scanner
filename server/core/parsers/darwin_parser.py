"""
macOS (Darwin) package and OS info parser.

Collects:
  - Homebrew packages (brew)
  - macOS system software via system_profiler
  - App Store apps via pkgutil / system_profiler
  - Python/pip, Node/npm if installed
"""

from __future__ import annotations

import json
import re

from server.core.parsers.base import BaseParser, ParsedOSInfo, ParsedPackage


class DarwinParser(BaseParser):
    @property
    def os_type(self) -> str:
        return "darwin"

    def os_info_commands(self) -> list[str]:
        return [
            "sw_vers",
            "uname -m",
            "hostname",
            "uname -r",
        ]

    def package_commands(self) -> list[str]:
        return [
            # Homebrew formulae
            "brew list --versions 2>/dev/null",
            # Homebrew casks (GUI apps installed via brew)
            "brew list --cask --versions 2>/dev/null",
            # System-level packages via pkgutil
            "pkgutil --pkgs 2>/dev/null | head -500",
            # App versions from pkgutil
            "pkgutil --pkg-info-plist $(pkgutil --pkgs 2>/dev/null | head -100) 2>/dev/null | "
            "grep -A1 'pkg-version' | grep string | sed 's/.*<string>\\(.*\\)<\\/string>/\\1/' 2>/dev/null",
            # system_profiler for installed apps
            "system_profiler SPApplicationsDataType -json 2>/dev/null",
            # pip packages (system python)
            "pip3 list --format=json 2>/dev/null",
            # npm global packages
            "npm list -g --depth=0 --json 2>/dev/null",
        ]

    def parse_os_info(self, outputs: dict[str, str]) -> ParsedOSInfo:
        info = ParsedOSInfo(os_type="darwin")
        for cmd, output in outputs.items():
            output = output.strip()
            if not output:
                continue
            if "sw_vers" in cmd:
                for line in output.splitlines():
                    if "ProductName" in line:
                        info.os_name = line.split(":", 1)[1].strip()
                    elif "ProductVersion" in line:
                        info.os_version = line.split(":", 1)[1].strip()
                    elif "BuildVersion" in line:
                        info.os_build = line.split(":", 1)[1].strip()
            elif "uname -m" in cmd:
                arch = output.strip()
                info.architecture = "arm64" if arch == "arm64" else "x86_64"
            elif "hostname" in cmd and "uname" not in cmd:
                info.hostname = output.split("\n")[0]
            elif "uname -r" in cmd:
                info.kernel_version = output
        return info

    def parse_packages(self, outputs: dict[str, str]) -> list[ParsedPackage]:
        packages: list[ParsedPackage] = []
        seen: set[tuple[str, str]] = set()

        for cmd, output in outputs.items():
            if not output.strip():
                continue
            if "brew list --versions" in cmd and "--cask" not in cmd:
                packages.extend(self._parse_brew(output, seen, cask=False))
            elif "brew list --cask" in cmd:
                packages.extend(self._parse_brew(output, seen, cask=True))
            elif "system_profiler SPApplicationsDataType" in cmd:
                packages.extend(self._parse_system_profiler(output, seen))
            elif "pip3 list" in cmd:
                packages.extend(self._parse_pip(output, seen))
            elif "npm list" in cmd:
                packages.extend(self._parse_npm(output, seen))

        return packages

    def _parse_brew(self, output: str, seen: set, cask: bool = False) -> list[ParsedPackage]:
        pkgs = []
        mgr = "brew-cask" if cask else "brew"
        for line in output.splitlines():
            parts = line.split()
            if not parts:
                continue
            name = parts[0]
            version = parts[1] if len(parts) > 1 else ""
            key = (name, version)
            if key in seen:
                continue
            seen.add(key)
            pkgs.append(ParsedPackage(name=name, version=version, package_manager=mgr))
        return pkgs

    def _parse_system_profiler(self, output: str, seen: set) -> list[ParsedPackage]:
        pkgs = []
        try:
            data = json.loads(output)
            apps = data.get("SPApplicationsDataType", [])
            for app in apps:
                name = app.get("_name", "")
                version = app.get("version", "")
                if not name:
                    continue
                key = (name, version)
                if key in seen:
                    continue
                seen.add(key)
                pkgs.append(ParsedPackage(
                    name=name,
                    version=version,
                    package_manager="macos_app",
                ))
        except (json.JSONDecodeError, TypeError):
            pass
        return pkgs

    def _parse_pip(self, output: str, seen: set) -> list[ParsedPackage]:
        pkgs = []
        try:
            data = json.loads(output)
            for item in data:
                name = item.get("name", "")
                version = item.get("version", "")
                if not name:
                    continue
                key = (name, version)
                if key in seen:
                    continue
                seen.add(key)
                pkgs.append(ParsedPackage(name=name, version=version, package_manager="pip"))
        except (json.JSONDecodeError, TypeError):
            pass
        return pkgs

    def _parse_npm(self, output: str, seen: set) -> list[ParsedPackage]:
        pkgs = []
        try:
            data = json.loads(output)
            deps = data.get("dependencies", {})
            for name, info in deps.items():
                version = info.get("version", "") if isinstance(info, dict) else ""
                key = (name, version)
                if key in seen:
                    continue
                seen.add(key)
                pkgs.append(ParsedPackage(name=name, version=version, package_manager="npm"))
        except (json.JSONDecodeError, TypeError):
            pass
        return pkgs
