"""
Windows package and OS info parser.

Uses PowerShell commands over WinRM to enumerate:
  - Installed software via Win32_Product and Uninstall registry keys
  - Windows Updates via Get-HotFix and Windows Update COM API
  - OS information via Get-ComputerInfo / WMI
"""

from __future__ import annotations

import json
import re

from server.core.parsers.base import BaseParser, ParsedOSInfo, ParsedPackage


class WindowsParser(BaseParser):
    @property
    def os_type(self) -> str:
        return "windows"

    def os_info_commands(self) -> list[str]:
        return [
            # OS info as JSON
            r"""
$os = Get-WmiObject -Class Win32_OperatingSystem
[PSCustomObject]@{
    Caption     = $os.Caption
    Version     = $os.Version
    BuildNumber = $os.BuildNumber
    OSArch      = $os.OSArchitecture
    Hostname    = $env:COMPUTERNAME
} | ConvertTo-Json -Compress
""".strip(),
        ]

    def package_commands(self) -> list[str]:
        return [
            # Installed apps from both 32-bit and 64-bit registry uninstall keys
            r"""
$paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$apps = foreach ($path in $paths) {
    try {
        Get-ItemProperty $path -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -and $_.DisplayVersion } |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
    } catch {}
}
$apps | Select-Object -Unique * | ConvertTo-Json -Compress -Depth 2
""".strip(),
            # Installed Windows Updates / hotfixes
            r"""
Get-HotFix | Select-Object HotFixID, Description, InstalledOn |
ConvertTo-Json -Compress -Depth 2
""".strip(),
            # Windows features (optional components)
            r"""
try {
    Get-WindowsOptionalFeature -Online |
    Where-Object { $_.State -eq 'Enabled' } |
    Select-Object FeatureName, State |
    ConvertTo-Json -Compress -Depth 2
} catch { '[]' }
""".strip(),
        ]

    def parse_os_info(self, outputs: dict[str, str]) -> ParsedOSInfo:
        info = ParsedOSInfo(os_type="windows")
        for cmd, output in outputs.items():
            if not output.strip():
                continue
            try:
                data = json.loads(output.strip())
                info.os_name = data.get("Caption", "Windows")
                info.os_version = data.get("Version", "")
                info.os_build = data.get("BuildNumber", "")
                arch = data.get("OSArch", "")
                info.architecture = "x86_64" if "64" in arch else "x86"
                info.hostname = data.get("Hostname", "")
            except (json.JSONDecodeError, AttributeError):
                continue
        return info

    def parse_packages(self, outputs: dict[str, str]) -> list[ParsedPackage]:
        packages: list[ParsedPackage] = []
        seen: set[tuple[str, str]] = set()

        for cmd, output in outputs.items():
            if not output.strip():
                continue

            if "Uninstall" in cmd or "registry" in cmd.lower():
                packages.extend(self._parse_registry_apps(output, seen))
            elif "Get-HotFix" in cmd or "HotFix" in cmd:
                packages.extend(self._parse_hotfixes(output, seen))
            elif "WindowsOptionalFeature" in cmd or "FeatureName" in cmd:
                packages.extend(self._parse_features(output, seen))

        return packages

    def _parse_registry_apps(self, output: str, seen: set) -> list[ParsedPackage]:
        pkgs = []
        try:
            raw = json.loads(output.strip())
            # May be a single object or a list
            if isinstance(raw, dict):
                raw = [raw]
            for item in raw:
                if not isinstance(item, dict):
                    continue
                name = item.get("DisplayName") or ""
                version = item.get("DisplayVersion") or ""
                vendor = item.get("Publisher") or ""
                install_date = item.get("InstallDate") or None
                if not name:
                    continue
                key = (name, version)
                if key in seen:
                    continue
                seen.add(key)
                pkgs.append(ParsedPackage(
                    name=name,
                    version=version,
                    vendor=vendor,
                    package_manager="msi",
                    install_date=install_date,
                ))
        except (json.JSONDecodeError, TypeError):
            pass
        return pkgs

    def _parse_hotfixes(self, output: str, seen: set) -> list[ParsedPackage]:
        pkgs = []
        try:
            raw = json.loads(output.strip())
            if isinstance(raw, dict):
                raw = [raw]
            for item in raw:
                if not isinstance(item, dict):
                    continue
                hotfix_id = item.get("HotFixID") or ""
                description = item.get("Description") or "Windows Update"
                installed_on = item.get("InstalledOn") or None
                if not hotfix_id:
                    continue
                key = (hotfix_id, "")
                if key in seen:
                    continue
                seen.add(key)
                pkgs.append(ParsedPackage(
                    name=hotfix_id,
                    version=description,
                    vendor="Microsoft",
                    package_manager="windows_update",
                    install_date=installed_on,
                ))
        except (json.JSONDecodeError, TypeError):
            pass
        return pkgs

    def _parse_features(self, output: str, seen: set) -> list[ParsedPackage]:
        pkgs = []
        try:
            raw = json.loads(output.strip())
            if isinstance(raw, dict):
                raw = [raw]
            for item in raw:
                if not isinstance(item, dict):
                    continue
                name = item.get("FeatureName") or ""
                if not name:
                    continue
                key = (name, "enabled")
                if key in seen:
                    continue
                seen.add(key)
                pkgs.append(ParsedPackage(
                    name=name,
                    version="enabled",
                    package_manager="windows_feature",
                    vendor="Microsoft",
                ))
        except (json.JSONDecodeError, TypeError):
            pass
        return pkgs
