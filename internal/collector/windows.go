//go:build windows

package collector

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"

	"github.com/ogrejake/claude-scanner/internal/models"
)

type windowsCollector struct{}

func newPlatformCollector() Collector { return &windowsCollector{} }

func (c *windowsCollector) CollectOSInfo() (*models.OSInfo, error) {
	info := &models.OSInfo{OSType: "windows"}

	script := `
$os = Get-WmiObject -Class Win32_OperatingSystem
[PSCustomObject]@{
    Caption     = $os.Caption
    Version     = $os.Version
    BuildNumber = $os.BuildNumber
    OSArch      = $os.OSArchitecture
    Hostname    = $env:COMPUTERNAME
} | ConvertTo-Json -Compress`

	out, err := runPowerShell(script)
	if err != nil {
		return info, nil
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(out), &data); err == nil {
		if v, ok := data["Caption"].(string); ok {
			info.OSName = v
		}
		if v, ok := data["Version"].(string); ok {
			info.OSVersion = v
		}
		if v, ok := data["BuildNumber"].(string); ok {
			info.OSBuild = v
		}
		if v, ok := data["OSArch"].(string); ok {
			if strings.Contains(v, "64") {
				info.Architecture = "x86_64"
			} else {
				info.Architecture = "x86"
			}
		}
		if v, ok := data["Hostname"].(string); ok {
			info.Hostname = v
		}
	}
	if h, err := os.Hostname(); err == nil && info.Hostname == "" {
		info.Hostname = h
	}
	return info, nil
}

func (c *windowsCollector) CollectPackages() ([]models.PackageInfo, error) {
	script := `
$paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$apps = foreach ($path in $paths) {
    try {
        Get-ItemProperty $path -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -and $_.DisplayVersion } |
        Select-Object DisplayName, DisplayVersion, Publisher
    } catch {}
}
$apps | Select-Object -Unique * | ConvertTo-Json -Compress -Depth 2`

	out, err := runPowerShell(script)
	if err != nil {
		return nil, nil
	}

	var raw []map[string]interface{}
	// May be a single object
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		var single map[string]interface{}
		if err2 := json.Unmarshal([]byte(out), &single); err2 == nil {
			raw = []map[string]interface{}{single}
		}
	}

	var packages []models.PackageInfo
	for _, item := range raw {
		name, _ := item["DisplayName"].(string)
		version, _ := item["DisplayVersion"].(string)
		vendor, _ := item["Publisher"].(string)
		if name == "" {
			continue
		}
		packages = append(packages, models.PackageInfo{
			Name:           name,
			Version:        version,
			Vendor:         vendor,
			PackageManager: "msi",
		})
	}
	return packages, nil
}

func runPowerShell(script string) (string, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
