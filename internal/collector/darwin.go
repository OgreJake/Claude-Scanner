//go:build darwin

package collector

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"strings"

	"github.com/ogrejake/claude-scanner/internal/models"
)

type darwinCollector struct{}

func newPlatformCollector() Collector { return &darwinCollector{} }

func (c *darwinCollector) CollectOSInfo() (*models.OSInfo, error) {
	info := &models.OSInfo{OSType: "darwin"}

	out, err := exec.Command("sw_vers").Output()
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(out))
		for scanner.Scan() {
			line := scanner.Text()
			k, v, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			k = strings.TrimSpace(k)
			v = strings.TrimSpace(v)
			switch k {
			case "ProductName":
				info.OSName = v
			case "ProductVersion":
				info.OSVersion = v
			case "BuildVersion":
				info.OSBuild = v
			}
		}
	}

	if out, err := exec.Command("uname", "-m").Output(); err == nil {
		arch := strings.TrimSpace(string(out))
		if arch == "arm64" {
			info.Architecture = "arm64"
		} else {
			info.Architecture = "x86_64"
		}
	}
	if out, err := exec.Command("uname", "-r").Output(); err == nil {
		info.KernelVersion = strings.TrimSpace(string(out))
	}
	if h, err := os.Hostname(); err == nil {
		info.Hostname = h
	}
	return info, nil
}

func (c *darwinCollector) CollectPackages() ([]models.PackageInfo, error) {
	var packages []models.PackageInfo

	// Homebrew
	if pkgs, err := collectBrew(); err == nil {
		packages = append(packages, pkgs...)
	}
	// system_profiler
	if pkgs, err := collectSystemProfiler(); err == nil {
		packages = append(packages, pkgs...)
	}
	return packages, nil
}

func collectBrew() ([]models.PackageInfo, error) {
	out, err := exec.Command("brew", "list", "--versions").Output()
	if err != nil {
		return nil, err
	}
	var pkgs []models.PackageInfo
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) < 2 {
			continue
		}
		pkgs = append(pkgs, models.PackageInfo{
			Name:           parts[0],
			Version:        parts[1],
			PackageManager: "brew",
		})
	}
	return pkgs, nil
}

func collectSystemProfiler() ([]models.PackageInfo, error) {
	out, err := exec.Command("system_profiler", "SPApplicationsDataType", "-json").Output()
	if err != nil {
		return nil, err
	}
	var data map[string]interface{}
	if err := json.Unmarshal(out, &data); err != nil {
		return nil, err
	}
	apps, _ := data["SPApplicationsDataType"].([]interface{})
	var pkgs []models.PackageInfo
	for _, app := range apps {
		m, ok := app.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := m["_name"].(string)
		version, _ := m["version"].(string)
		if name == "" {
			continue
		}
		pkgs = append(pkgs, models.PackageInfo{
			Name:           name,
			Version:        version,
			PackageManager: "macos_app",
		})
	}
	return pkgs, nil
}
