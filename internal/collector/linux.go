//go:build linux

package collector

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"strings"

	"github.com/ogrejake/claude-scanner/internal/models"
)

type linuxCollector struct{}

func newPlatformCollector() Collector { return &linuxCollector{} }

func (c *linuxCollector) CollectOSInfo() (*models.OSInfo, error) {
	info := &models.OSInfo{OSType: "linux"}

	// Read /etc/os-release
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := scanner.Text()
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			v = strings.Trim(v, `"`)
			switch k {
			case "PRETTY_NAME":
				info.OSName = v
			case "VERSION_ID":
				info.OSVersion = v
			}
		}
	}

	// uname -r for kernel
	if out, err := exec.Command("uname", "-r").Output(); err == nil {
		info.KernelVersion = strings.TrimSpace(string(out))
	}
	// uname -m for arch
	if out, err := exec.Command("uname", "-m").Output(); err == nil {
		info.Architecture = strings.TrimSpace(string(out))
	}
	// hostname
	if h, err := os.Hostname(); err == nil {
		info.Hostname = h
	}
	return info, nil
}

func (c *linuxCollector) CollectPackages() ([]models.PackageInfo, error) {
	var packages []models.PackageInfo

	// Try dpkg first (Debian/Ubuntu)
	if pkgs, err := collectDpkg(); err == nil {
		packages = append(packages, pkgs...)
	}
	// Try rpm (RHEL/CentOS/Fedora)
	if pkgs, err := collectRpm(); err == nil {
		packages = append(packages, pkgs...)
	}
	// Try apk (Alpine)
	if pkgs, err := collectApk(); err == nil {
		packages = append(packages, pkgs...)
	}

	return packages, nil
}

func collectDpkg() ([]models.PackageInfo, error) {
	out, err := exec.Command(
		"dpkg-query", "-W",
		"-f=${Package}\t${Version}\t${Architecture}\t${Status}\n",
	).Output()
	if err != nil {
		return nil, err
	}

	var pkgs []models.PackageInfo
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), "\t")
		if len(parts) < 3 {
			continue
		}
		if len(parts) >= 4 && !strings.Contains(parts[3], "install ok installed") {
			continue
		}
		pkgs = append(pkgs, models.PackageInfo{
			Name:           parts[0],
			Version:        parts[1],
			Arch:           parts[2],
			PackageManager: "dpkg",
		})
	}
	return pkgs, nil
}

func collectRpm() ([]models.PackageInfo, error) {
	out, err := exec.Command(
		"rpm", "-qa",
		"--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{VENDOR}\n",
	).Output()
	if err != nil {
		return nil, err
	}

	var pkgs []models.PackageInfo
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), "\t")
		if len(parts) < 2 {
			continue
		}
		pkg := models.PackageInfo{
			Name:           parts[0],
			Version:        parts[1],
			PackageManager: "rpm",
		}
		if len(parts) > 2 {
			pkg.Arch = parts[2]
		}
		if len(parts) > 3 {
			pkg.Vendor = parts[3]
		}
		pkgs = append(pkgs, pkg)
	}
	return pkgs, nil
}

func collectApk() ([]models.PackageInfo, error) {
	out, err := exec.Command("apk", "info", "-v").Output()
	if err != nil {
		return nil, err
	}

	var pkgs []models.PackageInfo
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Format: "pkgname-version"
		lastDash := strings.LastIndex(line, "-")
		if lastDash <= 0 {
			continue
		}
		name := line[:lastDash]
		version := line[lastDash+1:]
		pkgs = append(pkgs, models.PackageInfo{
			Name:           name,
			Version:        version,
			PackageManager: "apk",
		})
	}
	return pkgs, nil
}
