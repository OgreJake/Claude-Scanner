//go:build freebsd || openbsd || netbsd || solaris

package collector

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/ogrejake/claude-scanner/internal/models"
)

type unixCollector struct{}

func newPlatformCollector() Collector { return &unixCollector{} }

var pkgNameVersionRe = regexp.MustCompile(`^([a-zA-Z0-9_\-+.]+)-(\d[\w.+_\-]*)`)

func (c *unixCollector) CollectOSInfo() (*models.OSInfo, error) {
	info := &models.OSInfo{OSType: "unix"}
	if out, err := exec.Command("uname", "-srm").Output(); err == nil {
		parts := strings.Fields(string(out))
		if len(parts) >= 1 {
			info.OSName = parts[0]
		}
		if len(parts) >= 2 {
			info.KernelVersion = parts[1]
			info.OSVersion = parts[1]
		}
		if len(parts) >= 3 {
			info.Architecture = parts[2]
		}
	}
	if h, err := os.Hostname(); err == nil {
		info.Hostname = h
	}
	return info, nil
}

func (c *unixCollector) CollectPackages() ([]models.PackageInfo, error) {
	var packages []models.PackageInfo

	// FreeBSD pkg-ng
	if pkgs, err := collectFreeBSDPkg(); err == nil {
		packages = append(packages, pkgs...)
	}
	// Legacy pkg_info
	if len(packages) == 0 {
		if pkgs, err := collectPkgInfo(); err == nil {
			packages = append(packages, pkgs...)
		}
	}
	return packages, nil
}

func collectFreeBSDPkg() ([]models.PackageInfo, error) {
	out, err := exec.Command("pkg", "info", "-a", "--raw").Output()
	if err != nil {
		return nil, err
	}
	var pkgs []models.PackageInfo
	var name, version string
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
		case "name":
			name = v
		case "version":
			version = v
			if name != "" {
				pkgs = append(pkgs, models.PackageInfo{
					Name:           name,
					Version:        version,
					PackageManager: "pkg",
				})
				name, version = "", ""
			}
		}
	}
	return pkgs, nil
}

func collectPkgInfo() ([]models.PackageInfo, error) {
	out, err := exec.Command("pkg_info").Output()
	if err != nil {
		return nil, err
	}
	var pkgs []models.PackageInfo
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		m := pkgNameVersionRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		pkgs = append(pkgs, models.PackageInfo{
			Name:           m[1],
			Version:        m[2],
			PackageManager: "pkg_info",
		})
	}
	return pkgs, nil
}
