// Package collector defines the interface for OS-specific package collection.
// Each OS implementation is in a separate file with appropriate build tags.
package collector

import "github.com/ogrejake/claude-scanner/internal/models"

// Collector enumerates installed packages and OS information on the local host.
type Collector interface {
	// CollectOSInfo returns metadata about the running operating system.
	CollectOSInfo() (*models.OSInfo, error)
	// CollectPackages returns all installed packages.
	CollectPackages() ([]models.PackageInfo, error)
}

// New returns the appropriate Collector for the current OS (selected via build tags).
func New() Collector {
	return newPlatformCollector()
}
