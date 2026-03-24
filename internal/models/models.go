// Package models contains shared data structures used by both the agent
// and the network scanner Go binaries.
package models

import "time"

// PackageInfo represents an installed software package on a target host.
type PackageInfo struct {
	Name           string     `json:"name"`
	Version        string     `json:"version"`
	Arch           string     `json:"arch,omitempty"`
	PackageManager string     `json:"package_manager,omitempty"`
	Vendor         string     `json:"vendor,omitempty"`
	CPE            string     `json:"cpe,omitempty"`
	InstallDate    *time.Time `json:"install_date,omitempty"`
}

// OSInfo holds information about the target operating system.
type OSInfo struct {
	OSType        string `json:"os_type"` // linux | windows | darwin | unix
	OSName        string `json:"os_name"`
	OSVersion     string `json:"os_version"`
	OSBuild       string `json:"os_build,omitempty"`
	Architecture  string `json:"architecture"`
	KernelVersion string `json:"kernel_version,omitempty"`
	Hostname      string `json:"hostname"`
}

// CollectionResult is the top-level payload returned by an agent collect call.
type CollectionResult struct {
	OS       *OSInfo       `json:"os"`
	Packages []PackageInfo `json:"packages"`
	CollectedAt time.Time  `json:"collected_at"`
}

// PortState represents a single TCP/UDP port scan result.
type PortState struct {
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"` // tcp | udp
	State       string `json:"state"`    // open | closed | filtered
	ServiceName string `json:"service_name,omitempty"`
	Product     string `json:"product,omitempty"`
	Version     string `json:"version,omitempty"`
	Banner      string `json:"banner,omitempty"`
	CPE         string `json:"cpe,omitempty"`
}

// TLSInfo holds TLS/SSL certificate and cipher information.
type TLSInfo struct {
	Subject       string    `json:"subject,omitempty"`
	Issuer        string    `json:"issuer,omitempty"`
	NotBefore     time.Time `json:"not_before,omitempty"`
	NotAfter      time.Time `json:"not_after,omitempty"`
	IsExpired     bool      `json:"is_expired"`
	DaysToExpiry  int       `json:"days_to_expiry"`
	TLSVersion    string    `json:"tls_version,omitempty"`
	CipherSuite   string    `json:"cipher_suite,omitempty"`
	WeakCipher    bool      `json:"weak_cipher"`
	SelfSigned    bool      `json:"self_signed"`
	SANs          []string  `json:"sans,omitempty"`
}

// NetworkScanResult holds the full network scan result for one host.
type NetworkScanResult struct {
	Host      string      `json:"host"`
	IP        string      `json:"ip"`
	Ports     []PortState `json:"ports"`
	OS        string      `json:"os_guess,omitempty"`
	ScannedAt time.Time   `json:"scanned_at"`
}

// AgentCollectRequest is the JSON body for an agent collect endpoint.
type AgentCollectRequest struct {
	ScanTargetID string `json:"scan_target_id"`
}

// AgentResponse wraps a response from the Go agent.
type AgentResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}
