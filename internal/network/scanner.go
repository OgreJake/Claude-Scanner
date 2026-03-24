// Package network provides TCP/UDP port scanning and service detection.
package network

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/ogrejake/claude-scanner/internal/models"
)

// DefaultPortList covers the most commonly exploited ports.
var DefaultPortList = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 119, 135, 139, 143,
	161, 389, 443, 445, 465, 514, 587, 631, 636, 993, 995,
	1433, 1521, 2049, 2375, 2376, 3000, 3306, 3389, 4443,
	5432, 5900, 5985, 5986, 6379, 7001, 8080, 8443, 8888,
	9200, 9300, 11211, 27017, 27018, 50000,
}

// ScanOptions controls scanner behaviour.
type ScanOptions struct {
	Ports       []int
	Concurrency int           // max parallel port probes
	Timeout     time.Duration // per-port connect timeout
	BannerGrab  bool          // attempt to read service banner
	TLSInspect  bool          // probe TLS on likely HTTPS ports
}

func DefaultOptions() ScanOptions {
	return ScanOptions{
		Ports:       DefaultPortList,
		Concurrency: 200,
		Timeout:     3 * time.Second,
		BannerGrab:  true,
		TLSInspect:  true,
	}
}

// Scanner performs TCP port scanning.
type Scanner struct {
	opts ScanOptions
}

func New(opts ScanOptions) *Scanner {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 200
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 3 * time.Second
	}
	return &Scanner{opts: opts}
}

// Scan probes all configured ports on the given host IP.
func (s *Scanner) Scan(ctx context.Context, host, ip string) (*models.NetworkScanResult, error) {
	result := &models.NetworkScanResult{
		Host:      host,
		IP:        ip,
		ScannedAt: time.Now().UTC(),
	}

	sem := make(chan struct{}, s.opts.Concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, port := range s.opts.Ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			select {
			case <-ctx.Done():
				return
			default:
			}

			ps := s.probePort(ctx, ip, p)
			if ps.State == "open" {
				if s.opts.BannerGrab {
					ps.Banner = s.grabBanner(ctx, ip, p)
				}
				if s.opts.TLSInspect && isTLSPort(p) {
					ps.Banner = "" // banner already got via TLS
					if info := InspectTLS(ctx, ip, p, s.opts.Timeout); info != nil {
						ps.ServiceName = "https"
					}
				}
				// Service name from well-known port lookup
				if ps.ServiceName == "" {
					ps.ServiceName = wellKnownService(p)
				}
				mu.Lock()
				result.Ports = append(result.Ports, ps)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()

	// Sort by port number
	sort.Slice(result.Ports, func(i, j int) bool {
		return result.Ports[i].Port < result.Ports[j].Port
	})

	// Guess OS from open ports
	result.OS = guessOS(result.Ports)

	return result, nil
}

func (s *Scanner) probePort(ctx context.Context, ip string, port int) models.PortState {
	ps := models.PortState{
		Port:     port,
		Protocol: "tcp",
		State:    "filtered",
	}

	addr := fmt.Sprintf("%s:%d", ip, port)
	dialer := net.Dialer{Timeout: s.opts.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		if isConnectionRefused(err) {
			ps.State = "closed"
		}
		return ps
	}
	conn.Close()
	ps.State = "open"
	return ps
}

func (s *Scanner) grabBanner(ctx context.Context, ip string, port int) string {
	addr := fmt.Sprintf("%s:%d", ip, port)
	dialer := net.Dialer{Timeout: s.opts.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n > 0 {
		banner := string(buf[:n])
		// Trim non-printable bytes
		var clean []byte
		for _, b := range []byte(banner) {
			if b >= 32 || b == '\n' || b == '\r' {
				clean = append(clean, b)
			}
		}
		s := string(clean)
		if len(s) > 256 {
			s = s[:256]
		}
		return s
	}
	return ""
}

func isConnectionRefused(err error) bool {
	if err == nil {
		return false
	}
	return contains(err.Error(), "connection refused") ||
		contains(err.Error(), "refused")
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub ||
		len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func isTLSPort(port int) bool {
	tlsPorts := map[int]bool{443: true, 465: true, 636: true, 993: true, 995: true, 8443: true, 4443: true, 5986: true}
	return tlsPorts[port]
}

func wellKnownService(port int) string {
	services := map[int]string{
		21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
		80: "http", 110: "pop3", 111: "rpcbind", 119: "nntp", 135: "msrpc",
		139: "netbios-ssn", 143: "imap", 161: "snmp", 389: "ldap",
		443: "https", 445: "microsoft-ds", 465: "smtps", 514: "syslog",
		587: "submission", 636: "ldaps", 993: "imaps", 995: "pop3s",
		1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker",
		2376: "docker-tls", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
		5900: "vnc", 5985: "winrm-http", 5986: "winrm-https",
		6379: "redis", 8080: "http-alt", 8443: "https-alt",
		9200: "elasticsearch", 27017: "mongodb",
	}
	if s, ok := services[port]; ok {
		return s
	}
	return ""
}

func guessOS(ports []models.PortState) string {
	hasRDP := false
	hasSMB := false
	hasSSH := false
	for _, p := range ports {
		switch p.Port {
		case 3389:
			hasRDP = true
		case 445:
			hasSMB = true
		case 22:
			hasSSH = true
		}
	}
	if hasRDP || hasSMB {
		return "windows"
	}
	if hasSSH {
		return "linux"
	}
	return "unknown"
}
