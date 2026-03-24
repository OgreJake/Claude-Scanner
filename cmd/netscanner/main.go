// Claude Scanner — Network Scanner CLI
//
// Standalone network scanner that performs TCP port scanning, banner grabbing,
// and TLS inspection. Results are printed as JSON for consumption by the
// Python API server.
//
// Usage:
//   claude-netscanner --host 10.0.1.10 --ports 22,80,443,3389
//   claude-netscanner --host 10.0.1.10 --all-ports
//   claude-netscanner --host-file targets.txt --concurrency 200
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ogrejake/claude-scanner/internal/models"
	"github.com/ogrejake/claude-scanner/internal/network"
	"github.com/spf13/cobra"
)

var (
	targetHost   string
	targetFile   string
	portsFlag    string
	allPorts     bool
	concurrency  int
	timeoutSec   int
	noBanner     bool
	noTLS        bool
	outputFormat string
)

var rootCmd = &cobra.Command{
	Use:   "claude-netscanner",
	Short: "Network port scanner and service fingerprinter",
	Long:  "TCP port scanner with banner grabbing and TLS inspection. Part of Claude Scanner.",
	RunE:  runScan,
}

func init() {
	rootCmd.Flags().StringVarP(&targetHost, "host", "H", "", "Target host (IP or hostname)")
	rootCmd.Flags().StringVarP(&targetFile, "host-file", "f", "", "File with one host per line")
	rootCmd.Flags().StringVarP(&portsFlag, "ports", "p", "", "Comma-separated ports (default: top 50)")
	rootCmd.Flags().BoolVar(&allPorts, "all-ports", false, "Scan all 65535 ports (slow)")
	rootCmd.Flags().IntVarP(&concurrency, "concurrency", "c", 200, "Max parallel port probes")
	rootCmd.Flags().IntVarP(&timeoutSec, "timeout", "t", 3, "Per-port timeout in seconds")
	rootCmd.Flags().BoolVar(&noBanner, "no-banner", false, "Skip banner grabbing")
	rootCmd.Flags().BoolVar(&noTLS, "no-tls", false, "Skip TLS inspection")
	rootCmd.Flags().StringVarP(&outputFormat, "output", "o", "json", "Output format: json | text")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	var hosts []string

	if targetHost != "" {
		ip, err := resolveHost(targetHost)
		if err != nil {
			return fmt.Errorf("cannot resolve host %q: %w", targetHost, err)
		}
		hosts = append(hosts, ip+"|"+targetHost)
	}

	if targetFile != "" {
		data, err := os.ReadFile(targetFile)
		if err != nil {
			return fmt.Errorf("cannot read host file: %w", err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			ip, err := resolveHost(line)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: cannot resolve %s: %v\n", line, err)
				continue
			}
			hosts = append(hosts, ip+"|"+line)
		}
	}

	if len(hosts) == 0 {
		return fmt.Errorf("no hosts specified. Use --host or --host-file")
	}

	ports := network.DefaultPortList
	if allPorts {
		ports = make([]int, 65535)
		for i := range ports {
			ports[i] = i + 1
		}
	} else if portsFlag != "" {
		ports = parsePorts(portsFlag)
	}

	opts := network.ScanOptions{
		Ports:       ports,
		Concurrency: concurrency,
		Timeout:     time.Duration(timeoutSec) * time.Second,
		BannerGrab:  !noBanner,
		TLSInspect:  !noTLS,
	}
	scanner := network.New(opts)

	ctx := context.Background()
	var results []*models.NetworkScanResult

	for _, h := range hosts {
		parts := strings.SplitN(h, "|", 2)
		ip := parts[0]
		hostname := parts[0]
		if len(parts) == 2 {
			hostname = parts[1]
		}

		fmt.Fprintf(os.Stderr, "Scanning %s (%s) ...\n", hostname, ip)
		result, err := scanner.Scan(ctx, hostname, ip)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error scanning %s: %v\n", hostname, err)
			continue
		}
		results = append(results, result)
	}

	switch outputFormat {
	case "text":
		printText(results)
	default:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
	}
	return nil
}

func resolveHost(host string) (string, error) {
	if net.ParseIP(host) != nil {
		return host, nil
	}
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		return "", fmt.Errorf("lookup failed: %w", err)
	}
	return addrs[0], nil
}

func parsePorts(s string) []int {
	var ports []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			lo, _ := strconv.Atoi(bounds[0])
			hi, _ := strconv.Atoi(bounds[1])
			for p := lo; p <= hi; p++ {
				ports = append(ports, p)
			}
		} else if p, err := strconv.Atoi(part); err == nil {
			ports = append(ports, p)
		}
	}
	return ports
}

func printText(results []*models.NetworkScanResult) {
	for _, r := range results {
		fmt.Printf("\nHost: %s (%s)  OS guess: %s\n", r.Host, r.IP, r.OS)
		fmt.Printf("%-8s %-10s %-20s %s\n", "PORT", "STATE", "SERVICE", "BANNER")
		fmt.Println(strings.Repeat("-", 70))
		for _, p := range r.Ports {
			banner := p.Banner
			if len(banner) > 40 {
				banner = banner[:40] + "..."
			}
			banner = strings.ReplaceAll(banner, "\n", " ")
			fmt.Printf("%-8s %-10s %-20s %s\n",
				fmt.Sprintf("%d/%s", p.Port, p.Protocol),
				p.State,
				p.ServiceName,
				banner,
			)
		}
	}
}
