// TLS/SSL inspection for network services.
package network

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ogrejake/claude-scanner/internal/models"
)

// WeakCiphers are cipher suites considered cryptographically weak.
var WeakCiphers = map[uint16]bool{
	tls.TLS_RSA_WITH_RC4_128_MD5:                true,
	tls.TLS_RSA_WITH_RC4_128_SHA:                true,
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:           true,
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:          true,
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:        true,
}

// InspectTLS connects to ip:port with TLS and returns certificate/cipher details.
// Returns nil if the connection fails or the host doesn't speak TLS.
func InspectTLS(ctx context.Context, ip string, port int, timeout time.Duration) *models.TLSInfo {
	addr := fmt.Sprintf("%s:%d", ip, port)
	dialer := &net.Dialer{Timeout: timeout}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, // We want to inspect even invalid certs
	})
	if err != nil {
		return nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	info := &models.TLSInfo{}

	// TLS version
	switch state.Version {
	case tls.VersionTLS10:
		info.TLSVersion = "TLS 1.0"
	case tls.VersionTLS11:
		info.TLSVersion = "TLS 1.1"
	case tls.VersionTLS12:
		info.TLSVersion = "TLS 1.2"
	case tls.VersionTLS13:
		info.TLSVersion = "TLS 1.3"
	default:
		info.TLSVersion = "unknown"
	}

	// Cipher suite
	info.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	info.WeakCipher = WeakCiphers[state.CipherSuite]

	// Certificate details
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		info.Subject = cert.Subject.CommonName
		info.Issuer = cert.Issuer.CommonName
		info.NotBefore = cert.NotBefore
		info.NotAfter = cert.NotAfter
		info.IsExpired = time.Now().After(cert.NotAfter)
		info.DaysToExpiry = int(time.Until(cert.NotAfter).Hours() / 24)
		info.SelfSigned = cert.Issuer.String() == cert.Subject.String()

		for _, san := range cert.DNSNames {
			info.SANs = append(info.SANs, san)
		}
		for _, ip := range cert.IPAddresses {
			info.SANs = append(info.SANs, ip.String())
		}
	}

	return info
}

// CheckWeakTLSProtocol attempts to connect using an older TLS version.
// Returns true if the server accepts TLS 1.0 or TLS 1.1.
func CheckWeakTLSProtocol(ip string, port int, timeout time.Duration) bool {
	addr := fmt.Sprintf("%s:%d", ip, port)
	dialer := &net.Dialer{Timeout: timeout}

	for _, version := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         version,
			MaxVersion:         version,
		})
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}
