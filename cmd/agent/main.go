// Claude Scanner Agent
//
// A lightweight HTTP server deployed to target hosts for agent-based scanning.
// It collects OS info and package data locally (no remote shell required) and
// serves results to the central Claude Scanner API server.
//
// Auth: Bearer token (shared secret configured via AGENT_TOKEN env var).
// TLS:  Self-signed certificate (central server verifies by token, not cert).
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ogrejake/claude-scanner/internal/collector"
	"github.com/ogrejake/claude-scanner/internal/models"
)

var (
	agentToken = getEnv("AGENT_TOKEN", "")
	listenAddr = ":" + getEnv("AGENT_PORT", "9443")
	agentVersion = "0.1.0"
)

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ---------------------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------------------

func bearerAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if agentToken == "" {
			// Token not configured — reject all requests
			http.Error(w, "agent not configured", http.StatusServiceUnavailable)
			return
		}
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer "+agentToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

func healthHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"version": agentVersion,
	})
}

func collectOSInfoHandler(w http.ResponseWriter, r *http.Request) {
	c := collector.New()
	info, err := c.CollectOSInfo()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, models.AgentResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, models.AgentResponse{
		Success: true,
		Data:    info,
	})
}

func collectPackagesHandler(w http.ResponseWriter, r *http.Request) {
	c := collector.New()
	packages, err := c.CollectPackages()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, models.AgentResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}
	result := models.CollectionResult{
		Packages:    packages,
		CollectedAt: time.Now().UTC(),
	}
	writeJSON(w, http.StatusOK, models.AgentResponse{
		Success: true,
		Data:    result,
	})
}

func fullCollectHandler(w http.ResponseWriter, r *http.Request) {
	c := collector.New()
	osInfo, _ := c.CollectOSInfo()
	packages, _ := c.CollectPackages()

	result := models.CollectionResult{
		OS:          osInfo,
		Packages:    packages,
		CollectedAt: time.Now().UTC(),
	}
	writeJSON(w, http.StatusOK, models.AgentResponse{
		Success: true,
		Data:    result,
	})
}

// ---------------------------------------------------------------------------
// Self-signed TLS certificate
// ---------------------------------------------------------------------------

func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Claude Scanner Agent"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	if agentToken == "" {
		log.Fatal("AGENT_TOKEN environment variable is required")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/api/v1/collect/osinfo",   bearerAuth(collectOSInfoHandler))
	mux.HandleFunc("/api/v1/collect/packages", bearerAuth(collectPackagesHandler))
	mux.HandleFunc("/api/v1/collect/full",     bearerAuth(fullCollectHandler))

	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("Failed to generate TLS certificate: %v", err)
	}

	server := &http.Server{
		Addr:    listenAddr,
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		log.Printf("Claude Scanner Agent v%s listening on %s (TLS)", agentVersion, listenAddr)
		if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("ListenAndServeTLS: %v", err)
		}
	}()

	<-stop
	log.Println("Shutting down agent...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
	log.Println("Agent stopped.")
}
