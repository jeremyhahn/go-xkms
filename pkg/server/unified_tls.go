// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// unifiedTLSProvider serves the unified API server's certificate through a
// GetCertificate callback so the material can rotate without restarting the
// embedded node's listeners. The node starts before the CA composes, so the
// initial certificate is either operator-supplied files or a node-local
// bootstrap self-signed keypair; once the CA is initialized and
// ensureTLSServerCert has issued the real server certificate,
// upgradeUnifiedTLSCert swaps it in.
type unifiedTLSProvider struct {
	cert atomic.Pointer[tls.Certificate]
}

// getCertificate implements tls.Config.GetCertificate.
func (p *unifiedTLSProvider) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c := p.cert.Load(); c != nil {
		return c, nil
	}
	return nil, ErrNoTLSCertAvailable
}

// unifiedBootstrapCertDir is the storage-path subdirectory holding the
// bootstrap keypair, persisted so the presented certificate is stable across
// restarts (first-contact pinning flows tolerate an upgrade to the CA-issued
// certificate, not a new random identity every boot).
const unifiedBootstrapCertDir = "unified-tls"

// buildUnifiedTLSConfig assembles the TLS configuration handed to the
// embedded qrdb node's server (qrdb transports are TLS-only). Certificate
// preference order: operator-supplied cert_file/key_file, else a persisted
// node-local bootstrap self-signed certificate generated on first boot.
// The returned config serves through the rotating provider so the CA-issued
// certificate replaces the bootstrap material once the CA composes.
func (s *Server) buildUnifiedTLSConfig() (*tls.Config, error) {
	provider := &unifiedTLSProvider{}

	if s.config.TLS.CertFile != "" && s.config.TLS.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(s.config.TLS.CertFile, s.config.TLS.KeyFile)
		if err != nil {
			return nil, &ErrTLSCertOp{Operation: "load unified server certificate", Err: err}
		}
		provider.cert.Store(&cert)
	} else {
		cert, err := s.ensureBootstrapCert()
		if err != nil {
			return nil, err
		}
		provider.cert.Store(cert)
	}

	s.mu.Lock()
	s.unifiedTLS = provider
	s.mu.Unlock()

	return &tls.Config{
		GetCertificate: provider.getCertificate,
		MinVersion:     tls.VersionTLS13,
	}, nil
}

// upgradeUnifiedTLSCert swaps the CA-issued server certificate into the
// unified provider once the CA has composed (called after
// ensureTLSServerCert). A failure leaves the bootstrap certificate serving —
// degraded but available — and is reported to the caller for logging.
func (s *Server) upgradeUnifiedTLSCert() error {
	s.mu.Lock()
	provider := s.unifiedTLS
	s.mu.Unlock()
	if provider == nil {
		return nil
	}
	cfg, err := s.buildTLSConfig()
	if err != nil {
		return err
	}
	if len(cfg.Certificates) == 0 {
		return ErrNoTLSCertAvailable
	}
	provider.cert.Store(&cfg.Certificates[0])
	s.logger.Info("unified API server: CA-issued TLS certificate installed",
		"cn", s.config.TLS.ServerCN)
	return nil
}

// ensureBootstrapCert loads the persisted node-local bootstrap keypair or
// generates and persists a new one (ECDSA P-256, self-signed, SANs covering
// the configured host, the server CN, localhost and the loopback
// addresses). It exists so the unified server can terminate TLS before the
// CA composes without demanding operator-managed files.
func (s *Server) ensureBootstrapCert() (*tls.Certificate, error) {
	dir := filepath.Join(s.config.Storage.Path, unifiedBootstrapCertDir)
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		if leaf, perr := x509.ParseCertificate(cert.Certificate[0]); perr == nil &&
			time.Now().Before(leaf.NotAfter.Add(-24*time.Hour)) {
			s.logger.Info("unified API server: serving persisted bootstrap TLS certificate until the CA composes")
			return &cert, nil
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, &ErrTLSCertOp{Operation: "generate bootstrap TLS key", Err: err}
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, &ErrTLSCertOp{Operation: "generate bootstrap TLS serial", Err: err}
	}

	cn := s.config.TLS.ServerCN
	if cn == "" {
		cn = "xkmsd-bootstrap"
	}
	dnsNames := []string{"localhost"}
	ips := []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	if host := s.config.Server.Host; host != "" {
		if ip := net.ParseIP(host); ip != nil {
			ips = append(ips, ip)
		} else {
			dnsNames = append(dnsNames, host)
		}
	}
	if cn != "" && net.ParseIP(cn) == nil {
		dnsNames = append(dnsNames, cn)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, &ErrTLSCertOp{Operation: "create bootstrap TLS certificate", Err: err}
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, &ErrTLSCertOp{Operation: "encode bootstrap TLS key", Err: err}
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Persist when a storage path exists (memory-backed test nodes skip);
	// a persistence failure degrades to an ephemeral certificate rather
	// than refusing to serve.
	if s.config.Storage.Path != "" {
		if err := os.MkdirAll(dir, 0o700); err == nil {
			_ = os.WriteFile(certPath, certPEM, 0o600)
			_ = os.WriteFile(keyPath, keyPEM, 0o600)
		}
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, &ErrTLSCertOp{Operation: "assemble bootstrap TLS certificate", Err: err}
	}
	s.logger.Info("unified API server: generated bootstrap TLS certificate; the CA-issued certificate installs after composition",
		"cn", cn)
	return &cert, nil
}
