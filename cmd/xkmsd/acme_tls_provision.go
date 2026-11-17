package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"

	nativeca "github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// ErrACMEListenerCertPartial reports that only one of acme.tls.cert_file and
// acme.tls.key_file exists, so xkmsd can neither load nor safely issue a pair.
var ErrACMEListenerCertPartial = errors.New("acme: only one of the listener TLS cert and key files exists")

// ensureACMEListenerCert makes sure the ACME listener's certificate and key
// exist before buildACMETLSConfig loads them. When both files are absent the
// certificate is issued from issuer (the xkmsd CA) for an ECDSA P-256 key
// generated here, with SANs from the hosts of external_url and https_addr and
// the CA's default validity. Existing files are never overwritten; a lone cert
// or key fails with an error naming both paths.
func ensureACMEListenerCert(ctx context.Context, issuer nativeca.CAIssuer, cfg *config.ACMEConfig, logger *slog.Logger) error {
	certPath, keyPath := cfg.TLS.CertFile, cfg.TLS.KeyFile
	certExists, err := fileExists(certPath)
	if err != nil {
		return err
	}
	keyExists, err := fileExists(keyPath)
	if err != nil {
		return err
	}
	switch {
	case certExists && keyExists:
		return nil
	case certExists != keyExists:
		return fmt.Errorf("%w: cert_file %s (exists=%t), key_file %s (exists=%t): provide both or remove both to have xkmsd issue them",
			ErrACMEListenerCertPartial, certPath, certExists, keyPath, keyExists)
	}

	dnsNames, ips := acmeListenerSANs(cfg)
	if len(dnsNames) == 0 && len(ips) == 0 {
		return fmt.Errorf("acme: no host in external_url %q or https_addr %q to issue the listener certificate for", cfg.ExternalURL, cfg.HTTPSAddr)
	}
	cn := ""
	if len(dnsNames) > 0 {
		cn = dnsNames[0]
	} else {
		cn = ips[0]
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("acme: generate listener key: %w", err)
	}
	issued, err := issuer.IssueCertificateForKey(ctx, &nativeca.CertificateRequest{
		Subject:     nativeca.Subject{CommonName: cn},
		SANS:        &nativeca.SubjectAlternativeNames{DNS: dnsNames, IPs: ips},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// The ACME listener is a service of the system tenant.
		TenantID: "system",
	}, key.Public())
	if err != nil {
		return fmt.Errorf("acme: issue listener certificate: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("acme: encode listener key: %w", err)
	}
	certPEM := listenerCertChainPEM(issued)

	for _, p := range []string{certPath, keyPath} {
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			return fmt.Errorf("acme: create directory for %s: %w", p, err)
		}
	}
	if err := writeNewFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	if err := writeNewFile(certPath, certPEM, 0o644); err != nil {
		_ = os.Remove(keyPath)
		return err
	}
	logger.Info("ACME listener certificate issued by the xkmsd CA",
		slog.String("cert_file", certPath),
		slog.String("key_file", keyPath),
		slog.Any("dns", dnsNames),
		slog.Any("ips", ips),
		slog.Time("not_after", issued.NotAfter))
	return nil
}

// acmeListenerSANs returns the DNS names and IP addresses the listener
// certificate covers: the host of external_url and the host of https_addr,
// skipping empty and unspecified (wildcard bind) addresses.
func acmeListenerSANs(cfg *config.ACMEConfig) (dnsNames, ips []string) {
	seen := map[string]bool{}
	add := func(host string) {
		if host == "" || seen[host] {
			return
		}
		seen[host] = true
		if ip := net.ParseIP(host); ip != nil {
			if !ip.IsUnspecified() {
				ips = append(ips, ip.String())
			}
			return
		}
		dnsNames = append(dnsNames, host)
	}
	if u, err := url.Parse(cfg.ExternalURL); err == nil {
		add(u.Hostname())
	}
	if host, _, err := net.SplitHostPort(cfg.HTTPSAddr); err == nil {
		add(host)
	}
	return dnsNames, ips
}

// listenerCertChainPEM is the leaf followed by any intermediates, so a client
// that trusts only the root can build the chain.
func listenerCertChainPEM(issued *nativeca.IssuedCertificate) []byte {
	out := append([]byte(nil), issued.CertificatePEM...)
	rest := issued.ChainPEM
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if issued.Certificate != nil && bytes.Equal(block.Bytes, issued.Certificate.Raw) {
			continue
		}
		out = append(out, pem.EncodeToMemory(block)...)
	}
	return out
}

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("acme: stat %s: %w", path, err)
}

// writeNewFile creates path with perm and fails if it already exists.
func writeNewFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm) // #nosec G304 - path from trusted config
	if err != nil {
		return fmt.Errorf("acme: create %s: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return fmt.Errorf("acme: write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("acme: close %s: %w", path, err)
	}
	return nil
}
