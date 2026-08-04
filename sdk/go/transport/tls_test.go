// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTLSTestKeypair generates a self-signed certificate and writes the
// certificate and key PEM files into dir, returning their paths.
func writeTLSTestKeypair(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tls-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certFile, keyFile
}

func TestLoadCertPool(t *testing.T) {
	dir := t.TempDir()
	caFile, _ := writeTLSTestKeypair(t, dir)

	t.Run("valid bundle", func(t *testing.T) {
		pool, err := LoadCertPool(caFile)
		if err != nil {
			t.Fatalf("LoadCertPool: %v", err)
		}
		if pool == nil {
			t.Fatal("expected non-nil pool")
		}
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := LoadCertPool(filepath.Join(dir, "nonexistent.pem"))
		var readErr *CAFileReadError
		if !errors.As(err, &readErr) {
			t.Fatalf("expected *CAFileReadError, got %T: %v", err, err)
		}
		if readErr.Unwrap() == nil {
			t.Fatal("expected wrapped read error")
		}
	})

	t.Run("no certificates in file", func(t *testing.T) {
		junk := filepath.Join(dir, "junk.pem")
		if err := os.WriteFile(junk, []byte("not a certificate"), 0600); err != nil {
			t.Fatalf("write junk: %v", err)
		}
		_, err := LoadCertPool(junk)
		var parseErr *CAFileParseError
		if !errors.As(err, &parseErr) {
			t.Fatalf("expected *CAFileParseError, got %T: %v", err, err)
		}
		if parseErr.Path != junk {
			t.Fatalf("expected path %q, got %q", junk, parseErr.Path)
		}
	})
}

func TestBuildTLSConfig(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeTLSTestKeypair(t, dir)

	t.Run("zero options yields minimal TLS 1.3 config", func(t *testing.T) {
		cfg, err := BuildTLSConfig(TLSOptions{})
		if err != nil {
			t.Fatalf("BuildTLSConfig: %v", err)
		}
		if cfg.MinVersion != tls.VersionTLS13 {
			t.Fatalf("expected TLS 1.3 minimum, got %#x", cfg.MinVersion)
		}
		if cfg.RootCAs != nil || len(cfg.Certificates) != 0 || cfg.ServerName != "" {
			t.Fatal("expected zero-value pool, certificates, and server name")
		}
	})

	t.Run("server name override", func(t *testing.T) {
		cfg, err := BuildTLSConfig(TLSOptions{ServerName: "xkms.example.com"})
		if err != nil {
			t.Fatalf("BuildTLSConfig: %v", err)
		}
		if cfg.ServerName != "xkms.example.com" {
			t.Fatalf("expected server name override, got %q", cfg.ServerName)
		}
	})

	t.Run("ca bundle loaded into root pool", func(t *testing.T) {
		cfg, err := BuildTLSConfig(TLSOptions{CAFile: certFile})
		if err != nil {
			t.Fatalf("BuildTLSConfig: %v", err)
		}
		if cfg.RootCAs == nil {
			t.Fatal("expected RootCAs pool")
		}
	})

	t.Run("client keypair loaded for mTLS", func(t *testing.T) {
		cfg, err := BuildTLSConfig(TLSOptions{CertFile: certFile, KeyFile: keyFile})
		if err != nil {
			t.Fatalf("BuildTLSConfig: %v", err)
		}
		if len(cfg.Certificates) != 1 {
			t.Fatalf("expected 1 client certificate, got %d", len(cfg.Certificates))
		}
	})

	t.Run("cert without key is ignored", func(t *testing.T) {
		cfg, err := BuildTLSConfig(TLSOptions{CertFile: certFile})
		if err != nil {
			t.Fatalf("BuildTLSConfig: %v", err)
		}
		if len(cfg.Certificates) != 0 {
			t.Fatal("expected no client certificate when key file is missing")
		}
	})

	t.Run("missing ca file returns typed read error", func(t *testing.T) {
		_, err := BuildTLSConfig(TLSOptions{CAFile: filepath.Join(dir, "missing.pem")})
		var readErr *CAFileReadError
		if !errors.As(err, &readErr) {
			t.Fatalf("expected *CAFileReadError, got %T: %v", err, err)
		}
	})

	t.Run("bad client keypair returns typed load error", func(t *testing.T) {
		junk := filepath.Join(dir, "badkey.pem")
		if err := os.WriteFile(junk, []byte("not a key"), 0600); err != nil {
			t.Fatalf("write junk key: %v", err)
		}
		_, err := BuildTLSConfig(TLSOptions{CertFile: certFile, KeyFile: junk})
		var certErr *ClientCertLoadError
		if !errors.As(err, &certErr) {
			t.Fatalf("expected *ClientCertLoadError, got %T: %v", err, err)
		}
		if certErr.Unwrap() == nil {
			t.Fatal("expected wrapped load error")
		}
	})

	t.Run("ca error takes precedence over client cert error", func(t *testing.T) {
		_, err := BuildTLSConfig(TLSOptions{
			CAFile:   filepath.Join(dir, "missing.pem"),
			CertFile: certFile,
			KeyFile:  filepath.Join(dir, "missing-key.pem"),
		})
		var readErr *CAFileReadError
		if !errors.As(err, &readErr) {
			t.Fatalf("expected CA error precedence (*CAFileReadError), got %T: %v", err, err)
		}
	})
}
