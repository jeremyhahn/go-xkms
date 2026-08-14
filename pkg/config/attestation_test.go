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

package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
)

// writeRootPEM writes a self-signed root certificate to a PEM file and returns
// its path.
func writeRootPEM(t *testing.T, dir, name string) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		IsCA:                  true,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	path := filepath.Join(dir, name+".pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func TestAttestationConfigVerifiers_LoadsPerFormatAnchors(t *testing.T) {
	dir := t.TempDir()
	yubicoPath := writeRootPEM(t, dir, "yubico-root")
	tpmPath := writeRootPEM(t, dir, "tpm-root")

	cfg := &AttestationConfig{
		Formats: map[string]*truststore.Config{
			" YubiKey-PIV ": {ExternalRootPaths: []string{yubicoPath}},
			"tpm2":          {ExternalRootPaths: []string{tpmPath}},
		},
	}

	verifiers, err := cfg.Verifiers()
	if err != nil {
		t.Fatalf("Verifiers() error: %v", err)
	}
	if len(verifiers) != 2 {
		t.Fatalf("expected 2 verifiers, got %d", len(verifiers))
	}
	for _, format := range []string{"yubikey-piv", "tpm2"} {
		v, ok := verifiers[format]
		if !ok {
			t.Fatalf("missing verifier for format %q", format)
		}
		if v.TrustAnchorCount() != 1 {
			t.Fatalf("format %q: expected 1 anchor, got %d", format, v.TrustAnchorCount())
		}
	}
}

func TestAttestationConfigVerifiers_NilConfig(t *testing.T) {
	var cfg *AttestationConfig
	verifiers, err := cfg.Verifiers()
	if err != nil {
		t.Fatalf("Verifiers() error: %v", err)
	}
	if verifiers != nil {
		t.Fatalf("expected nil verifiers, got %v", verifiers)
	}
}

func TestAttestationConfigVerifiers_RejectsUnanchorableFormats(t *testing.T) {
	dir := t.TempDir()
	rootPath := writeRootPEM(t, dir, "root")

	tests := []struct {
		name    string
		cfg     *AttestationConfig
		wantErr error
	}{
		{
			name:    "empty format identifier",
			cfg:     &AttestationConfig{Formats: map[string]*truststore.Config{"  ": {ExternalRootPaths: []string{rootPath}}}},
			wantErr: ErrAttestationFormatEmpty,
		},
		{
			name:    "missing trust store",
			cfg:     &AttestationConfig{Formats: map[string]*truststore.Config{"tpm2": nil}},
			wantErr: ErrAttestationTrustStoreMissing,
		},
		{
			name:    "trust store with no roots",
			cfg:     &AttestationConfig{Formats: map[string]*truststore.Config{"tpm2": {}}},
			wantErr: ErrAttestationTrustStoreEmpty,
		},
		{
			name:    "missing root file",
			cfg:     &AttestationConfig{Formats: map[string]*truststore.Config{"tpm2": {ExternalRootPaths: []string{filepath.Join(dir, "absent.pem")}}}},
			wantErr: truststore.ErrFileNotFound,
		},
		{
			name:    "unknown embedded root",
			cfg:     &AttestationConfig{Formats: map[string]*truststore.Config{"tpm2": {EmbeddedRoots: []string{"not-a-real-root"}}}},
			wantErr: truststore.ErrUnknownEmbeddedRoot,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			verifiers, err := tc.cfg.Verifiers()
			if err == nil {
				t.Fatalf("expected error, got verifiers %v", verifiers)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected %v, got %v", tc.wantErr, err)
			}
			if verifiers != nil {
				t.Fatalf("expected nil verifiers on error, got %v", verifiers)
			}
		})
	}
}
