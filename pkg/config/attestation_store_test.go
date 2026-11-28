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

package config_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
	"github.com/jeremyhahn/go-xkms/pkg/compose"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

func selfSignedRoot(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
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
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// TestAttestationConfigVerifiers_AppraisesOverPersistedStore: a root held
// only by the persisted trust-root store (not listed in config) is in the
// appraisal verifier's purpose trust pool.
func TestAttestationConfigVerifiers_AppraisesOverPersistedStore(t *testing.T) {
	configRoot := selfSignedRoot(t, "config-root")
	path := filepath.Join(t.TempDir(), "config-root.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: configRoot.Raw}), 0o600); err != nil {
		t.Fatalf("write root: %v", err)
	}

	store, err := compose.BuildTrustRootStore(testutil.NewMemoryDAOFactory())
	if err != nil {
		t.Fatalf("BuildTrustRootStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	storeRoot := selfSignedRoot(t, "store-only-tpm-root")
	if err := store.Add(context.Background(), storeRoot, &truststore.AddCertificateOptions{Purpose: truststore.PurposeTPMManufacturer}); err != nil {
		t.Fatalf("store.Add: %v", err)
	}

	cfg := &config.AttestationConfig{
		Formats: map[string]*truststore.Config{"tpm2": {ExternalRootPaths: []string{path}}},
	}
	verifiers, err := cfg.Verifiers(store)
	if err != nil {
		t.Fatalf("Verifiers(store): %v", err)
	}
	v := verifiers["tpm2"]
	if v == nil {
		t.Fatal("missing tpm2 verifier")
	}
	pool, err := v.BuildTrustPool(truststore.PurposeTPMManufacturer)
	if err != nil {
		t.Fatalf("BuildTrustPool: %v", err)
	}
	if _, err := storeRoot.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Fatalf("store-only root not in the appraisal trust pool: %v", err)
	}
}
