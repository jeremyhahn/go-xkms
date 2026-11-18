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

	"github.com/jeremyhahn/go-xkms/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
	"github.com/jeremyhahn/go-xkms/pkg/compose"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// issuedChain returns a CA root and a leaf it signed.
func issuedChain(t *testing.T, name string) (root, leaf *x509.Certificate) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		IsCA:                  true,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	if root, err = x509.ParseCertificate(der); err != nil {
		t.Fatalf("parse root: %v", err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject:      pkix.Name{CommonName: name + " leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err = x509.CreateCertificate(rand.Reader, leafTmpl, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	if leaf, err = x509.ParseCertificate(der); err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return root, leaf
}

// TestAttestationConfigVerifiers_ChainAnchoredOverPersistedStore: CSR
// appraisal (VerifyChainAnchored, as pkg/xkms servicer_ca runs it) trusts a
// chain anchored at a root installed in the persisted store under the
// format's purpose, and refuses it once that root is quarantined.
func TestAttestationConfigVerifiers_ChainAnchoredOverPersistedStore(t *testing.T) {
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
	storeRoot, leaf := issuedChain(t, "store-only-tpm-root")
	ctx := context.Background()
	if err := store.Add(ctx, storeRoot, &truststore.AddCertificateOptions{Purpose: truststore.PurposeTPMManufacturer}); err != nil {
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
	stmt := &attestation.AttestationStatement{Format: "tpm2", CertificateChain: []*x509.Certificate{leaf, storeRoot}}
	if err := v.VerifyChainAnchored(stmt, nil); err != nil {
		t.Fatalf("a chain anchored at a store root is refused: %v", err)
	}

	if _, err := store.SetPurpose(ctx, truststore.Fingerprint(storeRoot), truststore.PurposeSynced); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	if err := v.VerifyChainAnchored(stmt, nil); err == nil {
		t.Fatal("a chain anchored at a quarantined root still verifies")
	}
}

// writeRootPEM writes root to a PEM file and returns its path.
func writeRootPEM(t *testing.T, root *x509.Certificate) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}), 0o600); err != nil {
		t.Fatalf("write root: %v", err)
	}
	return path
}

// TestAttestationConfigVerifiers_StoreAuthoritativeOverConfigRoots: with a
// store configured, the persisted store is the only anchor source for
// chain appraisal. A root present in both the config file and the store is
// refused once quarantined in the store, a root quarantined before startup
// stays quarantined, and a config-only root is imported into the store once
// under the format's purpose.
func TestAttestationConfigVerifiers_StoreAuthoritativeOverConfigRoots(t *testing.T) {
	ctx := context.Background()
	newStore := func(t *testing.T) *truststore.DAOStore {
		t.Helper()
		store, err := compose.BuildTrustRootStore(testutil.NewMemoryDAOFactory())
		if err != nil {
			t.Fatalf("BuildTrustRootStore: %v", err)
		}
		t.Cleanup(func() { _ = store.Close() })
		return store
	}

	t.Run("in both sources, quarantined after startup", func(t *testing.T) {
		store := newStore(t)
		root, leaf := issuedChain(t, "shared-tpm-root")
		if err := store.Add(ctx, root, &truststore.AddCertificateOptions{Purpose: truststore.PurposeTPMManufacturer}); err != nil {
			t.Fatalf("store.Add: %v", err)
		}
		cfg := &config.AttestationConfig{
			Formats: map[string]*truststore.Config{"tpm2": {ExternalRootPaths: []string{writeRootPEM(t, root)}}},
		}
		verifiers, err := cfg.Verifiers(store)
		if err != nil {
			t.Fatalf("Verifiers(store): %v", err)
		}
		stmt := &attestation.AttestationStatement{Format: "tpm2", CertificateChain: []*x509.Certificate{leaf, root}}
		if err := verifiers["tpm2"].VerifyChainAnchored(stmt, nil); err != nil {
			t.Fatalf("chain refused before quarantine: %v", err)
		}
		if _, err := store.SetPurpose(ctx, truststore.Fingerprint(root), truststore.PurposeSynced); err != nil {
			t.Fatalf("quarantine: %v", err)
		}
		if err := verifiers["tpm2"].VerifyChainAnchored(stmt, nil); err == nil {
			t.Fatal("a root quarantined in the store still verifies through its config copy")
		}
	})

	t.Run("quarantined in the store before startup", func(t *testing.T) {
		store := newStore(t)
		root, leaf := issuedChain(t, "prequarantined-tpm-root")
		if err := store.Add(ctx, root, &truststore.AddCertificateOptions{Purpose: truststore.PurposeSynced}); err != nil {
			t.Fatalf("store.Add: %v", err)
		}
		cfg := &config.AttestationConfig{
			Formats: map[string]*truststore.Config{"tpm2": {ExternalRootPaths: []string{writeRootPEM(t, root)}}},
		}
		verifiers, err := cfg.Verifiers(store)
		if err != nil {
			t.Fatalf("Verifiers(store): %v", err)
		}
		stmt := &attestation.AttestationStatement{Format: "tpm2", CertificateChain: []*x509.Certificate{leaf, root}}
		if err := verifiers["tpm2"].VerifyChainAnchored(stmt, nil); err == nil {
			t.Fatal("startup import lifted the store quarantine of a configured root")
		}
	})

	t.Run("config-only root is imported under the format purpose", func(t *testing.T) {
		store := newStore(t)
		root, leaf := issuedChain(t, "config-only-tpm-root")
		cfg := &config.AttestationConfig{
			Formats: map[string]*truststore.Config{"tpm2": {ExternalRootPaths: []string{writeRootPEM(t, root)}}},
		}
		verifiers, err := cfg.Verifiers(store)
		if err != nil {
			t.Fatalf("Verifiers(store): %v", err)
		}
		stmt := &attestation.AttestationStatement{Format: "tpm2", CertificateChain: []*x509.Certificate{leaf, root}}
		if err := verifiers["tpm2"].VerifyChainAnchored(stmt, nil); err != nil {
			t.Fatalf("imported config root refused: %v", err)
		}
		if _, err := store.SetPurpose(ctx, truststore.Fingerprint(root), truststore.PurposeSynced); err != nil {
			t.Fatalf("config root not imported into the store: %v", err)
		}
		if err := verifiers["tpm2"].VerifyChainAnchored(stmt, nil); err == nil {
			t.Fatal("an imported config root quarantined in the store still verifies")
		}
	})
}
