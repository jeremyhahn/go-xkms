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

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/dice"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	acmesdk "github.com/jeremyhahn/go-xkms/sdk/go/acme"
)

// newTestRoot mints a self-signed CA and the key that signed it.
func newTestRoot(t *testing.T, name string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert, key
}

// writeAnchorFile writes cert as a PEM trust anchor file and returns its path.
func writeAnchorFile(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "anchor.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// testDeviceAttestVerifier is the production verifier over a throwaway TPM root.
func testDeviceAttestVerifier(t *testing.T) acmesdk.ACMEDeviceAttest01Verifier {
	t.Helper()
	root, _ := newTestRoot(t, "TPM Test Root")
	verifier, err := buildDeviceAttestVerifier(config.ACMEChallengesConfig{
		DeviceAttest01: true,
		DeviceAttest:   config.ACMEDeviceAttestConfig{TPMRoots: []string{writeAnchorFile(t, root)}},
	})
	if err != nil {
		t.Fatalf("buildDeviceAttestVerifier: %v", err)
	}
	return verifier
}

func TestBuildDeviceAttestVerifier(t *testing.T) {
	root, _ := newTestRoot(t, "TPM Root")

	t.Run("disabled builds nothing", func(t *testing.T) {
		verifier, err := buildDeviceAttestVerifier(config.ACMEChallengesConfig{})
		if verifier != nil || err != nil {
			t.Fatalf("got (%v, %v), want (nil, nil)", verifier, err)
		}
	})

	t.Run("enabled with a TPM root builds the production verifier", func(t *testing.T) {
		verifier, err := buildDeviceAttestVerifier(config.ACMEChallengesConfig{
			DeviceAttest01: true,
			DeviceAttest:   config.ACMEDeviceAttestConfig{TPMRoots: []string{writeAnchorFile(t, root)}},
		})
		if err != nil {
			t.Fatalf("buildDeviceAttestVerifier: %v", err)
		}
		if _, ok := verifier.(*acmesdk.ACMETrustAnchorVerifier); !ok {
			t.Fatalf("verifier = %T, want *ACMETrustAnchorVerifier", verifier)
		}
	})

	t.Run("enabled with no trust anchor is refused", func(t *testing.T) {
		verifier, err := buildDeviceAttestVerifier(config.ACMEChallengesConfig{DeviceAttest01: true})
		if !errors.Is(err, acmesdk.ACMEErrNoTrustAnchors) || verifier != nil {
			t.Fatalf("got (%v, %v), want (nil, ACMEErrNoTrustAnchors)", verifier, err)
		}
	})

	t.Run("an unreadable anchor file is refused", func(t *testing.T) {
		_, err := buildDeviceAttestVerifier(config.ACMEChallengesConfig{
			DeviceAttest01: true,
			DeviceAttest:   config.ACMEDeviceAttestConfig{TPMRoots: []string{filepath.Join(t.TempDir(), "missing.pem")}},
		})
		if !errors.Is(err, ErrACMEDeviceAttestAnchorRead) {
			t.Fatalf("err = %v, want ErrACMEDeviceAttestAnchorRead", err)
		}
	})

	t.Run("an anchor file with no certificate is refused", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "garbage.pem")
		if err := os.WriteFile(path, []byte("not pem"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := buildDeviceAttestVerifier(config.ACMEChallengesConfig{
			DeviceAttest01: true,
			DeviceAttest:   config.ACMEDeviceAttestConfig{DICERoots: []string{path}},
		})
		if !errors.Is(err, ErrACMEDeviceAttestAnchorParse) {
			t.Fatalf("err = %v, want ErrACMEDeviceAttestAnchorParse", err)
		}
	})
}

// TestBuildDeviceAttestVerifier_DICEFailsClosedWithoutARegistry proves the
// daemon, which injects no device registry, authorizes no DICE device: an
// alias that chains to a configured DICE root and answers its challenge is
// still refused, because a chain alone never anchors DICE evidence.
func TestBuildDeviceAttestVerifier_DICEFailsClosedWithoutARegistry(t *testing.T) {
	root, rootKey := newTestRoot(t, "DICE Root")
	const keyAuth = "token.thumbprint"

	ueid, err := dice.CreateUeidExtension([]byte{1, 2, 3, 4})
	if err != nil {
		t.Fatal(err)
	}
	uccs, err := dice.CreateUccsEvidenceExtension(&dice.ClaimsSet{Nonce: acmesdk.ACMEDICENonce(keyAuth)})
	if err != nil {
		t.Fatal(err)
	}
	aliasKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber:    big.NewInt(2),
		Subject:         pkix.Name{CommonName: "alias"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{ueid, uccs},
	}, root, aliasKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	object := &acmesdk.ACMEDeviceAttestObject{
		Format:       string(acmesdk.ACMEDeviceAttestFormatDICE),
		AttStatement: acmesdk.ACMEDeviceAttestStatement{X5c: []interface{}{leafDER}},
	}

	verifier, err := buildDeviceAttestVerifier(config.ACMEChallengesConfig{
		DeviceAttest01: true,
		DeviceAttest:   config.ACMEDeviceAttestConfig{DICERoots: []string{writeAnchorFile(t, root)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyAttestationObject(object, []byte(keyAuth)); !errors.Is(err, acmesdk.ACMEErrDeviceNotAuthorized) {
		t.Fatalf("err = %v, want ACMEErrDeviceNotAuthorized: a dice chain alone was accepted", err)
	}

	anchored, ok := verifier.(*acmesdk.ACMETrustAnchorVerifier)
	if !ok {
		t.Fatalf("verifier = %T, want *ACMETrustAnchorVerifier", verifier)
	}
	_, err = anchored.VerifyRegisteredDevice(context.Background(), leaf, keyAuth)
	if !errors.Is(err, acmesdk.ACMEErrDeviceNotAuthorized) || !errors.Is(err, acmesdk.ACMEErrNoDeviceResolver) {
		t.Fatalf("err = %v, want ACMEErrDeviceNotAuthorized wrapping ACMEErrNoDeviceResolver", err)
	}
}

// TestStartACMEServer_DeviceAttestAnchors proves the shipped daemon, on its
// real CA, refuses to start device-attest-01 with nothing to anchor it to and
// starts it once a root is configured: the flag is no longer unusable.
func TestStartACMEServer_DeviceAttestAnchors(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("no anchor refuses startup with a typed error", func(t *testing.T) {
		srv, _ := newEmbeddedQRDBServerWithCA(t)
		cfg := &config.Config{ACME: acmeSuccessConfig(t)}
		cfg.ACME.Challenges = config.ACMEChallengesConfig{DeviceAttest01: true}

		as, err := startACMEServer(srv, cfg, logger)
		if as != nil {
			t.Fatal("a server was started with device-attest-01 and no trust anchor")
		}
		if !errors.Is(err, ErrACMEDeviceAttestAnchors) || !errors.Is(err, acmesdk.ACMEErrNoTrustAnchors) {
			t.Fatalf("err = %v, want ErrACMEDeviceAttestAnchors wrapping ACMEErrNoTrustAnchors", err)
		}
	})

	t.Run("a configured anchor starts the shipped CA", func(t *testing.T) {
		srv, _ := newEmbeddedQRDBServerWithCA(t)
		root, _ := newTestRoot(t, "TPM Root")
		cfg := &config.Config{ACME: acmeSuccessConfig(t)}
		cfg.ACME.Challenges = config.ACMEChallengesConfig{
			DeviceAttest01: true,
			DeviceAttest:   config.ACMEDeviceAttestConfig{TPMRoots: []string{writeAnchorFile(t, root)}},
		}

		as, err := startACMEServer(srv, cfg, logger)
		if err != nil {
			t.Fatalf("startACMEServer: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := as.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	})
}
