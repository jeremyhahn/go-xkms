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

// TestBuildDeviceAttestVerifier_DICEPolicyReachesTheVerifier proves the DICE
// requirements in the configuration are the verifier's: an alias with no
// DiceTcbInfo anchors and answers its challenge, and is refused only when
// acme.challenges.device_attest.dice_require_tcb_info says so.
func TestBuildDeviceAttestVerifier_DICEPolicyReachesTheVerifier(t *testing.T) {
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
	object := &acmesdk.ACMEDeviceAttestObject{
		Format:       string(acmesdk.ACMEDeviceAttestFormatDICE),
		AttStatement: acmesdk.ACMEDeviceAttestStatement{X5c: []interface{}{leafDER}},
	}

	anchors := config.ACMEDeviceAttestConfig{DICERoots: []string{writeAnchorFile(t, root)}}
	lax, err := buildDeviceAttestVerifier(config.ACMEChallengesConfig{DeviceAttest01: true, DeviceAttest: anchors})
	if err != nil {
		t.Fatal(err)
	}
	if err := lax.VerifyAttestationObject(object, []byte(keyAuth)); err != nil {
		t.Fatalf("default policy refused a conforming alias: %v", err)
	}

	anchors.DICERequireTCBInfo = true
	strict, err := buildDeviceAttestVerifier(config.ACMEChallengesConfig{DeviceAttest01: true, DeviceAttest: anchors})
	if err != nil {
		t.Fatal(err)
	}
	if err := strict.VerifyAttestationObject(object, []byte(keyAuth)); err == nil {
		t.Fatal("dice_require_tcb_info did not reach the verifier: an alias with no DiceTcbInfo was accepted")
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
