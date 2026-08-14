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

//go:build integration && pkcs11 && pkcs11_tool
// +build integration,pkcs11,pkcs11_tool

// Package module drives pkcs11-tool's --derive verb against the go-xkms
// PKCS#11 shared library to exercise CKM_ECDH1_DERIVE end to end (T4).
//
// pkcs11-tool's --derive CLI surface was verified directly against a
// SoftHSM2 token (a real, independent Cryptoki implementation) before this
// file was written:
//
//   - --input-file for ECDH1-DERIVE is NOT the raw SEC1 point. pkcs11-tool
//     parses it with OpenSSL's DER public-key reader (it failed with "Cannot
//     read EC key from <path>" against a raw point file), so the file must
//     hold a DER-encoded SubjectPublicKeyInfo, i.e. the same bytes
//     x509.MarshalPKIXPublicKey produces. pkcs11-tool itself extracts the
//     raw uncompressed point from that DER before placing it in
//     CK_ECDH1_DERIVE_PARAMS.pPublicData, which is what
//     pkg/pkcs11/module/mechanism.go's ValidateECDHPeerPoint validates on the
//     module side (an uncompressed SEC1 point, 0x04||X||Y).
//   - --key-type GENERIC:<n> requests an n-byte derived secret key object,
//     and --extractable is required for --output-file to receive the raw
//     CKA_VALUE afterward (pkcs11-tool refuses to read back a non-extractable
//     key's value).
//
// Build tags: integration,pkcs11,pkcs11_tool
package module

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"path/filepath"
	"testing"
)

// pkcs11ToolDeriveGeneratePeerSPKI generates a fresh P-256 key pair outside
// the token and returns the DER encoding of its public key
// (SubjectPublicKeyInfo), which is what pkcs11-tool's --derive expects as the
// peer's public key file for CKM_ECDH1_DERIVE.
func pkcs11ToolDeriveGeneratePeerSPKI(t *testing.T) []byte {
	t.Helper()

	peer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate peer EC key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&peer.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal peer public key: %v", err)
	}
	return der
}

// TestPKCS11Tool_ECDHDerive generates an EC P-256 key pair in the token,
// performs an ECDH derivation against an external peer's public key using
// pkcs11-tool --derive, and asserts a shared secret is produced (T4).
func TestPKCS11Tool_ECDHDerive(t *testing.T) {
	requireFilePersistence(t)
	requireTool(t)
	cfg := NewPKCS11ToolTestConfig(t)
	requireModule(t, cfg.ModulePath)

	SetupInitializedModule(t)

	t.Run("derive_ecdh1_p256", func(t *testing.T) {
		keyLabel := "ecdh-derive-p256"
		keyID := "70"

		keygenOutput, keygenStderr, keygenErr := runPKCS11ToolCommand(t, cfg,
			"--login", "--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--keypairgen",
			"--key-type", "EC:secp256r1",
			"--label", keyLabel,
			"--id", keyID,
		)
		if keygenErr != nil {
			t.Fatalf("EC P-256 key generation failed: %v\nstdout: %s\nstderr: %s", keygenErr, keygenOutput, keygenStderr)
		}

		peerSPKI := pkcs11ToolDeriveGeneratePeerSPKI(t)
		peerFile := writeTestDataFile(t, cfg.TempDir, "ecdh_peer_pub.der", peerSPKI)
		secretFile := filepath.Join(cfg.TempDir, "ecdh_derived_secret.bin")

		deriveOutput, deriveStderr, deriveErr := runPKCS11ToolCommand(t, cfg,
			"--login", "--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--derive",
			"--id", keyID,
			"--mechanism", "ECDH1-DERIVE",
			"--input-file", peerFile,
			"--output-file", secretFile,
			"--key-type", "GENERIC:32",
			"--extractable",
		)
		if deriveErr != nil {
			t.Fatalf("pkcs11-tool --derive failed: %v\nstdout: %s\nstderr: %s", deriveErr, deriveOutput, deriveStderr)
		}

		secret := readTestDataFile(t, secretFile)
		if len(secret) == 0 {
			t.Fatal("expected a non-empty derived shared secret")
		}
		if len(secret) != 32 {
			t.Fatalf("expected a 32-byte derived secret (--key-type GENERIC:32), got %d bytes", len(secret))
		}

		allZeros := true
		for _, b := range secret {
			if b != 0 {
				allZeros = false
				break
			}
		}
		if allZeros {
			t.Fatal("derived shared secret is all zeros, which indicates a broken derivation rather than a real ECDH result")
		}

		t.Logf("derived shared secret: %d bytes", len(secret))
	})

	t.Run("derive_ecdh1_p256_distinct_peers_yield_distinct_secrets", func(t *testing.T) {
		// A second derivation against a different peer public key must not
		// reproduce the first subtest's secret; that would indicate the
		// module is ignoring the caller-supplied peer point.
		keyLabel := "ecdh-derive-p256-b"
		keyID := "71"

		keygenOutput, keygenStderr, keygenErr := runPKCS11ToolCommand(t, cfg,
			"--login", "--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--keypairgen",
			"--key-type", "EC:secp256r1",
			"--label", keyLabel,
			"--id", keyID,
		)
		if keygenErr != nil {
			t.Fatalf("EC P-256 key generation failed: %v\nstdout: %s\nstderr: %s", keygenErr, keygenOutput, keygenStderr)
		}

		peerAFile := writeTestDataFile(t, cfg.TempDir, "ecdh_peer_a.der", pkcs11ToolDeriveGeneratePeerSPKI(t))
		peerBFile := writeTestDataFile(t, cfg.TempDir, "ecdh_peer_b.der", pkcs11ToolDeriveGeneratePeerSPKI(t))
		secretAFile := filepath.Join(cfg.TempDir, "ecdh_secret_a.bin")
		secretBFile := filepath.Join(cfg.TempDir, "ecdh_secret_b.bin")

		for _, run := range []struct {
			peerFile, secretFile string
		}{
			{peerAFile, secretAFile},
			{peerBFile, secretBFile},
		} {
			output, stderr, err := runPKCS11ToolCommand(t, cfg,
				"--login", "--pin", cfg.PIN,
				"--slot", cfg.SlotID,
				"--derive",
				"--id", keyID,
				"--mechanism", "ECDH1-DERIVE",
				"--input-file", run.peerFile,
				"--output-file", run.secretFile,
				"--key-type", "GENERIC:32",
				"--extractable",
			)
			if err != nil {
				t.Fatalf("pkcs11-tool --derive failed: %v\nstdout: %s\nstderr: %s", err, output, stderr)
			}
		}

		secretA := readTestDataFile(t, secretAFile)
		secretB := readTestDataFile(t, secretBFile)
		if len(secretA) == 0 || len(secretB) == 0 {
			t.Fatal("expected non-empty derived secrets from both peers")
		}
		if string(secretA) == string(secretB) {
			t.Fatal("derivations against two distinct peer public keys produced the same secret")
		}
	})
}
