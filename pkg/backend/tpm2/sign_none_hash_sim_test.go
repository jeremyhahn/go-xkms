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

//go:build tpm_simulator

package tpm2

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/testutil/tpmblobtest"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// This file covers the backend's behaviour for hash "NONE" -- crypto.Hash(0),
// which is what the PKCS#11 module's CKM_ECDSA and CKM_RSA_PKCS mechanisms
// resolve to by the time they reach a crypto.Signer here.

// simSigningBackend returns an auto-provisioned simulator-backed Backend.
func simSigningBackend(t *testing.T) *Backend {
	t.Helper()

	backend, err := NewBackend(&Config{
		UseSimulator: true,
		Keys:         tpmblobtest.New(t),
		CN:           "none-hash-test",
	})
	if err != nil {
		t.Fatalf("NewBackend on fresh simulator: %v", err)
	}
	t.Cleanup(func() {
		if cerr := backend.Close(); cerr != nil {
			t.Errorf("Close: %v", cerr)
		}
	})
	return backend
}

// TestSigner_NoneHash_ECDSA_ProducesVerifiableSignature proves the backend's
// crypto.Signer honours crypto.Hash(0) end to end. This is the exact call shape
// the service layer makes for a CKM_ECDSA operation, and it used to fail with
// "invalid hash function" before the digest ever reached the TPM.
func TestSigner_NoneHash_ECDSA_ProducesVerifiableSignature(t *testing.T) {
	backend := simSigningBackend(t)
	ctx := context.Background()

	attrs := &types.KeyAttributes{
		CN:            "none-hash-ecdsa",
		KeyAlgorithm:  x509.ECDSA,
		KeyType:       types.KeyTypeSigning,
		StoreType:     types.StoreTPM2,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	}
	if _, err := backend.GenerateKey(ctx, attrs); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	signer, err := backend.Signer(ctx, attrs)
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}

	digest := sha256.Sum256([]byte("already-hashed payload"))
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign with crypto.Hash(0): %v", err)
	}

	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Public() returned %T, want *ecdsa.PublicKey", signer.Public())
	}
	if !ecdsa.VerifyASN1(pub, digest[:], signature) {
		t.Fatal("signature must verify against the key's public half")
	}

	other := sha256.Sum256([]byte("a different payload"))
	if ecdsa.VerifyASN1(pub, other[:], signature) {
		t.Fatal("signature must not verify against an unrelated digest")
	}
}

// TestSigner_NoneHash_RSA_RefusedAsUnsupportedOperation is the bad-input
// counterpart, and the point of it is which error comes back.
//
// The TPM genuinely cannot sign a caller-supplied PKCS#1 v1.5 DigestInfo (see
// pkgtpm2.ErrRawRSASignUnsupported for the command-level evidence). An
// application must be able to tell that capability boundary from a device
// malfunction, so the refusal is reported on the backend's ErrUnsupportedOperation
// sentinel -- the same one every other unsupported operation uses -- rather than
// as a generic "TPM sign failed".
func TestSigner_NoneHash_RSA_RefusedAsUnsupportedOperation(t *testing.T) {
	backend := simSigningBackend(t)
	ctx := context.Background()

	attrs := &types.KeyAttributes{
		CN:            "none-hash-rsa",
		KeyAlgorithm:  x509.RSA,
		KeyType:       types.KeyTypeSigning,
		StoreType:     types.StoreTPM2,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	}
	if _, err := backend.GenerateKey(ctx, attrs); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	signer, err := backend.Signer(ctx, attrs)
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}

	// The 51-byte DigestInfo a PKCS#11 caller hands a token for raw
	// CKM_RSA_PKCS (RFC 8017 A.2.4).
	digest := sha256.Sum256([]byte("payload"))
	digestInfo := append([]byte{
		0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
		0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
	}, digest[:]...)

	signature, err := signer.Sign(rand.Reader, digestInfo, crypto.Hash(0))
	if err == nil {
		t.Fatalf("raw RSA must be refused, got a %d-byte signature", len(signature))
	}
	if !errors.Is(err, ErrUnsupportedOperation) {
		t.Errorf("error must satisfy ErrUnsupportedOperation so callers can tell a "+
			"capability boundary from a fault, got: %v", err)
	}
	if !errors.Is(err, pkgtpm2.ErrRawRSASignUnsupported) {
		t.Errorf("error must carry the specific cause, got: %v", err)
	}
}

// TestSigner_NamedHash_RSA_StillSigns keeps the refusal above from widening: an
// RSA signature over a named digest lets the TPM build the DigestInfo itself and
// must keep working.
func TestSigner_NamedHash_RSA_StillSigns(t *testing.T) {
	backend := simSigningBackend(t)
	ctx := context.Background()

	attrs := &types.KeyAttributes{
		CN:            "named-hash-rsa",
		KeyAlgorithm:  x509.RSA,
		KeyType:       types.KeyTypeSigning,
		StoreType:     types.StoreTPM2,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	}
	if _, err := backend.GenerateKey(ctx, attrs); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	signer, err := backend.Signer(ctx, attrs)
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}

	digest := sha256.Sum256([]byte("payload"))
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
		t.Fatalf("Sign with crypto.SHA256: %v", err)
	}
}

// TestSigner_PSSOptions_RSA_ProducesPSSSignature pins that the signer keeps the
// caller's rsa.PSSOptions: a crypto.Signer caller that asks for RSA-PSS (a COSE
// PS256 signer, for one) declares PSS in what it emits, so a PKCS#1 v1.5
// signature returned under those options never verifies.
func TestSigner_PSSOptions_RSA_ProducesPSSSignature(t *testing.T) {
	backend := simSigningBackend(t)
	ctx := context.Background()

	attrs := &types.KeyAttributes{
		CN:            "pss-options-rsa",
		KeyAlgorithm:  x509.RSA,
		KeyType:       types.KeyTypeSigning,
		StoreType:     types.StoreTPM2,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	}
	if _, err := backend.GenerateKey(ctx, attrs); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	signer, err := backend.Signer(ctx, attrs)
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	pub, ok := signer.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatalf("Public: got %T, want *rsa.PublicKey", signer.Public())
	}

	pssOpts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	digest := sha256.Sum256([]byte("payload"))
	signature, err := signer.Sign(rand.Reader, digest[:], pssOpts)
	if err != nil {
		t.Fatalf("Sign with rsa.PSSOptions: %v", err)
	}
	if err := rsa.VerifyPSS(pub, crypto.SHA256, digest[:], signature, pssOpts); err != nil {
		t.Fatalf("VerifyPSS rejected the signature made under rsa.PSSOptions: %v", err)
	}
}

// TestGenerateKey_Repeated_DoesNotExhaustTPMObjectMemory is the backend-level
// consequence test for the object-context leak.
//
// GenerateKey is the operation certificate issuance performs, and each RSA
// generation used to strand one transient object slot -- so the third key a
// daemon generated on a connection failed with TPM_RC_OBJECT_MEMORY, and every
// later operation on unrelated keys failed with it too.
func TestGenerateKey_Repeated_DoesNotExhaustTPMObjectMemory(t *testing.T) {
	backend := simSigningBackend(t)
	ctx := context.Background()

	// Comfortably more than any TPM's transient object slot count.
	const iterations = 12
	for i := 0; i < iterations; i++ {
		attrs := &types.KeyAttributes{
			CN:            fmt.Sprintf("gen-%d", i),
			KeyAlgorithm:  x509.RSA,
			KeyType:       types.KeyTypeSigning,
			StoreType:     types.StoreTPM2,
			RSAAttributes: &types.RSAAttributes{KeySize: 2048},
		}
		if _, err := backend.GenerateKey(ctx, attrs); err != nil {
			t.Fatalf("iteration %d: GenerateKey: %v", i, err)
		}
	}
}
