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

//go:build codec_json

package pkcs11

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// TestEmbeddedTransport_ConnectClose covers the in-process transport's
// no-op lifecycle: nothing to dial or tear down, but callers rely on both
// returning nil rather than panicking on a zero-value transport.
func TestEmbeddedTransport_ConnectClose(t *testing.T) {
	var tr EmbeddedTransport
	if err := tr.Connect(context.Background()); err != nil {
		t.Errorf("Connect() error = %v, want nil", err)
	}
	if err := tr.Close(); err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}
}

// TestEmbeddedTransport_GenerateKey covers each algorithm branch GenerateKey
// dispatches on, plus the failure paths that never reach the backend.
func TestEmbeddedTransport_GenerateKey(t *testing.T) {
	tr := newDeriveTestTransport(t)
	ctx := context.Background()

	t.Run("rsa default size", func(t *testing.T) {
		resp, err := tr.GenerateKey(ctx, &transport.GenerateKeyRequest{
			KeyID: "rsa-default", Backend: deriveBackend, KeyType: "RSA",
		})
		if err != nil {
			t.Fatalf("GenerateKey() error = %v", err)
		}
		if resp.PublicKeyPEM == "" {
			t.Error("expected a non-empty public key PEM")
		}
	})

	t.Run("ecdsa explicit curve", func(t *testing.T) {
		resp, err := tr.GenerateKey(ctx, &transport.GenerateKeyRequest{
			KeyID: "ecdsa-p384", Backend: deriveBackend, KeyType: "ECDSA", Curve: "P-384",
		})
		if err != nil {
			t.Fatalf("GenerateKey() error = %v", err)
		}
		if resp.PublicKeyPEM == "" {
			t.Error("expected a non-empty public key PEM")
		}
	})

	t.Run("ecdsa invalid curve", func(t *testing.T) {
		_, err := tr.GenerateKey(ctx, &transport.GenerateKeyRequest{
			KeyID: "ecdsa-bad-curve", Backend: deriveBackend, KeyType: "ECDSA", Curve: "not-a-curve",
		})
		if err == nil {
			t.Fatal("expected an error for an unrecognised curve")
		}
	})

	t.Run("ed25519", func(t *testing.T) {
		resp, err := tr.GenerateKey(ctx, &transport.GenerateKeyRequest{
			KeyID: "ed25519-key", Backend: deriveBackend, KeyType: "Ed25519",
		})
		if err != nil {
			t.Fatalf("GenerateKey() error = %v", err)
		}
		if resp.PublicKeyPEM == "" {
			t.Error("expected a non-empty public key PEM")
		}
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		_, err := tr.GenerateKey(ctx, &transport.GenerateKeyRequest{
			KeyID: "mystery-key", Backend: deriveBackend, KeyType: "DSA",
		})
		if err == nil {
			t.Fatal("expected an error for an unsupported algorithm")
		}
	})

	t.Run("backend not found", func(t *testing.T) {
		_, err := tr.GenerateKey(ctx, &transport.GenerateKeyRequest{
			KeyID: "x", Backend: "does-not-exist", KeyType: "RSA",
		})
		if !errors.Is(err, ErrBackendNotFound) {
			t.Fatalf("GenerateKey() error = %v, want ErrBackendNotFound", err)
		}
	})

	t.Run("nil request", func(t *testing.T) {
		_, err := tr.GenerateKey(ctx, nil)
		if !errors.Is(err, ErrNilRequest) {
			t.Fatalf("GenerateKey(nil) error = %v, want ErrNilRequest", err)
		}
	})
}

// TestEmbeddedTransport_SignVerify covers the Ed25519 pure-signing branch,
// the prehash branch used by every other algorithm, and Verify's use of the
// signer's own public key to check both a genuine and a tampered signature.
func TestEmbeddedTransport_SignVerify(t *testing.T) {
	tr := newDeriveTestTransport(t)
	ctx := context.Background()

	if _, err := tr.GenerateKey(ctx, &transport.GenerateKeyRequest{
		KeyID: "sign-ecdsa", Backend: deriveBackend, KeyType: "ECDSA", Curve: "P-256",
	}); err != nil {
		t.Fatalf("GenerateKey(ECDSA) error = %v", err)
	}
	if _, err := tr.GenerateKey(ctx, &transport.GenerateKeyRequest{
		KeyID: "sign-ed25519", Backend: deriveBackend, KeyType: "Ed25519",
	}); err != nil {
		t.Fatalf("GenerateKey(Ed25519) error = %v", err)
	}

	t.Run("ecdsa sign and verify", func(t *testing.T) {
		data := []byte("the operation this signature authorizes")
		signResp, err := tr.Sign(ctx, &transport.SignRequest{
			Backend: deriveBackend, KeyID: "sign-ecdsa", Data: data, Hash: "SHA256",
		})
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}

		verifyResp, err := tr.Verify(ctx, &transport.VerifyRequest{
			Backend: deriveBackend, KeyID: "sign-ecdsa", Data: data, Signature: signResp.Signature, Hash: "SHA256",
		})
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if !verifyResp.Valid {
			t.Error("Verify() Valid = false, want true for a genuine signature")
		}
	})

	t.Run("ed25519 pure signing and verify", func(t *testing.T) {
		data := []byte("ed25519 never prehashes")
		signResp, err := tr.Sign(ctx, &transport.SignRequest{
			Backend: deriveBackend, KeyID: "sign-ed25519", Data: data,
		})
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}

		verifyResp, err := tr.Verify(ctx, &transport.VerifyRequest{
			Backend: deriveBackend, KeyID: "sign-ed25519", Data: data, Signature: signResp.Signature,
		})
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if !verifyResp.Valid {
			t.Error("Verify() Valid = false, want true for a genuine signature")
		}
	})

	t.Run("verify rejects a tampered signature", func(t *testing.T) {
		data := []byte("original data")
		signResp, err := tr.Sign(ctx, &transport.SignRequest{
			Backend: deriveBackend, KeyID: "sign-ecdsa", Data: data,
		})
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}
		tampered := append([]byte{}, signResp.Signature...)
		tampered[0] ^= 0xFF

		verifyResp, err := tr.Verify(ctx, &transport.VerifyRequest{
			Backend: deriveBackend, KeyID: "sign-ecdsa", Data: data, Signature: tampered,
		})
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if verifyResp.Valid {
			t.Error("Verify() Valid = true for a tampered signature, want false")
		}
	})

	t.Run("sign key not found", func(t *testing.T) {
		_, err := tr.Sign(ctx, &transport.SignRequest{Backend: deriveBackend, KeyID: "no-such-key", Data: []byte("x")})
		if !errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("Sign() error = %v, want ErrKeyNotFound", err)
		}
	})

	t.Run("verify backend not found", func(t *testing.T) {
		_, err := tr.Verify(ctx, &transport.VerifyRequest{Backend: "does-not-exist", KeyID: "sign-ecdsa"})
		if !errors.Is(err, ErrBackendNotFound) {
			t.Fatalf("Verify() error = %v, want ErrBackendNotFound", err)
		}
	})

	t.Run("nil requests", func(t *testing.T) {
		if _, err := tr.Sign(ctx, nil); !errors.Is(err, ErrNilRequest) {
			t.Errorf("Sign(nil) error = %v, want ErrNilRequest", err)
		}
		if _, err := tr.Verify(ctx, nil); !errors.Is(err, ErrNilRequest) {
			t.Errorf("Verify(nil) error = %v, want ErrNilRequest", err)
		}
	})
}

// TestEmbeddedTransport_EncryptDecrypt covers the symmetric round trip and
// the request-validation paths that return before touching the backend.
func TestEmbeddedTransport_EncryptDecrypt(t *testing.T) {
	tr := newDeriveTestTransport(t)
	ctx := context.Background()
	newSymmetricKey(t, "encrypt-key", true)

	t.Run("round trip", func(t *testing.T) {
		plaintext := []byte("the message the caller wants kept confidential")
		encResp, err := tr.Encrypt(ctx, &transport.EncryptRequest{
			Backend: deriveBackend, KeyID: "encrypt-key", Plaintext: plaintext,
		})
		if err != nil {
			t.Fatalf("Encrypt() error = %v", err)
		}
		if len(encResp.Ciphertext) == 0 {
			t.Fatal("expected non-empty ciphertext")
		}

		decResp, err := tr.Decrypt(ctx, &transport.DecryptRequest{
			Backend: deriveBackend, KeyID: "encrypt-key",
			Ciphertext: encResp.Ciphertext, Nonce: encResp.Nonce, Tag: encResp.Tag,
		})
		if err != nil {
			t.Fatalf("Decrypt() error = %v", err)
		}
		if string(decResp.Plaintext) != string(plaintext) {
			t.Errorf("Decrypt() Plaintext = %q, want %q", decResp.Plaintext, plaintext)
		}
	})

	t.Run("encrypt backend not found", func(t *testing.T) {
		_, err := tr.Encrypt(ctx, &transport.EncryptRequest{Backend: "does-not-exist", KeyID: "encrypt-key"})
		if !errors.Is(err, ErrBackendNotFound) {
			t.Fatalf("Encrypt() error = %v, want ErrBackendNotFound", err)
		}
	})

	t.Run("decrypt of corrupted ciphertext fails", func(t *testing.T) {
		encResp, err := tr.Encrypt(ctx, &transport.EncryptRequest{
			Backend: deriveBackend, KeyID: "encrypt-key", Plaintext: []byte("data"),
		})
		if err != nil {
			t.Fatalf("Encrypt() error = %v", err)
		}
		corrupted := append([]byte{}, encResp.Ciphertext...)
		corrupted[0] ^= 0xFF

		_, err = tr.Decrypt(ctx, &transport.DecryptRequest{
			Backend: deriveBackend, KeyID: "encrypt-key",
			Ciphertext: corrupted, Nonce: encResp.Nonce, Tag: encResp.Tag,
		})
		if !errors.Is(err, ErrDecryptionFailed) {
			t.Fatalf("Decrypt(corrupted) error = %v, want ErrDecryptionFailed", err)
		}
	})

	t.Run("nil requests", func(t *testing.T) {
		if _, err := tr.Encrypt(ctx, nil); !errors.Is(err, ErrNilRequest) {
			t.Errorf("Encrypt(nil) error = %v, want ErrNilRequest", err)
		}
		if _, err := tr.Decrypt(ctx, nil); !errors.Is(err, ErrNilRequest) {
			t.Errorf("Decrypt(nil) error = %v, want ErrNilRequest", err)
		}
	})
}

// TestEmbeddedTransport_EncryptAsym covers the RSA-OAEP path, including the
// type check that refuses to encrypt against a non-RSA key.
func TestEmbeddedTransport_EncryptAsym(t *testing.T) {
	tr := newDeriveTestTransport(t)
	ctx := context.Background()

	if _, err := tr.GenerateKey(ctx, &transport.GenerateKeyRequest{
		KeyID: "oaep-rsa", Backend: deriveBackend, KeyType: "RSA", KeySize: 2048,
	}); err != nil {
		t.Fatalf("GenerateKey(RSA) error = %v", err)
	}
	if _, err := tr.GenerateKey(ctx, &transport.GenerateKeyRequest{
		KeyID: "oaep-ecdsa", Backend: deriveBackend, KeyType: "ECDSA", Curve: "P-256",
	}); err != nil {
		t.Fatalf("GenerateKey(ECDSA) error = %v", err)
	}

	t.Run("success", func(t *testing.T) {
		resp, err := tr.EncryptAsym(ctx, &transport.EncryptAsymRequest{
			Backend: deriveBackend, KeyID: "oaep-rsa", Plaintext: []byte("wrap me"), Hash: "SHA256",
		})
		if err != nil {
			t.Fatalf("EncryptAsym() error = %v", err)
		}
		if len(resp.Ciphertext) == 0 {
			t.Error("expected non-empty ciphertext")
		}
	})

	t.Run("non-RSA key is refused", func(t *testing.T) {
		_, err := tr.EncryptAsym(ctx, &transport.EncryptAsymRequest{
			Backend: deriveBackend, KeyID: "oaep-ecdsa", Plaintext: []byte("wrap me"),
		})
		if !errors.Is(err, ErrEncryptionFailed) {
			t.Fatalf("EncryptAsym(ECDSA key) error = %v, want ErrEncryptionFailed", err)
		}
	})

	t.Run("key not found", func(t *testing.T) {
		_, err := tr.EncryptAsym(ctx, &transport.EncryptAsymRequest{
			Backend: deriveBackend, KeyID: "no-such-key", Plaintext: []byte("x"),
		})
		if err == nil {
			t.Fatal("expected an error for a missing key")
		}
	})

	t.Run("nil request", func(t *testing.T) {
		if _, err := tr.EncryptAsym(ctx, nil); !errors.Is(err, ErrNilRequest) {
			t.Errorf("EncryptAsym(nil) error = %v, want ErrNilRequest", err)
		}
	})
}

// TestEmbeddedTransport_DeriveKeyECDH covers ECDH key agreement against a
// peer key generated with the Go stdlib, independent of any xkms backend.
func TestEmbeddedTransport_DeriveKeyECDH(t *testing.T) {
	tr := newDeriveTestTransport(t)
	ctx := context.Background()

	if _, err := tr.GenerateKey(ctx, &transport.GenerateKeyRequest{
		KeyID: "ecdh-local", Backend: deriveBackend, KeyType: "ECDSA", Curve: "P-256",
	}); err != nil {
		t.Fatalf("GenerateKey(ECDSA) error = %v", err)
	}

	peer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}
	peerDER, err := x509.MarshalPKIXPublicKey(&peer.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v", err)
	}

	t.Run("success", func(t *testing.T) {
		resp, err := tr.DeriveKeyECDH(ctx, &transport.DeriveKeyECDHRequest{
			Backend: deriveBackend, KeyID: "ecdh-local", PeerPublicKey: peerDER,
		})
		if err != nil {
			t.Fatalf("DeriveKeyECDH() error = %v", err)
		}
		if len(resp.DerivedKey) != 32 {
			t.Errorf("DerivedKey length = %d, want 32 (the default)", len(resp.DerivedKey))
		}
	})

	t.Run("key not found", func(t *testing.T) {
		_, err := tr.DeriveKeyECDH(ctx, &transport.DeriveKeyECDHRequest{
			Backend: deriveBackend, KeyID: "no-such-key", PeerPublicKey: peerDER,
		})
		if !errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("DeriveKeyECDH() error = %v, want ErrKeyNotFound", err)
		}
	})

	t.Run("backend not found", func(t *testing.T) {
		_, err := tr.DeriveKeyECDH(ctx, &transport.DeriveKeyECDHRequest{Backend: "does-not-exist"})
		if !errors.Is(err, ErrBackendNotFound) {
			t.Fatalf("DeriveKeyECDH() error = %v, want ErrBackendNotFound", err)
		}
	})

	t.Run("nil request", func(t *testing.T) {
		if _, err := tr.DeriveKeyECDH(ctx, nil); !errors.Is(err, ErrNilRequest) {
			t.Errorf("DeriveKeyECDH(nil) error = %v, want ErrNilRequest", err)
		}
	})
}

// TestEmbeddedTransport_GetImportParameters covers the import-ceremony
// bootstrap: a caller asks for a wrapping public key before sending
// externally generated key material.
func TestEmbeddedTransport_GetImportParameters(t *testing.T) {
	tr := newDeriveTestTransport(t)
	ctx := context.Background()

	t.Run("rsa wrapping key", func(t *testing.T) {
		resp, err := tr.GetImportParameters(ctx, &transport.GetImportParametersRequest{
			Backend: deriveBackend, KeyID: "import-target", KeyType: "RSA", KeySize: 2048,
			Algorithm: string(xkms.WrappingAlgorithmRSAES_OAEP_SHA_256),
		})
		if err != nil {
			t.Fatalf("GetImportParameters() error = %v", err)
		}
		if len(resp.WrappingPublicKey) == 0 {
			t.Error("expected a non-empty wrapping public key")
		}
	})

	t.Run("unsupported key template", func(t *testing.T) {
		_, err := tr.GetImportParameters(ctx, &transport.GetImportParametersRequest{
			Backend: deriveBackend, KeyType: "not-an-algorithm",
		})
		if !errors.Is(err, ErrImportTemplateUnsupported) {
			t.Fatalf("GetImportParameters() error = %v, want ErrImportTemplateUnsupported", err)
		}
	})

	t.Run("nil request", func(t *testing.T) {
		if _, err := tr.GetImportParameters(ctx, nil); !errors.Is(err, ErrNilRequest) {
			t.Errorf("GetImportParameters(nil) error = %v, want ErrNilRequest", err)
		}
	})
}

// TestEmbeddedTransport_PIVDelegation covers the eight PIV operations, each
// a one-line delegation to the package-level xkms PIV functions. None of
// this process's compiled-in backends support PIV without a physical smart
// card, so every call takes the error path -- proving the delegation
// reaches the real xkms entry point and surfaces its error rather than
// panicking or silently succeeding.
func TestEmbeddedTransport_PIVDelegation(t *testing.T) {
	tr := newDeriveTestTransport(t)
	ctx := context.Background()

	if _, err := tr.ListPIVSlots(ctx, &transport.ListPIVSlotsRequest{Backend: deriveBackend}); err == nil {
		t.Error("ListPIVSlots() = nil error, want an error (no PIV-capable backend)")
	}
	if _, err := tr.GetPIVCertificate(ctx, &transport.GetPIVCertificateRequest{Backend: deriveBackend}); err == nil {
		t.Error("GetPIVCertificate() = nil error, want an error")
	}
	if _, err := tr.GeneratePIVKey(ctx, &transport.GeneratePIVKeyRequest{Backend: deriveBackend}); err == nil {
		t.Error("GeneratePIVKey() = nil error, want an error")
	}
	if err := tr.StorePIVCertificate(ctx, &transport.StorePIVCertificateRequest{Backend: deriveBackend}); err == nil {
		t.Error("StorePIVCertificate() = nil error, want an error")
	}
	if err := tr.DeletePIVCertificate(ctx, &transport.DeletePIVCertificateRequest{Backend: deriveBackend}); err == nil {
		t.Error("DeletePIVCertificate() = nil error, want an error")
	}
	if err := tr.ImportPIVCertificate(ctx, &transport.StorePIVCertificateRequest{Backend: deriveBackend}); err == nil {
		t.Error("ImportPIVCertificate() = nil error, want an error")
	}
	if _, err := tr.ExportPIVCertificate(ctx, &transport.GetPIVCertificateRequest{Backend: deriveBackend}); err == nil {
		t.Error("ExportPIVCertificate() = nil error, want an error")
	}
	if _, err := tr.GeneratePIVCSR(ctx, &transport.GeneratePIVCSRRequest{Backend: deriveBackend}); err == nil {
		t.Error("GeneratePIVCSR() = nil error, want an error")
	}
}

// TestParseHashAlgorithm covers the name-to-crypto.Hash table, including the
// case-insensitive and hyphenated spellings PKCS#11 callers use, and the
// SHA-256 fallback for an unrecognised name.
func TestParseHashAlgorithm(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"sha256", "SHA-256"}, {"SHA256", "SHA-256"}, {"sha-256", "SHA-256"}, {"SHA-256", "SHA-256"},
		{"sha384", "SHA-384"}, {"sha512", "SHA-512"}, {"sha1", "SHA-1"},
		{"", "SHA-256"}, {"not-a-hash", "SHA-256"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseHashAlgorithm(tc.name).String(); got != tc.want {
				t.Errorf("parseHashAlgorithm(%q) = %s, want %s", tc.name, got, tc.want)
			}
		})
	}
}

// TestExtractPublicKeyPEM covers each key type extractPublicKeyPEM
// recognises and the type it must refuse.
func TestExtractPublicKeyPEM(t *testing.T) {
	t.Run("ecdsa", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey() error = %v", err)
		}
		pem, err := extractPublicKeyPEM(priv)
		if err != nil {
			t.Fatalf("extractPublicKeyPEM() error = %v", err)
		}
		if pem == "" {
			t.Error("expected a non-empty PEM block")
		}
	})

	t.Run("unsupported type", func(t *testing.T) {
		_, err := extractPublicKeyPEM("not-a-key")
		if err == nil {
			t.Fatal("expected an error for an unsupported private key type")
		}
	})
}

// TestVerifySignatureHelper covers the three key-algorithm branches and the
// default case for an algorithm the helper does not recognise.
func TestVerifySignatureHelper(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}
	data := []byte("verify me")

	t.Run("wrong public key type for algorithm", func(t *testing.T) {
		// An RSA-shaped verification against an ECDSA public key must fail
		// closed (type assertion miss), not panic.
		if verifySignature(&priv.PublicKey, data, []byte("sig"), "SHA256", x509.RSA) {
			t.Error("verifySignature() = true for a type mismatch, want false")
		}
	})

	t.Run("unrecognised algorithm", func(t *testing.T) {
		if verifySignature(&priv.PublicKey, data, []byte("sig"), "SHA256", x509.UnknownPublicKeyAlgorithm) {
			t.Error("verifySignature() = true for an unrecognised algorithm, want false")
		}
	})

	t.Run("rsa genuine and tampered", func(t *testing.T) {
		rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa.GenerateKey() error = %v", err)
		}
		digest := sha256.Sum256(data)
		sig, err := rsa.SignPKCS1v15(rand.Reader, rsaPriv, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatalf("rsa.SignPKCS1v15() error = %v", err)
		}
		if !verifySignature(&rsaPriv.PublicKey, data, sig, "SHA256", x509.RSA) {
			t.Error("verifySignature() = false for a genuine RSA signature, want true")
		}
		badSig := append([]byte{}, sig...)
		badSig[0] ^= 0xFF
		if verifySignature(&rsaPriv.PublicKey, data, badSig, "SHA256", x509.RSA) {
			t.Error("verifySignature() = true for a tampered RSA signature, want false")
		}
	})

	t.Run("ed25519 genuine and tampered, and a type mismatch", func(t *testing.T) {
		edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519.GenerateKey() error = %v", err)
		}
		sig := ed25519.Sign(edPriv, data)
		if !verifySignature(edPub, data, sig, "", x509.Ed25519) {
			t.Error("verifySignature() = false for a genuine Ed25519 signature, want true")
		}
		badSig := append([]byte{}, sig...)
		badSig[0] ^= 0xFF
		if verifySignature(edPub, data, badSig, "", x509.Ed25519) {
			t.Error("verifySignature() = true for a tampered Ed25519 signature, want false")
		}
		if verifySignature(&priv.PublicKey, data, sig, "", x509.Ed25519) {
			t.Error("verifySignature() = true for an ECDSA key claimed as Ed25519, want false")
		}
	})
}

// TestNewEmbeddedTransport_NotInitialized covers the guard that refuses to
// hand out a transport bound to a process-global xkms service that has not
// been started -- every subsequent call would panic or nil-dereference
// rather than fail cleanly.
func TestNewEmbeddedTransport_NotInitialized(t *testing.T) {
	xkms.Reset()
	t.Cleanup(xkms.Reset)

	_, err := NewEmbeddedTransport()
	if !errors.Is(err, ErrServiceNotInitialized) {
		t.Fatalf("NewEmbeddedTransport() error = %v, want ErrServiceNotInitialized", err)
	}
}

// wrapAESKW is the PKCS#11 CKM_AES_KEY_WRAP algorithm name
// (types.WrapAESKW), used directly as a literal because the sdk/go
// re-export of the key-wrap algorithm constants
// (sdk/go/types.go) does not yet carry it -- unlike WrapRSAOAEPSHA256,
// which is re-exported as xkms.WrappingAlgorithmRSAES_OAEP_SHA_256 and used
// below unchanged.
const wrapAESKW = "AES_KW"

// TestEmbeddedTransport_WrapUnwrapKeyByID_AESKW_RoundTrip proves WrapKeyByID
// and UnwrapKeyByID -- the PKCS#11 C_WrapKey/C_UnwrapKey primitives -- wrap a
// resident target key directly under a resident wrapping key using RFC 3394
// AES Key Wrap and recover the identical material, rather than routing
// through the unrelated key-IMPORT ceremony (xkms.ExportKey/WrapKey, which
// always wraps under a freshly generated ephemeral key pair and can never
// produce a blob CKM_AES_KEY_WRAP peers expect).
func TestEmbeddedTransport_WrapUnwrapKeyByID_AESKW_RoundTrip(t *testing.T) {
	tr := newDeriveTestTransport(t)
	ctx := context.Background()

	wrappingKey := newSymmetricKey(t, "wrap-kek-aeskw", true)
	targetKey := newSymmetricKey(t, "wrap-target-aeskw", true)
	wantMaterial := exportedKeyMaterial(t, targetKey)

	wrapResp, err := tr.WrapKeyByID(ctx, &transport.WrapKeyByIDRequest{
		WrappingKeyBackend: deriveBackend, WrappingKeyID: wrappingKey.CN,
		TargetKeyBackend: deriveBackend, TargetKeyID: targetKey.CN,
		Algorithm: wrapAESKW,
	})
	if err != nil {
		t.Fatalf("WrapKeyByID() error = %v", err)
	}
	if wrapResp.Algorithm != wrapAESKW {
		t.Errorf("WrapKeyByID() Algorithm = %q, want %q", wrapResp.Algorithm, wrapAESKW)
	}
	if bytes.Equal(wrapResp.WrappedKey, wantMaterial) {
		t.Fatal("WrapKeyByID() returned the plaintext key material unwrapped")
	}

	const unwrappedKeyID = "unwrapped-target-aeskw"
	unwrapResp, err := tr.UnwrapKeyByID(ctx, &transport.UnwrapKeyByIDRequest{
		WrappedKey:           wrapResp.WrappedKey,
		UnwrappingKeyBackend: deriveBackend, UnwrappingKeyID: wrappingKey.CN,
		Algorithm:        wrapAESKW,
		TargetKeyBackend: deriveBackend, TargetKeyID: unwrappedKeyID,
		TargetKeyType: "AES", TargetExportable: true,
	})
	if err != nil {
		t.Fatalf("UnwrapKeyByID() error = %v", err)
	}
	if !unwrapResp.Success {
		t.Fatal("UnwrapKeyByID() Success = false, want true")
	}
	if unwrapResp.KeyID != unwrappedKeyID {
		t.Errorf("UnwrapKeyByID() KeyID = %q, want %q", unwrapResp.KeyID, unwrappedKeyID)
	}

	exportResp, err := tr.ExportKeyMaterial(ctx, &transport.ExportKeyMaterialRequest{
		Backend: deriveBackend, KeyID: unwrappedKeyID,
	})
	if err != nil {
		t.Fatalf("ExportKeyMaterial() of the unwrapped key error = %v", err)
	}
	if !bytes.Equal(exportResp.KeyMaterial, wantMaterial) {
		t.Errorf("unwrapped key material = %x, want %x", exportResp.KeyMaterial, wantMaterial)
	}
}

// TestEmbeddedTransport_WrapUnwrapKeyByID_RSAOAEP_RoundTrip proves the same
// ceremony with an asymmetric wrapping key, RSA-OAEP-SHA-256
// (CKM_RSA_PKCS_OAEP): the wrapping key is a resident RSA key pair -- wrap
// encrypts under its public half, unwrap decrypts with its own
// crypto.Decrypter -- never a freshly generated ephemeral pair.
func TestEmbeddedTransport_WrapUnwrapKeyByID_RSAOAEP_RoundTrip(t *testing.T) {
	tr := newDeriveTestTransport(t)
	ctx := context.Background()

	if _, err := tr.GenerateKey(ctx, &transport.GenerateKeyRequest{
		KeyID: "wrap-kek-oaep", Backend: deriveBackend, KeyType: "RSA", KeySize: 2048,
	}); err != nil {
		t.Fatalf("GenerateKey(RSA) error = %v", err)
	}
	targetKey := newSymmetricKey(t, "wrap-target-oaep", true)
	wantMaterial := exportedKeyMaterial(t, targetKey)

	wrapResp, err := tr.WrapKeyByID(ctx, &transport.WrapKeyByIDRequest{
		WrappingKeyBackend: deriveBackend, WrappingKeyID: "wrap-kek-oaep",
		TargetKeyBackend: deriveBackend, TargetKeyID: targetKey.CN,
		Algorithm: string(xkms.WrappingAlgorithmRSAES_OAEP_SHA_256),
	})
	if err != nil {
		t.Fatalf("WrapKeyByID() error = %v", err)
	}

	const unwrappedKeyID = "unwrapped-target-oaep"
	unwrapResp, err := tr.UnwrapKeyByID(ctx, &transport.UnwrapKeyByIDRequest{
		WrappedKey:           wrapResp.WrappedKey,
		UnwrappingKeyBackend: deriveBackend, UnwrappingKeyID: "wrap-kek-oaep",
		Algorithm:        string(xkms.WrappingAlgorithmRSAES_OAEP_SHA_256),
		TargetKeyBackend: deriveBackend, TargetKeyID: unwrappedKeyID,
		TargetKeyType: "AES", TargetExportable: true,
	})
	if err != nil {
		t.Fatalf("UnwrapKeyByID() error = %v", err)
	}
	if !unwrapResp.Success {
		t.Fatal("UnwrapKeyByID() Success = false, want true")
	}

	exportResp, err := tr.ExportKeyMaterial(ctx, &transport.ExportKeyMaterialRequest{
		Backend: deriveBackend, KeyID: unwrappedKeyID,
	})
	if err != nil {
		t.Fatalf("ExportKeyMaterial() of the unwrapped key error = %v", err)
	}
	if !bytes.Equal(exportResp.KeyMaterial, wantMaterial) {
		t.Errorf("unwrapped key material = %x, want %x", exportResp.KeyMaterial, wantMaterial)
	}
}

// TestEmbeddedTransport_WrapUnwrapKeyByID_ErrorPaths covers the request
// validation and first-hop failures of the wrap/unwrap-by-ID ceremony: a nil
// request, an unresolvable target or wrapping/unwrapping key, and an
// algorithm the service does not implement. Every failure is reported as the
// package's ErrWrappingFailed sentinel, with the underlying cause from
// pkg/xkms attached and still reachable through errors.Is/errors.As.
func TestEmbeddedTransport_WrapUnwrapKeyByID_ErrorPaths(t *testing.T) {
	tr := newDeriveTestTransport(t)
	ctx := context.Background()

	wrappingKey := newSymmetricKey(t, "wrap-error-kek", true)
	targetKey := newSymmetricKey(t, "wrap-error-target", true)

	t.Run("wrap nil request", func(t *testing.T) {
		if _, err := tr.WrapKeyByID(ctx, nil); !errors.Is(err, ErrNilRequest) {
			t.Errorf("WrapKeyByID(nil) error = %v, want ErrNilRequest", err)
		}
	})

	t.Run("wrap target key not found", func(t *testing.T) {
		_, err := tr.WrapKeyByID(ctx, &transport.WrapKeyByIDRequest{
			WrappingKeyBackend: deriveBackend, WrappingKeyID: wrappingKey.CN,
			TargetKeyBackend: deriveBackend, TargetKeyID: "no-such-target-key",
			Algorithm: wrapAESKW,
		})
		if !errors.Is(err, ErrWrappingFailed) {
			t.Fatalf("WrapKeyByID() error = %v, want ErrWrappingFailed", err)
		}
	})

	t.Run("wrap unknown wrapping key", func(t *testing.T) {
		_, err := tr.WrapKeyByID(ctx, &transport.WrapKeyByIDRequest{
			WrappingKeyBackend: deriveBackend, WrappingKeyID: "no-such-wrapping-key",
			TargetKeyBackend: deriveBackend, TargetKeyID: targetKey.CN,
			Algorithm: wrapAESKW,
		})
		if !errors.Is(err, ErrWrappingFailed) {
			t.Fatalf("WrapKeyByID() error = %v, want ErrWrappingFailed", err)
		}
	})

	t.Run("wrap unsupported algorithm", func(t *testing.T) {
		_, err := tr.WrapKeyByID(ctx, &transport.WrapKeyByIDRequest{
			WrappingKeyBackend: deriveBackend, WrappingKeyID: wrappingKey.CN,
			TargetKeyBackend: deriveBackend, TargetKeyID: targetKey.CN,
			Algorithm: "NOT-A-REAL-WRAP-ALGORITHM",
		})
		if !errors.Is(err, ErrWrappingFailed) {
			t.Fatalf("WrapKeyByID() error = %v, want ErrWrappingFailed", err)
		}
	})

	t.Run("unwrap nil request", func(t *testing.T) {
		if _, err := tr.UnwrapKeyByID(ctx, nil); !errors.Is(err, ErrNilRequest) {
			t.Errorf("UnwrapKeyByID(nil) error = %v, want ErrNilRequest", err)
		}
	})

	t.Run("unwrap unwrapping key not found", func(t *testing.T) {
		_, err := tr.UnwrapKeyByID(ctx, &transport.UnwrapKeyByIDRequest{
			UnwrappingKeyBackend: deriveBackend, UnwrappingKeyID: "no-such-unwrapping-key",
			WrappedKey: []byte("opaque"), Algorithm: wrapAESKW,
			TargetKeyBackend: deriveBackend, TargetKeyID: "unwrap-error-target",
			TargetKeyType: "AES",
		})
		if !errors.Is(err, ErrWrappingFailed) {
			t.Fatalf("UnwrapKeyByID() error = %v, want ErrWrappingFailed", err)
		}
	})

	t.Run("unwrap unsupported algorithm", func(t *testing.T) {
		_, err := tr.UnwrapKeyByID(ctx, &transport.UnwrapKeyByIDRequest{
			UnwrappingKeyBackend: deriveBackend, UnwrappingKeyID: wrappingKey.CN,
			WrappedKey: []byte("opaque"), Algorithm: "NOT-A-REAL-WRAP-ALGORITHM",
			TargetKeyBackend: deriveBackend, TargetKeyID: "unwrap-error-target",
			TargetKeyType: "AES",
		})
		if !errors.Is(err, ErrWrappingFailed) {
			t.Fatalf("UnwrapKeyByID() error = %v, want ErrWrappingFailed", err)
		}
	})
}

// TestEmbeddedTransport_ImportKey_RoundTrip runs the same import ceremony
// GetImportParameters begins: an RSA key generated outside the backend is
// wrapped under the negotiated wrapping public key and imported, then a
// signature made with the imported key is checked against the original
// public key -- proof the backend now holds that exact key, not merely that
// ImportKey reported success.
func TestEmbeddedTransport_ImportKey_RoundTrip(t *testing.T) {
	tr := newDeriveTestTransport(t)
	ctx := context.Background()

	extKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	keyMaterial, err := x509.MarshalPKCS8PrivateKey(extKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}

	paramsResp, err := tr.GetImportParameters(ctx, &transport.GetImportParametersRequest{
		Backend: deriveBackend, KeyID: "imported-rsa", KeyType: "RSA", KeySize: 2048,
		Algorithm: string(xkms.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256),
	})
	if err != nil {
		t.Fatalf("GetImportParameters() error = %v", err)
	}

	wrappingPub, err := x509.ParsePKIXPublicKey(paramsResp.WrappingPublicKey)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey() error = %v", err)
	}

	wrapped, err := xkms.WrapKey(ctx, deriveBackend, keyMaterial, &xkms.ImportParameters{
		WrappingPublicKey: wrappingPub,
		ImportToken:       paramsResp.ImportToken,
		Algorithm:         xkms.WrappingAlgorithm(paramsResp.Algorithm),
		KeySpec:           paramsResp.KeySpec,
	})
	if err != nil {
		t.Fatalf("xkms.WrapKey() error = %v", err)
	}

	importResp, err := tr.ImportKey(ctx, &transport.ImportKeyRequest{
		Backend: deriveBackend, KeyID: "imported-rsa", KeyType: "RSA", KeySize: 2048,
		WrappedKeyMaterial: wrapped.WrappedKey,
		Algorithm:          string(wrapped.Algorithm),
		ImportToken:        paramsResp.ImportToken,
	})
	if err != nil {
		t.Fatalf("ImportKey() error = %v", err)
	}
	if !importResp.Success {
		t.Fatal("ImportKey() Success = false, want true")
	}

	data := []byte("signed by the imported key")
	signResp, err := tr.Sign(ctx, &transport.SignRequest{Backend: deriveBackend, KeyID: "imported-rsa", Data: data, Hash: "SHA256"})
	if err != nil {
		t.Fatalf("Sign() with imported key error = %v", err)
	}
	digest := sha256.Sum256(data)
	if err := rsa.VerifyPKCS1v15(&extKey.PublicKey, crypto.SHA256, digest[:], signResp.Signature); err != nil {
		t.Errorf("the imported key signed with a different key than was exported: %v", err)
	}
}
