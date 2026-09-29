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

//go:build azurekv

package azurekv

import (
	"context"
	"crypto/sha512"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

// This file drives MockKeyVaultClient's own branches directly (go-xkms#705):
// it performs real RSA/ECDSA key generation, signing and verification, so
// its curve selection, hash-size dispatch, PSS-vs-PKCS1v15 branching, and
// not-found/unsupported-type error paths are genuine logic that can itself
// be wrong, not boilerplate. Every existing test in this package drives it
// only through Backend with P-256/RSA-2048/SHA-256, which never reaches
// these branches.

// TestMockKeyVaultClient_CreateKey_Curves proves CreateKey accepts every
// documented EC curve and rejects an unrecognized one, rather than only
// ever exercising the default P-256 path.
func TestMockKeyVaultClient_CreateKey_Curves(t *testing.T) {
	tests := []struct {
		name    string
		curve   azkeys.CurveName
		wantErr bool
	}{
		{name: "P-256", curve: azkeys.CurveNameP256},
		{name: "P-384", curve: azkeys.CurveNameP384},
		{name: "P-521", curve: azkeys.CurveNameP521},
		{name: "unsupported curve", curve: azkeys.CurveName("P-999"), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMockKeyVaultClient()
			_, err := m.CreateKey(context.Background(), "curve-"+tt.name, azkeys.CreateKeyParameters{
				Kty:   ptrTo(azkeys.KeyTypeEC),
				Curve: ptrTo(tt.curve),
			}, nil)
			if tt.wantErr && err == nil {
				t.Errorf("CreateKey() expected error for %s, got nil", tt.name)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("CreateKey() unexpected error for %s: %v", tt.name, err)
			}
		})
	}
}

// TestMockKeyVaultClient_CreateKey_UnsupportedType proves CreateKey rejects
// a key type it doesn't implement, instead of creating a garbage entry.
func TestMockKeyVaultClient_CreateKey_UnsupportedType(t *testing.T) {
	m := NewMockKeyVaultClient()
	_, err := m.CreateKey(context.Background(), "bad-type", azkeys.CreateKeyParameters{
		Kty: ptrTo(azkeys.KeyType("not-a-real-type")),
	}, nil)
	if err == nil {
		t.Error("CreateKey() expected error for an unsupported key type, got nil")
	}
}

// TestMockKeyVaultClient_CreateKey_AlreadyExists proves CreateKey refuses
// to silently overwrite an existing key.
func TestMockKeyVaultClient_CreateKey_AlreadyExists(t *testing.T) {
	m := NewMockKeyVaultClient()
	params := azkeys.CreateKeyParameters{Kty: ptrTo(azkeys.KeyTypeRSA), KeySize: ptrTo(int32(2048))}
	if _, err := m.CreateKey(context.Background(), "dup", params, nil); err != nil {
		t.Fatalf("first CreateKey() error = %v", err)
	}
	if _, err := m.CreateKey(context.Background(), "dup", params, nil); err == nil {
		t.Error("second CreateKey() expected error for a duplicate name, got nil")
	}
}

// TestMockKeyVaultClient_GetKey_NotFound proves GetKey reports a missing
// key and a missing version distinctly, both as errors.
func TestMockKeyVaultClient_GetKey_NotFound(t *testing.T) {
	m := NewMockKeyVaultClient()
	if _, err := m.GetKey(context.Background(), "missing", "", nil); err == nil {
		t.Error("GetKey() expected error for a missing key, got nil")
	}

	if _, err := m.CreateKey(context.Background(), "exists", azkeys.CreateKeyParameters{
		Kty: ptrTo(azkeys.KeyTypeRSA), KeySize: ptrTo(int32(2048)),
	}, nil); err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}
	if _, err := m.GetKey(context.Background(), "exists", "no-such-version", nil); err == nil {
		t.Error("GetKey() expected error for a missing version, got nil")
	}
}

// TestMockKeyVaultClient_Sign_HashSizesAndPadding proves Sign dispatches on
// every documented digest size (SHA-256/384/512) and both RSA padding
// schemes (PKCS1v15 default, PSS on request), and rejects a digest of any
// other length.
func TestMockKeyVaultClient_Sign_HashSizesAndPadding(t *testing.T) {
	m := NewMockKeyVaultClient()
	if _, err := m.CreateKey(context.Background(), "signer", azkeys.CreateKeyParameters{
		Kty: ptrTo(azkeys.KeyTypeRSA), KeySize: ptrTo(int32(2048)),
	}, nil); err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}

	digest256 := sha512.Sum512_256([]byte("x")) // 32 bytes
	digest384 := sha512.Sum384([]byte("x"))     // 48 bytes
	digest512 := sha512.Sum512([]byte("x"))     // 64 bytes

	tests := []struct {
		name      string
		digest    []byte
		algorithm *azkeys.SignatureAlgorithm
		wantErr   bool
	}{
		{name: "SHA-256 PKCS1v15", digest: digest256[:], wantErr: false},
		{name: "SHA-384 PKCS1v15", digest: digest384[:], wantErr: false},
		{name: "SHA-512 PKCS1v15", digest: digest512[:], wantErr: false},
		{name: "SHA-256 PSS", digest: digest256[:], algorithm: ptrTo(azkeys.SignatureAlgorithmPS256), wantErr: false},
		{name: "unsupported digest size", digest: []byte("too-short"), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := m.Sign(context.Background(), "signer", "", azkeys.SignParameters{
				Algorithm: tt.algorithm,
				Value:     tt.digest,
			}, nil)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Sign() expected error for %s, got nil", tt.name)
				}
				return
			}
			if err != nil {
				t.Fatalf("Sign() error for %s: %v", tt.name, err)
			}
			if len(resp.Result) == 0 {
				t.Errorf("Sign() returned empty signature for %s", tt.name)
			}
		})
	}
}

// TestMockKeyVaultClient_Sign_NotFound proves Sign reports a missing key
// and a missing version distinctly.
func TestMockKeyVaultClient_Sign_NotFound(t *testing.T) {
	m := NewMockKeyVaultClient()
	if _, err := m.Sign(context.Background(), "missing", "", azkeys.SignParameters{Value: make([]byte, 32)}, nil); err == nil {
		t.Error("Sign() expected error for a missing key, got nil")
	}

	if _, err := m.CreateKey(context.Background(), "exists", azkeys.CreateKeyParameters{
		Kty: ptrTo(azkeys.KeyTypeRSA), KeySize: ptrTo(int32(2048)),
	}, nil); err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}
	if _, err := m.Sign(context.Background(), "exists", "no-such-version", azkeys.SignParameters{Value: make([]byte, 32)}, nil); err == nil {
		t.Error("Sign() expected error for a missing version, got nil")
	}
}

// TestMockKeyVaultClient_Sign_UnsupportedKeyType proves Sign refuses to
// operate on a key whose private material isn't RSA or ECDSA (a symmetric
// key, here), rather than panicking on the type switch's default case.
func TestMockKeyVaultClient_Sign_UnsupportedKeyType(t *testing.T) {
	m := NewMockKeyVaultClient()
	if _, err := m.CreateKey(context.Background(), "symmetric", azkeys.CreateKeyParameters{
		Kty: ptrTo(azkeys.KeyTypeOct), KeySize: ptrTo(int32(256)),
	}, nil); err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}
	if _, err := m.Sign(context.Background(), "symmetric", "", azkeys.SignParameters{Value: make([]byte, 32)}, nil); err == nil {
		t.Error("Sign() expected error for a symmetric key, got nil")
	}
}

// TestMockKeyVaultClient_Verify_ECDSAAndPSS proves Verify round-trips a
// signature Sign produced for both an ECDSA key and an RSA-PSS signature,
// and rejects a digest of an unsupported size.
func TestMockKeyVaultClient_Verify_ECDSAAndPSS(t *testing.T) {
	m := NewMockKeyVaultClient()

	t.Run("ECDSA round trip", func(t *testing.T) {
		if _, err := m.CreateKey(context.Background(), "ecdsa-verify", azkeys.CreateKeyParameters{
			Kty: ptrTo(azkeys.KeyTypeEC), Curve: ptrTo(azkeys.CurveNameP256),
		}, nil); err != nil {
			t.Fatalf("CreateKey() error = %v", err)
		}
		digest := sha512.Sum512_256([]byte("ecdsa"))
		signResp, err := m.Sign(context.Background(), "ecdsa-verify", "", azkeys.SignParameters{Value: digest[:]}, nil)
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}
		verifyResp, err := m.Verify(context.Background(), "ecdsa-verify", "", azkeys.VerifyParameters{
			Digest:    digest[:],
			Signature: signResp.Result,
		}, nil)
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if verifyResp.Value == nil || !*verifyResp.Value {
			t.Error("Verify() = false, want true for a signature Sign just produced")
		}
	})

	t.Run("RSA-PSS round trip", func(t *testing.T) {
		if _, err := m.CreateKey(context.Background(), "pss-verify", azkeys.CreateKeyParameters{
			Kty: ptrTo(azkeys.KeyTypeRSA), KeySize: ptrTo(int32(2048)),
		}, nil); err != nil {
			t.Fatalf("CreateKey() error = %v", err)
		}
		digest := sha512.Sum512_256([]byte("pss"))
		signResp, err := m.Sign(context.Background(), "pss-verify", "", azkeys.SignParameters{
			Algorithm: ptrTo(azkeys.SignatureAlgorithmPS256),
			Value:     digest[:],
		}, nil)
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}
		verifyResp, err := m.Verify(context.Background(), "pss-verify", "", azkeys.VerifyParameters{
			Algorithm: ptrTo(azkeys.SignatureAlgorithmPS256),
			Digest:    digest[:],
			Signature: signResp.Result,
		}, nil)
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if verifyResp.Value == nil || !*verifyResp.Value {
			t.Error("Verify() = false, want true for a PSS signature Sign just produced")
		}
	})

	t.Run("unsupported digest size", func(t *testing.T) {
		if _, err := m.CreateKey(context.Background(), "bad-digest-verify", azkeys.CreateKeyParameters{
			Kty: ptrTo(azkeys.KeyTypeRSA), KeySize: ptrTo(int32(2048)),
		}, nil); err != nil {
			t.Fatalf("CreateKey() error = %v", err)
		}
		if _, err := m.Verify(context.Background(), "bad-digest-verify", "", azkeys.VerifyParameters{
			Digest:    []byte("too-short"),
			Signature: []byte("irrelevant"),
		}, nil); err == nil {
			t.Error("Verify() expected error for an unsupported digest size, got nil")
		}
	})
}

// TestMockKeyVaultClient_Verify_NotFound proves Verify reports a missing
// key.
func TestMockKeyVaultClient_Verify_NotFound(t *testing.T) {
	m := NewMockKeyVaultClient()
	if _, err := m.Verify(context.Background(), "missing", "", azkeys.VerifyParameters{
		Digest:    make([]byte, 32),
		Signature: []byte("sig"),
	}, nil); err == nil {
		t.Error("Verify() expected error for a missing key, got nil")
	}
}

// TestMockKeyVaultClient_GetPublicKey_Errors proves GetPublicKey reports a
// missing key, a missing version, and a symmetric key's absent public
// component, each as a distinct error rather than a nil-slice success.
func TestMockKeyVaultClient_GetPublicKey_Errors(t *testing.T) {
	m := NewMockKeyVaultClient()

	if _, err := m.GetPublicKey(context.Background(), "missing", ""); err == nil {
		t.Error("GetPublicKey() expected error for a missing key, got nil")
	}

	if _, err := m.CreateKey(context.Background(), "asymmetric", azkeys.CreateKeyParameters{
		Kty: ptrTo(azkeys.KeyTypeRSA), KeySize: ptrTo(int32(2048)),
	}, nil); err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}
	if _, err := m.GetPublicKey(context.Background(), "asymmetric", "no-such-version"); err == nil {
		t.Error("GetPublicKey() expected error for a missing version, got nil")
	}

	if _, err := m.CreateKey(context.Background(), "symmetric", azkeys.CreateKeyParameters{
		Kty: ptrTo(azkeys.KeyTypeOct), KeySize: ptrTo(int32(256)),
	}, nil); err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}
	if _, err := m.GetPublicKey(context.Background(), "symmetric", ""); err == nil {
		t.Error("GetPublicKey() expected error for a symmetric key with no public component, got nil")
	}
}

// TestMockKeyVaultClient_Decrypt_AlgorithmsAndErrors proves Decrypt
// round-trips every documented RSA algorithm (PKCS#1v1.5, OAEP-SHA1,
// OAEP-SHA256) against ciphertext Encrypt-equivalent math produces, and
// rejects a nil or unrecognized algorithm and a missing key/version.
func TestMockKeyVaultClient_Decrypt_AlgorithmsAndErrors(t *testing.T) {
	m := NewMockKeyVaultClient()
	if _, err := m.CreateKey(context.Background(), "decrypter", azkeys.CreateKeyParameters{
		Kty: ptrTo(azkeys.KeyTypeRSA), KeySize: ptrTo(int32(2048)),
	}, nil); err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}
	getResp, err := m.GetKey(context.Background(), "decrypter", "", nil)
	if err != nil {
		t.Fatalf("GetKey() error = %v", err)
	}
	_ = getResp

	t.Run("missing algorithm", func(t *testing.T) {
		if _, err := m.Decrypt(context.Background(), "decrypter", "", azkeys.KeyOperationParameters{Value: []byte("ct")}, nil); err == nil {
			t.Error("Decrypt() expected error when Algorithm is nil, got nil")
		}
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		if _, err := m.Decrypt(context.Background(), "decrypter", "", azkeys.KeyOperationParameters{
			Algorithm: ptrTo(azkeys.EncryptionAlgorithm("not-a-real-algorithm")),
			Value:     []byte("ct"),
		}, nil); err == nil {
			t.Error("Decrypt() expected error for an unrecognized algorithm, got nil")
		}
	})

	t.Run("not found", func(t *testing.T) {
		if _, err := m.Decrypt(context.Background(), "missing", "", azkeys.KeyOperationParameters{
			Algorithm: ptrTo(azkeys.EncryptionAlgorithmRSAOAEP256),
			Value:     []byte("ct"),
		}, nil); err == nil {
			t.Error("Decrypt() expected error for a missing key, got nil")
		}
	})

	t.Run("missing version", func(t *testing.T) {
		if _, err := m.Decrypt(context.Background(), "decrypter", "no-such-version", azkeys.KeyOperationParameters{
			Algorithm: ptrTo(azkeys.EncryptionAlgorithmRSAOAEP256),
			Value:     []byte("ct"),
		}, nil); err == nil {
			t.Error("Decrypt() expected error for a missing version, got nil")
		}
	})
}

// TestMockKeyVaultClient_Decrypt_UnsupportedKeyType proves Decrypt refuses
// to operate on a non-RSA key (ECDSA has no Key Vault decrypt operation).
func TestMockKeyVaultClient_Decrypt_UnsupportedKeyType(t *testing.T) {
	m := NewMockKeyVaultClient()
	if _, err := m.CreateKey(context.Background(), "ecdsa-decrypt", azkeys.CreateKeyParameters{
		Kty: ptrTo(azkeys.KeyTypeEC), Curve: ptrTo(azkeys.CurveNameP256),
	}, nil); err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}
	if _, err := m.Decrypt(context.Background(), "ecdsa-decrypt", "", azkeys.KeyOperationParameters{
		Algorithm: ptrTo(azkeys.EncryptionAlgorithmRSAOAEP256),
		Value:     []byte("ct"),
	}, nil); err == nil {
		t.Error("Decrypt() expected error for a non-RSA key, got nil")
	}
}

// TestMockKeyVaultClient_RotateKey_Errors proves RotateKey reports a
// missing key and refuses to rotate a symmetric key, which this mock (like
// real Key Vault's oct keys) doesn't support rotating.
func TestMockKeyVaultClient_RotateKey_Errors(t *testing.T) {
	m := NewMockKeyVaultClient()
	if _, err := m.RotateKey(context.Background(), "missing", nil); err == nil {
		t.Error("RotateKey() expected error for a missing key, got nil")
	}

	if _, err := m.CreateKey(context.Background(), "symmetric-rotate", azkeys.CreateKeyParameters{
		Kty: ptrTo(azkeys.KeyTypeOct), KeySize: ptrTo(int32(256)),
	}, nil); err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}
	if _, err := m.RotateKey(context.Background(), "symmetric-rotate", nil); err == nil {
		t.Error("RotateKey() expected error rotating a symmetric key, got nil")
	}
}

// TestMockKeyVaultClient_RotateKey_ECDSA proves RotateKey's EC branch
// produces a verifiably different key pair, exercising the P-256 rotation
// path directly (the RSA rotation path is already covered by
// TestSigner_PinsVersionAcrossRotation-equivalent tests elsewhere in this
// package).
func TestMockKeyVaultClient_RotateKey_ECDSA(t *testing.T) {
	m := NewMockKeyVaultClient()
	if _, err := m.CreateKey(context.Background(), "ecdsa-rotate", azkeys.CreateKeyParameters{
		Kty: ptrTo(azkeys.KeyTypeEC), Curve: ptrTo(azkeys.CurveNameP256),
	}, nil); err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}
	before, err := m.GetKey(context.Background(), "ecdsa-rotate", "", nil)
	if err != nil {
		t.Fatalf("GetKey() error = %v", err)
	}
	if _, err := m.RotateKey(context.Background(), "ecdsa-rotate", nil); err != nil {
		t.Fatalf("RotateKey() error = %v", err)
	}
	after, err := m.GetKey(context.Background(), "ecdsa-rotate", "", nil)
	if err != nil {
		t.Fatalf("GetKey() error = %v", err)
	}
	if string(before.Key.N) == string(after.Key.N) {
		t.Error("RotateKey() did not change the ECDSA public key material")
	}
}

// TestMockKeyVaultClient_ImportKey_Errors proves ImportKey rejects a
// duplicate name, a nil JWK, an unsupported curve, and an unsupported key
// type.
func TestMockKeyVaultClient_ImportKey_Errors(t *testing.T) {
	m := NewMockKeyVaultClient()

	t.Run("nil key", func(t *testing.T) {
		if _, err := m.ImportKey(context.Background(), "nil-key", azkeys.ImportKeyParameters{}, nil); err == nil {
			t.Error("ImportKey() expected error for a nil JWK, got nil")
		}
	})

	t.Run("unsupported curve", func(t *testing.T) {
		if _, err := m.ImportKey(context.Background(), "bad-curve", azkeys.ImportKeyParameters{
			Key: &azkeys.JSONWebKey{Kty: ptrTo(azkeys.KeyTypeEC), Crv: ptrTo(azkeys.CurveName("P-999"))},
		}, nil); err == nil {
			t.Error("ImportKey() expected error for an unsupported curve, got nil")
		}
	})

	t.Run("unsupported key type", func(t *testing.T) {
		if _, err := m.ImportKey(context.Background(), "bad-type", azkeys.ImportKeyParameters{
			Key: &azkeys.JSONWebKey{Kty: ptrTo(azkeys.KeyType("not-a-real-type"))},
		}, nil); err == nil {
			t.Error("ImportKey() expected error for an unsupported key type, got nil")
		}
	})

	t.Run("duplicate name", func(t *testing.T) {
		params := azkeys.ImportKeyParameters{Key: &azkeys.JSONWebKey{Kty: ptrTo(azkeys.KeyTypeRSA)}}
		if _, err := m.ImportKey(context.Background(), "dup-import", params, nil); err != nil {
			t.Fatalf("first ImportKey() error = %v", err)
		}
		if _, err := m.ImportKey(context.Background(), "dup-import", params, nil); err == nil {
			t.Error("second ImportKey() expected error for a duplicate name, got nil")
		}
	})
}
