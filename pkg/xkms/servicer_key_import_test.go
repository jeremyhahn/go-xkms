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

package xkms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// importRoundTripCase is one algorithm's worth of the import ceremony: a key
// generated outside the service, the wire names the request uses for it, and
// an oracle that verifies a signature the service later produces with it.
type importRoundTripCase struct {
	name string
	// keyType is the ImportKeyRequest.KeyType wire value, which names the
	// algorithm.
	keyType string
	keySize int
	curve   string
	// keySpec is what the backend must report back from GetImportParameters.
	// It is derived entirely from the key template, so it is the direct
	// evidence that the template reached the backend rather than being dropped.
	keySpec string
	// algorithm is the algorithm ListKeys and GetKey must report for the
	// imported key -- its OWN algorithm, not a default.
	algorithm string
	generate  func(t *testing.T) (crypto.PrivateKey, crypto.PublicKey)
	// verify checks a signature outside the service, against the public half
	// of the key that was generated outside it. A service that stored the
	// wrong material, or stored it under an identifier that resolves to some
	// other key, cannot satisfy this.
	verify func(t *testing.T, pub crypto.PublicKey, message, signature []byte)
}

func importRoundTripCases() []importRoundTripCase {
	return []importRoundTripCase{
		{
			name:      "rsa",
			keyType:   "rsa",
			keySize:   2048,
			keySpec:   "RSA_2048",
			algorithm: "RSA",
			generate: func(t *testing.T) (crypto.PrivateKey, crypto.PublicKey) {
				t.Helper()
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				return key, &key.PublicKey
			},
			verify: func(t *testing.T, pub crypto.PublicKey, message, signature []byte) {
				t.Helper()
				rsaPub, ok := pub.(*rsa.PublicKey)
				require.True(t, ok)
				digest := sha256.Sum256(message)
				require.NoError(t, rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], signature))
			},
		},
		{
			// P-384 rather than the default curve: a service that dropped the
			// curve and substituted P-256 would produce a key whose signatures
			// do not verify under this P-384 public key, and a KeySpec of
			// ECC_NIST_P256.
			name:      "ecdsa",
			keyType:   "ecdsa",
			curve:     "P-384",
			keySpec:   "ECC_NIST_P384",
			algorithm: "ECDSA",
			generate: func(t *testing.T) (crypto.PrivateKey, crypto.PublicKey) {
				t.Helper()
				key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)
				return key, &key.PublicKey
			},
			verify: func(t *testing.T, pub crypto.PublicKey, message, signature []byte) {
				t.Helper()
				ecPub, ok := pub.(*ecdsa.PublicKey)
				require.True(t, ok)
				digest := sha256.Sum256(message)
				assert.True(t, ecdsa.VerifyASN1(ecPub, digest[:], signature))
			},
		},
		{
			name:      "ed25519",
			keyType:   "ed25519",
			keySpec:   "ED25519",
			algorithm: "Ed25519",
			generate: func(t *testing.T) (crypto.PrivateKey, crypto.PublicKey) {
				t.Helper()
				pub, priv, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)
				return priv, pub
			},
			verify: func(t *testing.T, pub crypto.PublicKey, message, signature []byte) {
				t.Helper()
				edPub, ok := pub.(ed25519.PublicKey)
				require.True(t, ok)
				assert.True(t, ed25519.Verify(edPub, message, signature))
			},
		},
	}
}

// TestImportKeyAsymmetricRoundTrip runs the whole BYOK ceremony against a real
// software backend, once per asymmetric algorithm, and proves the imported key
// is the key that was imported.
//
// ImportKey could not import an asymmetric key at all. buildImportKeyAttributes
// set a purpose and no algorithm, so:
//
//   - an RSA import failed outright, the backend's key-type check reporting
//     "expected RSA key but attributes specify 0";
//   - an Ed25519 or ECDSA import SUCCEEDED and was then stored under an
//     identifier ending in "unknown", which types.KeyAttributes.ID() produces
//     when no algorithm is set and no other code path constructs. ListKeys
//     read that identifier back and reported the key as RSA, and every
//     subsequent operation looked for a key that was not there.
//
// The second failure is why this test signs and verifies rather than only
// asserting on attributes: a mock backend would have accepted the meaningless
// identifier and reported whatever it was told, so a test built on one goes
// green on exactly the bug that shipped.
func TestImportKeyAsymmetricRoundTrip(t *testing.T) {
	for _, tc := range importRoundTripCases() {
		t.Run(tc.name, func(t *testing.T) {
			svc := setupDeriveService(t)
			ctx := context.Background()
			keyID := "imported-" + tc.name

			priv, pub := tc.generate(t)
			keyMaterial, err := x509.MarshalPKCS8PrivateKey(priv)
			require.NoError(t, err)

			// The hybrid algorithm is used throughout: an RSA-2048 private key
			// in PKCS#8 is far larger than a single RSA-OAEP block.
			const wrapAlgorithm = string(backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)

			params, err := svc.GetImportParameters(ctx, &transport.GetImportParametersRequest{
				Backend:   "software",
				KeyID:     keyID,
				Algorithm: wrapAlgorithm,
				KeyType:   tc.keyType,
				KeySize:   tc.keySize,
				Curve:     tc.curve,
			})
			require.NoError(t, err)
			require.NotEmpty(t, params.WrappingPublicKey)
			assert.Equal(t, tc.keySpec, params.KeySpec,
				"the ceremony must be negotiated for the key the request described")

			wrapped, err := svc.WrapKey(ctx, &transport.WrapKeyRequest{
				Backend:           "software",
				KeyMaterial:       keyMaterial,
				Algorithm:         params.Algorithm,
				WrappingPublicKey: params.WrappingPublicKey,
				ImportToken:       params.ImportToken,
				KeySpec:           params.KeySpec,
			})
			require.NoError(t, err)
			require.NotEmpty(t, wrapped.WrappedKeyMaterial)

			importResp, err := svc.ImportKey(ctx, &transport.ImportKeyRequest{
				Backend:            "software",
				KeyID:              keyID,
				KeyType:            tc.keyType,
				KeySize:            tc.keySize,
				Curve:              tc.curve,
				WrappedKeyMaterial: wrapped.WrappedKeyMaterial,
				Algorithm:          wrapped.Algorithm,
				ImportToken:        params.ImportToken,
			})
			require.NoError(t, err)
			require.True(t, importResp.Success)

			// The key reports its own algorithm, not a default.
			list, err := svc.ListKeys(ctx, "software")
			require.NoError(t, err)
			var listed *transport.KeyInfo
			for i := range list.Keys {
				if list.Keys[i].KeyID == keyID {
					listed = &list.Keys[i]
					break
				}
			}
			require.NotNil(t, listed, "the imported key must be visible under the id it was imported with")
			assert.Equal(t, tc.algorithm, listed.Algorithm)

			got, err := svc.GetKey(ctx, "software", keyID)
			require.NoError(t, err)
			assert.Equal(t, tc.algorithm, got.Algorithm)
			assert.NotEmpty(t, got.PublicKeyPEM)

			// Sign with the imported key and verify outside the service.
			message := []byte("import round trip for " + tc.name)
			signResp, err := svc.Sign(ctx, &transport.SignRequest{
				Backend: "software",
				KeyID:   keyID,
				Data:    message,
			})
			require.NoError(t, err)
			require.NotEmpty(t, signResp.Signature)
			tc.verify(t, pub, message, signResp.Signature)
		})
	}
}

// TestImportKeyRejectsMisdescribedKeys covers the requests that cannot be
// honoured. Each of them used to be accepted, and each produced a key stored
// under an identifier that does not describe it -- or, for RSA, an error from
// deep inside the backend rather than from the request that caused it.
func TestImportKeyRejectsMisdescribedKeys(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*transport.ImportKeyRequest)
		wantErr error
	}{
		{
			name:    "no key type",
			mutate:  func(r *transport.ImportKeyRequest) { r.KeyType = "" },
			wantErr: ErrMissingRequiredField,
		},
		{
			name:    "purpose name is not an algorithm",
			mutate:  func(r *transport.ImportKeyRequest) { r.KeyType = "signing" },
			wantErr: ErrInvalidKeyType,
		},
		{
			name:    "unsupported algorithm",
			mutate:  func(r *transport.ImportKeyRequest) { r.KeyType = "kyber" },
			wantErr: ErrInvalidKeyType,
		},
		{
			name: "unparseable curve",
			mutate: func(r *transport.ImportKeyRequest) {
				r.KeyType = "ecdsa"
				r.Curve = "P-999"
			},
			wantErr: ErrInvalidCurve,
		},
		{
			name: "unusable symmetric size",
			mutate: func(r *transport.ImportKeyRequest) {
				r.KeyType = "aes"
				r.KeySize = 512
			},
			wantErr: ErrInvalidKeyAttributes,
		},
		{
			// go-xkms#1204: buildImportKeyAttributes now runs
			// KeyAttributes.Validate through applyKeyTemplate, so an import
			// that declares an RSA modulus under 2048 bits is refused here
			// rather than reaching the backend's ImportKey unchecked.
			name: "undersized rsa key size",
			mutate: func(r *transport.ImportKeyRequest) {
				r.KeyType = "rsa"
				r.KeySize = 1024
			},
			wantErr: ErrInvalidKeyAttributes,
		},
		{
			name: "unresolvable hash",
			mutate: func(r *transport.ImportKeyRequest) {
				r.Hash = "SHA-3000"
			},
			wantErr: ErrInvalidHashFunction,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := setupDeriveService(t)

			req := &transport.ImportKeyRequest{
				Backend:            "software",
				KeyID:              "rejected-key",
				KeyType:            "rsa",
				KeySize:            2048,
				WrappedKeyMaterial: []byte("wrapped"),
				Algorithm:          string(backend.WrappingAlgorithmRSAES_OAEP_SHA_256),
				ImportToken:        []byte("token"),
			}
			tt.mutate(req)

			_, err := svc.ImportKey(context.Background(), req)
			require.Error(t, err)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

// TestImportKeyHonoursDeclaredRSAKeySize proves the declared key size reaches
// the backend rather than being dropped: the software backend refuses material
// whose modulus does not match the size the attributes claim, so an import that
// names 4096 for a 2048-bit key must fail.
//
// Without this, a servicer that hard-coded the RSA default would import the key
// happily and record a size that is simply untrue.
func TestImportKeyHonoursDeclaredRSAKeySize(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keyMaterial, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	const wrapAlgorithm = string(backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)

	params, err := svc.GetImportParameters(ctx, &transport.GetImportParametersRequest{
		Backend:   "software",
		KeyID:     "size-mismatch",
		Algorithm: wrapAlgorithm,
		KeyType:   "rsa",
		KeySize:   4096,
	})
	require.NoError(t, err)
	assert.Equal(t, "RSA_4096", params.KeySpec,
		"the declared size must reach the backend, which reports it back as the key spec")

	wrapped, err := svc.WrapKey(ctx, &transport.WrapKeyRequest{
		Backend:           "software",
		KeyMaterial:       keyMaterial,
		Algorithm:         params.Algorithm,
		WrappingPublicKey: params.WrappingPublicKey,
		ImportToken:       params.ImportToken,
	})
	require.NoError(t, err)

	_, err = svc.ImportKey(ctx, &transport.ImportKeyRequest{
		Backend:            "software",
		KeyID:              "size-mismatch",
		KeyType:            "rsa",
		KeySize:            4096,
		WrappedKeyMaterial: wrapped.WrappedKeyMaterial,
		Algorithm:          wrapped.Algorithm,
		ImportToken:        params.ImportToken,
	})
	require.Error(t, err, "a 2048-bit key declared as 4096 bits must be refused")
}

// TestImportKeySymmetricStillWorks guards the symmetric branch against
// regression while the asymmetric branch was added. A symmetric import is
// exportable by default (PKCS#11 v3.2 §4.9 Table 30), takes its size from
// KeySize with AESKeySize as the fallback, and defaults to AES-256.
func TestImportKeySymmetricStillWorks(t *testing.T) {
	tests := []struct {
		name       string
		keyType    string
		keySize    int
		aesKeySize int
		material   []byte
	}{
		{name: "key size", keyType: "symmetric", keySize: 128, material: make([]byte, 16)},
		{name: "aes key size fallback", keyType: "aes", aesKeySize: 192, material: make([]byte, 24)},
		{name: "defaults to aes-256", keyType: "symmetric", material: make([]byte, 32)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := setupDeriveService(t)
			ctx := context.Background()
			keyID := "imported-secret"

			_, err := rand.Read(tt.material)
			require.NoError(t, err)

			params, err := svc.GetImportParameters(ctx, &transport.GetImportParametersRequest{
				Backend:   "software",
				KeyID:     keyID,
				Algorithm: string(backend.WrappingAlgorithmRSAES_OAEP_SHA_256),
				KeyType:   tt.keyType,
				KeySize:   tt.keySize,
			})
			require.NoError(t, err)

			wrapped, err := svc.WrapKey(ctx, &transport.WrapKeyRequest{
				Backend:           "software",
				KeyMaterial:       tt.material,
				Algorithm:         params.Algorithm,
				WrappingPublicKey: params.WrappingPublicKey,
				ImportToken:       params.ImportToken,
			})
			require.NoError(t, err)

			_, err = svc.ImportKey(ctx, &transport.ImportKeyRequest{
				Backend:            "software",
				KeyID:              keyID,
				KeyType:            tt.keyType,
				KeySize:            tt.keySize,
				AESKeySize:         tt.aesKeySize,
				WrappedKeyMaterial: wrapped.WrappedKeyMaterial,
				Algorithm:          wrapped.Algorithm,
				ImportToken:        params.ImportToken,
			})
			require.NoError(t, err)

			// Exportable by default, and the bytes that come back are the ones
			// that went in.
			export, err := svc.ExportKeyMaterial(ctx, &transport.ExportKeyMaterialRequest{
				Backend: "software",
				KeyID:   keyID,
			})
			require.NoError(t, err)
			assert.Equal(t, tt.material, export.KeyMaterial)
		})
	}
}

// ===========================================================================
// GetImportParameters key template
// ===========================================================================

// TestGetImportParametersUsesTheKeyTemplate pins that the request's key
// template decides the ceremony's key spec.
//
// Only the common name used to be passed to the backend, so every ceremony was
// negotiated for a key of unknown kind and the backend answered "UNKNOWN"
// however precisely the caller had described the key. Routing a transport that
// does thread the template through this method would have regressed it.
func TestGetImportParametersUsesTheKeyTemplate(t *testing.T) {
	tests := []struct {
		name        string
		keyType     string
		keySize     int
		curve       string
		wantKeySpec string
	}{
		{name: "rsa 2048", keyType: "rsa", keySize: 2048, wantKeySpec: "RSA_2048"},
		{name: "rsa 3072", keyType: "rsa", keySize: 3072, wantKeySpec: "RSA_3072"},
		{name: "rsa 4096", keyType: "rsa", keySize: 4096, wantKeySpec: "RSA_4096"},
		{name: "ecdsa p-521", keyType: "ecdsa", curve: "P-521", wantKeySpec: "ECC_NIST_P521"},
		{name: "ed25519", keyType: "ed25519", wantKeySpec: "ED25519"},
		{name: "aes 128", keyType: "aes", keySize: 128, wantKeySpec: "AES_128"},
		// A caller that has not chosen a key kind can still ask for a wrapping
		// key: there is no template to drop in that case.
		{name: "no template", wantKeySpec: "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := setupDeriveService(t)

			resp, err := svc.GetImportParameters(context.Background(), &transport.GetImportParametersRequest{
				Backend:   "software",
				KeyID:     "ceremony-key",
				Algorithm: string(backend.WrappingAlgorithmRSAES_OAEP_SHA_256),
				KeyType:   tt.keyType,
				KeySize:   tt.keySize,
				Curve:     tt.curve,
			})
			require.NoError(t, err)
			assert.Equal(t, tt.wantKeySpec, resp.KeySpec)
		})
	}
}

// TestKeyTemplateRefusalNamesTheCallersField pins that the refusal names the
// field the caller actually sent.
//
// ImportKey, GetImportParameters and UnwrapKeyByID share one template
// resolver, and a shared resolver that reported a name of its own would tell a
// caller debugging a C_UnwrapKey template that some other field was wrong. The
// gRPC transport surfaces this text verbatim.
func TestKeyTemplateRefusalNamesTheCallersField(t *testing.T) {
	_, err := unwrapTargetAttributes(&transport.UnwrapKeyByIDRequest{
		TargetKeyID:      "k",
		TargetKeyBackend: "software",
		TargetKeyType:    "kyber",
	}, 32, types.StoreSoftware)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported target key type: kyber")

	_, err = buildImportKeyAttributes(&transport.ImportKeyRequest{
		KeyID:   "k",
		KeyType: "kyber",
	}, "software", types.StoreSoftware)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key type: kyber")
}

// TestGetImportParametersRejectsAnUnusableTemplate pins that a template the
// service cannot honour is refused here, rather than being silently discarded
// and discovered only when the later ImportKey fails.
func TestGetImportParametersRejectsAnUnusableTemplate(t *testing.T) {
	svc := setupDeriveService(t)

	_, err := svc.GetImportParameters(context.Background(), &transport.GetImportParametersRequest{
		Backend:   "software",
		KeyID:     "ceremony-key",
		Algorithm: string(backend.WrappingAlgorithmRSAES_OAEP_SHA_256),
		KeyType:   "ecdsa",
		Curve:     "P-999",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCurve)
}

// TestGetImportParametersRejectsUndersizedRSA proves the import-template
// path -- applyKeyTemplate, shared by GetImportParameters, ImportKey and
// UnwrapKeyByID -- refuses an RSA modulus below types.RSAKeySize2048 exactly
// as buildKeyAttributes does for GenerateKey. Before applyKeyTemplate called
// KeyAttributes.Validate, a caller could negotiate (and then complete) a BYOK
// ceremony for a 1024-bit RSA key with no refusal anywhere (go-xkms#1204).
func TestGetImportParametersRejectsUndersizedRSA(t *testing.T) {
	svc := setupDeriveService(t)

	_, err := svc.GetImportParameters(context.Background(), &transport.GetImportParametersRequest{
		Backend:   "software",
		KeyID:     "ceremony-key",
		Algorithm: string(backend.WrappingAlgorithmRSAES_OAEP_SHA_256),
		KeyType:   "rsa",
		KeySize:   1024,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
	assert.Contains(t, err.Error(), "RSA key size must be at least 2048")
}
