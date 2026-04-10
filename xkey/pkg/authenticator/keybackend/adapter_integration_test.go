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

//go:build integration

package keybackend

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"os"
	"sync"
	"testing"

	"github.com/fxamacker/cbor/v2"
	softwarebackend "github.com/jeremyhahn/go-xkms/pkg/backend/software"
	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// backendEntry describes a backend for the table-driven test matrix.
type backendEntry struct {
	name     string
	skip     func(t *testing.T)
	adapter  func(t *testing.T) *BackendAdapter
	hardware bool
}

// testBackends holds all backend entries. Additional backends (e.g., pkcs11)
// register themselves via init() in build-tagged companion files.
var testBackends []backendEntry

func init() {
	testBackends = append(testBackends,
		backendEntry{
			name:     "software",
			skip:     func(t *testing.T) { t.Helper() },
			adapter:  newSoftwareAdapter,
			hardware: false,
		},
		backendEntry{
			name:     "tpm2",
			skip:     skipIfNoTPM,
			adapter:  newTPM2Adapter,
			hardware: true,
		},
	)
}

// registerBackend appends a backend entry to the test matrix.
// Called from build-tagged companion files (e.g., adapter_integration_pkcs11_test.go).
func registerBackend(entry backendEntry) {
	testBackends = append(testBackends, entry)
}

// ---------------------------------------------------------------------------
// Skip helpers
// ---------------------------------------------------------------------------

// skipIfNoTPM skips the test if /dev/tpmrm0 is not available.
func skipIfNoTPM(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/dev/tpmrm0"); err != nil {
		t.Skip("TPM device /dev/tpmrm0 not available")
	}
}

// ---------------------------------------------------------------------------
// Adapter constructors
// ---------------------------------------------------------------------------

// newSoftwareAdapter creates a BackendAdapter backed by a real software backend.
func newSoftwareAdapter(t *testing.T) *BackendAdapter {
	t.Helper()
	config := &softwarebackend.Config{
		KeyStorage: storage.NewMemory(),
	}
	backend, err := softwarebackend.NewBackend(config)
	require.NoError(t, err)
	t.Cleanup(func() { backend.Close() })
	return NewBackendAdapter(backend, types.BackendTypeSoftware)
}

// newTPM2Adapter creates a BackendAdapter backed by a real TPM2 backend.
func newTPM2Adapter(t *testing.T) *BackendAdapter {
	t.Helper()
	keyDir := t.TempDir()
	config := &tpm2backend.Config{
		Device: "/dev/tpmrm0",
		KeyDir: keyDir,
	}
	backend, err := tpm2backend.NewBackend(config)
	require.NoError(t, err)
	t.Cleanup(func() { backend.Close() })
	return NewBackendAdapter(backend, types.BackendTypeTPM2)
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// randomCredentialID generates a random 32-byte credential ID.
func randomCredentialID(t *testing.T) []byte {
	t.Helper()
	id := make([]byte, 32)
	_, err := rand.Read(id)
	require.NoError(t, err)
	return id
}

// decodeCOSEPublicKey decodes a COSE-encoded public key into a crypto.PublicKey.
func decodeCOSEPublicKey(t *testing.T, coseBytes []byte) crypto.PublicKey {
	t.Helper()

	var raw map[int]interface{}
	err := cbor.Unmarshal(coseBytes, &raw)
	require.NoError(t, err, "failed to unmarshal COSE key")

	ktyRaw, ok := raw[1]
	require.True(t, ok, "COSE key missing kty (1)")
	kty := toInt(t, ktyRaw)

	switch kty {
	case COSEKeyTypeEC2:
		return decodeCOSEEC2Key(t, raw)
	case COSEKeyTypeOKP:
		return decodeCOSEOKPKey(t, raw)
	default:
		t.Fatalf("unsupported COSE key type: %d", kty)
		return nil
	}
}

// decodeCOSEEC2Key decodes a COSE EC2 (ECDSA) public key.
func decodeCOSEEC2Key(t *testing.T, raw map[int]interface{}) *ecdsa.PublicKey {
	t.Helper()

	crvRaw, ok := raw[-1]
	require.True(t, ok, "COSE EC2 key missing crv (-1)")
	crv := toInt(t, crvRaw)

	var curve elliptic.Curve
	switch crv {
	case COSECurveP256:
		curve = elliptic.P256()
	case COSECurveP384:
		curve = elliptic.P384()
	case COSECurveP521:
		curve = elliptic.P521()
	default:
		t.Fatalf("unsupported COSE curve: %d", crv)
	}

	xBytes, ok := raw[-2].([]byte)
	require.True(t, ok, "COSE EC2 key missing x (-2)")
	yBytes, ok := raw[-3].([]byte)
	require.True(t, ok, "COSE EC2 key missing y (-3)")

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
}

// decodeCOSEOKPKey decodes a COSE OKP (Ed25519) public key.
func decodeCOSEOKPKey(t *testing.T, raw map[int]interface{}) ed25519.PublicKey {
	t.Helper()

	crvRaw, ok := raw[-1]
	require.True(t, ok, "COSE OKP key missing crv (-1)")
	crv := toInt(t, crvRaw)
	require.Equal(t, COSECurveEd25519, crv, "expected Ed25519 curve")

	xBytes, ok := raw[-2].([]byte)
	require.True(t, ok, "COSE OKP key missing x (-2)")
	require.Len(t, xBytes, ed25519.PublicKeySize, "Ed25519 public key must be 32 bytes")

	return ed25519.PublicKey(xBytes)
}

// toInt converts a CBOR-decoded numeric value to int.
func toInt(t *testing.T, v interface{}) int {
	t.Helper()
	switch n := v.(type) {
	case int64:
		return int(n)
	case uint64:
		return int(n)
	case int:
		return n
	case float64:
		return int(n)
	default:
		t.Fatalf("cannot convert %T to int", v)
		return 0
	}
}

// verifySignature cryptographically verifies a signature using the COSE-encoded public key.
func verifySignature(t *testing.T, publicKeyCOSE []byte, algorithm int, data, signature []byte) {
	t.Helper()

	pubKey := decodeCOSEPublicKey(t, publicKeyCOSE)

	switch algorithm {
	case COSEAlgES256, COSEAlgES384, COSEAlgES512:
		var hash crypto.Hash
		switch algorithm {
		case COSEAlgES256:
			hash = crypto.SHA256
		case COSEAlgES384:
			hash = crypto.SHA384
		case COSEAlgES512:
			hash = crypto.SHA512
		}
		h := hash.New()
		h.Write(data)
		digest := h.Sum(nil)

		ecKey, ok := pubKey.(*ecdsa.PublicKey)
		require.True(t, ok, "expected *ecdsa.PublicKey, got %T", pubKey)
		valid := ecdsa.VerifyASN1(ecKey, digest, signature)
		require.True(t, valid, "ECDSA signature verification failed for algorithm %d", algorithm)

	case COSEAlgEdDSA:
		edKey, ok := pubKey.(ed25519.PublicKey)
		require.True(t, ok, "expected ed25519.PublicKey, got %T", pubKey)
		valid := ed25519.Verify(edKey, data, signature)
		require.True(t, valid, "EdDSA signature verification failed")

	default:
		t.Fatalf("unsupported algorithm for verification: %d", algorithm)
	}
}

// ---------------------------------------------------------------------------
// Test 1: GenerateES256
// ---------------------------------------------------------------------------

func TestAllBackends_GenerateES256(t *testing.T) {
	for _, be := range testBackends {
		t.Run(be.name, func(t *testing.T) {
			be.skip(t)
			adapter := be.adapter(t)
			credID := randomCredentialID(t)

			handle, publicKeyCOSE, err := adapter.GenerateCredentialKey(COSEAlgES256, credID)
			require.NoError(t, err)
			require.NotNil(t, handle)

			assert.Equal(t, types.BackendType(be.name), handle.BackendID())
			assert.Equal(t, COSEAlgES256, handle.Algorithm())
			assert.Equal(t, credID, handle.CredentialID())

			require.NotEmpty(t, publicKeyCOSE, "COSE public key must not be empty")
			pubKey := decodeCOSEPublicKey(t, publicKeyCOSE)
			ecKey, ok := pubKey.(*ecdsa.PublicKey)
			require.True(t, ok, "expected *ecdsa.PublicKey, got %T", pubKey)
			assert.Equal(t, elliptic.P256().Params().Name, ecKey.Curve.Params().Name,
				"expected P-256 curve")
		})
	}
}

// ---------------------------------------------------------------------------
// Test 2: SignAndVerifyES256
// ---------------------------------------------------------------------------

func TestAllBackends_SignAndVerifyES256(t *testing.T) {
	for _, be := range testBackends {
		t.Run(be.name, func(t *testing.T) {
			be.skip(t)
			adapter := be.adapter(t)
			credID := randomCredentialID(t)
			testData := []byte("FIDO2 authenticator data || client data hash")

			handle, publicKeyCOSE, err := adapter.GenerateCredentialKey(COSEAlgES256, credID)
			require.NoError(t, err)
			require.NotNil(t, handle)

			sig, err := adapter.Sign(handle, COSEAlgES256, testData)
			require.NoError(t, err)
			require.NotEmpty(t, sig)

			verifySignature(t, publicKeyCOSE, COSEAlgES256, testData, sig)
		})
	}
}

// ---------------------------------------------------------------------------
// Test 3: LoadKeyAndSign
// ---------------------------------------------------------------------------

func TestAllBackends_LoadKeyAndSign(t *testing.T) {
	for _, be := range testBackends {
		t.Run(be.name, func(t *testing.T) {
			be.skip(t)
			adapter1 := be.adapter(t)
			credID := randomCredentialID(t)
			testData := []byte("load-and-sign roundtrip test")

			// Generate key with adapter 1.
			handle1, publicKeyCOSE, err := adapter1.GenerateCredentialKey(COSEAlgES256, credID)
			require.NoError(t, err)
			require.NotNil(t, handle1)

			// Create adapter 2 from the same underlying provider, simulating a
			// fresh adapter instance that shares the same backend state.
			adapter2 := NewBackendAdapter(adapter1.provider, adapter1.backendType)

			// LoadKey should find the previously generated key.
			handle2, err := adapter2.LoadKey(credID, COSEAlgES256)
			require.NoError(t, err)
			require.NotNil(t, handle2)
			assert.Equal(t, credID, handle2.CredentialID())
			assert.Equal(t, COSEAlgES256, handle2.Algorithm())

			// Sign with the loaded handle and verify against the original public key.
			sig, err := adapter2.Sign(handle2, COSEAlgES256, testData)
			require.NoError(t, err)
			require.NotEmpty(t, sig)

			verifySignature(t, publicKeyCOSE, COSEAlgES256, testData, sig)
		})
	}
}

// ---------------------------------------------------------------------------
// Test 4: DeleteKey
// ---------------------------------------------------------------------------

func TestAllBackends_DeleteKey(t *testing.T) {
	for _, be := range testBackends {
		t.Run(be.name, func(t *testing.T) {
			be.skip(t)
			adapter := be.adapter(t)
			credID := randomCredentialID(t)

			// Generate a key.
			handle, _, err := adapter.GenerateCredentialKey(COSEAlgES256, credID)
			require.NoError(t, err)
			require.NotNil(t, handle)

			// Verify it loads.
			loaded, err := adapter.LoadKey(credID, COSEAlgES256)
			require.NoError(t, err)
			require.NotNil(t, loaded)

			// Delete it.
			err = adapter.DeleteKey(handle)
			require.NoError(t, err)

			// LoadKey must now return ErrKeyNotFound.
			_, err = adapter.LoadKey(credID, COSEAlgES256)
			assert.ErrorIs(t, err, ErrKeyNotFound)
		})
	}
}

// ---------------------------------------------------------------------------
// Test 5: ExportPrivateKey
// ---------------------------------------------------------------------------

func TestAllBackends_ExportPrivateKey(t *testing.T) {
	for _, be := range testBackends {
		t.Run(be.name, func(t *testing.T) {
			be.skip(t)
			adapter := be.adapter(t)
			credID := randomCredentialID(t)

			handle, _, err := adapter.GenerateCredentialKey(COSEAlgES256, credID)
			require.NoError(t, err)
			require.NotNil(t, handle)

			pkcs8Bytes, err := adapter.ExportPrivateKey(handle)

			if be.hardware {
				// Hardware backends must refuse export.
				assert.ErrorIs(t, err, ErrExportNotSupported)
				assert.Nil(t, pkcs8Bytes)
			} else {
				// Software backend must return valid PKCS#8 bytes.
				require.NoError(t, err)
				require.NotEmpty(t, pkcs8Bytes)

				privKey, parseErr := x509.ParsePKCS8PrivateKey(pkcs8Bytes)
				require.NoError(t, parseErr)
				_, ok := privKey.(*ecdsa.PrivateKey)
				require.True(t, ok, "expected *ecdsa.PrivateKey from PKCS#8, got %T", privKey)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test 6: Capabilities
// ---------------------------------------------------------------------------

func TestAllBackends_Capabilities(t *testing.T) {
	for _, be := range testBackends {
		t.Run(be.name, func(t *testing.T) {
			be.skip(t)
			adapter := be.adapter(t)
			caps := adapter.Capabilities()

			if be.hardware {
				assert.True(t, caps.HardwareBacked, "hardware backend must report HardwareBacked=true")
				assert.False(t, caps.SupportsExport, "hardware backend must report SupportsExport=false")
				assert.Contains(t, caps.SupportedAlgorithms, COSEAlgES256,
					"hardware backend must support at least ES256")
			} else {
				assert.False(t, caps.HardwareBacked, "software backend must report HardwareBacked=false")
				assert.True(t, caps.SupportsExport, "software backend must report SupportsExport=true")
				assert.Contains(t, caps.SupportedAlgorithms, COSEAlgES256)
				assert.Contains(t, caps.SupportedAlgorithms, COSEAlgES384)
				assert.Contains(t, caps.SupportedAlgorithms, COSEAlgES512)
				assert.Contains(t, caps.SupportedAlgorithms, COSEAlgEdDSA)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test 7: ConcurrentGenerate
// ---------------------------------------------------------------------------

func TestAllBackends_ConcurrentGenerate(t *testing.T) {
	for _, be := range testBackends {
		t.Run(be.name, func(t *testing.T) {
			be.skip(t)
			adapter := be.adapter(t)

			const numKeys = 5
			var wg sync.WaitGroup
			wg.Add(numKeys)

			type result struct {
				handle        KeyHandle
				publicKeyCOSE []byte
				err           error
			}
			results := make([]result, numKeys)

			for i := 0; i < numKeys; i++ {
				go func(idx int) {
					defer wg.Done()
					credID := randomCredentialID(t)
					h, pk, err := adapter.GenerateCredentialKey(COSEAlgES256, credID)
					results[idx] = result{handle: h, publicKeyCOSE: pk, err: err}
				}(i)
			}
			wg.Wait()

			// All must succeed.
			for i, r := range results {
				require.NoError(t, r.err, "key generation %d failed", i)
				require.NotNil(t, r.handle, "handle %d is nil", i)
				require.NotEmpty(t, r.publicKeyCOSE, "public key %d is empty", i)
			}

			// All credential IDs must be unique.
			seen := make(map[string]struct{}, numKeys)
			for i, r := range results {
				key := string(r.handle.CredentialID())
				_, dup := seen[key]
				assert.False(t, dup, "duplicate credential ID at index %d", i)
				seen[key] = struct{}{}
			}

			// Cryptographically verify each key can sign.
			testData := []byte("concurrent generation verification")
			for i, r := range results {
				sig, err := adapter.Sign(r.handle, COSEAlgES256, testData)
				require.NoError(t, err, "sign failed for key %d", i)
				verifySignature(t, r.publicKeyCOSE, COSEAlgES256, testData, sig)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test 8: StoreTypeMapping
// ---------------------------------------------------------------------------

func TestAllBackends_StoreTypeMapping(t *testing.T) {
	// Verify every known backend type maps to its expected StoreType (not the
	// default fallthrough). This is a pure function test, no hardware needed.
	testCases := []struct {
		backendType types.BackendType
		expected    types.StoreType
	}{
		{types.BackendTypeSoftware, types.StoreSoftware},
		{types.BackendTypeTPM2, types.StoreTPM2},
		{types.BackendTypePKCS11, types.StorePKCS11},
		{types.BackendTypeAWSKMS, types.StoreAWSKMS},
		{types.BackendTypeGCPKMS, types.StoreGCPKMS},
		{types.BackendTypeAzureKV, types.StoreAzureKV},
		{types.BackendTypeVault, types.StoreVault},
		{types.BackendTypePhone, types.StorePhone},
		// Module-ID-style backend types use prefix matching.
		{"pkcs11-libykcs11", types.StorePKCS11},
		{"pkcs11-softhsm-slot-0", types.StorePKCS11},
		{"tpm2-custom", types.StoreTPM2},
		{"awskms-prod", types.StoreAWSKMS},
		{"gcpkms-prod", types.StoreGCPKMS},
		{"azurekv-prod", types.StoreAzureKV},
		{"vault-dev", types.StoreVault},
		// Unknown backend falls through to StoreType(bt).
		{"unknown-backend", types.StoreType("unknown-backend")},
	}

	for _, tc := range testCases {
		t.Run(string(tc.backendType), func(t *testing.T) {
			got := storeTypeForBackend(tc.backendType)
			assert.Equal(t, tc.expected, got)
		})
	}

	// Additionally verify each live backend adapter returns the correct mapping.
	for _, be := range testBackends {
		t.Run(be.name+"/live", func(t *testing.T) {
			be.skip(t)
			adapter := be.adapter(t)
			got := storeTypeForBackend(adapter.Type())
			switch be.name {
			case "software":
				assert.Equal(t, types.StoreSoftware, got)
			case "tpm2":
				assert.Equal(t, types.StoreTPM2, got)
			case "pkcs11":
				assert.Equal(t, types.StorePKCS11, got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test 9: MultipleAlgorithms
// ---------------------------------------------------------------------------

func TestAllBackends_MultipleAlgorithms(t *testing.T) {
	type algEntry struct {
		name      string
		algorithm int
		curve     elliptic.Curve // nil for EdDSA
		isEdDSA   bool
	}

	allAlgorithms := []algEntry{
		{"ES256", COSEAlgES256, elliptic.P256(), false},
		{"ES384", COSEAlgES384, elliptic.P384(), false},
		{"ES512", COSEAlgES512, elliptic.P521(), false},
		{"EdDSA", COSEAlgEdDSA, nil, true},
	}

	for _, be := range testBackends {
		t.Run(be.name, func(t *testing.T) {
			be.skip(t)
			adapter := be.adapter(t)
			caps := adapter.Capabilities()

			// Build the set of algorithms this backend actually supports.
			supported := make(map[int]bool, len(caps.SupportedAlgorithms))
			for _, alg := range caps.SupportedAlgorithms {
				supported[alg] = true
			}

			for _, alg := range allAlgorithms {
				t.Run(alg.name, func(t *testing.T) {
					if !supported[alg.algorithm] {
						t.Skipf("%s does not support %s", be.name, alg.name)
					}

					credID := randomCredentialID(t)
					testData := []byte("multi-algorithm test: " + alg.name)

					// Generate.
					handle, publicKeyCOSE, err := adapter.GenerateCredentialKey(alg.algorithm, credID)
					require.NoError(t, err)
					require.NotNil(t, handle)
					assert.Equal(t, alg.algorithm, handle.Algorithm())

					require.NotEmpty(t, publicKeyCOSE)
					pubKey := decodeCOSEPublicKey(t, publicKeyCOSE)

					if alg.isEdDSA {
						_, ok := pubKey.(ed25519.PublicKey)
						require.True(t, ok, "expected ed25519.PublicKey for EdDSA, got %T", pubKey)
					} else {
						ecKey, ok := pubKey.(*ecdsa.PublicKey)
						require.True(t, ok, "expected *ecdsa.PublicKey for %s, got %T", alg.name, pubKey)
						assert.Equal(t, alg.curve.Params().Name, ecKey.Curve.Params().Name,
							"curve mismatch for %s", alg.name)
					}

					// Sign and verify.
					sig, err := adapter.Sign(handle, alg.algorithm, testData)
					require.NoError(t, err)
					require.NotEmpty(t, sig)

					verifySignature(t, publicKeyCOSE, alg.algorithm, testData, sig)

					// Software: also verify export works for all algorithms.
					if !be.hardware {
						pkcs8Bytes, exportErr := adapter.ExportPrivateKey(handle)
						require.NoError(t, exportErr)
						require.NotEmpty(t, pkcs8Bytes)

						privKey, parseErr := x509.ParsePKCS8PrivateKey(pkcs8Bytes)
						require.NoError(t, parseErr)

						if alg.isEdDSA {
							_, ok := privKey.(ed25519.PrivateKey)
							require.True(t, ok, "expected ed25519.PrivateKey from PKCS#8")
						} else {
							_, ok := privKey.(*ecdsa.PrivateKey)
							require.True(t, ok, "expected *ecdsa.PrivateKey from PKCS#8")
						}
					}
				})
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test 10: GenerateKeyInPIVSlot
// ---------------------------------------------------------------------------

func TestAllBackends_GenerateKeyInPIVSlot(t *testing.T) {
	for _, be := range testBackends {
		t.Run(be.name, func(t *testing.T) {
			be.skip(t)
			adapter := be.adapter(t)

			credID := randomCredentialID(t)
			testData := []byte("PIV slot key generation test")

			// Generate a credential key the normal way.
			handle, publicKeyCOSE, err := adapter.GenerateCredentialKey(COSEAlgES256, credID)
			require.NoError(t, err)
			require.NotNil(t, handle)
			assert.Equal(t, credID, handle.CredentialID())
			assert.Equal(t, COSEAlgES256, handle.Algorithm())

			// Verify the key can be used for signing regardless of backend.
			sig, err := adapter.Sign(handle, COSEAlgES256, testData)
			require.NoError(t, err)
			require.NotEmpty(t, sig)
			verifySignature(t, publicKeyCOSE, COSEAlgES256, testData, sig)

			// For PKCS#11: PIVSlot is set in KeyAttributes via the provider.
			// For software/TPM2: PIVSlot field is ignored, key generates normally.
			// Either way, the key must be loadable after generation.
			loaded, err := adapter.LoadKey(credID, COSEAlgES256)
			require.NoError(t, err)
			require.NotNil(t, loaded)
			assert.Equal(t, credID, loaded.CredentialID())
		})
	}
}

// ---------------------------------------------------------------------------
// Test 11: ListKeysAfterGenerate
// ---------------------------------------------------------------------------

func TestAllBackends_ListKeysAfterGenerate(t *testing.T) {
	for _, be := range testBackends {
		t.Run(be.name, func(t *testing.T) {
			be.skip(t)
			adapter := be.adapter(t)

			// Generate 2 keys with distinct credential IDs.
			credID1 := randomCredentialID(t)
			credID2 := randomCredentialID(t)

			handle1, _, err := adapter.GenerateCredentialKey(COSEAlgES256, credID1)
			require.NoError(t, err)
			require.NotNil(t, handle1)

			handle2, _, err := adapter.GenerateCredentialKey(COSEAlgES256, credID2)
			require.NoError(t, err)
			require.NotNil(t, handle2)

			// ListKeys should return at least our 2 generated keys.
			keys, err := adapter.provider.ListKeys()
			require.NoError(t, err)
			assert.GreaterOrEqual(t, len(keys), 2,
				"ListKeys should return at least 2 keys after generating 2 credentials")

			// Verify the expected StoreType is present on each returned key.
			expectedStore := storeTypeForBackend(adapter.Type())
			for _, ka := range keys {
				assert.Equal(t, expectedStore, ka.StoreType,
					"ListKeys entry should have StoreType matching backend")
			}
		})
	}
}
