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

//go:build integration && linux && pkcs11

// Package fido2 provides integration tests for the FIDO2 subsystem.
// This file tests the FIDO2KeyBackend interface, which is the upper-most
// abstraction of the key backend package. It exercises the full WebAuthn
// MakeCredential and GetAssertion flows against all supported backends
// (software and TPM2) to verify end-to-end correctness.
package fido2

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"log/slog"
	"os"
	"sync"
	"testing"

	"github.com/fxamacker/cbor/v2"
	pkcs11backend "github.com/jeremyhahn/go-xkms/pkg/backend/pkcs11"
	softwarebackend "github.com/jeremyhahn/go-xkms/pkg/backend/software"
	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	filestorage "github.com/jeremyhahn/go-xkms/pkg/storage/file"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	tpm2store "github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator/keybackend"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// extractSignCount extracts the signature counter from authenticator data bytes.
// The sign count occupies bytes [33:37] as a big-endian uint32.
func extractSignCount(authData []byte) uint32 {
	return binary.BigEndian.Uint32(authData[33:37])
}

// webauthnFlow runs the full CTAP2 MakeCredential -> GetAssertion flow and
// verifies the assertion signature RP-side using ecdsa.VerifyASN1. This helper
// exercises the public API from outside the authenticator package.
func webauthnFlow(t *testing.T, auth *authenticator.Authenticator, algorithm int, userID string) {
	t.Helper()

	rpID := "example.com"
	clientDataHash := make([]byte, authenticator.ClientDataHashSize)
	_, err := rand.Read(clientDataHash)
	require.NoError(t, err)

	// === MakeCredential ===
	makeCredReq := map[int]interface{}{
		1: clientDataHash,
		2: map[string]interface{}{"id": rpID, "name": "Example RP"},
		3: map[string]interface{}{
			"id":          []byte(userID),
			"name":        userID + "@example.com",
			"displayName": "Backend Test User " + userID,
		},
		4: []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"alg":  algorithm,
			},
		},
	}

	makeCredBytes, err := cbor.Marshal(makeCredReq)
	require.NoError(t, err)

	makeCredResp, err := auth.ProcessCBOR(authenticator.CmdMakeCredential, makeCredBytes)
	require.NoError(t, err)
	require.Equal(t, byte(authenticator.StatusOK), makeCredResp[0],
		"MakeCredential should succeed")

	// Decode MakeCredential response
	var makeCredResult map[int]interface{}
	err = cbor.Unmarshal(makeCredResp[1:], &makeCredResult)
	require.NoError(t, err)

	// Extract authData and parse credential ID + public key
	authData, ok := makeCredResult[2].([]byte)
	require.True(t, ok, "authData should be bytes")
	require.True(t, len(authData) > 37+16+2,
		"authData should contain attested credential data")

	// Parse attested credential data from authData
	// Layout: rpIdHash(32) + flags(1) + signCount(4) + aaguid(16) + credIdLen(2) + credId(N) + coseKey(...)
	offset := 37 // rpIdHash + flags + signCount
	offset += 16 // aaguid
	credIDLen := int(authData[offset])<<8 | int(authData[offset+1])
	offset += 2
	credentialID := authData[offset : offset+credIDLen]
	offset += credIDLen
	publicKeyCOSE := authData[offset:]

	require.NotEmpty(t, credentialID, "credentialID should not be empty")
	require.NotEmpty(t, publicKeyCOSE, "publicKeyCOSE should not be empty")

	// Decode the COSE public key
	pubKey, decodedAlg, err := authenticator.DecodeCOSEPublicKey(publicKeyCOSE)
	require.NoError(t, err)
	require.Equal(t, algorithm, decodedAlg,
		"decoded algorithm should match requested algorithm")

	// === GetAssertion ===
	assertionClientDataHash := make([]byte, authenticator.ClientDataHashSize)
	_, err = rand.Read(assertionClientDataHash)
	require.NoError(t, err)

	getAssertionReq := map[int]interface{}{
		1: rpID,
		2: assertionClientDataHash,
		3: []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"id":   credentialID,
			},
		},
	}

	getAssertionBytes, err := cbor.Marshal(getAssertionReq)
	require.NoError(t, err)

	assertionResp, err := auth.ProcessCBOR(authenticator.CmdGetAssertion, getAssertionBytes)
	require.NoError(t, err)
	require.Equal(t, byte(authenticator.StatusOK), assertionResp[0],
		"GetAssertion should succeed")

	// Decode GetAssertion response
	var assertionResult map[int]interface{}
	err = cbor.Unmarshal(assertionResp[1:], &assertionResult)
	require.NoError(t, err)

	assertionAuthData, ok := assertionResult[2].([]byte)
	require.True(t, ok, "assertion authData should be bytes")

	signature, ok := assertionResult[3].([]byte)
	require.True(t, ok, "signature should be bytes")
	require.NotEmpty(t, signature)

	// === RP-side Signature Verification ===
	// WebAuthn RP verifies: sign(authData || clientDataHash) using ASN.1/DER
	signData := make([]byte, len(assertionAuthData)+len(assertionClientDataHash))
	copy(signData, assertionAuthData)
	copy(signData[len(assertionAuthData):], assertionClientDataHash)

	ecPubKey, ok := pubKey.(*ecdsa.PublicKey)
	require.True(t, ok, "public key should be ECDSA")

	// Hash with the correct algorithm for the curve
	var hasher hash.Hash
	switch algorithm {
	case authenticator.COSEAlgES256:
		hasher = sha256.New()
	case authenticator.COSEAlgES384:
		hasher = sha512.New384()
	default:
		t.Fatalf("unsupported algorithm for hash: %d", algorithm)
	}
	hasher.Write(signData)
	digest := hasher.Sum(nil)

	valid := ecdsa.VerifyASN1(ecPubKey, digest, signature)
	require.True(t, valid,
		"RP-side signature verification must pass (ASN.1/DER format)")

	// Verify sign count incremented
	signCount := extractSignCount(assertionAuthData)
	assert.Greater(t, signCount, uint32(0),
		"sign count should be greater than zero after assertion")
}

// backendTestCase defines a parameterized test configuration for running WebAuthn
// flows against different key backends.
type backendTestCase struct {
	name       string
	backendFn  func() (keybackend.FIDO2KeyBackend, error)
	algorithms []int
}

// newSoftwareBackendAdapter creates a software KeyProvider wrapped in a
// BackendAdapter for integration testing.
func newSoftwareBackendAdapter() (keybackend.FIDO2KeyBackend, error) {
	keyStorage, err := storage.NewMemoryBackend()
	if err != nil {
		return nil, err
	}
	provider, err := softwarebackend.NewBackend(&softwarebackend.Config{
		KeyStorage: keyStorage,
	})
	if err != nil {
		return nil, err
	}
	return keybackend.NewBackendAdapter(provider, types.BackendTypeSoftware), nil
}

// sharedTPM2Backend holds a single TPM2 backend adapter shared across all
// test cases. The in-process TPM simulator uses a global mutex, so only one
// simulator instance can be active at a time. The backend is provisioned once
// and reused for all FIDO2 WebAuthn flows.
var (
	sharedTPM2Adapter keybackend.FIDO2KeyBackend
	sharedTPM2InitErr error
	sharedTPM2Once    sync.Once
)

// newTPM2BackendAdapter returns a shared TPM2 BackendAdapter backed by the
// in-process TPM simulator. The simulator is provisioned (EK + SRK) on first
// call and reused for all subsequent calls. A no-close wrapper prevents the
// authenticator's Close() from marking the shared adapter as closed.
func newTPM2BackendAdapter() (keybackend.FIDO2KeyBackend, error) {
	sharedTPM2Once.Do(func() {
		sharedTPM2Adapter, sharedTPM2InitErr = initTPM2BackendAdapter()
	})
	if sharedTPM2InitErr != nil {
		return nil, sharedTPM2InitErr
	}
	return &noCloseBackend{FIDO2KeyBackend: sharedTPM2Adapter}, nil
}

// noCloseBackend wraps a FIDO2KeyBackend and makes Close() a no-op.
// Used for shared backends that outlive individual test cases.
type noCloseBackend struct {
	keybackend.FIDO2KeyBackend
}

func (n *noCloseBackend) Close() error { return nil }

func initTPM2BackendAdapter() (keybackend.FIDO2KeyBackend, error) {
	tmpDir, err := os.MkdirTemp("", "fido2-tpm2-test-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp key dir: %w", err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	fsBackend, err := filestorage.New(tmpDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create file storage: %w", err)
	}
	keyBackend := tpm2store.NewFileBackend(logger, fsBackend)

	tpmConfig := pkgtpm2.DefaultConfig
	tpmConfig.UseSimulator = true
	tpmConfig.EK.PlatformPolicy = false
	tpmConfig.EK.HierarchyAuth = ""
	tpmConfig.SSRK.PlatformPolicy = false
	tpmConfig.SSRK.HierarchyAuth = ""
	tpmConfig.IDevID = nil
	tpmConfig.IAK = nil

	tpm, err := pkgtpm2.NewTPM2(&pkgtpm2.Params{
		Config:  &tpmConfig,
		Backend: keyBackend,
		Logger:  logger,
	})
	if err != nil && tpm == nil {
		return nil, fmt.Errorf("failed to open TPM simulator: %w", err)
	}
	if err != nil {
		ekAttrs, ekErr := pkgtpm2.EKAttributesFromConfig(*tpmConfig.EK, nil, nil)
		if ekErr != nil {
			tpm.Close()
			return nil, fmt.Errorf("failed to build EK attributes: %w", ekErr)
		}
		if ekCreateErr := tpm.CreateEK(ekAttrs); ekCreateErr != nil {
			tpm.Close()
			return nil, fmt.Errorf("failed to create EK: %w", ekCreateErr)
		}
		srkAttrs, srkErr := pkgtpm2.SRKAttributesFromConfig(*tpmConfig.SSRK, nil)
		if srkErr != nil {
			tpm.Close()
			return nil, fmt.Errorf("failed to build SRK attributes: %w", srkErr)
		}
		srkAttrs.Parent = ekAttrs
		if srkCreateErr := tpm.CreateSRK(srkAttrs); srkCreateErr != nil {
			tpm.Close()
			return nil, fmt.Errorf("failed to create SRK: %w", srkCreateErr)
		}
	}

	provider, err := tpm2backend.NewBackendWithTPM(&tpm2backend.ExternalTPMConfig{
		TPM:        tpm,
		KeyBackend: keyBackend,
		Logger:     logger,
	})
	if err != nil {
		tpm.Close()
		return nil, fmt.Errorf("failed to create TPM2 backend: %w", err)
	}
	return keybackend.NewBackendAdapter(provider, types.BackendTypeTPM2), nil
}

// newPKCS11BackendAdapter creates a PKCS#11 KeyProvider (via SoftHSM2)
// wrapped in a BackendAdapter for integration testing.
func newPKCS11BackendAdapter() (keybackend.FIDO2KeyBackend, error) {
	library := envOrDefault("PKCS11_MODULE", "/usr/lib/softhsm/libsofthsm2.so")
	tokenLabel := envOrDefault("PKCS11_TOKEN_LABEL", "test-token")
	pin := envOrDefault("PKCS11_PIN", "1234")
	soPin := envOrDefault("PKCS11_SO_PIN", "1234")

	keyStorage, err := storage.NewMemoryBackend()
	if err != nil {
		return nil, err
	}
	certStorage, err := storage.NewMemoryBackend()
	if err != nil {
		return nil, err
	}

	provider, err := pkcs11backend.NewBackend(&pkcs11backend.Config{
		Library:     library,
		TokenLabel:  tokenLabel,
		PIN:         pin,
		SOPIN:       soPin,
		KeyStorage:  keyStorage,
		CertStorage: certStorage,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create PKCS#11 backend: %w", err)
	}

	if err := provider.Initialize(soPin, pin); err != nil {
		return nil, fmt.Errorf("failed to initialize PKCS#11 token: %w", err)
	}

	return keybackend.NewBackendAdapter(provider, types.BackendTypePKCS11), nil
}

// envOrDefault reads an environment variable or returns the default value.
func envOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

// getBackendTestCases returns test configurations for all supported backends.
// All backends are tested through the BackendAdapter, which wraps go-xkms
// KeyProvider implementations into the FIDO2KeyBackend interface.
// All backends must be available in the integration test container.
func getBackendTestCases() []backendTestCase {
	return []backendTestCase{
		{
			name:       "Software",
			backendFn:  newSoftwareBackendAdapter,
			algorithms: []int{authenticator.COSEAlgES256, authenticator.COSEAlgES384},
		},
		{
			name:       "TPM2",
			backendFn:  newTPM2BackendAdapter,
			algorithms: []int{authenticator.COSEAlgES256},
		},
		{
			name:       "PKCS11",
			backendFn:  newPKCS11BackendAdapter,
			algorithms: []int{authenticator.COSEAlgES256, authenticator.COSEAlgES384},
		},
	}
}

// TestWebAuthnFlow_AllBackends_ES256 tests the full WebAuthn MakeCredential and
// GetAssertion flow with all backends using ES256.
func TestWebAuthnFlow_AllBackends_ES256(t *testing.T) {
	for _, tc := range getBackendTestCases() {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			backend, err := tc.backendFn()
			require.NoError(t, err)

			config := authenticator.DefaultConfig()
			config.Storage = authenticator.NewMemoryStorage()
			config.KeyBackend = backend

			auth, err := authenticator.NewAuthenticator(config)
			require.NoError(t, err)
			defer func() { _ = auth.Close() }()

			webauthnFlow(t, auth, authenticator.COSEAlgES256, "user-"+tc.name+"-es256")
		})
	}
}

// TestWebAuthnFlow_AllBackends_ES384 tests the full WebAuthn flow with all backends
// that support ES384. TPM2 is excluded because the TPM 2.0 FIDO2 spec mandates
// P-256 only.
func TestWebAuthnFlow_AllBackends_ES384(t *testing.T) {
	for _, tc := range getBackendTestCases() {
		tc := tc
		// Only run backends that support ES384.
		supportsES384 := false
		for _, alg := range tc.algorithms {
			if alg == authenticator.COSEAlgES384 {
				supportsES384 = true
				break
			}
		}
		if !supportsES384 {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			backend, err := tc.backendFn()
			require.NoError(t, err)

			config := authenticator.DefaultConfig()
			config.Storage = authenticator.NewMemoryStorage()
			config.KeyBackend = backend
			config.SupportedAlgorithms = []int{
				authenticator.COSEAlgES256,
				authenticator.COSEAlgES384,
			}

			auth, err := authenticator.NewAuthenticator(config)
			require.NoError(t, err)
			defer func() { _ = auth.Close() }()

			webauthnFlow(t, auth, authenticator.COSEAlgES384, "user-"+tc.name+"-es384")
		})
	}
}

// TestWebAuthnFlow_AllBackends_MultipleRegistrations tests registering multiple
// credentials with each backend and authenticating with each independently.
func TestWebAuthnFlow_AllBackends_MultipleRegistrations(t *testing.T) {
	for _, tc := range getBackendTestCases() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			backend, err := tc.backendFn()
			require.NoError(t, err)

			config := authenticator.DefaultConfig()
			config.Storage = authenticator.NewMemoryStorage()
			config.KeyBackend = backend

			auth, err := authenticator.NewAuthenticator(config)
			require.NoError(t, err)
			defer func() { _ = auth.Close() }()

			for i := 0; i < 3; i++ {
				userID := fmt.Sprintf("user-%s-multi-%d", tc.name, i)
				webauthnFlow(t, auth, authenticator.COSEAlgES256, userID)
			}
		})
	}
}

// TestWebAuthnFlow_AllBackends_SignCounterIncrements tests that the signature
// counter increments correctly across multiple authentications for each backend.
func TestWebAuthnFlow_AllBackends_SignCounterIncrements(t *testing.T) {
	for _, tc := range getBackendTestCases() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			backend, err := tc.backendFn()
			require.NoError(t, err)

			config := authenticator.DefaultConfig()
			config.Storage = authenticator.NewMemoryStorage()
			config.KeyBackend = backend

			auth, err := authenticator.NewAuthenticator(config)
			require.NoError(t, err)
			defer func() { _ = auth.Close() }()

			testSignCounterIncrements(t, auth, tc.name)
		})
	}
}

// testSignCounterIncrements is a helper that tests sign counter behavior.
func testSignCounterIncrements(t *testing.T, auth *authenticator.Authenticator, backendName string) {
	t.Helper()

	rpID := "example.com"

	// MakeCredential
	clientDataHash := make([]byte, authenticator.ClientDataHashSize)
	_, err := rand.Read(clientDataHash)
	require.NoError(t, err)

	makeCredReq := map[int]interface{}{
		1: clientDataHash,
		2: map[string]interface{}{"id": rpID, "name": "Example RP"},
		3: map[string]interface{}{
			"id":          []byte("user-signcount-" + backendName),
			"name":        "signcount-" + backendName + "@example.com",
			"displayName": "Sign Count Test User " + backendName,
		},
		4: []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"alg":  authenticator.COSEAlgES256,
			},
		},
	}

	makeCredBytes, err := cbor.Marshal(makeCredReq)
	require.NoError(t, err)

	makeCredResp, err := auth.ProcessCBOR(authenticator.CmdMakeCredential, makeCredBytes)
	require.NoError(t, err)
	require.Equal(t, byte(authenticator.StatusOK), makeCredResp[0])

	// Extract credential ID from MakeCredential response
	var makeCredResult map[int]interface{}
	err = cbor.Unmarshal(makeCredResp[1:], &makeCredResult)
	require.NoError(t, err)

	authData, ok := makeCredResult[2].([]byte)
	require.True(t, ok)

	offset := 37 + 16 // rpIdHash + flags + signCount + aaguid
	credIDLen := int(authData[offset])<<8 | int(authData[offset+1])
	offset += 2
	credentialID := authData[offset : offset+credIDLen]

	// GetAssertion 3 times and verify monotonically increasing sign count
	var previousSignCount uint32

	for i := 0; i < 3; i++ {
		assertionClientDataHash := make([]byte, authenticator.ClientDataHashSize)
		_, err = rand.Read(assertionClientDataHash)
		require.NoError(t, err)

		getAssertionReq := map[int]interface{}{
			1: rpID,
			2: assertionClientDataHash,
			3: []interface{}{
				map[string]interface{}{
					"type": "public-key",
					"id":   credentialID,
				},
			},
		}

		getAssertionBytes, err := cbor.Marshal(getAssertionReq)
		require.NoError(t, err)

		assertionResp, err := auth.ProcessCBOR(authenticator.CmdGetAssertion, getAssertionBytes)
		require.NoError(t, err)
		require.Equal(t, byte(authenticator.StatusOK), assertionResp[0],
			"GetAssertion iteration %d should succeed", i)

		var assertionResult map[int]interface{}
		err = cbor.Unmarshal(assertionResp[1:], &assertionResult)
		require.NoError(t, err)

		assertionAuthData, ok := assertionResult[2].([]byte)
		require.True(t, ok)

		currentSignCount := extractSignCount(assertionAuthData)
		assert.Greater(t, currentSignCount, previousSignCount,
			"sign count should increase on iteration %d (got %d, previous %d)",
			i, currentSignCount, previousSignCount)

		previousSignCount = currentSignCount
	}
}

// TestWebAuthnFlow_AllBackends_RejectsWrongCredential tests that authentication
// fails with an unknown credential ID for each backend.
func TestWebAuthnFlow_AllBackends_RejectsWrongCredential(t *testing.T) {
	for _, tc := range getBackendTestCases() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			backend, err := tc.backendFn()
			require.NoError(t, err)

			config := authenticator.DefaultConfig()
			config.Storage = authenticator.NewMemoryStorage()
			config.KeyBackend = backend

			auth, err := authenticator.NewAuthenticator(config)
			require.NoError(t, err)
			defer func() { _ = auth.Close() }()

			testRejectsWrongCredential(t, auth, tc.name)
		})
	}
}

// testRejectsWrongCredential is a helper that tests credential validation.
func testRejectsWrongCredential(t *testing.T, auth *authenticator.Authenticator, backendName string) {
	t.Helper()

	rpID := "example.com"

	// MakeCredential for user A
	clientDataHash := make([]byte, authenticator.ClientDataHashSize)
	_, err := rand.Read(clientDataHash)
	require.NoError(t, err)

	makeCredReq := map[int]interface{}{
		1: clientDataHash,
		2: map[string]interface{}{"id": rpID, "name": "Example RP"},
		3: map[string]interface{}{
			"id":          []byte("user-wrong-cred-" + backendName),
			"name":        "wrongcred-" + backendName + "@example.com",
			"displayName": "Wrong Cred Test User " + backendName,
		},
		4: []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"alg":  authenticator.COSEAlgES256,
			},
		},
	}

	makeCredBytes, err := cbor.Marshal(makeCredReq)
	require.NoError(t, err)

	makeCredResp, err := auth.ProcessCBOR(authenticator.CmdMakeCredential, makeCredBytes)
	require.NoError(t, err)
	require.Equal(t, byte(authenticator.StatusOK), makeCredResp[0])

	// GetAssertion with a fake credential ID that does not exist
	fakeCredentialID := make([]byte, 32)
	_, err = rand.Read(fakeCredentialID)
	require.NoError(t, err)

	assertionClientDataHash := make([]byte, authenticator.ClientDataHashSize)
	_, err = rand.Read(assertionClientDataHash)
	require.NoError(t, err)

	getAssertionReq := map[int]interface{}{
		1: rpID,
		2: assertionClientDataHash,
		3: []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"id":   fakeCredentialID,
			},
		},
	}

	getAssertionBytes, err := cbor.Marshal(getAssertionReq)
	require.NoError(t, err)

	assertionResp, err := auth.ProcessCBOR(authenticator.CmdGetAssertion, getAssertionBytes)
	require.Error(t, err, "GetAssertion with wrong credential should fail")
	require.NotEqual(t, byte(authenticator.StatusOK), assertionResp[0],
		"response status should not be OK for wrong credential")
}

// TestWebAuthnFlow_AllBackends_CrossOriginRejection tests that credentials
// registered for one RP cannot be used with a different RP.
func TestWebAuthnFlow_AllBackends_CrossOriginRejection(t *testing.T) {
	for _, tc := range getBackendTestCases() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			backend, err := tc.backendFn()
			require.NoError(t, err)

			config := authenticator.DefaultConfig()
			config.Storage = authenticator.NewMemoryStorage()
			config.KeyBackend = backend

			auth, err := authenticator.NewAuthenticator(config)
			require.NoError(t, err)
			defer func() { _ = auth.Close() }()

			testCrossOriginRejection(t, auth, tc.name)
		})
	}
}

// testCrossOriginRejection tests RP ID validation.
func testCrossOriginRejection(t *testing.T, auth *authenticator.Authenticator, backendName string) {
	t.Helper()

	rpID1 := "example.com"
	rpID2 := "attacker.com"

	// Register credential with rpID1
	clientDataHash := make([]byte, authenticator.ClientDataHashSize)
	_, err := rand.Read(clientDataHash)
	require.NoError(t, err)

	makeCredReq := map[int]interface{}{
		1: clientDataHash,
		2: map[string]interface{}{"id": rpID1, "name": "Example RP"},
		3: map[string]interface{}{
			"id":          []byte("user-crossorigin-" + backendName),
			"name":        "crossorigin-" + backendName + "@example.com",
			"displayName": "Cross Origin Test User " + backendName,
		},
		4: []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"alg":  authenticator.COSEAlgES256,
			},
		},
	}

	makeCredBytes, err := cbor.Marshal(makeCredReq)
	require.NoError(t, err)

	makeCredResp, err := auth.ProcessCBOR(authenticator.CmdMakeCredential, makeCredBytes)
	require.NoError(t, err)
	require.Equal(t, byte(authenticator.StatusOK), makeCredResp[0])

	// Extract credential ID
	var makeCredResult map[int]interface{}
	err = cbor.Unmarshal(makeCredResp[1:], &makeCredResult)
	require.NoError(t, err)

	authData, ok := makeCredResult[2].([]byte)
	require.True(t, ok)

	offset := 37 + 16
	credIDLen := int(authData[offset])<<8 | int(authData[offset+1])
	offset += 2
	credentialID := authData[offset : offset+credIDLen]

	// Try to authenticate with credential using different rpID (attacker.com)
	assertionClientDataHash := make([]byte, authenticator.ClientDataHashSize)
	_, err = rand.Read(assertionClientDataHash)
	require.NoError(t, err)

	getAssertionReq := map[int]interface{}{
		1: rpID2, // Different RP!
		2: assertionClientDataHash,
		3: []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"id":   credentialID,
			},
		},
	}

	getAssertionBytes, err := cbor.Marshal(getAssertionReq)
	require.NoError(t, err)

	assertionResp, err := auth.ProcessCBOR(authenticator.CmdGetAssertion, getAssertionBytes)
	require.Error(t, err, "GetAssertion with wrong rpID should fail")
	require.NotEqual(t, byte(authenticator.StatusOK), assertionResp[0],
		"response status should not be OK for cross-origin credential")
}
