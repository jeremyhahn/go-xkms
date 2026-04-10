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

package authenticator

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// createAssertionTestCredential creates a test credential and stores it for assertion testing.
func createAssertionTestCredential(t *testing.T, auth *Authenticator, rpID string, discoverable bool) *StoredCredential {
	t.Helper()

	// Generate credential ID
	credID, err := GenerateCredentialID()
	require.NoError(t, err)

	// Generate key pair
	privateKey, publicKeyCOSE, err := GenerateCredentialKey(COSEAlgES256)
	require.NoError(t, err)

	// Encode private key to PKCS#8
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)

	// Generate HMAC secret key
	hmacSecretKey, err := GenerateHMACSecretKey()
	require.NoError(t, err)

	cred := &StoredCredential{
		CredentialID:    credID,
		RPID:            rpID,
		RPName:          "Test RP",
		UserID:          []byte("user-123"),
		UserName:        "testuser@example.com",
		UserDisplayName: "Test User",
		PrivateKey:      privateKeyBytes,
		PublicKeyCOSE:   publicKeyCOSE,
		Algorithm:       COSEAlgES256,
		SignCount:       0,
		Discoverable:    discoverable,
		HMACSecretKey:   hmacSecretKey,
		CreatedAt:       time.Now().Unix(),
	}

	err = auth.storage.Store(cred)
	require.NoError(t, err)

	return cred
}

// generateTestClientDataHash creates a test client data hash.
func generateTestClientDataHash() []byte {
	data := make([]byte, 64)
	_, _ = rand.Read(data)
	hash := sha256.Sum256(data)
	return hash[:]
}

// blockingUPHandler blocks forever on user presence requests.
// Used to verify that pinUvAuthParam correctly bypasses UP.
type blockingUPHandler struct{}

func (h *blockingUPHandler) RequestUserPresence(ctx context.Context, req *UserPresenceRequest) (*UserPresenceResult, error) {
	// Block until context is cancelled - simulates an unresponsive terminal
	<-ctx.Done()
	return nil, ctx.Err()
}

func (h *blockingUPHandler) RequestUserVerification(ctx context.Context, req *UserVerificationRequest) (*UserVerificationResult, error) {
	return &UserVerificationResult{Verified: true}, nil
}

// trackingUPHandler records whether RequestUserPresence was called and
// either approves or denies based on the approve field.
type trackingUPHandler struct {
	called  atomic.Bool
	approve bool
}

func (h *trackingUPHandler) RequestUserPresence(ctx context.Context, req *UserPresenceRequest) (*UserPresenceResult, error) {
	h.called.Store(true)
	if !h.approve {
		return nil, ErrUserPresenceDenied
	}
	return &UserPresenceResult{Approved: true}, nil
}

func (h *trackingUPHandler) RequestUserVerification(ctx context.Context, req *UserVerificationRequest) (*UserVerificationResult, error) {
	return nil, ErrTerminalUnavailable
}

func TestGetAssertion_Success(t *testing.T) {
	auth := createTestAuthenticator(t)
	rpID := "example.com"
	cred := createAssertionTestCredential(t, auth, rpID, false)

	clientDataHash := generateTestClientDataHash()

	// Build CBOR request
	request := map[int]interface{}{
		getAssertionParamRPID:           rpID,
		getAssertionParamClientDataHash: clientDataHash,
		getAssertionParamAllowList: []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"id":   cred.CredentialID,
			},
		},
	}

	reqBytes, err := cbor.Marshal(request)
	require.NoError(t, err)

	// Execute via ProcessCBOR
	respBytes, err := auth.ProcessCBOR(CmdGetAssertion, reqBytes)
	require.NoError(t, err)
	require.NotEmpty(t, respBytes)

	// Verify status byte is OK
	require.Equal(t, byte(StatusOK), respBytes[0])

	// Decode response (skip status byte)
	var response map[int]interface{}
	err = cbor.Unmarshal(respBytes[1:], &response)
	require.NoError(t, err)

	// Verify response fields
	require.NotNil(t, response[getAssertionRespCredential])

	authData, ok := response[getAssertionRespAuthData].([]byte)
	require.True(t, ok)
	require.GreaterOrEqual(t, len(authData), minAuthDataLen)

	signature, ok := response[getAssertionRespSignature].([]byte)
	require.True(t, ok)
	require.NotEmpty(t, signature)

	// Verify signature counter was incremented
	updatedCred, err := auth.storage.Load(cred.CredentialID)
	require.NoError(t, err)
	require.Equal(t, uint32(1), updatedCred.SignCount)
}

func TestGetAssertion_DiscoverableCredential(t *testing.T) {
	auth := createTestAuthenticator(t)
	rpID := "example.com"
	cred := createAssertionTestCredential(t, auth, rpID, true)

	clientDataHash := generateTestClientDataHash()

	// Build CBOR request without allowList (discoverable credential flow)
	request := map[int]interface{}{
		getAssertionParamRPID:           rpID,
		getAssertionParamClientDataHash: clientDataHash,
	}

	reqBytes, err := cbor.Marshal(request)
	require.NoError(t, err)

	// Execute
	respBytes, err := auth.ProcessCBOR(CmdGetAssertion, reqBytes)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), respBytes[0])

	// Decode response
	var response map[int]interface{}
	err = cbor.Unmarshal(respBytes[1:], &response)
	require.NoError(t, err)

	// Verify user info is included for discoverable credentials
	userInfo := response[getAssertionRespUser]
	require.NotNil(t, userInfo, "User info should be present for discoverable credentials")

	// Verify credential ID matches
	credInfo := response[getAssertionRespCredential]
	require.NotNil(t, credInfo)

	var credID []byte
	switch m := credInfo.(type) {
	case map[interface{}]interface{}:
		credID = m["id"].([]byte)
	case map[string]interface{}:
		credID = m["id"].([]byte)
	}
	require.True(t, bytes.Equal(credID, cred.CredentialID))
}

func TestGetAssertion_MissingRPID(t *testing.T) {
	auth := createTestAuthenticator(t)
	clientDataHash := generateTestClientDataHash()

	// Build CBOR request without rpId
	request := map[int]interface{}{
		getAssertionParamClientDataHash: clientDataHash,
	}

	reqBytes, err := cbor.Marshal(request)
	require.NoError(t, err)

	// Execute
	respBytes, err := auth.ProcessCBOR(CmdGetAssertion, reqBytes)
	require.Error(t, err)
	require.NotEqual(t, byte(StatusOK), respBytes[0])
}

func TestGetAssertion_MissingClientDataHash(t *testing.T) {
	auth := createTestAuthenticator(t)

	// Build CBOR request without clientDataHash
	request := map[int]interface{}{
		getAssertionParamRPID: "example.com",
	}

	reqBytes, err := cbor.Marshal(request)
	require.NoError(t, err)

	// Execute
	respBytes, err := auth.ProcessCBOR(CmdGetAssertion, reqBytes)
	require.Error(t, err)
	require.NotEqual(t, byte(StatusOK), respBytes[0])
}

func TestGetAssertion_InvalidClientDataHashLength(t *testing.T) {
	auth := createTestAuthenticator(t)

	// Build CBOR request with invalid clientDataHash length
	request := map[int]interface{}{
		getAssertionParamRPID:           "example.com",
		getAssertionParamClientDataHash: []byte("too-short"),
	}

	reqBytes, err := cbor.Marshal(request)
	require.NoError(t, err)

	// Execute
	respBytes, err := auth.ProcessCBOR(CmdGetAssertion, reqBytes)
	require.Error(t, err)
	require.NotEqual(t, byte(StatusOK), respBytes[0])
}

func TestGetAssertion_NoMatchingCredentials(t *testing.T) {
	auth := createTestAuthenticator(t)
	clientDataHash := generateTestClientDataHash()

	// Build CBOR request for non-existent RP
	request := map[int]interface{}{
		getAssertionParamRPID:           "nonexistent.com",
		getAssertionParamClientDataHash: clientDataHash,
	}

	reqBytes, err := cbor.Marshal(request)
	require.NoError(t, err)

	// Execute
	respBytes, err := auth.ProcessCBOR(CmdGetAssertion, reqBytes)
	require.Error(t, err)
	require.Equal(t, byte(StatusNoCredentials), respBytes[0])
}

func TestGetAssertion_AllowListNoMatch(t *testing.T) {
	auth := createTestAuthenticator(t)
	rpID := "example.com"
	createAssertionTestCredential(t, auth, rpID, false)

	clientDataHash := generateTestClientDataHash()
	nonExistentCredID := make([]byte, 32)
	_, _ = rand.Read(nonExistentCredID)

	// Build CBOR request with non-matching allowList
	request := map[int]interface{}{
		getAssertionParamRPID:           rpID,
		getAssertionParamClientDataHash: clientDataHash,
		getAssertionParamAllowList: []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"id":   nonExistentCredID,
			},
		},
	}

	reqBytes, err := cbor.Marshal(request)
	require.NoError(t, err)

	// Execute
	respBytes, err := auth.ProcessCBOR(CmdGetAssertion, reqBytes)
	require.Error(t, err)
	require.Equal(t, byte(StatusNoCredentials), respBytes[0])
}

func TestGetAssertion_InvalidAllowList(t *testing.T) {
	auth := createTestAuthenticator(t)
	clientDataHash := generateTestClientDataHash()

	// Build CBOR request with invalid allowList format
	request := map[int]interface{}{
		getAssertionParamRPID:           "example.com",
		getAssertionParamClientDataHash: clientDataHash,
		getAssertionParamAllowList:      "not-an-array",
	}

	reqBytes, err := cbor.Marshal(request)
	require.NoError(t, err)

	// Execute
	respBytes, err := auth.ProcessCBOR(CmdGetAssertion, reqBytes)
	require.Error(t, err)
	require.NotEqual(t, byte(StatusOK), respBytes[0])
}

func TestGetAssertion_InvalidCredentialDescriptor(t *testing.T) {
	auth := createTestAuthenticator(t)
	clientDataHash := generateTestClientDataHash()

	// Build CBOR request with missing credential ID
	request := map[int]interface{}{
		getAssertionParamRPID:           "example.com",
		getAssertionParamClientDataHash: clientDataHash,
		getAssertionParamAllowList: []interface{}{
			map[string]interface{}{
				"type": "public-key",
				// Missing "id"
			},
		},
	}

	reqBytes, err := cbor.Marshal(request)
	require.NoError(t, err)

	// Execute
	respBytes, err := auth.ProcessCBOR(CmdGetAssertion, reqBytes)
	require.Error(t, err)
	require.NotEqual(t, byte(StatusOK), respBytes[0])
}

func TestGetAssertion_WithOptions(t *testing.T) {
	auth := createTestAuthenticator(t)
	rpID := "example.com"
	cred := createAssertionTestCredential(t, auth, rpID, false)

	clientDataHash := generateTestClientDataHash()

	// Build CBOR request with options
	request := map[int]interface{}{
		getAssertionParamRPID:           rpID,
		getAssertionParamClientDataHash: clientDataHash,
		getAssertionParamAllowList: []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"id":   cred.CredentialID,
			},
		},
		getAssertionParamOptions: map[string]interface{}{
			"up": true,
			"uv": false,
		},
	}

	reqBytes, err := cbor.Marshal(request)
	require.NoError(t, err)

	// Execute
	respBytes, err := auth.ProcessCBOR(CmdGetAssertion, reqBytes)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), respBytes[0])

	// Decode response
	var response map[int]interface{}
	err = cbor.Unmarshal(respBytes[1:], &response)
	require.NoError(t, err)

	// Verify authData contains correct flags
	authData := response[getAssertionRespAuthData].([]byte)
	flags := AuthDataFlags(authData[32])
	require.True(t, flags.Has(FlagUP), "UP flag should be set")
	require.False(t, flags.Has(FlagUV), "UV flag should not be set")
}

func TestGetAssertion_HMACSecretExtension(t *testing.T) {
	auth := createTestAuthenticator(t)
	rpID := "example.com"
	cred := createAssertionTestCredential(t, auth, rpID, false)

	clientDataHash := generateTestClientDataHash()
	salt1 := make([]byte, 32)
	_, _ = rand.Read(salt1)

	// Build CBOR request with hmac-secret extension
	request := map[int]interface{}{
		getAssertionParamRPID:           rpID,
		getAssertionParamClientDataHash: clientDataHash,
		getAssertionParamAllowList: []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"id":   cred.CredentialID,
			},
		},
		getAssertionParamExtensions: map[string]interface{}{
			"hmac-secret": map[string]interface{}{
				"salt1": salt1,
			},
		},
	}

	reqBytes, err := cbor.Marshal(request)
	require.NoError(t, err)

	// Execute
	respBytes, err := auth.ProcessCBOR(CmdGetAssertion, reqBytes)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), respBytes[0])

	// Decode response
	var response map[int]interface{}
	err = cbor.Unmarshal(respBytes[1:], &response)
	require.NoError(t, err)

	// Verify authData has ED flag set
	authData := response[getAssertionRespAuthData].([]byte)
	flags := AuthDataFlags(authData[32])
	require.True(t, flags.Has(FlagED), "ED flag should be set for extension data")
}

func TestGetAssertion_HMACSecretExtension_TwoSalts(t *testing.T) {
	auth := createTestAuthenticator(t)
	rpID := "example.com"
	cred := createAssertionTestCredential(t, auth, rpID, false)

	clientDataHash := generateTestClientDataHash()
	salt1 := make([]byte, 32)
	salt2 := make([]byte, 32)
	_, _ = rand.Read(salt1)
	_, _ = rand.Read(salt2)

	// Build CBOR request with hmac-secret extension (two salts)
	request := map[int]interface{}{
		getAssertionParamRPID:           rpID,
		getAssertionParamClientDataHash: clientDataHash,
		getAssertionParamAllowList: []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"id":   cred.CredentialID,
			},
		},
		getAssertionParamExtensions: map[string]interface{}{
			"hmac-secret": map[string]interface{}{
				"salt1": salt1,
				"salt2": salt2,
			},
		},
	}

	reqBytes, err := cbor.Marshal(request)
	require.NoError(t, err)

	// Execute
	respBytes, err := auth.ProcessCBOR(CmdGetAssertion, reqBytes)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), respBytes[0])

	// Verify response is valid
	var response map[int]interface{}
	err = cbor.Unmarshal(respBytes[1:], &response)
	require.NoError(t, err)

	// Verify authData has ED flag set
	authData := response[getAssertionRespAuthData].([]byte)
	flags := AuthDataFlags(authData[32])
	require.True(t, flags.Has(FlagED), "ED flag should be set for extension data")
}

func TestGetAssertion_HMACSecretExtension_InvalidSalt(t *testing.T) {
	auth := createTestAuthenticator(t)
	rpID := "example.com"
	cred := createAssertionTestCredential(t, auth, rpID, false)

	clientDataHash := generateTestClientDataHash()

	// Build CBOR request with invalid salt (wrong size)
	request := map[int]interface{}{
		getAssertionParamRPID:           rpID,
		getAssertionParamClientDataHash: clientDataHash,
		getAssertionParamAllowList: []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"id":   cred.CredentialID,
			},
		},
		getAssertionParamExtensions: map[string]interface{}{
			"hmac-secret": map[string]interface{}{
				"salt1": []byte("too-short"),
			},
		},
	}

	reqBytes, err := cbor.Marshal(request)
	require.NoError(t, err)

	// Execute
	respBytes, err := auth.ProcessCBOR(CmdGetAssertion, reqBytes)
	require.Error(t, err)
	require.NotEqual(t, byte(StatusOK), respBytes[0])
}

func TestGetAssertion_HMACSecretExtension_Disabled(t *testing.T) {
	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.EnableHMACSecret = false // Disable hmac-secret

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)

	rpID := "example.com"
	cred := createAssertionTestCredential(t, auth, rpID, false)

	clientDataHash := generateTestClientDataHash()
	salt1 := make([]byte, 32)
	_, _ = rand.Read(salt1)

	// Build CBOR request with hmac-secret extension
	request := map[int]interface{}{
		getAssertionParamRPID:           rpID,
		getAssertionParamClientDataHash: clientDataHash,
		getAssertionParamAllowList: []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"id":   cred.CredentialID,
			},
		},
		getAssertionParamExtensions: map[string]interface{}{
			"hmac-secret": map[string]interface{}{
				"salt1": salt1,
			},
		},
	}

	reqBytes, err := cbor.Marshal(request)
	require.NoError(t, err)

	// Execute
	respBytes, err := auth.ProcessCBOR(CmdGetAssertion, reqBytes)
	require.Error(t, err)
	require.NotEqual(t, byte(StatusOK), respBytes[0])
}

func TestGetAssertion_MultipleCredentials(t *testing.T) {
	auth := createTestAuthenticator(t)
	rpID := "example.com"

	// Create multiple discoverable credentials
	createAssertionTestCredential(t, auth, rpID, true)
	createAssertionTestCredential(t, auth, rpID, true)

	clientDataHash := generateTestClientDataHash()

	// Build CBOR request without allowList
	request := map[int]interface{}{
		getAssertionParamRPID:           rpID,
		getAssertionParamClientDataHash: clientDataHash,
	}

	reqBytes, err := cbor.Marshal(request)
	require.NoError(t, err)

	// Execute
	respBytes, err := auth.ProcessCBOR(CmdGetAssertion, reqBytes)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), respBytes[0])

	// Decode response
	var response map[int]interface{}
	err = cbor.Unmarshal(respBytes[1:], &response)
	require.NoError(t, err)

	// Verify numberOfCredentials is set
	numCreds, ok := response[getAssertionRespNumberOfCredentials]
	require.True(t, ok, "numberOfCredentials should be set for multiple credentials")

	numCredsUint, err := toUint8Value(numCreds)
	require.NoError(t, err)
	require.Equal(t, uint8(2), numCredsUint)

	// Verify we can get the next assertion
	resp2Bytes, err := auth.ProcessCBOR(CmdGetNextAssertion, nil)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp2Bytes[0])

	// Verify the credential ID is different from the first response
	var resp2 map[int]interface{}
	err = cbor.Unmarshal(resp2Bytes[1:], &resp2)
	require.NoError(t, err)

	firstCredID := getCredentialIDFromResponse(response[getAssertionRespCredential])
	secondCredID := getCredentialIDFromResponse(resp2[getAssertionRespCredential])
	require.False(t, bytes.Equal(firstCredID, secondCredID), "GetNextAssertion should return different credential")
}

// getCredentialIDFromResponse extracts credential ID from response credential map.
func getCredentialIDFromResponse(credInfo interface{}) []byte {
	switch m := credInfo.(type) {
	case map[interface{}]interface{}:
		return m["id"].([]byte)
	case map[string]interface{}:
		return m["id"].([]byte)
	}
	return nil
}

func TestGetNextAssertion_NoState(t *testing.T) {
	auth := createTestAuthenticator(t)

	// Call GetNextAssertion without prior GetAssertion
	respBytes, err := auth.ProcessCBOR(CmdGetNextAssertion, nil)
	require.Error(t, err)
	require.Equal(t, byte(StatusNoCredentials), respBytes[0])
}

func TestGetNextAssertion_Exhausted(t *testing.T) {
	auth := createTestAuthenticator(t)
	rpID := "example.com"

	// Create only one credential
	createAssertionTestCredential(t, auth, rpID, true)

	clientDataHash := generateTestClientDataHash()

	// Build CBOR request
	request := map[int]interface{}{
		getAssertionParamRPID:           rpID,
		getAssertionParamClientDataHash: clientDataHash,
	}

	reqBytes, err := cbor.Marshal(request)
	require.NoError(t, err)

	// Execute first assertion
	respBytes, err := auth.ProcessCBOR(CmdGetAssertion, reqBytes)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), respBytes[0])

	// Try to get next (should fail as only one credential)
	resp2Bytes, err := auth.ProcessCBOR(CmdGetNextAssertion, nil)
	require.Error(t, err)
	require.Equal(t, byte(StatusNoCredentials), resp2Bytes[0])
}

func TestClearAssertionState(t *testing.T) {
	auth := createTestAuthenticator(t)
	rpID := "example.com"
	createAssertionTestCredential(t, auth, rpID, true)
	createAssertionTestCredential(t, auth, rpID, true)

	clientDataHash := generateTestClientDataHash()

	// Build CBOR request
	request := map[int]interface{}{
		getAssertionParamRPID:           rpID,
		getAssertionParamClientDataHash: clientDataHash,
	}

	reqBytes, err := cbor.Marshal(request)
	require.NoError(t, err)

	// Execute first assertion
	_, err = auth.ProcessCBOR(CmdGetAssertion, reqBytes)
	require.NoError(t, err)

	// Clear state
	auth.ClearAssertionState()

	// Try to get next (should fail as state cleared)
	respBytes, err := auth.ProcessCBOR(CmdGetNextAssertion, nil)
	require.Error(t, err)
	require.Equal(t, byte(StatusNoCredentials), respBytes[0])
}

func TestValidateGetAssertionRequest(t *testing.T) {
	tests := []struct {
		name    string
		request *GetAssertionRequest
		wantErr error
	}{
		{
			name:    "nil request",
			request: nil,
			wantErr: ErrInvalidParameter,
		},
		{
			name: "missing rpId",
			request: &GetAssertionRequest{
				ClientDataHash: make([]byte, 32),
			},
			wantErr: ErrGetAssertionMissingRPID,
		},
		{
			name: "invalid clientDataHash length",
			request: &GetAssertionRequest{
				RPID:           "example.com",
				ClientDataHash: []byte("too-short"),
			},
			wantErr: ErrGetAssertionInvalidClientDataHash,
		},
		{
			name: "invalid credential descriptor type",
			request: &GetAssertionRequest{
				RPID:           "example.com",
				ClientDataHash: make([]byte, 32),
				AllowList: []CredentialDescriptor{
					{Type: "invalid-type", ID: make([]byte, 32)},
				},
			},
			wantErr: ErrGetAssertionInvalidCredentialDescriptor,
		},
		{
			name: "empty credential ID",
			request: &GetAssertionRequest{
				RPID:           "example.com",
				ClientDataHash: make([]byte, 32),
				AllowList: []CredentialDescriptor{
					{Type: "public-key", ID: []byte{}},
				},
			},
			wantErr: ErrGetAssertionInvalidCredentialDescriptor,
		},
		{
			name: "valid request",
			request: &GetAssertionRequest{
				RPID:           "example.com",
				ClientDataHash: make([]byte, 32),
				AllowList: []CredentialDescriptor{
					{Type: "public-key", ID: make([]byte, 32)},
				},
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateGetAssertionRequest(tt.request)
			if tt.wantErr == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tt.wantErr)
			}
		})
	}
}

func TestMatchesCredentialID(t *testing.T) {
	credID := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	otherID := []byte{8, 7, 6, 5, 4, 3, 2, 1}

	tests := []struct {
		name         string
		credentialID []byte
		allowList    []CredentialDescriptor
		want         bool
	}{
		{
			name:         "matching credential",
			credentialID: credID,
			allowList: []CredentialDescriptor{
				{Type: "public-key", ID: credID},
			},
			want: true,
		},
		{
			name:         "no match",
			credentialID: credID,
			allowList: []CredentialDescriptor{
				{Type: "public-key", ID: otherID},
			},
			want: false,
		},
		{
			name:         "empty allowList",
			credentialID: credID,
			allowList:    []CredentialDescriptor{},
			want:         false,
		},
		{
			name:         "multiple entries with match",
			credentialID: credID,
			allowList: []CredentialDescriptor{
				{Type: "public-key", ID: otherID},
				{Type: "public-key", ID: credID},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchesCredentialID(tt.credentialID, tt.allowList)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestDecodeGetAssertionRequest_InterfaceKeyedMaps(t *testing.T) {
	clientDataHash := generateTestClientDataHash()
	credID := make([]byte, 32)
	_, _ = rand.Read(credID)

	// Build request using interface{} keyed maps (as CBOR might decode)
	request := map[int]interface{}{
		getAssertionParamRPID:           "example.com",
		getAssertionParamClientDataHash: clientDataHash,
		getAssertionParamAllowList: []interface{}{
			map[interface{}]interface{}{
				"type": "public-key",
				"id":   credID,
			},
		},
		getAssertionParamExtensions: map[interface{}]interface{}{
			"test": true,
		},
		getAssertionParamOptions: map[interface{}]interface{}{
			"up": true,
			"uv": false,
		},
	}

	reqBytes, err := cbor.Marshal(request)
	require.NoError(t, err)

	decoded, err := decodeGetAssertionRequest(reqBytes)
	require.NoError(t, err)

	require.Equal(t, "example.com", decoded.RPID)
	require.True(t, bytes.Equal(decoded.ClientDataHash, clientDataHash))
	require.Len(t, decoded.AllowList, 1)
	require.True(t, decoded.Options["up"])
	require.False(t, decoded.Options["uv"])
}

func TestEncodeGetAssertionResponse(t *testing.T) {
	tests := []struct {
		name     string
		response *GetAssertionResponse
		wantErr  bool
	}{
		{
			name:     "nil response",
			response: nil,
			wantErr:  true,
		},
		{
			name: "missing authData",
			response: &GetAssertionResponse{
				Credential: &CredentialDescriptor{
					Type: "public-key",
					ID:   make([]byte, 32),
				},
				Signature: make([]byte, 64),
			},
			wantErr: true,
		},
		{
			name: "missing signature",
			response: &GetAssertionResponse{
				Credential: &CredentialDescriptor{
					Type: "public-key",
					ID:   make([]byte, 32),
				},
				AuthData: make([]byte, 37),
			},
			wantErr: true,
		},
		{
			name: "valid response",
			response: &GetAssertionResponse{
				Credential: &CredentialDescriptor{
					Type: "public-key",
					ID:   make([]byte, 32),
				},
				AuthData:  make([]byte, 37),
				Signature: make([]byte, 64),
			},
			wantErr: false,
		},
		{
			name: "valid response with user",
			response: &GetAssertionResponse{
				Credential: &CredentialDescriptor{
					Type: "public-key",
					ID:   make([]byte, 32),
				},
				AuthData:  make([]byte, 37),
				Signature: make([]byte, 64),
				User: &User{
					ID:          []byte("user-id"),
					Name:        "user@example.com",
					DisplayName: "Test User",
				},
			},
			wantErr: false,
		},
		{
			name: "valid response with numberOfCredentials",
			response: &GetAssertionResponse{
				Credential: &CredentialDescriptor{
					Type: "public-key",
					ID:   make([]byte, 32),
				},
				AuthData:            make([]byte, 37),
				Signature:           make([]byte, 64),
				NumberOfCredentials: 3,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encodeGetAssertionResponse(tt.response)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestComputeAssertionHMACSHA256(t *testing.T) {
	key := make([]byte, 32)
	data := make([]byte, 32)
	_, _ = rand.Read(key)
	_, _ = rand.Read(data)

	result1 := computeAssertionHMACSHA256(key, data)
	result2 := computeAssertionHMACSHA256(key, data)

	// Same inputs should produce same outputs
	require.True(t, bytes.Equal(result1, result2), "HMAC-SHA256 should be deterministic")

	// Output should be 32 bytes
	require.Len(t, result1, 32)

	// Different data should produce different output
	differentData := make([]byte, 32)
	_, _ = rand.Read(differentData)
	result3 := computeAssertionHMACSHA256(key, differentData)

	require.False(t, bytes.Equal(result1, result3), "Different inputs should produce different HMAC outputs")
}

func TestParseAssertionPrivateKey(t *testing.T) {
	// Generate an ECDSA key
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ecKeyBytes, err := x509.MarshalPKCS8PrivateKey(ecKey)
	require.NoError(t, err)

	// Test parsing ECDSA key
	parsed, err := parseAssertionPrivateKey(ecKeyBytes)
	require.NoError(t, err)

	_, ok := parsed.(*ecdsa.PrivateKey)
	require.True(t, ok, "Parsed key should be ECDSA")

	// Test invalid data
	_, err = parseAssertionPrivateKey([]byte("invalid"))
	require.ErrorIs(t, err, ErrInvalidPrivateKey)
}

func TestToUint8Value(t *testing.T) {
	tests := []struct {
		name    string
		input   interface{}
		want    uint8
		wantErr bool
	}{
		{"uint8", uint8(42), 42, false},
		{"int", int(42), 42, false},
		{"int8", int8(42), 42, false},
		{"int16", int16(42), 42, false},
		{"int32", int32(42), 42, false},
		{"int64", int64(42), 42, false},
		{"uint", uint(42), 42, false},
		{"uint16", uint16(42), 42, false},
		{"uint32", uint32(42), 42, false},
		{"uint64", uint64(42), 42, false},
		{"string", "42", 0, true},
		{"float64", float64(42), 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := toUint8Value(tt.input)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.want, got)
			}
		})
	}
}

func TestDecodeGetAssertionOptions_InvalidFormat(t *testing.T) {
	_, err := decodeGetAssertionOptions("not-a-map")
	require.ErrorIs(t, err, ErrGetAssertionInvalidOptions)
}

func TestGetAssertion_WrongRPID(t *testing.T) {
	auth := createTestAuthenticator(t)
	rpID := "example.com"
	cred := createAssertionTestCredential(t, auth, rpID, false)

	clientDataHash := generateTestClientDataHash()

	// Build CBOR request with wrong RPID
	request := map[int]interface{}{
		getAssertionParamRPID:           "wrong-rp.com",
		getAssertionParamClientDataHash: clientDataHash,
		getAssertionParamAllowList: []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"id":   cred.CredentialID,
			},
		},
	}

	reqBytes, err := cbor.Marshal(request)
	require.NoError(t, err)

	// Execute - should fail because credential RPID doesn't match
	respBytes, err := auth.ProcessCBOR(CmdGetAssertion, reqBytes)
	require.Error(t, err)
	require.Equal(t, byte(StatusNoCredentials), respBytes[0])
}

func TestGetAssertion_NonDiscoverableWithoutAllowList(t *testing.T) {
	auth := createTestAuthenticator(t)
	rpID := "example.com"
	createAssertionTestCredential(t, auth, rpID, false) // Non-discoverable

	clientDataHash := generateTestClientDataHash()

	// Build CBOR request without allowList (only discoverable credentials are found)
	request := map[int]interface{}{
		getAssertionParamRPID:           rpID,
		getAssertionParamClientDataHash: clientDataHash,
	}

	reqBytes, err := cbor.Marshal(request)
	require.NoError(t, err)

	// Execute - should fail because credential is not discoverable
	respBytes, err := auth.ProcessCBOR(CmdGetAssertion, reqBytes)
	require.Error(t, err)
	require.Equal(t, byte(StatusNoCredentials), respBytes[0])
}

func TestGetAssertion_SkipsNonPublicKeyType(t *testing.T) {
	auth := createTestAuthenticator(t)
	rpID := "example.com"
	cred := createAssertionTestCredential(t, auth, rpID, false)

	clientDataHash := generateTestClientDataHash()

	// Build CBOR request with mixed types in allowList
	request := map[int]interface{}{
		getAssertionParamRPID:           rpID,
		getAssertionParamClientDataHash: clientDataHash,
		getAssertionParamAllowList: []interface{}{
			map[string]interface{}{
				"type": "invalid-type",
				"id":   make([]byte, 32),
			},
			map[string]interface{}{
				"type": "public-key",
				"id":   cred.CredentialID,
			},
		},
	}

	reqBytes, err := cbor.Marshal(request)
	require.NoError(t, err)

	// Execute - should succeed, skipping the invalid type
	respBytes, err := auth.ProcessCBOR(CmdGetAssertion, reqBytes)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), respBytes[0])

	var response map[int]interface{}
	err = cbor.Unmarshal(respBytes[1:], &response)
	require.NoError(t, err)
	require.NotNil(t, response[getAssertionRespCredential])
}

func TestGetAssertion_CredentialWithTransports(t *testing.T) {
	auth := createTestAuthenticator(t)
	rpID := "example.com"
	cred := createAssertionTestCredential(t, auth, rpID, false)

	clientDataHash := generateTestClientDataHash()

	// Build CBOR request with transports in allowList
	request := map[int]interface{}{
		getAssertionParamRPID:           rpID,
		getAssertionParamClientDataHash: clientDataHash,
		getAssertionParamAllowList: []interface{}{
			map[string]interface{}{
				"type":       "public-key",
				"id":         cred.CredentialID,
				"transports": []interface{}{"internal", "usb"},
			},
		},
	}

	reqBytes, err := cbor.Marshal(request)
	require.NoError(t, err)

	// Execute
	respBytes, err := auth.ProcessCBOR(CmdGetAssertion, reqBytes)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), respBytes[0])

	var response map[int]interface{}
	err = cbor.Unmarshal(respBytes[1:], &response)
	require.NoError(t, err)
	require.NotNil(t, response[getAssertionRespCredential])
}

func TestGetAssertion_EmptyData(t *testing.T) {
	auth := createTestAuthenticator(t)

	// Execute with empty data
	respBytes, err := auth.ProcessCBOR(CmdGetAssertion, []byte{})
	require.Error(t, err)
	require.NotEqual(t, byte(StatusOK), respBytes[0])
}

func TestGetAssertion_InvalidCBOR(t *testing.T) {
	auth := createTestAuthenticator(t)

	// Execute with invalid CBOR
	respBytes, err := auth.ProcessCBOR(CmdGetAssertion, []byte{0xFF, 0xFF, 0xFF})
	require.Error(t, err)
	require.NotEqual(t, byte(StatusOK), respBytes[0])
}

// TestWebAuthnSignatureVerification verifies the complete WebAuthn signature flow
// the same way a relying party like webauthn.io would verify it.
func TestWebAuthnSignatureVerification(t *testing.T) {
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	rpID := "webauthn.io"
	clientDataHash := generateTestClientDataHash()

	// Step 1: MakeCredential (Registration)
	makeCredReq := map[int]interface{}{
		makeCredentialKeyClientDataHash: clientDataHash,
		makeCredentialKeyRP: map[string]interface{}{
			"id":   rpID,
			"name": "WebAuthn Test",
		},
		makeCredentialKeyUser: map[string]interface{}{
			"id":          []byte("test-user-id"),
			"name":        "testuser",
			"displayName": "Test User",
		},
		makeCredentialKeyPubKeyCredParams: []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"alg":  COSEAlgES256,
			},
		},
	}

	makeCredReqBytes, err := cbor.Marshal(makeCredReq)
	require.NoError(t, err)

	makeCredRespBytes, err := auth.ProcessCBOR(CmdMakeCredential, makeCredReqBytes)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), makeCredRespBytes[0])

	// Parse MakeCredential response
	var makeCredResp map[int]interface{}
	err = cbor.Unmarshal(makeCredRespBytes[1:], &makeCredResp)
	require.NoError(t, err)

	regAuthData, ok := makeCredResp[makeCredentialResponseKeyAuthData].([]byte)
	require.True(t, ok, "authData should be bytes")

	// Parse authData to extract public key
	parsedAuthData, err := ParseAuthData(regAuthData)
	require.NoError(t, err)
	require.True(t, parsedAuthData.HasAttestedCredentialData())

	// Extract credential ID and public key from registration
	credentialID := parsedAuthData.CredentialID
	publicKeyCOSE := parsedAuthData.PublicKey

	t.Logf("Registration complete - credentialID: %x", credentialID[:8])
	t.Logf("Public key COSE: %x", publicKeyCOSE)

	// Step 2: GetAssertion (Authentication)
	authClientDataHash := generateTestClientDataHash() // Different clientDataHash for auth

	getAssertReq := map[int]interface{}{
		getAssertionParamRPID:           rpID,
		getAssertionParamClientDataHash: authClientDataHash,
		getAssertionParamAllowList: []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"id":   credentialID,
			},
		},
	}

	getAssertReqBytes, err := cbor.Marshal(getAssertReq)
	require.NoError(t, err)

	getAssertRespBytes, err := auth.ProcessCBOR(CmdGetAssertion, getAssertReqBytes)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), getAssertRespBytes[0])

	// Parse GetAssertion response
	var getAssertResp map[int]interface{}
	err = cbor.Unmarshal(getAssertRespBytes[1:], &getAssertResp)
	require.NoError(t, err)

	assertionAuthData, ok := getAssertResp[getAssertionRespAuthData].([]byte)
	require.True(t, ok, "authData should be bytes")

	signature, ok := getAssertResp[getAssertionRespSignature].([]byte)
	require.True(t, ok, "signature should be bytes")

	t.Logf("Authentication complete - authData length: %d", len(assertionAuthData))
	t.Logf("Signature: %x", signature)

	// Step 3: Verify signature (as webauthn.io would do)
	// Parse the public key from registration
	pubKey, _, err := DecodeCOSEPublicKey(publicKeyCOSE)
	require.NoError(t, err)

	ecPubKey, ok := pubKey.(*ecdsa.PublicKey)
	require.True(t, ok, "expected ECDSA public key")

	// Build the signed data: authData || clientDataHash
	signedData := make([]byte, len(assertionAuthData)+len(authClientDataHash))
	copy(signedData, assertionAuthData)
	copy(signedData[len(assertionAuthData):], authClientDataHash)

	// Hash the signed data (ES256 uses SHA-256)
	digest := sha256.Sum256(signedData)

	// Verify ASN.1/DER signature (WebAuthn spec mandates DER encoding)
	valid := ecdsa.VerifyASN1(ecPubKey, digest[:], signature)
	require.True(t, valid, "signature verification should succeed")

	t.Log("WebAuthn signature verification PASSED!")
}

// TestWebAuthnSignatureVerificationWithPIN verifies the WebAuthn flow with PIN enabled.
func TestWebAuthnSignatureVerificationWithPIN(t *testing.T) {
	storage := NewMemoryStorage()
	config := &Config{
		AAGUID:                 DefaultAAGUID,
		SupportedAlgorithms:    []int{COSEAlgES256},
		MaxCredentials:         100,
		MaxResidentCredentials: 25,
		PINMinLength:           4,
		PINMaxRetries:          8,
		EnableHMACSecret:       true,
		EnableResidentKey:      true,
		Storage:                storage,
	}

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	// Set PIN to enable UV
	err = auth.SetPINForTesting("123456")
	require.NoError(t, err)
	require.True(t, auth.IsPINSet(), "PIN should be set")

	rpID := "webauthn.io"
	clientDataHash := generateTestClientDataHash()

	// Step 1: MakeCredential (Registration) with PIN enabled
	makeCredReq := map[int]interface{}{
		makeCredentialKeyClientDataHash: clientDataHash,
		makeCredentialKeyRP: map[string]interface{}{
			"id":   rpID,
			"name": "WebAuthn Test",
		},
		makeCredentialKeyUser: map[string]interface{}{
			"id":          []byte("test-user-id"),
			"name":        "testuser",
			"displayName": "Test User",
		},
		makeCredentialKeyPubKeyCredParams: []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"alg":  COSEAlgES256,
			},
		},
	}

	makeCredReqBytes, err := cbor.Marshal(makeCredReq)
	require.NoError(t, err)

	makeCredRespBytes, err := auth.ProcessCBOR(CmdMakeCredential, makeCredReqBytes)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), makeCredRespBytes[0])

	// Parse MakeCredential response
	var makeCredResp map[int]interface{}
	err = cbor.Unmarshal(makeCredRespBytes[1:], &makeCredResp)
	require.NoError(t, err)

	regAuthData, ok := makeCredResp[makeCredentialResponseKeyAuthData].([]byte)
	require.True(t, ok)

	// Verify UV flag is not set without pinUvAuthParam in the request
	parsedRegAuthData, err := ParseAuthData(regAuthData)
	require.NoError(t, err)
	require.False(t, parsedRegAuthData.UserVerified(), "UV flag should not be set without pinUvAuthParam")
	t.Logf("Registration flags: 0x%02x (UV=%v)", byte(parsedRegAuthData.Flags), parsedRegAuthData.UserVerified())

	credentialID := parsedRegAuthData.CredentialID
	publicKeyCOSE := parsedRegAuthData.PublicKey

	// Step 2: GetAssertion (Authentication) with PIN enabled
	authClientDataHash := generateTestClientDataHash()

	getAssertReq := map[int]interface{}{
		getAssertionParamRPID:           rpID,
		getAssertionParamClientDataHash: authClientDataHash,
		getAssertionParamAllowList: []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"id":   credentialID,
			},
		},
	}

	getAssertReqBytes, err := cbor.Marshal(getAssertReq)
	require.NoError(t, err)

	getAssertRespBytes, err := auth.ProcessCBOR(CmdGetAssertion, getAssertReqBytes)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), getAssertRespBytes[0])

	// Parse GetAssertion response
	var getAssertResp map[int]interface{}
	err = cbor.Unmarshal(getAssertRespBytes[1:], &getAssertResp)
	require.NoError(t, err)

	assertionAuthData, ok := getAssertResp[getAssertionRespAuthData].([]byte)
	require.True(t, ok)

	// Verify UV flag is not set without pinUvAuthParam in the request
	parsedAssertAuthData, err := ParseAuthData(assertionAuthData)
	require.NoError(t, err)
	require.False(t, parsedAssertAuthData.UserVerified(), "UV flag should not be set in assertion without pinUvAuthParam")
	t.Logf("Assertion flags: 0x%02x (UV=%v)", byte(parsedAssertAuthData.Flags), parsedAssertAuthData.UserVerified())

	signature, ok := getAssertResp[getAssertionRespSignature].([]byte)
	require.True(t, ok)

	// Step 3: Verify signature
	pubKey, _, err := DecodeCOSEPublicKey(publicKeyCOSE)
	require.NoError(t, err)

	ecPubKey, ok := pubKey.(*ecdsa.PublicKey)
	require.True(t, ok)

	signedData := make([]byte, len(assertionAuthData)+len(authClientDataHash))
	copy(signedData, assertionAuthData)
	copy(signedData[len(assertionAuthData):], authClientDataHash)

	digest := sha256.Sum256(signedData)

	// Verify ASN.1/DER signature (WebAuthn spec mandates DER encoding)
	valid := ecdsa.VerifyASN1(ecPubKey, digest[:], signature)
	require.True(t, valid, "signature verification should succeed with PIN enabled")

	t.Log("WebAuthn signature verification with PIN PASSED!")
}

// TestGetAssertion_PINAuthSkipsUserPresence verifies that a valid pinUvAuthParam
// causes GetAssertion to bypass user presence, as per CTAP2 spec section 6.2.2.
// A blocking UP handler is used to prove that UP is never requested.
func TestGetAssertion_PINAuthSkipsUserPresence(t *testing.T) {
	// Create authenticator with auto-grant handler for credential creation
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	rpID := "example.com"
	clientDataHash := generateTestClientDataHash()

	// Step 1: Register a credential using the default auto-grant UP handler
	makeCredReq := map[int]interface{}{
		makeCredentialKeyClientDataHash: clientDataHash,
		makeCredentialKeyRP: map[string]interface{}{
			"id":   rpID,
			"name": "Example",
		},
		makeCredentialKeyUser: map[string]interface{}{
			"id":          []byte("user1"),
			"name":        "user",
			"displayName": "User",
		},
		makeCredentialKeyPubKeyCredParams: []interface{}{
			map[string]interface{}{"type": "public-key", "alg": COSEAlgES256},
		},
	}

	makeCredReqBytes, err := cbor.Marshal(makeCredReq)
	require.NoError(t, err)

	makeCredRespBytes, err := auth.ProcessCBOR(CmdMakeCredential, makeCredReqBytes)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), makeCredRespBytes[0])

	// Parse to get credential ID
	var makeCredResp map[int]interface{}
	err = cbor.Unmarshal(makeCredRespBytes[1:], &makeCredResp)
	require.NoError(t, err)

	regAuthDataBytes := makeCredResp[makeCredentialResponseKeyAuthData].([]byte)
	parsedRegAuthData, err := ParseAuthData(regAuthDataBytes)
	require.NoError(t, err)
	credentialID := parsedRegAuthData.CredentialID

	// Step 2: Set up PIN protocol state with a known token
	pinToken := make([]byte, 32)
	for i := range pinToken {
		pinToken[i] = byte(i + 42)
	}
	auth.pinState.protocol = &pinProtocolState{
		pinUvAuthToken:   pinToken,
		tokenPermissions: PINPermissionGetAssertion,
	}

	// Step 3: Switch to blocking UP handler. If GetAssertion requests UP,
	// the test will hang indefinitely (and eventually time out).
	auth.upHandler = &blockingUPHandler{}

	// Step 4: Compute valid pinUvAuthParam for the assertion clientDataHash
	assertionClientDataHash := generateTestClientDataHash()
	mac := hmac.New(sha256.New, pinToken)
	mac.Write(assertionClientDataHash)
	pinUvAuthParam := mac.Sum(nil)[:16]

	// Step 5: Build GetAssertion CBOR request with valid pinUvAuthParam
	getAssertReq := map[int]interface{}{
		getAssertionParamRPID:              rpID,
		getAssertionParamClientDataHash:    assertionClientDataHash,
		getAssertionParamPINUVAuthParam:    pinUvAuthParam,
		getAssertionParamPINUVAuthProtocol: uint8(1),
		getAssertionParamAllowList: []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"id":   credentialID,
			},
		},
	}

	getAssertReqBytes, err := cbor.Marshal(getAssertReq)
	require.NoError(t, err)

	// Step 6: Execute via ProcessCBOR. This must succeed without blocking
	// because valid pinUvAuthParam bypasses user presence per CTAP2 spec.
	respBytes, err := auth.ProcessCBOR(CmdGetAssertion, getAssertReqBytes)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), respBytes[0])

	// Verify the response contains valid assertion data
	var response map[int]interface{}
	err = cbor.Unmarshal(respBytes[1:], &response)
	require.NoError(t, err)

	require.NotNil(t, response[getAssertionRespCredential])
	require.NotEmpty(t, response[getAssertionRespAuthData])
	require.NotEmpty(t, response[getAssertionRespSignature])

	// Verify UP and UV flags are both set
	authDataBytes := response[getAssertionRespAuthData].([]byte)
	flags := AuthDataFlags(authDataBytes[32])
	require.True(t, flags.Has(FlagUP), "UP flag should be set")
	require.True(t, flags.Has(FlagUV), "UV flag should be set when pinUvAuthParam is valid")
}

// TestMapKeyBackendError tests the error mapping for key backend errors.
func TestMapKeyBackendError(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		expected error
	}{
		{
			name:     "nil error",
			errMsg:   "",
			expected: nil,
		},
		{
			name:     "key not found",
			errMsg:   "phone: key not found",
			expected: ErrNoCredentials,
		},
		{
			name:     "not found generic",
			errMsg:   "credential not found",
			expected: ErrNoCredentials,
		},
		{
			name:     "does not exist",
			errMsg:   "key does not exist on device",
			expected: ErrNoCredentials,
		},
		{
			name:     "user cancelled",
			errMsg:   "phone: user cancelled",
			expected: ErrOperationDenied,
		},
		{
			name:     "cancelled generic",
			errMsg:   "operation was cancelled",
			expected: ErrOperationDenied,
		},
		{
			name:     "denied",
			errMsg:   "access denied",
			expected: ErrOperationDenied,
		},
		{
			name:     "biometric failed",
			errMsg:   "biometric verification failed",
			expected: ErrOperationDenied,
		},
		{
			name:     "verification failed",
			errMsg:   "user verification failed",
			expected: ErrOperationDenied,
		},
		{
			name:     "timeout",
			errMsg:   "operation timeout",
			expected: ErrOperationDenied,
		},
		{
			name:     "timed out",
			errMsg:   "request timed out",
			expected: ErrOperationDenied,
		},
		{
			name:     "not connected",
			errMsg:   "phone: not connected",
			expected: ErrCryptoError,
		},
		{
			name:     "connection failed",
			errMsg:   "connection failed to device",
			expected: ErrCryptoError,
		},
		{
			name:     "generic error",
			errMsg:   "some unknown error",
			expected: ErrCryptoError,
		},
		{
			name:     "case insensitive key not found",
			errMsg:   "KEY NOT FOUND",
			expected: ErrNoCredentials,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.errMsg != "" {
				err = errors.New(tt.errMsg)
			}

			result := mapKeyBackendError(err)

			if tt.expected == nil {
				require.Nil(t, result)
			} else {
				require.Equal(t, tt.expected, result)
			}
		})
	}
}

// --- Public GetAssertion API tests ---

// TestGetAssertionPublicAPI_Success tests the public GetAssertion method with a
// pre-registered credential and verifies the response contains valid assertion data.
func TestGetAssertionPublicAPI_Success(t *testing.T) {
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	rpID := "example.com"
	clientDataHash := generateTestClientDataHash()

	// Register a credential using the public MakeCredential API
	makeCredResp, err := auth.MakeCredential(
		clientDataHash,
		RelyingParty{ID: rpID, Name: "Example"},
		User{ID: []byte("user-1"), Name: "alice", DisplayName: "Alice"},
		[]PublicKeyCredentialParam{{Type: "public-key", Alg: COSEAlgES256}},
		nil,
	)
	require.NoError(t, err)
	require.NotNil(t, makeCredResp)

	// Parse the registration authData to extract the credential ID
	parsedAuthData, err := ParseAuthData(makeCredResp.AuthData)
	require.NoError(t, err)
	require.True(t, parsedAuthData.HasAttestedCredentialData())

	credentialID := parsedAuthData.CredentialID

	// Perform assertion using the public GetAssertion API
	assertionClientDataHash := generateTestClientDataHash()
	allowList := []CredentialDescriptor{
		{Type: "public-key", ID: credentialID},
	}

	assertionResp, err := auth.GetAssertion(assertionClientDataHash, rpID, allowList, nil)
	require.NoError(t, err)
	require.NotNil(t, assertionResp)

	// Verify response fields
	require.NotNil(t, assertionResp.Credential)
	require.Equal(t, "public-key", assertionResp.Credential.Type)
	require.True(t, bytes.Equal(credentialID, assertionResp.Credential.ID))

	require.NotEmpty(t, assertionResp.AuthData)
	require.GreaterOrEqual(t, len(assertionResp.AuthData), minAuthDataLen)

	require.NotEmpty(t, assertionResp.Signature)

	// Verify the UP flag is set in the authData
	assertionAuthData, err := ParseAuthData(assertionResp.AuthData)
	require.NoError(t, err)
	require.True(t, assertionAuthData.Flags.Has(FlagUP), "UP flag should be set")

	// Verify the signature is valid using the public key from registration
	publicKeyCOSE := parsedAuthData.PublicKey
	pubKey, _, err := DecodeCOSEPublicKey(publicKeyCOSE)
	require.NoError(t, err)

	ecPubKey, ok := pubKey.(*ecdsa.PublicKey)
	require.True(t, ok, "expected ECDSA public key")

	signedData := make([]byte, len(assertionResp.AuthData)+len(assertionClientDataHash))
	copy(signedData, assertionResp.AuthData)
	copy(signedData[len(assertionResp.AuthData):], assertionClientDataHash)

	digest := sha256.Sum256(signedData)
	valid := ecdsa.VerifyASN1(ecPubKey, digest[:], assertionResp.Signature)
	require.True(t, valid, "assertion signature should verify successfully")
}

// TestGetAssertionPublicAPI_EmptyRPID tests that GetAssertion returns
// ErrGetAssertionMissingRPID when the rpID parameter is empty.
func TestGetAssertionPublicAPI_EmptyRPID(t *testing.T) {
	auth := createTestAuthenticator(t)

	clientDataHash := generateTestClientDataHash()

	_, err := auth.GetAssertion(clientDataHash, "", nil, nil)
	require.ErrorIs(t, err, ErrGetAssertionMissingRPID)
}

// TestGetAssertionPublicAPI_InvalidClientDataHashLength tests that GetAssertion
// returns ErrGetAssertionInvalidClientDataHash when the hash is the wrong length.
func TestGetAssertionPublicAPI_InvalidClientDataHashLength(t *testing.T) {
	auth := createTestAuthenticator(t)

	tests := []struct {
		name string
		hash []byte
	}{
		{"too short", []byte("short")},
		{"too long", make([]byte, 64)},
		{"empty", []byte{}},
		{"nil", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := auth.GetAssertion(tt.hash, "example.com", nil, nil)
			require.ErrorIs(t, err, ErrGetAssertionInvalidClientDataHash)
		})
	}
}

// TestGetAssertionPublicAPI_NoMatchingCredentials tests that GetAssertion returns
// ErrNoCredentials when no credentials match the request criteria.
func TestGetAssertionPublicAPI_NoMatchingCredentials(t *testing.T) {
	auth := createTestAuthenticator(t)

	clientDataHash := generateTestClientDataHash()

	// No credentials registered at all
	_, err := auth.GetAssertion(clientDataHash, "nonexistent.com", nil, nil)
	require.ErrorIs(t, err, ErrNoCredentials)
}

// TestGetAssertionPublicAPI_AllowListNoMatch tests that GetAssertion returns
// ErrNoCredentials when the allowList contains no matching credential IDs.
func TestGetAssertionPublicAPI_AllowListNoMatch(t *testing.T) {
	auth := createTestAuthenticator(t)
	rpID := "example.com"

	// Register a credential
	clientDataHash := generateTestClientDataHash()
	_, err := auth.MakeCredential(
		clientDataHash,
		RelyingParty{ID: rpID, Name: "Example"},
		User{ID: []byte("user-1"), Name: "alice", DisplayName: "Alice"},
		[]PublicKeyCredentialParam{{Type: "public-key", Alg: COSEAlgES256}},
		nil,
	)
	require.NoError(t, err)

	// Try assertion with a non-matching credential ID
	fakeCredID := make([]byte, 32)
	_, _ = rand.Read(fakeCredID)
	allowList := []CredentialDescriptor{
		{Type: "public-key", ID: fakeCredID},
	}

	assertionClientDataHash := generateTestClientDataHash()
	_, err = auth.GetAssertion(assertionClientDataHash, rpID, allowList, nil)
	require.ErrorIs(t, err, ErrNoCredentials)
}

// TestGetAssertionPublicAPI_WithOptions tests that GetAssertion correctly passes
// options through to the underlying execution.
func TestGetAssertionPublicAPI_WithOptions(t *testing.T) {
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	rpID := "example.com"
	clientDataHash := generateTestClientDataHash()

	// Register a credential
	makeCredResp, err := auth.MakeCredential(
		clientDataHash,
		RelyingParty{ID: rpID, Name: "Example"},
		User{ID: []byte("user-1"), Name: "alice", DisplayName: "Alice"},
		[]PublicKeyCredentialParam{{Type: "public-key", Alg: COSEAlgES256}},
		nil,
	)
	require.NoError(t, err)

	parsedAuthData, err := ParseAuthData(makeCredResp.AuthData)
	require.NoError(t, err)
	credentialID := parsedAuthData.CredentialID

	// Perform assertion with explicit options
	assertionClientDataHash := generateTestClientDataHash()
	allowList := []CredentialDescriptor{
		{Type: "public-key", ID: credentialID},
	}

	opts := &GetAssertionOptions{
		Options: map[string]bool{
			"up": true,
			"uv": false,
		},
	}

	resp, err := auth.GetAssertion(assertionClientDataHash, rpID, allowList, opts)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Verify UP is set, UV is not set
	assertionAuthData, err := ParseAuthData(resp.AuthData)
	require.NoError(t, err)
	require.True(t, assertionAuthData.Flags.Has(FlagUP), "UP flag should be set")
	require.False(t, assertionAuthData.Flags.Has(FlagUV), "UV flag should not be set")
}

// TestGetAssertionPublicAPI_NilOptions tests that GetAssertion works correctly
// when opts is nil (all defaults apply).
func TestGetAssertionPublicAPI_NilOptions(t *testing.T) {
	auth := createTestAuthenticator(t)
	rpID := "example.com"
	cred := createAssertionTestCredential(t, auth, rpID, false)

	clientDataHash := generateTestClientDataHash()
	allowList := []CredentialDescriptor{
		{Type: "public-key", ID: cred.CredentialID},
	}

	resp, err := auth.GetAssertion(clientDataHash, rpID, allowList, nil)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.AuthData)
	require.NotEmpty(t, resp.Signature)
}

// TestGetAssertionPublicAPI_WrongRPID tests that GetAssertion returns ErrNoCredentials
// when the rpID does not match any stored credential.
func TestGetAssertionPublicAPI_WrongRPID(t *testing.T) {
	auth := createTestAuthenticator(t)
	rpID := "example.com"
	cred := createAssertionTestCredential(t, auth, rpID, false)

	clientDataHash := generateTestClientDataHash()
	allowList := []CredentialDescriptor{
		{Type: "public-key", ID: cred.CredentialID},
	}

	// Use a different RPID than the one the credential was registered with
	_, err := auth.GetAssertion(clientDataHash, "wrong-rp.com", allowList, nil)
	require.ErrorIs(t, err, ErrNoCredentials)
}

// TestGetAssertionPublicAPI_SignatureCountIncrement tests that the signature
// counter is properly incremented after each assertion.
func TestGetAssertionPublicAPI_SignatureCountIncrement(t *testing.T) {
	auth := createTestAuthenticator(t)
	rpID := "example.com"
	cred := createAssertionTestCredential(t, auth, rpID, false)

	allowList := []CredentialDescriptor{
		{Type: "public-key", ID: cred.CredentialID},
	}

	// Perform two assertions and verify the counter increments
	for i := uint32(1); i <= 2; i++ {
		clientDataHash := generateTestClientDataHash()
		_, err := auth.GetAssertion(clientDataHash, rpID, allowList, nil)
		require.NoError(t, err)

		updatedCred, err := auth.storage.Load(cred.CredentialID)
		require.NoError(t, err)
		require.Equal(t, i, updatedCred.SignCount, "sign count should be %d after assertion %d", i, i)
	}
}

// --- InternalPINHash tests for GetAssertion ---

// TestGetAssertion_InternalPINHash_Success verifies that a trusted in-process caller
// can perform an assertion by providing the correct InternalPINHash, bypassing the
// CTAP2 clientPin ECDH ceremony. The response must have the UV flag set and the
// signature must verify against the registered public key.
func TestGetAssertion_InternalPINHash_Success(t *testing.T) {
	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.EnablePIN = true

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	// Set PIN via SyncPINHash (the first 16 bytes of SHA-256 of the raw PIN).
	rawPIN := "123456"
	fullHash := sha256.Sum256([]byte(rawPIN))
	pinHash := fullHash[:PINHashSize]
	auth.SyncPINHash(pinHash)
	require.True(t, auth.IsPINSet(), "PIN should be set")

	rpID := "example.com"

	// Register a credential directly via storage (bypasses PIN enforcement in MakeCredential).
	cred := createAssertionTestCredential(t, auth, rpID, true)

	// Perform assertion with the correct InternalPINHash.
	clientDataHash := generateTestClientDataHash()
	opts := &GetAssertionOptions{
		Options: map[string]bool{
			"up": true,
			"uv": true,
		},
		InternalPINHash: pinHash,
	}

	resp, err := auth.GetAssertion(clientDataHash, rpID, nil, opts)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Verify the UV flag is set in the authData (byte 32, bit 0x04).
	require.GreaterOrEqual(t, len(resp.AuthData), 33, "authData must be at least 33 bytes")
	flags := AuthDataFlags(resp.AuthData[32])
	require.True(t, flags.Has(FlagUP), "UP flag should be set")
	require.True(t, flags.Has(FlagUV), "UV flag should be set when InternalPINHash is valid")

	// Verify the assertion signature using the credential's public key.
	pubKey, _, err := DecodeCOSEPublicKey(cred.PublicKeyCOSE)
	require.NoError(t, err)

	ecPubKey, ok := pubKey.(*ecdsa.PublicKey)
	require.True(t, ok, "expected ECDSA public key")

	signedData := make([]byte, len(resp.AuthData)+len(clientDataHash))
	copy(signedData, resp.AuthData)
	copy(signedData[len(resp.AuthData):], clientDataHash)

	digest := sha256.Sum256(signedData)
	valid := ecdsa.VerifyASN1(ecPubKey, digest[:], resp.Signature)
	require.True(t, valid, "assertion signature should verify with InternalPINHash")
}

// TestGetAssertion_InternalPINHash_WrongHash verifies that providing an incorrect
// InternalPINHash returns ErrPINInvalid instead of silently succeeding.
func TestGetAssertion_InternalPINHash_WrongHash(t *testing.T) {
	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.EnablePIN = true

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	// Set the correct PIN hash.
	rawPIN := "123456"
	fullHash := sha256.Sum256([]byte(rawPIN))
	pinHash := fullHash[:PINHashSize]
	auth.SyncPINHash(pinHash)
	require.True(t, auth.IsPINSet())

	rpID := "example.com"
	createAssertionTestCredential(t, auth, rpID, true)

	// Compute a wrong PIN hash (hash of a different PIN).
	wrongFullHash := sha256.Sum256([]byte("wrong-pin"))
	wrongPINHash := wrongFullHash[:PINHashSize]

	clientDataHash := generateTestClientDataHash()
	opts := &GetAssertionOptions{
		Options: map[string]bool{
			"up": true,
			"uv": true,
		},
		InternalPINHash: wrongPINHash,
	}

	_, err = auth.GetAssertion(clientDataHash, rpID, nil, opts)
	require.ErrorIs(t, err, ErrPINInvalid)
}

// TestGetAssertion_InternalPINHash_NoPINSet verifies that providing an InternalPINHash
// when no PIN has been configured on the authenticator returns ErrPINInvalid, since
// there is no stored PIN hash to compare against.
func TestGetAssertion_InternalPINHash_NoPINSet(t *testing.T) {
	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.EnablePIN = true

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	// Do NOT set a PIN - leave PINSet = false.
	require.False(t, auth.IsPINSet())

	rpID := "example.com"
	createAssertionTestCredential(t, auth, rpID, true)

	// Provide a PIN hash even though no PIN is set on the authenticator.
	somePINHash := sha256.Sum256([]byte("123456"))
	clientDataHash := generateTestClientDataHash()
	opts := &GetAssertionOptions{
		Options: map[string]bool{
			"up": true,
			"uv": true,
		},
		InternalPINHash: somePINHash[:PINHashSize],
	}

	_, err = auth.GetAssertion(clientDataHash, rpID, nil, opts)
	require.ErrorIs(t, err, ErrPINInvalid)
}

// --- User intent check tests ---

// TestGetAssertionUserIntentCheck_Approved verifies that when EnableUserIntentCheck
// is true, PIN is set, and no pinUvAuthParam is provided, the authenticator calls
// RequestUserPresence before returning ErrPINRequired. When the user approves the
// intent check, ErrPINRequired is returned so Chrome proceeds with PIN exchange.
func TestGetAssertionUserIntentCheck_Approved(t *testing.T) {
	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.EnablePIN = true
	config.RequireUserPresence = false
	config.EnableUserIntentCheck = true

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	rpID := "example.com"

	// Register a credential directly via storage (bypasses PIN enforcement in MakeCredential).
	cred := createAssertionTestCredential(t, auth, rpID, false)

	// Set a PIN using SyncPINHash AFTER credential creation.
	rawPIN := "123456"
	fullHash := sha256.Sum256([]byte(rawPIN))
	pinHash := fullHash[:PINHashSize]
	auth.SyncPINHash(pinHash)
	require.True(t, auth.IsPINSet())

	// Switch to tracking handler that approves
	tracker := &trackingUPHandler{approve: true}
	auth.upHandler = tracker

	// Send GetAssertion WITHOUT pinUvAuthParam but with uv=true (RP requires UV).
	// The intent check only triggers when UV is actually required by the RP.
	clientDataHash := generateTestClientDataHash()
	getAssertReq := map[int]interface{}{
		getAssertionParamRPID:           rpID,
		getAssertionParamClientDataHash: clientDataHash,
		getAssertionParamAllowList: []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"id":   cred.CredentialID,
			},
		},
		getAssertionParamOptions: map[string]bool{"up": true, "uv": true},
	}

	getAssertReqBytes, err := cbor.Marshal(getAssertReq)
	require.NoError(t, err)

	respBytes, err := auth.ProcessCBOR(CmdGetAssertion, getAssertReqBytes)

	// Assert: UP handler was called (intent check happened)
	require.True(t, tracker.called.Load(), "UP handler should have been called for intent check")

	// Assert: returns ErrPINRequired (user approved intent, Chrome should do PIN exchange)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrPINRequired)
	require.Equal(t, byte(StatusPINRequired), respBytes[0])
}

// TestGetAssertionUserIntentCheck_Denied verifies that when EnableUserIntentCheck
// is true and the user denies the presence check, the authenticator returns
// ErrOperationDenied so Chrome falls through to other devices.
func TestGetAssertionUserIntentCheck_Denied(t *testing.T) {
	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.EnablePIN = true
	config.RequireUserPresence = false
	config.EnableUserIntentCheck = true

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	rpID := "example.com"

	// Register a credential directly via storage (bypasses PIN enforcement in MakeCredential).
	cred := createAssertionTestCredential(t, auth, rpID, false)

	// Set a PIN AFTER credential creation.
	rawPIN := "123456"
	fullHash := sha256.Sum256([]byte(rawPIN))
	pinHash := fullHash[:PINHashSize]
	auth.SyncPINHash(pinHash)
	require.True(t, auth.IsPINSet())

	// Switch to tracking handler that DENIES
	tracker := &trackingUPHandler{approve: false}
	auth.upHandler = tracker

	// Send GetAssertion WITHOUT pinUvAuthParam but with uv=true (RP requires UV).
	clientDataHash := generateTestClientDataHash()
	getAssertReq := map[int]interface{}{
		getAssertionParamRPID:           rpID,
		getAssertionParamClientDataHash: clientDataHash,
		getAssertionParamAllowList: []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"id":   cred.CredentialID,
			},
		},
		getAssertionParamOptions: map[string]bool{"up": true, "uv": true},
	}

	getAssertReqBytes, err := cbor.Marshal(getAssertReq)
	require.NoError(t, err)

	respBytes, err := auth.ProcessCBOR(CmdGetAssertion, getAssertReqBytes)

	// Assert: UP handler was called (intent check happened)
	require.True(t, tracker.called.Load(), "UP handler should have been called for intent check")

	// Assert: returns ErrOperationDenied (user chose different key)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrOperationDenied)
	require.Equal(t, byte(StatusOperationDenied), respBytes[0])
}

// TestGetAssertionUserIntentCheck_Disabled verifies that when EnableUserIntentCheck
// is false, the authenticator returns ErrPINRequired directly without calling the
// UP handler for an intent check.
func TestGetAssertionUserIntentCheck_Disabled(t *testing.T) {
	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.EnablePIN = true
	config.RequireUserPresence = false
	config.EnableUserIntentCheck = false // Disabled

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	rpID := "example.com"

	// Register a credential directly via storage (bypasses PIN enforcement in MakeCredential).
	cred := createAssertionTestCredential(t, auth, rpID, false)

	// Set a PIN AFTER credential creation.
	rawPIN := "123456"
	fullHash := sha256.Sum256([]byte(rawPIN))
	pinHash := fullHash[:PINHashSize]
	auth.SyncPINHash(pinHash)
	require.True(t, auth.IsPINSet())

	// Switch to tracking handler that records calls
	tracker := &trackingUPHandler{approve: true}
	auth.upHandler = tracker

	// Send GetAssertion WITHOUT pinUvAuthParam but WITH uv=true (RP requires UV).
	// Even with uv=true, when intent check is disabled, PINRequired is returned
	// immediately without calling the UP handler.
	clientDataHash := generateTestClientDataHash()
	getAssertReq := map[int]interface{}{
		getAssertionParamRPID:           rpID,
		getAssertionParamClientDataHash: clientDataHash,
		getAssertionParamAllowList: []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"id":   cred.CredentialID,
			},
		},
		getAssertionParamOptions: map[string]bool{"up": true, "uv": true},
	}

	getAssertReqBytes, err := cbor.Marshal(getAssertReq)
	require.NoError(t, err)

	respBytes, err := auth.ProcessCBOR(CmdGetAssertion, getAssertReqBytes)

	// Assert: UP handler was NOT called (no intent check when disabled)
	require.False(t, tracker.called.Load(), "UP handler should NOT have been called when intent check is disabled")

	// Assert: returns ErrPINRequired directly
	require.Error(t, err)
	require.ErrorIs(t, err, ErrPINRequired)
	require.Equal(t, byte(StatusPINRequired), respBytes[0])
}

// TestGetAssertionUVFalse_TouchOnly verifies that when the RP sends uv=false
// (or omits uv) and no pinUvAuthParam is provided, the authenticator proceeds
// with user presence only (touch) without requiring PIN, matching YubiKey behavior.
// Per CTAP2 spec §6.2.2, PIN is only required when uv=true or alwaysUV is enabled.
func TestGetAssertionUVFalse_TouchOnly(t *testing.T) {
	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.EnablePIN = true
	config.RequireUserPresence = true

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	rpID := "aws.amazon.com"

	// Register a credential.
	cred := createAssertionTestCredential(t, auth, rpID, false)

	// Set a PIN.
	rawPIN := "123456"
	fullHash := sha256.Sum256([]byte(rawPIN))
	pinHash := fullHash[:PINHashSize]
	auth.SyncPINHash(pinHash)
	require.True(t, auth.IsPINSet())

	// Use an auto-approve handler for user presence (touch).
	auth.upHandler = &AutoGrantHandler{}

	// Send GetAssertion with uv=false, no pinUvAuthParam (like AWS does).
	clientDataHash := generateTestClientDataHash()
	getAssertReq := map[int]interface{}{
		getAssertionParamRPID:           rpID,
		getAssertionParamClientDataHash: clientDataHash,
		getAssertionParamAllowList: []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"id":   cred.CredentialID,
			},
		},
		getAssertionParamOptions: map[string]bool{"up": true, "uv": false},
	}

	getAssertReqBytes, err := cbor.Marshal(getAssertReq)
	require.NoError(t, err)

	respBytes, err := auth.ProcessCBOR(CmdGetAssertion, getAssertReqBytes)

	// Assert: assertion succeeded (touch-only, no PIN required).
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), respBytes[0])

	// Parse the response to verify flags.
	var respMap map[int]interface{}
	require.NoError(t, cbor.Unmarshal(respBytes[1:], &respMap))

	authData, ok := respMap[getAssertionRespAuthData].([]byte)
	require.True(t, ok)
	require.True(t, len(authData) >= 37, "authData must be at least 37 bytes")

	flags := AuthDataFlags(authData[32])
	// UP flag should be set (user touched).
	require.True(t, flags&FlagUP != 0, "UP flag must be set")
	// UV flag should NOT be set (uv=false, no PIN).
	require.True(t, flags&FlagUV == 0, "UV flag must NOT be set when uv=false")
}

// TestGetAssertionUVTrue_RequiresPIN verifies that when the RP sends uv=true
// but no pinUvAuthParam is provided, the authenticator returns ErrPINRequired.
func TestGetAssertionUVTrue_RequiresPIN(t *testing.T) {
	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.EnablePIN = true

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	rpID := "secure-bank.com"

	// Register a credential.
	cred := createAssertionTestCredential(t, auth, rpID, false)

	// Set a PIN.
	rawPIN := "123456"
	fullHash := sha256.Sum256([]byte(rawPIN))
	pinHash := fullHash[:PINHashSize]
	auth.SyncPINHash(pinHash)

	// Send GetAssertion with uv=true, no pinUvAuthParam.
	clientDataHash := generateTestClientDataHash()
	getAssertReq := map[int]interface{}{
		getAssertionParamRPID:           rpID,
		getAssertionParamClientDataHash: clientDataHash,
		getAssertionParamAllowList: []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"id":   cred.CredentialID,
			},
		},
		getAssertionParamOptions: map[string]bool{"up": true, "uv": true},
	}

	getAssertReqBytes, err := cbor.Marshal(getAssertReq)
	require.NoError(t, err)

	respBytes, err := auth.ProcessCBOR(CmdGetAssertion, getAssertReqBytes)

	// Assert: returns PINRequired (RP requires UV, PIN must be provided).
	require.Error(t, err)
	require.ErrorIs(t, err, ErrPINRequired)
	require.Equal(t, byte(StatusPINRequired), respBytes[0])
}
