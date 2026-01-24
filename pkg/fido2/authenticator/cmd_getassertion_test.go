// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package authenticator

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
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

	// Verify UV flag is set in registration
	parsedRegAuthData, err := ParseAuthData(regAuthData)
	require.NoError(t, err)
	require.True(t, parsedRegAuthData.UserVerified(), "UV flag should be set when PIN is enabled")
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

	// Verify UV flag is set in assertion
	parsedAssertAuthData, err := ParseAuthData(assertionAuthData)
	require.NoError(t, err)
	require.True(t, parsedAssertAuthData.UserVerified(), "UV flag should be set in assertion when PIN is enabled")
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
