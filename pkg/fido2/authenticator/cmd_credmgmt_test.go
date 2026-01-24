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
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// credMgmtMustMarshalPrivateKey marshals a private key to PKCS#8 format, panicking on error.
func credMgmtMustMarshalPrivateKey(key crypto.PrivateKey) []byte {
	data, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	return data
}

// createCredMgmtTestAuthenticator creates an authenticator with credential management enabled.
func createCredMgmtTestAuthenticator(t *testing.T) *Authenticator {
	t.Helper()
	storage := NewMemoryStorage()
	config := &Config{
		Storage:                    storage,
		MaxResidentCredentials:     100,
		SupportedAlgorithms:        []int{COSEAlgES256},
		EnableCredentialManagement: true,
		EnablePIN:                  true,
		PINMaxRetries:              8,
	}
	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	return auth
}

// createCredMgmtTestCredential creates a test credential with the given parameters.
func createCredMgmtTestCredential(t *testing.T, rpID, rpName, userID, userName, displayName string, discoverable bool) *StoredCredential {
	t.Helper()
	privateKey, publicKeyCOSE, err := GenerateCredentialKey(COSEAlgES256)
	require.NoError(t, err)

	credID, err := GenerateCredentialID()
	require.NoError(t, err)

	return &StoredCredential{
		CredentialID:    credID,
		RPID:            rpID,
		RPName:          rpName,
		UserID:          []byte(userID),
		UserName:        userName,
		UserDisplayName: displayName,
		Algorithm:       COSEAlgES256,
		PrivateKey:      credMgmtMustMarshalPrivateKey(privateKey),
		PublicKeyCOSE:   publicKeyCOSE,
		SignCount:       0,
		Discoverable:    discoverable,
		CreatedAt:       time.Now().Unix(),
	}
}

// setupPINTokenForCredMgmt sets up a PIN token with credential management permission.
func setupPINTokenForCredMgmt(t *testing.T, auth *Authenticator) []byte {
	t.Helper()

	// Set PIN on the authenticator.
	auth.state.PINSet = true
	auth.state.PINHash = make([]byte, 32)

	// Initialize PIN protocol state.
	auth.pinState.protocol = &pinProtocolState{
		pinUvAuthToken:   make([]byte, 32),
		tokenPermissions: PINPermissionCredentialMgmt,
	}

	return auth.pinState.protocol.pinUvAuthToken
}

// credMgmtRawRequestForTest mirrors the server's structure for extracting raw params bytes.
type credMgmtRawRequestForTest struct {
	SubCommand        uint8           `cbor:"1,keyasint"`
	SubCommandParams  cbor.RawMessage `cbor:"2,keyasint,omitempty"`
	PinUvAuthProtocol int             `cbor:"3,keyasint,omitempty"`
	PinUvAuthParam    []byte          `cbor:"4,keyasint,omitempty"`
}

// credMgmtCanonicalEncoder returns a CBOR encoder with deterministic (canonical) encoding.
// This ensures map keys are sorted consistently, which is required for PIN auth verification.
func credMgmtCanonicalEncoder() cbor.EncMode {
	em, _ := cbor.EncOptions{Sort: cbor.SortCanonical}.EncMode()
	return em
}

// buildCredMgmtRequest builds a credential management request with proper PIN auth.
// This helper ensures the pinAuth is computed over the exact CBOR bytes that the server will receive.
// Uses canonical CBOR encoding for deterministic output.
func buildCredMgmtRequest(t *testing.T, pinToken []byte, subCommand uint8, params map[int]interface{}) []byte {
	t.Helper()

	em := credMgmtCanonicalEncoder()

	// Step 1: Build request with placeholder pinAuth.
	placeholderAuth := make([]byte, 16)
	req := map[int]interface{}{
		credMgmtKeySubCommand:        subCommand,
		credMgmtKeyPinUvAuthProtocol: PINProtocol1,
		credMgmtKeyPinUvAuthParam:    placeholderAuth,
	}
	if len(params) > 0 {
		req[credMgmtKeySubCommandParams] = params
	}

	// Step 2: Marshal the request with canonical encoding.
	data, err := em.Marshal(req)
	require.NoError(t, err)

	// Step 3: Decode to extract the exact SubCommandParams bytes.
	var rawReq credMgmtRawRequestForTest
	err = cbor.Unmarshal(data, &rawReq)
	require.NoError(t, err)

	// Step 4: Compute the correct pinAuth using the extracted bytes.
	authData := []byte{subCommand}
	if len(rawReq.SubCommandParams) > 0 {
		authData = append(authData, rawReq.SubCommandParams...)
	}

	mac := hmac.New(sha256.New, pinToken)
	mac.Write(authData)
	correctPinAuth := mac.Sum(nil)[:16]

	// Step 5: Rebuild the request with correct pinAuth using same canonical encoder.
	req[credMgmtKeyPinUvAuthParam] = correctPinAuth
	finalData, err := em.Marshal(req)
	require.NoError(t, err)

	return finalData
}

func TestCredentialManagementNotEnabled(t *testing.T) {
	storage := NewMemoryStorage()
	config := &Config{
		Storage:                    storage,
		MaxResidentCredentials:     100,
		SupportedAlgorithms:        []int{COSEAlgES256},
		EnableCredentialManagement: false,
	}
	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	req := map[int]interface{}{
		credMgmtKeySubCommand: CredMgmtGetCredsMetadata,
	}
	data, err := cbor.Marshal(req)
	require.NoError(t, err)

	resp, err := auth.ProcessCBOR(CmdCredentialManagement, data)
	require.Error(t, err)
	require.Equal(t, ErrCredMgmtNotEnabled, err)
	require.Equal(t, byte(StatusInvalidCommand), resp[0])
}

func TestGetCredsMetadataEmptyStorage(t *testing.T) {
	auth := createCredMgmtTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	req := map[int]interface{}{
		credMgmtKeySubCommand: CredMgmtGetCredsMetadata,
	}
	data, err := cbor.Marshal(req)
	require.NoError(t, err)

	resp, err := auth.ProcessCBOR(CmdCredentialManagement, data)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])

	// Decode response.
	var respMap map[int]interface{}
	err = cbor.Unmarshal(resp[1:], &respMap)
	require.NoError(t, err)

	existing, err := credMgmtToInt(respMap[credMgmtResponseKeyExistingResidentCredsCount])
	require.NoError(t, err)
	require.Equal(t, 0, existing)

	remaining, err := credMgmtToInt(respMap[credMgmtResponseKeyMaxPossibleRemaining])
	require.NoError(t, err)
	require.Equal(t, 100, remaining) // MaxResidentCredentials
}

func TestGetCredsMetadataWithCredentials(t *testing.T) {
	auth := createCredMgmtTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	// Store some discoverable credentials.
	cred1 := createCredMgmtTestCredential(t, "example.com", "Example", "user1", "alice", "Alice", true)
	cred2 := createCredMgmtTestCredential(t, "example.com", "Example", "user2", "bob", "Bob", true)
	cred3 := createCredMgmtTestCredential(t, "other.com", "Other", "user3", "charlie", "Charlie", false) // Non-discoverable

	require.NoError(t, auth.storage.Store(cred1))
	require.NoError(t, auth.storage.Store(cred2))
	require.NoError(t, auth.storage.Store(cred3))

	req := map[int]interface{}{
		credMgmtKeySubCommand: CredMgmtGetCredsMetadata,
	}
	data, err := cbor.Marshal(req)
	require.NoError(t, err)

	resp, err := auth.ProcessCBOR(CmdCredentialManagement, data)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])

	var respMap map[int]interface{}
	err = cbor.Unmarshal(resp[1:], &respMap)
	require.NoError(t, err)

	existing, err := credMgmtToInt(respMap[credMgmtResponseKeyExistingResidentCredsCount])
	require.NoError(t, err)
	require.Equal(t, 2, existing) // Only discoverable credentials

	remaining, err := credMgmtToInt(respMap[credMgmtResponseKeyMaxPossibleRemaining])
	require.NoError(t, err)
	require.Equal(t, 98, remaining) // 100 - 2
}

func TestEnumerateRPsNoCredentials(t *testing.T) {
	auth := createCredMgmtTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	pinToken := setupPINTokenForCredMgmt(t, auth)
	data := buildCredMgmtRequest(t, pinToken, CredMgmtEnumerateRPsBegin, nil)

	resp, err := auth.ProcessCBOR(CmdCredentialManagement, data)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNoCredentials)
	require.Equal(t, byte(StatusNoCredentials), resp[0])
}

func TestEnumerateRPsListsAllUniqueRPs(t *testing.T) {
	auth := createCredMgmtTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	// Store credentials for multiple RPs.
	cred1 := createCredMgmtTestCredential(t, "example.com", "Example", "user1", "alice", "Alice", true)
	cred2 := createCredMgmtTestCredential(t, "example.com", "Example", "user2", "bob", "Bob", true)
	cred3 := createCredMgmtTestCredential(t, "other.com", "Other", "user3", "charlie", "Charlie", true)

	require.NoError(t, auth.storage.Store(cred1))
	require.NoError(t, auth.storage.Store(cred2))
	require.NoError(t, auth.storage.Store(cred3))

	pinToken := setupPINTokenForCredMgmt(t, auth)
	data := buildCredMgmtRequest(t, pinToken, CredMgmtEnumerateRPsBegin, nil)

	resp, err := auth.ProcessCBOR(CmdCredentialManagement, data)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])

	var respMap map[int]interface{}
	err = cbor.Unmarshal(resp[1:], &respMap)
	require.NoError(t, err)

	// Should have totalRPs = 2 (example.com and other.com).
	totalRPs, err := credMgmtToInt(respMap[credMgmtResponseKeyTotalRPs])
	require.NoError(t, err)
	require.Equal(t, 2, totalRPs)

	// RP info should be present.
	rpInfo := respMap[credMgmtResponseKeyRP]
	require.NotNil(t, rpInfo)

	rpIDHash := respMap[credMgmtResponseKeyRPIDHash]
	require.NotNil(t, rpIDHash)
}

func TestEnumerateRPsFullEnumeration(t *testing.T) {
	auth := createCredMgmtTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	// Store credentials for multiple RPs.
	cred1 := createCredMgmtTestCredential(t, "example.com", "Example", "user1", "alice", "Alice", true)
	cred2 := createCredMgmtTestCredential(t, "other.com", "Other", "user2", "bob", "Bob", true)
	cred3 := createCredMgmtTestCredential(t, "third.com", "Third", "user3", "charlie", "Charlie", true)

	require.NoError(t, auth.storage.Store(cred1))
	require.NoError(t, auth.storage.Store(cred2))
	require.NoError(t, auth.storage.Store(cred3))

	pinToken := setupPINTokenForCredMgmt(t, auth)

	// Begin enumeration.
	beginData := buildCredMgmtRequest(t, pinToken, CredMgmtEnumerateRPsBegin, nil)
	resp, err := auth.ProcessCBOR(CmdCredentialManagement, beginData)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])

	var firstRespMap map[int]interface{}
	err = cbor.Unmarshal(resp[1:], &firstRespMap)
	require.NoError(t, err)

	totalRPs, err := credMgmtToInt(firstRespMap[credMgmtResponseKeyTotalRPs])
	require.NoError(t, err)
	require.Equal(t, 3, totalRPs)

	// Get second RP.
	nextData := buildCredMgmtRequest(t, pinToken, CredMgmtEnumerateRPsGetNextRP, nil)
	resp, err = auth.ProcessCBOR(CmdCredentialManagement, nextData)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])

	var secondRespMap map[int]interface{}
	err = cbor.Unmarshal(resp[1:], &secondRespMap)
	require.NoError(t, err)

	// totalRPs should not be present in subsequent responses (or be 0).
	rpInfo := secondRespMap[credMgmtResponseKeyRP]
	require.NotNil(t, rpInfo)

	// Get third RP.
	resp, err = auth.ProcessCBOR(CmdCredentialManagement, nextData)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])

	// Try to get fourth RP (should fail - enumeration complete).
	resp, err = auth.ProcessCBOR(CmdCredentialManagement, nextData)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNoCredentials)
	require.Equal(t, byte(StatusNoCredentials), resp[0])

	// Subsequent calls should also fail with no enumeration in progress.
	resp, err = auth.ProcessCBOR(CmdCredentialManagement, nextData)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNoEnumerationInProgress)
	require.Equal(t, byte(StatusNoCredentials), resp[0])
}

func TestEnumerateCredentialsForSpecificRP(t *testing.T) {
	auth := createCredMgmtTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	// Store credentials for a specific RP.
	cred1 := createCredMgmtTestCredential(t, "example.com", "Example", "user1", "alice", "Alice", true)
	cred2 := createCredMgmtTestCredential(t, "example.com", "Example", "user2", "bob", "Bob", true)
	cred3 := createCredMgmtTestCredential(t, "other.com", "Other", "user3", "charlie", "Charlie", true)

	require.NoError(t, auth.storage.Store(cred1))
	require.NoError(t, auth.storage.Store(cred2))
	require.NoError(t, auth.storage.Store(cred3))

	pinToken := setupPINTokenForCredMgmt(t, auth)

	// Get RP ID hash for example.com.
	rpIDHash := sha256.Sum256([]byte("example.com"))
	params := map[int]interface{}{
		credMgmtParamRPIDHash: rpIDHash[:],
	}
	data := buildCredMgmtRequest(t, pinToken, CredMgmtEnumerateCredentialsBegin, params)

	resp, err := auth.ProcessCBOR(CmdCredentialManagement, data)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])

	var respMap map[int]interface{}
	err = cbor.Unmarshal(resp[1:], &respMap)
	require.NoError(t, err)

	// Should have totalCredentials = 2.
	totalCreds, err := credMgmtToInt(respMap[credMgmtResponseKeyTotalCredentials])
	require.NoError(t, err)
	require.Equal(t, 2, totalCreds)

	// User info should be present.
	userInfo := respMap[credMgmtResponseKeyUser]
	require.NotNil(t, userInfo)

	// Credential ID should be present.
	credID := respMap[credMgmtResponseKeyCredentialID]
	require.NotNil(t, credID)

	// Public key should be present.
	pubKey := respMap[credMgmtResponseKeyPublicKey]
	require.NotNil(t, pubKey)
}

func TestEnumerateCredentialsFullEnumeration(t *testing.T) {
	auth := createCredMgmtTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	// Store credentials for a specific RP.
	cred1 := createCredMgmtTestCredential(t, "example.com", "Example", "user1", "alice", "Alice", true)
	cred2 := createCredMgmtTestCredential(t, "example.com", "Example", "user2", "bob", "Bob", true)
	cred3 := createCredMgmtTestCredential(t, "example.com", "Example", "user3", "charlie", "Charlie", true)

	require.NoError(t, auth.storage.Store(cred1))
	require.NoError(t, auth.storage.Store(cred2))
	require.NoError(t, auth.storage.Store(cred3))

	pinToken := setupPINTokenForCredMgmt(t, auth)

	// Begin enumeration.
	rpIDHash := sha256.Sum256([]byte("example.com"))
	params := map[int]interface{}{
		credMgmtParamRPIDHash: rpIDHash[:],
	}
	beginData := buildCredMgmtRequest(t, pinToken, CredMgmtEnumerateCredentialsBegin, params)
	resp, err := auth.ProcessCBOR(CmdCredentialManagement, beginData)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])

	var firstRespMap map[int]interface{}
	err = cbor.Unmarshal(resp[1:], &firstRespMap)
	require.NoError(t, err)

	totalCreds, err := credMgmtToInt(firstRespMap[credMgmtResponseKeyTotalCredentials])
	require.NoError(t, err)
	require.Equal(t, 3, totalCreds)

	// Get second credential.
	nextData := buildCredMgmtRequest(t, pinToken, CredMgmtEnumerateCredentialsGetNextCred, nil)
	resp, err = auth.ProcessCBOR(CmdCredentialManagement, nextData)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])

	var secondRespMap map[int]interface{}
	err = cbor.Unmarshal(resp[1:], &secondRespMap)
	require.NoError(t, err)

	// Verify user info and credential ID are present.
	require.NotNil(t, secondRespMap[credMgmtResponseKeyUser])
	require.NotNil(t, secondRespMap[credMgmtResponseKeyCredentialID])

	// Get third credential.
	resp, err = auth.ProcessCBOR(CmdCredentialManagement, nextData)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])

	// Try to get fourth credential (should fail - enumeration complete).
	resp, err = auth.ProcessCBOR(CmdCredentialManagement, nextData)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNoCredentials)
	require.Equal(t, byte(StatusNoCredentials), resp[0])

	// Subsequent calls should also fail with no enumeration in progress.
	resp, err = auth.ProcessCBOR(CmdCredentialManagement, nextData)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNoEnumerationInProgress)
	require.Equal(t, byte(StatusNoCredentials), resp[0])
}

func TestEnumerateCredentialsNoMatchingRP(t *testing.T) {
	auth := createCredMgmtTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	// Store credentials for a different RP.
	cred := createCredMgmtTestCredential(t, "example.com", "Example", "user1", "alice", "Alice", true)
	require.NoError(t, auth.storage.Store(cred))

	pinToken := setupPINTokenForCredMgmt(t, auth)

	// Try to enumerate credentials for a non-existent RP.
	rpIDHash := sha256.Sum256([]byte("nonexistent.com"))
	params := map[int]interface{}{
		credMgmtParamRPIDHash: rpIDHash[:],
	}
	data := buildCredMgmtRequest(t, pinToken, CredMgmtEnumerateCredentialsBegin, params)

	resp, err := auth.ProcessCBOR(CmdCredentialManagement, data)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNoCredentials)
	require.Equal(t, byte(StatusNoCredentials), resp[0])
}

func TestCredMgmtDeleteCredential(t *testing.T) {
	auth := createCredMgmtTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	cred := createCredMgmtTestCredential(t, "example.com", "Example", "user1", "alice", "Alice", true)
	require.NoError(t, auth.storage.Store(cred))

	pinToken := setupPINTokenForCredMgmt(t, auth)

	params := map[int]interface{}{
		credMgmtParamCredentialID: map[string]interface{}{
			"type": "public-key",
			"id":   cred.CredentialID,
		},
	}
	data := buildCredMgmtRequest(t, pinToken, CredMgmtDeleteCredential, params)

	resp, err := auth.ProcessCBOR(CmdCredentialManagement, data)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])

	// Verify credential is deleted.
	_, err = auth.storage.Load(cred.CredentialID)
	require.ErrorIs(t, err, ErrCredentialNotFound)
}

func TestCredMgmtDeleteCredentialNotFound(t *testing.T) {
	auth := createCredMgmtTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	pinToken := setupPINTokenForCredMgmt(t, auth)

	// Try to delete non-existent credential.
	params := map[int]interface{}{
		credMgmtParamCredentialID: map[string]interface{}{
			"type": "public-key",
			"id":   []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		},
	}
	data := buildCredMgmtRequest(t, pinToken, CredMgmtDeleteCredential, params)

	resp, err := auth.ProcessCBOR(CmdCredentialManagement, data)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrCredentialNotFound)
	require.Equal(t, byte(StatusNoCredentials), resp[0])
}

func TestCredMgmtUpdateUserInformation(t *testing.T) {
	auth := createCredMgmtTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	cred := createCredMgmtTestCredential(t, "example.com", "Example", "user1", "alice", "Alice Smith", true)
	require.NoError(t, auth.storage.Store(cred))

	pinToken := setupPINTokenForCredMgmt(t, auth)

	params := map[int]interface{}{
		credMgmtParamCredentialID: map[string]interface{}{
			"type": "public-key",
			"id":   cred.CredentialID,
		},
		credMgmtParamUser: map[string]interface{}{
			"name":        "alice_updated",
			"displayName": "Alice Johnson",
		},
	}
	data := buildCredMgmtRequest(t, pinToken, CredMgmtUpdateUserInformation, params)

	resp, err := auth.ProcessCBOR(CmdCredentialManagement, data)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])

	// Verify credential is updated.
	updatedCred, err := auth.storage.Load(cred.CredentialID)
	require.NoError(t, err)
	require.Equal(t, "alice_updated", updatedCred.UserName)
	require.Equal(t, "Alice Johnson", updatedCred.UserDisplayName)
}

func TestCredMgmtUpdateUserInformationPartial(t *testing.T) {
	auth := createCredMgmtTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	cred := createCredMgmtTestCredential(t, "example.com", "Example", "user1", "alice", "Alice Smith", true)
	require.NoError(t, auth.storage.Store(cred))

	pinToken := setupPINTokenForCredMgmt(t, auth)

	// Only update displayName.
	params := map[int]interface{}{
		credMgmtParamCredentialID: map[string]interface{}{
			"type": "public-key",
			"id":   cred.CredentialID,
		},
		credMgmtParamUser: map[string]interface{}{
			"displayName": "Alice Johnson",
		},
	}
	data := buildCredMgmtRequest(t, pinToken, CredMgmtUpdateUserInformation, params)

	resp, err := auth.ProcessCBOR(CmdCredentialManagement, data)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])

	// Verify only displayName changed.
	updatedCred, err := auth.storage.Load(cred.CredentialID)
	require.NoError(t, err)
	require.Equal(t, "alice", updatedCred.UserName)                // Unchanged
	require.Equal(t, "Alice Johnson", updatedCred.UserDisplayName) // Updated
}

func TestCredMgmtUpdateUserInformationCredentialNotFound(t *testing.T) {
	auth := createCredMgmtTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	pinToken := setupPINTokenForCredMgmt(t, auth)

	// Try to update non-existent credential.
	params := map[int]interface{}{
		credMgmtParamCredentialID: map[string]interface{}{
			"type": "public-key",
			"id":   []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		},
		credMgmtParamUser: map[string]interface{}{
			"name": "updated_name",
		},
	}
	data := buildCredMgmtRequest(t, pinToken, CredMgmtUpdateUserInformation, params)

	resp, err := auth.ProcessCBOR(CmdCredentialManagement, data)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrCredentialNotFound)
	require.Equal(t, byte(StatusNoCredentials), resp[0])
}

func TestCredMgmtAuthenticationRequired(t *testing.T) {
	auth := createCredMgmtTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	// Try to enumerate RPs without authentication.
	req := map[int]interface{}{
		credMgmtKeySubCommand: CredMgmtEnumerateRPsBegin,
	}
	data, err := cbor.Marshal(req)
	require.NoError(t, err)

	resp, err := auth.ProcessCBOR(CmdCredentialManagement, data)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrPINNotSet)
	require.Equal(t, byte(StatusPINNotSet), resp[0])
}

func TestCredMgmtAuthenticationWithWrongPinAuth(t *testing.T) {
	auth := createCredMgmtTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	_ = setupPINTokenForCredMgmt(t, auth)

	// Use wrong pinUvAuthParam.
	wrongPinAuth := make([]byte, 16)

	req := map[int]interface{}{
		credMgmtKeySubCommand:        CredMgmtEnumerateRPsBegin,
		credMgmtKeyPinUvAuthProtocol: PINProtocol1,
		credMgmtKeyPinUvAuthParam:    wrongPinAuth,
	}
	data, err := cbor.Marshal(req)
	require.NoError(t, err)

	resp, err := auth.ProcessCBOR(CmdCredentialManagement, data)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrPINAuthInvalid)
	require.Equal(t, byte(StatusPINAuthInvalid), resp[0])
}

func TestCredMgmtAuthenticationWithMissingPermission(t *testing.T) {
	auth := createCredMgmtTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	// Set up PIN token without credentialMgmt permission.
	auth.state.PINSet = true
	auth.state.PINHash = make([]byte, 32)
	auth.pinState.protocol = &pinProtocolState{
		pinUvAuthToken:   make([]byte, 32),
		tokenPermissions: PINPermissionMakeCredential, // Wrong permission
	}

	pinToken := auth.pinState.protocol.pinUvAuthToken
	data := buildCredMgmtRequest(t, pinToken, CredMgmtEnumerateRPsBegin, nil)

	resp, err := auth.ProcessCBOR(CmdCredentialManagement, data)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrOperationDenied)
	require.Equal(t, byte(StatusOperationDenied), resp[0])
}

func TestCredMgmtInvalidSubcommand(t *testing.T) {
	auth := createCredMgmtTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	pinToken := setupPINTokenForCredMgmt(t, auth)
	data := buildCredMgmtRequest(t, pinToken, 0xFF, nil) // Invalid subcommand

	resp, err := auth.ProcessCBOR(CmdCredentialManagement, data)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidSubcommand)
	require.Equal(t, byte(StatusInvalidSubcommand), resp[0])
}

func TestCredMgmtMissingSubcommand(t *testing.T) {
	auth := createCredMgmtTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	// Request without subCommand field.
	req := map[int]interface{}{
		credMgmtKeyPinUvAuthProtocol: PINProtocol1,
	}
	data, err := cbor.Marshal(req)
	require.NoError(t, err)

	resp, err := auth.ProcessCBOR(CmdCredentialManagement, data)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidParameter)
	require.Equal(t, byte(StatusInvalidParameter), resp[0])
}

func TestCredMgmtEnumerateRPsGetNextRPWithoutBegin(t *testing.T) {
	auth := createCredMgmtTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	pinToken := setupPINTokenForCredMgmt(t, auth)
	data := buildCredMgmtRequest(t, pinToken, CredMgmtEnumerateRPsGetNextRP, nil)

	resp, err := auth.ProcessCBOR(CmdCredentialManagement, data)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNoEnumerationInProgress)
	require.Equal(t, byte(StatusNoCredentials), resp[0])
}

func TestCredMgmtEnumerateCredentialsGetNextWithoutBegin(t *testing.T) {
	auth := createCredMgmtTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	pinToken := setupPINTokenForCredMgmt(t, auth)
	data := buildCredMgmtRequest(t, pinToken, CredMgmtEnumerateCredentialsGetNextCred, nil)

	resp, err := auth.ProcessCBOR(CmdCredentialManagement, data)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNoEnumerationInProgress)
	require.Equal(t, byte(StatusNoCredentials), resp[0])
}

func TestCredMgmtEnumerateCredentialsMissingRPIDHash(t *testing.T) {
	auth := createCredMgmtTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	pinToken := setupPINTokenForCredMgmt(t, auth)

	// Missing rpIDHash in params.
	params := map[int]interface{}{}
	data := buildCredMgmtRequest(t, pinToken, CredMgmtEnumerateCredentialsBegin, params)

	resp, err := auth.ProcessCBOR(CmdCredentialManagement, data)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrMissingRPIDHash)
	_ = resp // Response checked above
}

func TestCredMgmtDeleteCredentialClearsEnumerationState(t *testing.T) {
	auth := createCredMgmtTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	// Store credentials.
	cred1 := createCredMgmtTestCredential(t, "example.com", "Example", "user1", "alice", "Alice", true)
	cred2 := createCredMgmtTestCredential(t, "example.com", "Example", "user2", "bob", "Bob", true)
	require.NoError(t, auth.storage.Store(cred1))
	require.NoError(t, auth.storage.Store(cred2))

	pinToken := setupPINTokenForCredMgmt(t, auth)

	// Begin credential enumeration.
	rpIDHash := sha256.Sum256([]byte("example.com"))
	beginParams := map[int]interface{}{
		credMgmtParamRPIDHash: rpIDHash[:],
	}
	beginData := buildCredMgmtRequest(t, pinToken, CredMgmtEnumerateCredentialsBegin, beginParams)

	_, err := auth.ProcessCBOR(CmdCredentialManagement, beginData)
	require.NoError(t, err)

	// Enumeration state should be set.
	require.NotNil(t, auth.credMgmtState)
	require.NotEmpty(t, auth.credMgmtState.credList)

	// Delete a credential.
	deleteParams := map[int]interface{}{
		credMgmtParamCredentialID: map[string]interface{}{
			"type": "public-key",
			"id":   cred1.CredentialID,
		},
	}
	deleteData := buildCredMgmtRequest(t, pinToken, CredMgmtDeleteCredential, deleteParams)

	_, err = auth.ProcessCBOR(CmdCredentialManagement, deleteData)
	require.NoError(t, err)

	// Enumeration state should be cleared.
	require.Nil(t, auth.credMgmtState)

	// GetNextCredential should fail now.
	nextData := buildCredMgmtRequest(t, pinToken, CredMgmtEnumerateCredentialsGetNextCred, nil)

	resp, err := auth.ProcessCBOR(CmdCredentialManagement, nextData)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNoEnumerationInProgress)
	require.Equal(t, byte(StatusNoCredentials), resp[0])
}

func TestCredMgmtDecodeRequestEmptyData(t *testing.T) {
	_, err := decodeCredentialManagementRequest(nil)
	require.ErrorIs(t, err, ErrInvalidParameter)

	_, err = decodeCredentialManagementRequest([]byte{})
	require.ErrorIs(t, err, ErrInvalidParameter)
}

func TestCredMgmtDecodeRequestInvalidCBOR(t *testing.T) {
	_, err := decodeCredentialManagementRequest([]byte{0xFF, 0xFF, 0xFF})
	require.ErrorIs(t, err, ErrCBORDecodingFailed)
}

func TestCredMgmtExtractRPIDHashInvalidLength(t *testing.T) {
	params := map[int]interface{}{
		credMgmtParamRPIDHash: []byte{1, 2, 3}, // Too short, should be 32 bytes
	}
	_, err := extractRPIDHash(params)
	require.ErrorIs(t, err, ErrInvalidParameter)
}

func TestCredMgmtExtractCredentialIDNilParams(t *testing.T) {
	_, err := extractCredentialID(nil)
	require.ErrorIs(t, err, ErrMissingCredentialID)
}

func TestCredMgmtExtractUserInfoNilParams(t *testing.T) {
	_, err := extractUserInfo(nil)
	require.ErrorIs(t, err, ErrMissingUserInfo)
}

func TestCredMgmtToUint8InvalidType(t *testing.T) {
	_, err := credMgmtToUint8("not a number")
	require.ErrorIs(t, err, ErrInvalidParameter)
}

func TestCredMgmtToIntInvalidType(t *testing.T) {
	_, err := credMgmtToInt("not a number")
	require.ErrorIs(t, err, ErrInvalidParameter)
}

func TestCredMgmtSubcommandConstants(t *testing.T) {
	// Verify subcommand constants match CTAP2.1 spec.
	require.Equal(t, uint8(0x01), uint8(CredMgmtGetCredsMetadata))
	require.Equal(t, uint8(0x02), uint8(CredMgmtEnumerateRPsBegin))
	require.Equal(t, uint8(0x03), uint8(CredMgmtEnumerateRPsGetNextRP))
	require.Equal(t, uint8(0x04), uint8(CredMgmtEnumerateCredentialsBegin))
	require.Equal(t, uint8(0x05), uint8(CredMgmtEnumerateCredentialsGetNextCred))
	require.Equal(t, uint8(0x06), uint8(CredMgmtDeleteCredential))
	require.Equal(t, uint8(0x07), uint8(CredMgmtUpdateUserInformation))
}

func TestCredMgmtExtractRPIDHashNilParams(t *testing.T) {
	_, err := extractRPIDHash(nil)
	require.ErrorIs(t, err, ErrMissingRPIDHash)
}

func TestCredMgmtExtractUserInfoInvalidType(t *testing.T) {
	params := map[int]interface{}{
		credMgmtParamUser: "not a map",
	}
	_, err := extractUserInfo(params)
	require.ErrorIs(t, err, ErrInvalidParameter)
}

func TestCredMgmtExtractCredentialIDInvalidType(t *testing.T) {
	params := map[int]interface{}{
		credMgmtParamCredentialID: "not a map or bytes",
	}
	_, err := extractCredentialID(params)
	require.ErrorIs(t, err, ErrInvalidParameter)
}

func TestCredMgmtExtractCredentialIDRawBytes(t *testing.T) {
	// Test with raw bytes (not a map).
	credID := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	params := map[int]interface{}{
		credMgmtParamCredentialID: credID,
	}
	result, err := extractCredentialID(params)
	require.NoError(t, err)
	require.Equal(t, credID, result)
}

func TestCredMgmtExtractCredentialIDInterfaceKeyedMap(t *testing.T) {
	// Test with map[interface{}]interface{} (CBOR decodes integer keys this way).
	credID := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	params := map[int]interface{}{
		credMgmtParamCredentialID: map[interface{}]interface{}{
			"type": "public-key",
			"id":   credID,
		},
	}
	result, err := extractCredentialID(params)
	require.NoError(t, err)
	require.Equal(t, credID, result)
}

func TestCredMgmtExtractCredentialIDMissingIDField(t *testing.T) {
	// Test with map missing "id" field.
	params := map[int]interface{}{
		credMgmtParamCredentialID: map[string]interface{}{
			"type": "public-key",
			// Missing "id" field
		},
	}
	_, err := extractCredentialID(params)
	require.ErrorIs(t, err, ErrInvalidParameter)
}

func TestCredMgmtExtractCredentialIDInvalidIDType(t *testing.T) {
	// Test with "id" field that is not []byte.
	params := map[int]interface{}{
		credMgmtParamCredentialID: map[string]interface{}{
			"type": "public-key",
			"id":   "not-bytes", // Should be []byte
		},
	}
	_, err := extractCredentialID(params)
	require.ErrorIs(t, err, ErrInvalidParameter)
}

func TestCredMgmtExtractUserInfoInterfaceKeyedMap(t *testing.T) {
	// Test with map[interface{}]interface{} (CBOR decodes integer keys this way).
	params := map[int]interface{}{
		credMgmtParamUser: map[interface{}]interface{}{
			"name":        "alice",
			"displayName": "Alice Smith",
		},
	}
	result, err := extractUserInfo(params)
	require.NoError(t, err)
	require.Equal(t, "alice", result["name"])
	require.Equal(t, "Alice Smith", result["displayName"])
}

func TestCredMgmtToUint8AllTypes(t *testing.T) {
	tests := []struct {
		name  string
		input interface{}
		want  uint8
	}{
		{"int", int(42), 42},
		{"int8", int8(42), 42},
		{"int16", int16(42), 42},
		{"int32", int32(42), 42},
		{"int64", int64(42), 42},
		{"uint", uint(42), 42},
		{"uint8", uint8(42), 42},
		{"uint16", uint16(42), 42},
		{"uint32", uint32(42), 42},
		{"uint64", uint64(42), 42},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := credMgmtToUint8(tt.input)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestCredMgmtToIntAllTypes(t *testing.T) {
	tests := []struct {
		name  string
		input interface{}
		want  int
	}{
		{"int", int(42), 42},
		{"int8", int8(42), 42},
		{"int16", int16(42), 42},
		{"int32", int32(42), 42},
		{"int64", int64(42), 42},
		{"uint", uint(42), 42},
		{"uint8", uint8(42), 42},
		{"uint16", uint16(42), 42},
		{"uint32", uint32(42), 42},
		{"uint64", uint64(42), 42},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := credMgmtToInt(tt.input)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestCredMgmtDeleteCredentialMissingCredentialID(t *testing.T) {
	auth := createCredMgmtTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	pinToken := setupPINTokenForCredMgmt(t, auth)

	// Request without credential ID.
	params := map[int]interface{}{}
	data := buildCredMgmtRequest(t, pinToken, CredMgmtDeleteCredential, params)

	resp, err := auth.ProcessCBOR(CmdCredentialManagement, data)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrMissingCredentialID)
	require.Equal(t, byte(StatusMissingParameter), resp[0])
}

func TestCredMgmtUpdateUserInformationMissingCredentialID(t *testing.T) {
	auth := createCredMgmtTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	pinToken := setupPINTokenForCredMgmt(t, auth)

	// Request without credential ID.
	params := map[int]interface{}{
		credMgmtParamUser: map[string]interface{}{
			"name": "updated_name",
		},
	}
	data := buildCredMgmtRequest(t, pinToken, CredMgmtUpdateUserInformation, params)

	resp, err := auth.ProcessCBOR(CmdCredentialManagement, data)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrMissingCredentialID)
	require.Equal(t, byte(StatusMissingParameter), resp[0])
}

func TestCredMgmtUpdateUserInformationMissingUserInfo(t *testing.T) {
	auth := createCredMgmtTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	cred := createCredMgmtTestCredential(t, "example.com", "Example", "user1", "alice", "Alice", true)
	require.NoError(t, auth.storage.Store(cred))

	pinToken := setupPINTokenForCredMgmt(t, auth)

	// Request without user info.
	params := map[int]interface{}{
		credMgmtParamCredentialID: map[string]interface{}{
			"type": "public-key",
			"id":   cred.CredentialID,
		},
	}
	data := buildCredMgmtRequest(t, pinToken, CredMgmtUpdateUserInformation, params)

	resp, err := auth.ProcessCBOR(CmdCredentialManagement, data)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrMissingUserInfo)
	require.Equal(t, byte(StatusMissingParameter), resp[0])
}

func TestCredMgmtEnumerateRPsSingleRP(t *testing.T) {
	auth := createCredMgmtTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	// Store credential for only one RP.
	cred := createCredMgmtTestCredential(t, "example.com", "Example", "user1", "alice", "Alice", true)
	require.NoError(t, auth.storage.Store(cred))

	pinToken := setupPINTokenForCredMgmt(t, auth)

	// Begin enumeration.
	beginData := buildCredMgmtRequest(t, pinToken, CredMgmtEnumerateRPsBegin, nil)
	resp, err := auth.ProcessCBOR(CmdCredentialManagement, beginData)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])

	var firstRespMap map[int]interface{}
	err = cbor.Unmarshal(resp[1:], &firstRespMap)
	require.NoError(t, err)

	totalRPs, err := credMgmtToInt(firstRespMap[credMgmtResponseKeyTotalRPs])
	require.NoError(t, err)
	require.Equal(t, 1, totalRPs)

	// Try to get next RP (should fail - only one RP).
	nextData := buildCredMgmtRequest(t, pinToken, CredMgmtEnumerateRPsGetNextRP, nil)
	resp, err = auth.ProcessCBOR(CmdCredentialManagement, nextData)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNoCredentials)
	require.Equal(t, byte(StatusNoCredentials), resp[0])
}

func TestCredMgmtEnumerateCredentialsSingleCredential(t *testing.T) {
	auth := createCredMgmtTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	// Store only one credential.
	cred := createCredMgmtTestCredential(t, "example.com", "Example", "user1", "alice", "Alice", true)
	require.NoError(t, auth.storage.Store(cred))

	pinToken := setupPINTokenForCredMgmt(t, auth)

	// Begin enumeration.
	rpIDHash := sha256.Sum256([]byte("example.com"))
	params := map[int]interface{}{
		credMgmtParamRPIDHash: rpIDHash[:],
	}
	beginData := buildCredMgmtRequest(t, pinToken, CredMgmtEnumerateCredentialsBegin, params)
	resp, err := auth.ProcessCBOR(CmdCredentialManagement, beginData)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])

	var firstRespMap map[int]interface{}
	err = cbor.Unmarshal(resp[1:], &firstRespMap)
	require.NoError(t, err)

	totalCreds, err := credMgmtToInt(firstRespMap[credMgmtResponseKeyTotalCredentials])
	require.NoError(t, err)
	require.Equal(t, 1, totalCreds)

	// Try to get next credential (should fail - only one credential).
	nextData := buildCredMgmtRequest(t, pinToken, CredMgmtEnumerateCredentialsGetNextCred, nil)
	resp, err = auth.ProcessCBOR(CmdCredentialManagement, nextData)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNoCredentials)
	require.Equal(t, byte(StatusNoCredentials), resp[0])
}
