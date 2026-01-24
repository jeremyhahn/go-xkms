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
	"crypto/hmac"
	"crypto/sha256"
	"errors"

	"github.com/fxamacker/cbor/v2"
)

// CTAP2.1 CredentialManagement subcommand codes.
const (
	CredMgmtGetCredsMetadata                = 0x01
	CredMgmtEnumerateRPsBegin               = 0x02
	CredMgmtEnumerateRPsGetNextRP           = 0x03
	CredMgmtEnumerateCredentialsBegin       = 0x04
	CredMgmtEnumerateCredentialsGetNextCred = 0x05
	CredMgmtDeleteCredential                = 0x06
	CredMgmtUpdateUserInformation           = 0x07
)

// CTAP2.1 CredentialManagement request parameter keys (CBOR map indices).
const (
	credMgmtKeySubCommand        = 0x01
	credMgmtKeySubCommandParams  = 0x02
	credMgmtKeyPinUvAuthProtocol = 0x03
	credMgmtKeyPinUvAuthParam    = 0x04
)

// CTAP2.1 CredentialManagement subcommand parameter keys.
const (
	credMgmtParamRPIDHash     = 0x01
	credMgmtParamCredentialID = 0x02
	credMgmtParamUser         = 0x03
)

// CTAP2.1 CredentialManagement response parameter keys (CBOR map indices).
const (
	credMgmtResponseKeyExistingResidentCredsCount = 0x01
	credMgmtResponseKeyMaxPossibleRemaining       = 0x02
	credMgmtResponseKeyRP                         = 0x03
	credMgmtResponseKeyRPIDHash                   = 0x04
	credMgmtResponseKeyTotalRPs                   = 0x05
	credMgmtResponseKeyUser                       = 0x06
	credMgmtResponseKeyCredentialID               = 0x07
	credMgmtResponseKeyPublicKey                  = 0x08
	credMgmtResponseKeyTotalCredentials           = 0x09
	credMgmtResponseKeyCredProtect                = 0x0A
	credMgmtResponseKeyLargeBlobKey               = 0x0B
)

// CredentialManagementRequest represents a CTAP2.1 authenticatorCredentialManagement request.
type CredentialManagementRequest struct {
	// SubCommand specifies the credential management operation to perform.
	SubCommand uint8

	// SubCommandParams contains parameters specific to the subcommand.
	SubCommandParams map[int]interface{}

	// SubCommandParamsRaw contains the original CBOR-encoded parameters for auth verification.
	SubCommandParamsRaw []byte

	// PinUvAuthProtocol specifies the PIN/UV protocol version (1 or 2).
	PinUvAuthProtocol int

	// PinUvAuthParam is the authentication parameter for credential management operations.
	PinUvAuthParam []byte
}

// CredentialManagement errors.
var (
	// ErrCredMgmtNotEnabled indicates credential management is not enabled.
	ErrCredMgmtNotEnabled = errors.New("authenticator: credential management not enabled")

	// ErrNoEnumerationInProgress indicates no RP/credential enumeration is active.
	ErrNoEnumerationInProgress = errors.New("authenticator: no enumeration in progress")

	// ErrEnumerationComplete indicates the enumeration has no more items.
	ErrEnumerationComplete = errors.New("authenticator: enumeration complete")

	// ErrMissingCredentialID indicates the credential ID parameter is missing.
	ErrMissingCredentialID = errors.New("authenticator: missing credential ID")

	// ErrMissingRPIDHash indicates the RP ID hash parameter is missing.
	ErrMissingRPIDHash = errors.New("authenticator: missing RP ID hash")

	// ErrMissingUserInfo indicates the user information parameter is missing.
	ErrMissingUserInfo = errors.New("authenticator: missing user information")
)

// credMgmtEnumerationState tracks the state of RP and credential enumeration.
type credMgmtEnumerationState struct {
	// rpList holds the list of unique RP entries during RP enumeration.
	rpList []rpEntry

	// currentRPIndex is the current position in RP enumeration.
	currentRPIndex int

	// credList holds credentials for the current RP during credential enumeration.
	credList []*StoredCredential

	// currentCredIndex is the current position in credential enumeration.
	currentCredIndex int

	// enumerationRPIDHash is the RP ID hash for current credential enumeration.
	enumerationRPIDHash []byte
}

// rpEntry represents a relying party entry for enumeration.
type rpEntry struct {
	rpID     string
	rpName   string
	rpIDHash []byte
}

// handleCredentialManagement implements the CTAP2.1 authenticatorCredentialManagement command (0x0A).
// It dispatches to the appropriate subcommand handler based on the request.
func (a *Authenticator) handleCredentialManagement(data []byte) ([]byte, error) {
	if !a.config.EnableCredentialManagement {
		return nil, ErrCredMgmtNotEnabled
	}

	req, err := decodeCredentialManagementRequest(data)
	if err != nil {
		return nil, err
	}

	// GetCredsMetadata does not require authentication.
	// All other subcommands require PIN/UV authentication with credentialMgmt permission.
	if req.SubCommand != CredMgmtGetCredsMetadata {
		if err := a.verifyCredMgmtAuth(req); err != nil {
			return nil, err
		}
	}

	switch req.SubCommand {
	case CredMgmtGetCredsMetadata:
		return a.handleGetCredsMetadata()

	case CredMgmtEnumerateRPsBegin:
		return a.handleEnumerateRPsBegin()

	case CredMgmtEnumerateRPsGetNextRP:
		return a.handleEnumerateRPsGetNextRP()

	case CredMgmtEnumerateCredentialsBegin:
		return a.handleEnumerateCredentialsBegin(req)

	case CredMgmtEnumerateCredentialsGetNextCred:
		return a.handleEnumerateCredentialsGetNextCredential()

	case CredMgmtDeleteCredential:
		return a.handleDeleteCredential(req)

	case CredMgmtUpdateUserInformation:
		return a.handleUpdateUserInformation(req)

	default:
		return nil, ErrInvalidSubcommand
	}
}

// handleGetCredsMetadata returns metadata about stored credentials.
func (a *Authenticator) handleGetCredsMetadata() ([]byte, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	existingCount, err := a.storage.CountDiscoverable()
	if err != nil {
		return nil, ErrStorageError
	}

	remaining := a.config.MaxResidentCredentials - existingCount
	if remaining < 0 {
		remaining = 0
	}

	response := map[int]interface{}{
		credMgmtResponseKeyExistingResidentCredsCount: existingCount,
		credMgmtResponseKeyMaxPossibleRemaining:       remaining,
	}

	respData, err := encodeCBOR(response)
	if err != nil {
		return nil, err
	}

	return a.successResponse(respData), nil
}

// handleEnumerateRPsBegin starts RP enumeration and returns the first RP.
func (a *Authenticator) handleEnumerateRPsBegin() ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Build list of unique RPs with discoverable credentials.
	rpMap := make(map[string]*rpEntry)

	// Iterate over all credentials to find unique RPs.
	// We need to scan all credentials since storage doesn't provide RP enumeration.
	allCreds, err := a.getAllDiscoverableCredentials()
	if err != nil {
		return nil, err
	}

	for _, cred := range allCreds {
		if _, exists := rpMap[cred.RPID]; !exists {
			hash := sha256.Sum256([]byte(cred.RPID))
			rpMap[cred.RPID] = &rpEntry{
				rpID:     cred.RPID,
				rpName:   cred.RPName,
				rpIDHash: hash[:],
			}
		}
	}

	if len(rpMap) == 0 {
		return nil, ErrNoCredentials
	}

	// Convert map to slice for enumeration.
	rpList := make([]rpEntry, 0, len(rpMap))
	for _, entry := range rpMap {
		rpList = append(rpList, *entry)
	}

	// Initialize enumeration state.
	a.initCredMgmtState()
	a.credMgmtState.rpList = rpList
	a.credMgmtState.currentRPIndex = 0

	// Return first RP.
	return a.buildRPResponse(rpList[0], len(rpList))
}

// handleEnumerateRPsGetNextRP returns the next RP in the enumeration.
func (a *Authenticator) handleEnumerateRPsGetNextRP() ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.credMgmtState == nil || len(a.credMgmtState.rpList) == 0 {
		return nil, ErrNoEnumerationInProgress
	}

	// Move to next RP.
	a.credMgmtState.currentRPIndex++

	if a.credMgmtState.currentRPIndex >= len(a.credMgmtState.rpList) {
		// Enumeration complete, clear state.
		a.credMgmtState.rpList = nil
		a.credMgmtState.currentRPIndex = 0
		return nil, ErrNoCredentials
	}

	rp := a.credMgmtState.rpList[a.credMgmtState.currentRPIndex]
	return a.buildRPResponse(rp, 0) // totalRPs only in first response
}

// handleEnumerateCredentialsBegin starts credential enumeration for a specific RP.
func (a *Authenticator) handleEnumerateCredentialsBegin(req *CredentialManagementRequest) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Extract RP ID hash from params.
	rpIDHash, err := extractRPIDHash(req.SubCommandParams)
	if err != nil {
		return nil, err
	}

	// Find credentials matching this RP ID hash.
	allCreds, err := a.getAllDiscoverableCredentials()
	if err != nil {
		return nil, err
	}

	var matchingCreds []*StoredCredential
	for _, cred := range allCreds {
		hash := sha256.Sum256([]byte(cred.RPID))
		if bytes.Equal(hash[:], rpIDHash) {
			matchingCreds = append(matchingCreds, cred)
		}
	}

	if len(matchingCreds) == 0 {
		return nil, ErrNoCredentials
	}

	// Initialize enumeration state.
	a.initCredMgmtState()
	a.credMgmtState.credList = matchingCreds
	a.credMgmtState.currentCredIndex = 0
	a.credMgmtState.enumerationRPIDHash = rpIDHash

	// Return first credential.
	return a.buildCredentialResponse(matchingCreds[0], len(matchingCreds))
}

// handleEnumerateCredentialsGetNextCredential returns the next credential in the enumeration.
func (a *Authenticator) handleEnumerateCredentialsGetNextCredential() ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.credMgmtState == nil || len(a.credMgmtState.credList) == 0 {
		return nil, ErrNoEnumerationInProgress
	}

	// Move to next credential.
	a.credMgmtState.currentCredIndex++

	if a.credMgmtState.currentCredIndex >= len(a.credMgmtState.credList) {
		// Enumeration complete, clear state.
		a.credMgmtState.credList = nil
		a.credMgmtState.currentCredIndex = 0
		a.credMgmtState.enumerationRPIDHash = nil
		return nil, ErrNoCredentials
	}

	cred := a.credMgmtState.credList[a.credMgmtState.currentCredIndex]
	return a.buildCredentialResponse(cred, 0) // totalCredentials only in first response
}

// handleDeleteCredential deletes a credential by its ID.
func (a *Authenticator) handleDeleteCredential(req *CredentialManagementRequest) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Extract credential ID from params.
	credentialID, err := extractCredentialID(req.SubCommandParams)
	if err != nil {
		return nil, err
	}

	// Delete the credential.
	if err := a.storage.Delete(credentialID); err != nil {
		if errors.Is(err, ErrCredentialNotFound) {
			return nil, ErrCredentialNotFound
		}
		return nil, ErrStorageError
	}

	// Clear any enumeration state since storage changed.
	a.credMgmtState = nil

	return a.successResponse(nil), nil
}

// handleUpdateUserInformation updates user display name for a credential.
func (a *Authenticator) handleUpdateUserInformation(req *CredentialManagementRequest) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Extract credential ID from params.
	credentialID, err := extractCredentialID(req.SubCommandParams)
	if err != nil {
		return nil, err
	}

	// Extract user info from params.
	userInfo, err := extractUserInfo(req.SubCommandParams)
	if err != nil {
		return nil, err
	}

	// Load the existing credential.
	cred, err := a.storage.Load(credentialID)
	if err != nil {
		if errors.Is(err, ErrCredentialNotFound) {
			return nil, ErrCredentialNotFound
		}
		return nil, ErrStorageError
	}

	// Update user information.
	if name, ok := userInfo["name"].(string); ok {
		cred.UserName = name
	}
	if displayName, ok := userInfo["displayName"].(string); ok {
		cred.UserDisplayName = displayName
	}

	// Save the updated credential.
	if err := a.storage.Store(cred); err != nil {
		return nil, ErrStorageError
	}

	return a.successResponse(nil), nil
}

// verifyCredMgmtAuth verifies the PIN/UV authentication for credential management.
func (a *Authenticator) verifyCredMgmtAuth(req *CredentialManagementRequest) error {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// Check if PIN is set.
	if !a.state.PINSet {
		return ErrPINNotSet
	}

	// Verify PIN protocol version.
	if req.PinUvAuthProtocol != PINProtocol1 {
		return ErrUnsupportedPINProtocol
	}

	// Verify pinUvAuthParam is provided.
	if len(req.PinUvAuthParam) == 0 {
		return ErrPINAuthInvalid
	}

	// Verify the PIN token exists and has the correct permission.
	if a.pinState.protocol == nil || a.pinState.protocol.pinUvAuthToken == nil {
		return ErrPINAuthInvalid
	}

	// Check if the token has credentialMgmt permission.
	if a.pinState.protocol.tokenPermissions&PINPermissionCredentialMgmt == 0 {
		return ErrOperationDenied
	}

	// Build the data to verify: subCommand (1 byte) + subCommandParams (original CBOR if present).
	authData := []byte{req.SubCommand}
	if len(req.SubCommandParamsRaw) > 0 {
		authData = append(authData, req.SubCommandParamsRaw...)
	}

	// Compute HMAC-SHA-256 over the auth data.
	mac := hmac.New(sha256.New, a.pinState.protocol.pinUvAuthToken)
	mac.Write(authData)
	expected := mac.Sum(nil)[:16]

	if !hmac.Equal(expected, req.PinUvAuthParam) {
		return ErrPINAuthInvalid
	}

	return nil
}

// getAllDiscoverableCredentials retrieves all discoverable credentials from storage.
func (a *Authenticator) getAllDiscoverableCredentials() ([]*StoredCredential, error) {
	// This is an implementation detail: we need to enumerate all credentials.
	// Since storage only provides LoadByRPID, we need to scan known RPs.
	// For MemoryStorage, we can access credentials directly via the interface.

	// First, get total count to check if there are any credentials.
	count, err := a.storage.CountDiscoverable()
	if err != nil {
		return nil, ErrStorageError
	}

	if count == 0 {
		return nil, nil
	}

	// Use the internal credential enumeration method if available.
	if enumStorage, ok := a.storage.(CredentialEnumerator); ok {
		return enumStorage.EnumerateDiscoverable()
	}

	// Fallback: return empty list if enumeration not supported.
	// Production implementations should use a storage that supports enumeration.
	return nil, nil
}

// CredentialEnumerator is an optional interface for storage backends that support
// credential enumeration for credential management operations.
type CredentialEnumerator interface {
	// EnumerateDiscoverable returns all discoverable credentials.
	EnumerateDiscoverable() ([]*StoredCredential, error)
}

// buildRPResponse builds the CBOR response for RP enumeration.
func (a *Authenticator) buildRPResponse(rp rpEntry, totalRPs int) ([]byte, error) {
	response := map[int]interface{}{
		credMgmtResponseKeyRP: map[string]interface{}{
			"id":   rp.rpID,
			"name": rp.rpName,
		},
		credMgmtResponseKeyRPIDHash: rp.rpIDHash,
	}

	if totalRPs > 0 {
		response[credMgmtResponseKeyTotalRPs] = totalRPs
	}

	respData, err := encodeCBOR(response)
	if err != nil {
		return nil, err
	}

	return a.successResponse(respData), nil
}

// buildCredentialResponse builds the CBOR response for credential enumeration.
func (a *Authenticator) buildCredentialResponse(cred *StoredCredential, totalCredentials int) ([]byte, error) {
	response := map[int]interface{}{
		credMgmtResponseKeyUser: map[string]interface{}{
			"id":          cred.UserID,
			"name":        cred.UserName,
			"displayName": cred.UserDisplayName,
		},
		credMgmtResponseKeyCredentialID: map[string]interface{}{
			"type": "public-key",
			"id":   cred.CredentialID,
		},
		credMgmtResponseKeyPublicKey: cred.PublicKeyCOSE,
	}

	if totalCredentials > 0 {
		response[credMgmtResponseKeyTotalCredentials] = totalCredentials
	}

	respData, err := encodeCBOR(response)
	if err != nil {
		return nil, err
	}

	return a.successResponse(respData), nil
}

// initCredMgmtState initializes the credential management enumeration state.
func (a *Authenticator) initCredMgmtState() {
	if a.credMgmtState == nil {
		a.credMgmtState = &credMgmtEnumerationState{}
	}
}

// credMgmtRawRequest is used for raw CBOR extraction during decoding.
type credMgmtRawRequest struct {
	SubCommand        uint8           `cbor:"1,keyasint"`
	SubCommandParams  cbor.RawMessage `cbor:"2,keyasint,omitempty"`
	PinUvAuthProtocol int             `cbor:"3,keyasint,omitempty"`
	PinUvAuthParam    []byte          `cbor:"4,keyasint,omitempty"`
}

// decodeCredentialManagementRequest decodes a CBOR-encoded CredentialManagement request.
func decodeCredentialManagementRequest(data []byte) (*CredentialManagementRequest, error) {
	if len(data) == 0 {
		return nil, ErrInvalidParameter
	}

	// First decode to get the raw SubCommandParams bytes.
	var rawReq credMgmtRawRequest
	if err := cbor.Unmarshal(data, &rawReq); err != nil {
		return nil, ErrCBORDecodingFailed
	}

	req := &CredentialManagementRequest{
		SubCommand:          rawReq.SubCommand,
		SubCommandParamsRaw: rawReq.SubCommandParams,
		PinUvAuthProtocol:   rawReq.PinUvAuthProtocol,
		PinUvAuthParam:      rawReq.PinUvAuthParam,
	}

	// Validate subCommand is present.
	if req.SubCommand == 0 {
		// Check if it was actually missing vs being 0.
		var rawMap map[int]interface{}
		if err := cbor.Unmarshal(data, &rawMap); err != nil {
			return nil, ErrCBORDecodingFailed
		}
		if _, ok := rawMap[credMgmtKeySubCommand]; !ok {
			return nil, ErrInvalidParameter
		}
	}

	// Now decode SubCommandParams into usable map if present.
	if len(req.SubCommandParamsRaw) > 0 {
		var params map[interface{}]interface{}
		if err := cbor.Unmarshal(req.SubCommandParamsRaw, &params); err == nil {
			req.SubCommandParams = make(map[int]interface{})
			for k, v := range params {
				if keyInt, err := credMgmtToInt(k); err == nil {
					req.SubCommandParams[keyInt] = v
				}
			}
		}
	}

	return req, nil
}

// extractRPIDHash extracts the RP ID hash from subcommand parameters.
func extractRPIDHash(params map[int]interface{}) ([]byte, error) {
	if params == nil {
		return nil, ErrMissingRPIDHash
	}

	rpIDHashRaw, ok := params[credMgmtParamRPIDHash]
	if !ok {
		return nil, ErrMissingRPIDHash
	}

	rpIDHash, ok := rpIDHashRaw.([]byte)
	if !ok || len(rpIDHash) != 32 {
		return nil, ErrInvalidParameter
	}

	return rpIDHash, nil
}

// extractCredentialID extracts the credential ID from subcommand parameters.
func extractCredentialID(params map[int]interface{}) ([]byte, error) {
	if params == nil {
		return nil, ErrMissingCredentialID
	}

	credIDRaw, ok := params[credMgmtParamCredentialID]
	if !ok {
		return nil, ErrMissingCredentialID
	}

	// Credential ID can be provided as a map with "id" field or as raw bytes.
	switch v := credIDRaw.(type) {
	case []byte:
		return v, nil
	case map[interface{}]interface{}:
		if idRaw, ok := v["id"]; ok {
			if id, ok := idRaw.([]byte); ok {
				return id, nil
			}
		}
	case map[string]interface{}:
		if idRaw, ok := v["id"]; ok {
			if id, ok := idRaw.([]byte); ok {
				return id, nil
			}
		}
	}

	return nil, ErrInvalidParameter
}

// extractUserInfo extracts user information from subcommand parameters.
func extractUserInfo(params map[int]interface{}) (map[string]interface{}, error) {
	if params == nil {
		return nil, ErrMissingUserInfo
	}

	userRaw, ok := params[credMgmtParamUser]
	if !ok {
		return nil, ErrMissingUserInfo
	}

	// User info can be provided as map[string]interface{} or map[interface{}]interface{}.
	switch v := userRaw.(type) {
	case map[string]interface{}:
		return v, nil
	case map[interface{}]interface{}:
		result := make(map[string]interface{})
		for k, val := range v {
			if keyStr, ok := k.(string); ok {
				result[keyStr] = val
			}
		}
		return result, nil
	}

	return nil, ErrInvalidParameter
}

// credMgmtToUint8 converts various integer types to uint8.
func credMgmtToUint8(v interface{}) (uint8, error) {
	switch n := v.(type) {
	case int:
		return uint8(n), nil
	case int8:
		return uint8(n), nil
	case int16:
		return uint8(n), nil
	case int32:
		return uint8(n), nil
	case int64:
		return uint8(n), nil
	case uint:
		return uint8(n), nil
	case uint8:
		return n, nil
	case uint16:
		return uint8(n), nil
	case uint32:
		return uint8(n), nil
	case uint64:
		return uint8(n), nil
	default:
		return 0, ErrInvalidParameter
	}
}

// credMgmtToInt converts various integer types to int.
func credMgmtToInt(v interface{}) (int, error) {
	switch n := v.(type) {
	case int:
		return n, nil
	case int8:
		return int(n), nil
	case int16:
		return int(n), nil
	case int32:
		return int(n), nil
	case int64:
		return int(n), nil
	case uint:
		return int(n), nil
	case uint8:
		return int(n), nil
	case uint16:
		return int(n), nil
	case uint32:
		return int(n), nil
	case uint64:
		return int(n), nil
	default:
		return 0, ErrInvalidParameter
	}
}
