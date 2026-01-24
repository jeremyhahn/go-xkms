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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/fxamacker/cbor/v2"
)

// CTAP2 GetAssertion request parameter keys.
const (
	getAssertionParamRPID              = 0x01
	getAssertionParamClientDataHash    = 0x02
	getAssertionParamAllowList         = 0x03
	getAssertionParamExtensions        = 0x04
	getAssertionParamOptions           = 0x05
	getAssertionParamPINUVAuthParam    = 0x06
	getAssertionParamPINUVAuthProtocol = 0x07
)

// CTAP2 GetAssertion response parameter keys.
const (
	getAssertionRespCredential          = 0x01
	getAssertionRespAuthData            = 0x02
	getAssertionRespSignature           = 0x03
	getAssertionRespUser                = 0x04
	getAssertionRespNumberOfCredentials = 0x05
)

// Client data hash size as specified by WebAuthn.
const getAssertionClientDataHashSize = 32

// hmac-secret salt sizes.
const (
	hmacSecretSaltSize       = 32
	hmacSecretOutputSingleSz = 32
	hmacSecretOutputDoubleSz = 64
)

// debugGetAssertion enables debug logging for GetAssertion flow.
// Set VFIDO2_DEBUG=1 environment variable to enable.
var debugGetAssertion = os.Getenv("VFIDO2_DEBUG") == "1"

// debugLog prints debug messages if debugging is enabled.
func debugLog(format string, args ...interface{}) {
	if debugGetAssertion {
		fmt.Printf("[GETASSERTION DEBUG] "+format+"\n", args...)
	}
}

// criticalLog always prints critical crypto debug info to stderr AND a debug file.
// This helps diagnose signature verification issues.
func criticalLog(format string, args ...interface{}) {
	msg := fmt.Sprintf("[CRYPTO DEBUG] "+format+"\n", args...)
	fmt.Fprint(os.Stderr, msg)
	// Also append to a debug file for easy capture
	if f, err := os.OpenFile("/tmp/vfido2_crypto.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600); err == nil {
		_, _ = f.WriteString(msg)
		_ = f.Close()
	}
}

// GetAssertion typed errors.
var (
	// ErrGetAssertionMissingRPID indicates the rpId parameter is missing.
	ErrGetAssertionMissingRPID = errors.New("authenticator: getAssertion missing rpId")

	// ErrGetAssertionMissingClientDataHash indicates the clientDataHash is missing.
	ErrGetAssertionMissingClientDataHash = errors.New("authenticator: getAssertion missing clientDataHash")

	// ErrGetAssertionInvalidClientDataHash indicates the clientDataHash has invalid length.
	ErrGetAssertionInvalidClientDataHash = errors.New("authenticator: getAssertion invalid clientDataHash length")

	// ErrGetAssertionInvalidAllowList indicates the allowList format is invalid.
	ErrGetAssertionInvalidAllowList = errors.New("authenticator: getAssertion invalid allowList format")

	// ErrGetAssertionInvalidCredentialDescriptor indicates a credential descriptor is malformed.
	ErrGetAssertionInvalidCredentialDescriptor = errors.New("authenticator: getAssertion invalid credential descriptor")

	// ErrGetAssertionInvalidExtensions indicates the extensions parameter is invalid.
	ErrGetAssertionInvalidExtensions = errors.New("authenticator: getAssertion invalid extensions format")

	// ErrGetAssertionInvalidOptions indicates the options parameter is invalid.
	ErrGetAssertionInvalidOptions = errors.New("authenticator: getAssertion invalid options format")

	// ErrGetAssertionHMACSecretInvalidSalt indicates the hmac-secret salt is invalid.
	ErrGetAssertionHMACSecretInvalidSalt = errors.New("authenticator: getAssertion hmac-secret invalid salt")

	// ErrGetAssertionHMACSecretDisabled indicates the hmac-secret extension is not enabled.
	ErrGetAssertionHMACSecretDisabled = errors.New("authenticator: getAssertion hmac-secret extension disabled")

	// ErrGetAssertionNoHMACSecretKey indicates the credential has no hmac-secret key.
	ErrGetAssertionNoHMACSecretKey = errors.New("authenticator: getAssertion credential missing hmac-secret key")
)

// GetAssertionRequest represents a CTAP2 authenticatorGetAssertion request.
type GetAssertionRequest struct {
	// RPID is the relying party identifier (required).
	RPID string

	// ClientDataHash is the SHA-256 hash of the client data (required, 32 bytes).
	ClientDataHash []byte

	// AllowList contains credential descriptors to match (optional).
	// If empty, discoverable credentials for the RPID are used.
	AllowList []CredentialDescriptor

	// Extensions contains requested extension inputs (optional).
	Extensions map[string]interface{}

	// Options contains authenticator options (optional).
	// Supported options: "up" (user presence), "uv" (user verification).
	Options map[string]bool

	// PINUVAuthParam is the PIN/UV auth parameter (optional).
	PINUVAuthParam []byte

	// PINUVAuthProtocol is the PIN/UV auth protocol version (optional).
	PINUVAuthProtocol uint8
}

// GetAssertionResponse represents a CTAP2 authenticatorGetAssertion response.
type GetAssertionResponse struct {
	// Credential contains the credential type and ID.
	Credential *CredentialDescriptor

	// AuthData is the authenticator data bytes.
	AuthData []byte

	// Signature is the assertion signature.
	Signature []byte

	// User contains user information for discoverable credentials (optional).
	User *User

	// NumberOfCredentials indicates total matching credentials when > 1.
	NumberOfCredentials uint
}

// handleGetAssertion processes a CTAP2 authenticatorGetAssertion command.
// This method implements the GetAssertion command for the Authenticator.
func (a *Authenticator) handleGetAssertion(data []byte) ([]byte, error) {
	debugLog("handleGetAssertion called, data length: %d", len(data))

	// Decode the CBOR request
	request, err := decodeGetAssertionRequest(data)
	if err != nil {
		debugLog("decodeGetAssertionRequest failed: %v", err)
		return nil, err
	}
	debugLog("decoded request: RPID=%s, allowList=%d entries", request.RPID, len(request.AllowList))

	// Execute the assertion
	response, err := a.executeGetAssertion(request)
	if err != nil {
		debugLog("executeGetAssertion failed: %v", err)
		return nil, err
	}
	debugLog("executeGetAssertion succeeded, response: authData=%d bytes, signature=%d bytes",
		len(response.AuthData), len(response.Signature))

	// Encode the response
	respBytes, err := encodeGetAssertionResponse(response)
	if err != nil {
		debugLog("encodeGetAssertionResponse failed: %v", err)
		return nil, err
	}
	debugLog("encodeGetAssertionResponse succeeded, CBOR length: %d bytes", len(respBytes))

	successResp := a.successResponse(respBytes)
	debugLog("successResponse created, total length: %d bytes (first byte: 0x%02x)",
		len(successResp), successResp[0])

	return successResp, nil
}

// decodeGetAssertionRequest decodes CBOR data into a GetAssertionRequest.
func decodeGetAssertionRequest(data []byte) (*GetAssertionRequest, error) {
	if len(data) == 0 {
		return nil, ErrGetAssertionMissingRPID
	}

	var params map[int]interface{}
	if err := cbor.Unmarshal(data, &params); err != nil {
		return nil, ErrInvalidParameter
	}

	request := &GetAssertionRequest{}

	// 0x01: rpId (string, required)
	rpIDRaw, ok := params[getAssertionParamRPID]
	if !ok {
		return nil, ErrGetAssertionMissingRPID
	}
	rpID, ok := rpIDRaw.(string)
	if !ok || rpID == "" {
		return nil, ErrGetAssertionMissingRPID
	}
	request.RPID = rpID

	// 0x02: clientDataHash (bytes, required)
	clientDataHashRaw, ok := params[getAssertionParamClientDataHash]
	if !ok {
		return nil, ErrGetAssertionMissingClientDataHash
	}
	clientDataHash, ok := clientDataHashRaw.([]byte)
	if !ok || len(clientDataHash) != getAssertionClientDataHashSize {
		return nil, ErrGetAssertionInvalidClientDataHash
	}
	request.ClientDataHash = clientDataHash

	// 0x03: allowList (array, optional)
	if allowListRaw, ok := params[getAssertionParamAllowList]; ok {
		allowList, err := decodeGetAssertionAllowList(allowListRaw)
		if err != nil {
			return nil, err
		}
		request.AllowList = allowList
	}

	// 0x04: extensions (map, optional)
	if extensionsRaw, ok := params[getAssertionParamExtensions]; ok {
		extensions, ok := extensionsRaw.(map[interface{}]interface{})
		if !ok {
			// Try string-keyed map
			if strMap, ok := extensionsRaw.(map[string]interface{}); ok {
				request.Extensions = strMap
			} else {
				return nil, ErrGetAssertionInvalidExtensions
			}
		} else {
			request.Extensions = convertInterfaceMapToStringMap(extensions)
		}
	}

	// 0x05: options (map, optional)
	if optionsRaw, ok := params[getAssertionParamOptions]; ok {
		options, err := decodeGetAssertionOptions(optionsRaw)
		if err != nil {
			return nil, err
		}
		request.Options = options
		debugLog("request options: %+v", request.Options)
	}

	// 0x06: pinUvAuthParam (bytes, optional)
	if pinUvAuthParamRaw, ok := params[getAssertionParamPINUVAuthParam]; ok {
		pinUvAuthParam, ok := pinUvAuthParamRaw.([]byte)
		if !ok {
			return nil, ErrInvalidParameter
		}
		request.PINUVAuthParam = pinUvAuthParam
	}

	// 0x07: pinUvAuthProtocol (uint, optional)
	if pinUvAuthProtocolRaw, ok := params[getAssertionParamPINUVAuthProtocol]; ok {
		protocol, err := toUint8Value(pinUvAuthProtocolRaw)
		if err != nil {
			return nil, ErrInvalidParameter
		}
		request.PINUVAuthProtocol = protocol
	}

	return request, nil
}

// decodeGetAssertionAllowList decodes the allowList parameter from CBOR.
func decodeGetAssertionAllowList(raw interface{}) ([]CredentialDescriptor, error) {
	list, ok := raw.([]interface{})
	if !ok {
		return nil, ErrGetAssertionInvalidAllowList
	}

	descriptors := make([]CredentialDescriptor, 0, len(list))
	for _, item := range list {
		desc, err := decodeGetAssertionCredentialDescriptor(item)
		if err != nil {
			return nil, err
		}
		descriptors = append(descriptors, desc)
	}

	return descriptors, nil
}

// decodeGetAssertionCredentialDescriptor decodes a single credential descriptor from CBOR.
func decodeGetAssertionCredentialDescriptor(raw interface{}) (CredentialDescriptor, error) {
	var desc CredentialDescriptor

	// Handle both interface{} and string keyed maps
	var typeStr string
	var idBytes []byte

	switch m := raw.(type) {
	case map[interface{}]interface{}:
		// type field
		if typeRaw, ok := m["type"]; ok {
			typeStr, _ = typeRaw.(string)
		}
		// id field
		if idRaw, ok := m["id"]; ok {
			idBytes, _ = idRaw.([]byte)
		}
		// transports field (optional)
		if transportsRaw, ok := m["transports"]; ok {
			if transportsList, ok := transportsRaw.([]interface{}); ok {
				for _, t := range transportsList {
					if ts, ok := t.(string); ok {
						desc.Transports = append(desc.Transports, ts)
					}
				}
			}
		}

	case map[string]interface{}:
		// type field
		if typeRaw, ok := m["type"]; ok {
			typeStr, _ = typeRaw.(string)
		}
		// id field
		if idRaw, ok := m["id"]; ok {
			idBytes, _ = idRaw.([]byte)
		}
		// transports field (optional)
		if transportsRaw, ok := m["transports"]; ok {
			if transportsList, ok := transportsRaw.([]interface{}); ok {
				for _, t := range transportsList {
					if ts, ok := t.(string); ok {
						desc.Transports = append(desc.Transports, ts)
					}
				}
			}
		}

	default:
		return desc, ErrGetAssertionInvalidCredentialDescriptor
	}

	// Validate required fields
	if typeStr == "" || len(idBytes) == 0 {
		return desc, ErrGetAssertionInvalidCredentialDescriptor
	}

	desc.Type = typeStr
	desc.ID = idBytes

	return desc, nil
}

// decodeGetAssertionOptions decodes the options parameter from CBOR.
func decodeGetAssertionOptions(raw interface{}) (map[string]bool, error) {
	options := make(map[string]bool)

	switch m := raw.(type) {
	case map[interface{}]interface{}:
		for k, v := range m {
			key, ok := k.(string)
			if !ok {
				continue
			}
			val, ok := v.(bool)
			if !ok {
				continue
			}
			options[key] = val
		}

	case map[string]interface{}:
		for k, v := range m {
			val, ok := v.(bool)
			if !ok {
				continue
			}
			options[k] = val
		}

	default:
		return nil, ErrGetAssertionInvalidOptions
	}

	return options, nil
}

// convertInterfaceMapToStringMap converts a map[interface{}]interface{} to map[string]interface{}.
func convertInterfaceMapToStringMap(m map[interface{}]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for k, v := range m {
		if key, ok := k.(string); ok {
			result[key] = v
		}
	}
	return result
}

// toUint8Value converts various numeric types to uint8.
func toUint8Value(v interface{}) (uint8, error) {
	switch n := v.(type) {
	case uint8:
		return n, nil
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

// executeGetAssertion performs the core assertion logic.
func (a *Authenticator) executeGetAssertion(request *GetAssertionRequest) (*GetAssertionResponse, error) {
	debugLog("executeGetAssertion: finding matching credentials for RPID=%s", request.RPID)

	// Find matching credentials
	matchingCreds, err := a.findMatchingCredentialsForAssertion(request)
	if err != nil {
		debugLog("findMatchingCredentialsForAssertion failed: %v", err)
		return nil, err
	}

	debugLog("found %d matching credentials", len(matchingCreds))

	if len(matchingCreds) == 0 {
		return nil, ErrNoCredentials
	}

	// Store matching credentials for potential GetNextAssertion calls
	a.mu.Lock()
	a.matchingCredentials = matchingCreds
	a.currentCredentialIndex = 0
	a.lastClientDataHash = make([]byte, len(request.ClientDataHash))
	copy(a.lastClientDataHash, request.ClientDataHash)
	a.mu.Unlock()

	// Select the first credential
	credential := matchingCreds[0]
	debugLog("selected credential: ID=%x, user=%s", credential.CredentialID[:8], credential.UserName)

	// Check credential protection level
	if err := a.checkAssertionCredentialProtection(credential, request); err != nil {
		debugLog("checkAssertionCredentialProtection failed: %v", err)
		return nil, err
	}

	// Generate the assertion for the selected credential
	return a.generateAssertionResponse(credential, request, len(matchingCreds))
}

// findMatchingCredentialsForAssertion finds credentials that match the request criteria.
func (a *Authenticator) findMatchingCredentialsForAssertion(request *GetAssertionRequest) ([]*StoredCredential, error) {
	var matchingCreds []*StoredCredential

	if len(request.AllowList) > 0 {
		// If allowList provided, find credentials with matching IDs and RPID
		for _, desc := range request.AllowList {
			if desc.Type != "public-key" {
				continue
			}

			cred, err := a.storage.Load(desc.ID)
			if err != nil {
				if errors.Is(err, ErrCredentialNotFound) {
					continue
				}
				return nil, ErrStorageError
			}

			// Verify RPID matches
			if cred.RPID == request.RPID {
				matchingCreds = append(matchingCreds, cred)
			}
		}
	} else {
		// If no allowList, find all discoverable credentials for RPID
		credentials, err := a.storage.LoadByRPID(request.RPID)
		if err != nil {
			return nil, ErrStorageError
		}

		// Filter for discoverable credentials only
		for _, cred := range credentials {
			if cred.Discoverable {
				matchingCreds = append(matchingCreds, cred)
			}
		}
	}

	return matchingCreds, nil
}

// checkAssertionCredentialProtection verifies the credential meets protection requirements.
func (a *Authenticator) checkAssertionCredentialProtection(cred *StoredCredential, request *GetAssertionRequest) error {
	// For now, this is a simplified check.
	// Full implementation would involve PIN verification based on credProtect level.
	return nil
}

// generateAssertionResponse creates the assertion response for a credential.
func (a *Authenticator) generateAssertionResponse(
	credential *StoredCredential,
	request *GetAssertionRequest,
	totalCredentials int,
) (*GetAssertionResponse, error) {
	debugLog("generateAssertionResponse: starting for credential ID=%x", credential.CredentialID[:8])

	// Increment signature counter
	credential.SignCount++
	debugLog("incremented signCount to %d", credential.SignCount)

	// Update the stored credential with new sign count
	if err := a.storage.Store(credential); err != nil {
		debugLog("storage.Store failed: %v", err)
		return nil, ErrStorageError
	}
	debugLog("credential stored successfully")

	// Request user presence
	debugLog("requesting user presence for RPID=%s, user=%s", request.RPID, credential.UserName)
	ctx := context.Background()
	if err := a.requestUserPresence(ctx, request.RPID, "", credential.UserName, "authenticate"); err != nil {
		debugLog("requestUserPresence failed: %v", err)
		return nil, err
	}
	debugLog("user presence confirmed successfully")

	// Build flags
	flags := FlagUP // User presence always set for assertions
	debugLog("initial flags: 0x%02x (UP set)", byte(flags))

	// Set UV flag if PIN is configured on the authenticator.
	// This is consistent with CTAP2.1 behavior where authenticators with
	// client PIN capability set UV flag when user interaction is performed.
	if a.state.PINSet {
		flags |= FlagUV
		debugLog("UV flag set (PIN configured), flags now: 0x%02x", byte(flags))
	} else if request.Options != nil {
		// Also set UV if explicitly requested and PIN auth param is provided
		if uv, ok := request.Options["uv"]; ok && uv {
			flags |= FlagUV
			debugLog("UV flag set (explicitly requested), flags now: 0x%02x", byte(flags))
		}
	}

	// Process extensions and build extension data
	var extensionOutputs map[string]interface{}
	if len(request.Extensions) > 0 {
		debugLog("processing %d extensions", len(request.Extensions))
		var err error
		extensionOutputs, err = a.processAssertionExtensions(credential, request.Extensions)
		if err != nil {
			debugLog("processAssertionExtensions failed: %v", err)
			return nil, err
		}
		if len(extensionOutputs) > 0 {
			flags |= FlagED
			debugLog("ED flag set, flags now: 0x%02x", byte(flags))
		}
	}

	// Build authenticator data
	debugLog("building authenticator data with RPID=%s, flags=0x%02x, signCount=%d",
		request.RPID, byte(flags), credential.SignCount)
	authDataBuilder := NewAuthDataBuilder(request.RPID).
		WithFlags(flags).
		WithSignCount(credential.SignCount)

	if len(extensionOutputs) > 0 {
		authDataBuilder.WithExtensions(extensionOutputs)
	}

	authData, err := authDataBuilder.Build()
	if err != nil {
		debugLog("authDataBuilder.Build failed: %v", err)
		return nil, err
	}
	debugLog("authData built successfully, length=%d bytes", len(authData))
	debugLog("authData hex: %x", authData)

	// Create signature over authData || clientDataHash
	signData := make([]byte, len(authData)+len(request.ClientDataHash))
	copy(signData, authData)
	copy(signData[len(authData):], request.ClientDataHash)
	debugLog("signData prepared, length=%d bytes (authData=%d + clientDataHash=%d)",
		len(signData), len(authData), len(request.ClientDataHash))
	debugLog("clientDataHash hex: %x", request.ClientDataHash)

	// Sign using key backend or legacy path
	debugLog("signing with algorithm=%d", credential.Algorithm)
	var signature []byte
	if a.keyBackend != nil {
		// Key backend path: load key handle and sign via backend
		debugLog("using key backend for signing")
		handle, loadErr := a.keyBackend.LoadKey(credential.CredentialID, credential.Algorithm)
		if loadErr != nil {
			debugLog("keyBackend.LoadKey failed: %v", loadErr)
			return nil, ErrCryptoError
		}
		signature, err = a.keyBackend.Sign(handle, credential.Algorithm, signData)
		if err != nil {
			debugLog("keyBackend.Sign failed: %v", err)
			return nil, ErrCryptoError
		}
	} else {
		// Legacy path: parse PKCS#8 private key and sign via crypto.go
		debugLog("parsing private key, length=%d bytes", len(credential.PrivateKey))
		privateKey, parseErr := parseAssertionPrivateKey(credential.PrivateKey)
		if parseErr != nil {
			debugLog("parseAssertionPrivateKey failed: %v", parseErr)
			return nil, ErrCryptoError
		}
		debugLog("private key parsed successfully, type=%T", privateKey)
		debugLog("stored publicKeyCOSE hex: %x", credential.PublicKeyCOSE)

		signature, err = Sign(privateKey, credential.Algorithm, signData)
		if err != nil {
			debugLog("Sign failed: %v", err)
			return nil, ErrCryptoError
		}
	}
	debugLog("signature created successfully, length=%d bytes", len(signature))
	debugLog("signature hex: %x", signature)

	// Always log critical crypto info to stderr for debugging
	criticalLog("=== ASSERTION CRYPTO DEBUG ===")
	criticalLog("rpId: %s", request.RPID)
	criticalLog("credentialID: %x", credential.CredentialID)
	criticalLog("authData (%d bytes): %x", len(authData), authData)
	criticalLog("clientDataHash (%d bytes): %x", len(request.ClientDataHash), request.ClientDataHash)
	criticalLog("signature (%d bytes): %x", len(signature), signature)
	criticalLog("publicKeyCOSE (%d bytes): %x", len(credential.PublicKeyCOSE), credential.PublicKeyCOSE)
	criticalLog("flags: 0x%02x, signCount: %d", byte(flags), credential.SignCount)

	// Local verification for debugging - verify ASN.1/DER signature using stored public key
	pubKey, _, coseErr := DecodeCOSEPublicKey(credential.PublicKeyCOSE)
	if coseErr != nil {
		criticalLog("WARNING: failed to decode public key: %v", coseErr)
	} else {
		if ecPubKey, ok := pubKey.(*ecdsa.PublicKey); ok {
			digest := sha256.Sum256(signData)
			valid := ecdsa.VerifyASN1(ecPubKey, digest[:], signature)
			criticalLog("LOCAL VERIFICATION (ASN.1/DER): %v", valid)
			if !valid {
				criticalLog("ERROR: signature fails local verification!")
			}
		}
	}
	criticalLog("=== END ASSERTION CRYPTO DEBUG ===")

	// Build response
	response := &GetAssertionResponse{
		Credential: &CredentialDescriptor{
			Type: "public-key",
			ID:   credential.CredentialID,
		},
		AuthData:  authData,
		Signature: signature,
	}
	debugLog("response struct created: credentialID=%d bytes, authData=%d bytes, signature=%d bytes",
		len(response.Credential.ID), len(response.AuthData), len(response.Signature))

	// Include user info for discoverable credentials ONLY when no allowList was provided.
	// Per CTAP2.1 spec: "user (0x04): MUST NOT be present if the allowList member
	// was present in the authenticatorGetAssertion request."
	if len(request.AllowList) == 0 && credential.Discoverable && len(credential.UserID) > 0 {
		response.User = &User{
			ID:          credential.UserID,
			Name:        credential.UserName,
			DisplayName: credential.UserDisplayName,
		}
		debugLog("user info included: name=%s", credential.UserName)
	}

	// Include number of credentials if multiple
	if totalCredentials > 1 {
		response.NumberOfCredentials = uint(totalCredentials)
		debugLog("numberOfCredentials set to %d", response.NumberOfCredentials)
	}

	debugLog("generateAssertionResponse completed successfully")
	return response, nil
}

// processAssertionExtensions processes extension inputs and returns outputs.
func (a *Authenticator) processAssertionExtensions(
	credential *StoredCredential,
	extensions map[string]interface{},
) (map[string]interface{}, error) {
	outputs := make(map[string]interface{})

	// Process hmac-secret extension
	if hmacSecretInput, ok := extensions["hmac-secret"]; ok {
		if !a.config.EnableHMACSecret {
			return nil, ErrGetAssertionHMACSecretDisabled
		}

		output, err := a.processHMACSecretExtension(credential, hmacSecretInput)
		if err != nil {
			return nil, err
		}
		outputs["hmac-secret"] = output
	}

	return outputs, nil
}

// processHMACSecretExtension processes the hmac-secret extension input.
func (a *Authenticator) processHMACSecretExtension(
	credential *StoredCredential,
	input interface{},
) ([]byte, error) {
	// Validate credential has HMAC secret key
	if len(credential.HMACSecretKey) != HMACSecretKeySize {
		return nil, ErrGetAssertionNoHMACSecretKey
	}

	// Parse the input
	var salt1, salt2 []byte

	switch v := input.(type) {
	case map[interface{}]interface{}:
		if s1, ok := v["salt1"]; ok {
			salt1, _ = s1.([]byte)
		}
		if s2, ok := v["salt2"]; ok {
			salt2, _ = s2.([]byte)
		}

	case map[string]interface{}:
		if s1, ok := v["salt1"]; ok {
			salt1, _ = s1.([]byte)
		}
		if s2, ok := v["salt2"]; ok {
			salt2, _ = s2.([]byte)
		}

	default:
		return nil, ErrGetAssertionHMACSecretInvalidSalt
	}

	// Validate salt1 (required)
	if len(salt1) != hmacSecretSaltSize {
		return nil, ErrGetAssertionHMACSecretInvalidSalt
	}

	// Compute HMAC-SHA256 for salt1
	output1 := computeAssertionHMACSHA256(credential.HMACSecretKey, salt1)

	// If salt2 provided, compute and concatenate
	if len(salt2) > 0 {
		if len(salt2) != hmacSecretSaltSize {
			return nil, ErrGetAssertionHMACSecretInvalidSalt
		}
		output2 := computeAssertionHMACSHA256(credential.HMACSecretKey, salt2)
		return append(output1, output2...), nil
	}

	return output1, nil
}

// computeAssertionHMACSHA256 computes HMAC-SHA256(key, data).
func computeAssertionHMACSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// parseAssertionPrivateKey parses a PKCS#8 encoded private key.
func parseAssertionPrivateKey(data []byte) (crypto.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		return nil, ErrInvalidPrivateKey
	}

	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		return k, nil
	case ed25519.PrivateKey:
		return k, nil
	default:
		return nil, ErrInvalidPrivateKey
	}
}

// encodeGetAssertionResponse encodes a GetAssertionResponse to CBOR.
func encodeGetAssertionResponse(response *GetAssertionResponse) ([]byte, error) {
	if response == nil {
		return nil, ErrInvalidParameter
	}

	result := make(map[int]interface{})

	// 0x01: credential
	if response.Credential != nil {
		credMap := map[string]interface{}{
			"type": response.Credential.Type,
			"id":   response.Credential.ID,
		}
		if len(response.Credential.Transports) > 0 {
			credMap["transports"] = response.Credential.Transports
		}
		result[getAssertionRespCredential] = credMap
	}

	// 0x02: authData (required)
	if len(response.AuthData) == 0 {
		return nil, ErrInvalidParameter
	}
	result[getAssertionRespAuthData] = response.AuthData

	// 0x03: signature (required)
	if len(response.Signature) == 0 {
		return nil, ErrInvalidParameter
	}
	result[getAssertionRespSignature] = response.Signature

	// 0x04: user (optional, for discoverable credentials)
	if response.User != nil {
		userMap := make(map[string]interface{})
		if len(response.User.ID) > 0 {
			userMap["id"] = response.User.ID
		}
		if response.User.Name != "" {
			userMap["name"] = response.User.Name
		}
		if response.User.DisplayName != "" {
			userMap["displayName"] = response.User.DisplayName
		}
		if len(userMap) > 0 {
			result[getAssertionRespUser] = userMap
		}
	}

	// 0x05: numberOfCredentials (optional, if > 1)
	if response.NumberOfCredentials > 1 {
		result[getAssertionRespNumberOfCredentials] = response.NumberOfCredentials
	}

	debugLog("encodeGetAssertionResponse: encoding map with %d entries", len(result))
	encoded, err := encodeCBOR(result)
	if err != nil {
		debugLog("encodeCBOR failed: %v", err)
		return nil, err
	}
	debugLog("encodeGetAssertionResponse: CBOR encoded to %d bytes", len(encoded))
	debugLog("encodeGetAssertionResponse: full response hex: %x", encoded)

	// Critical debug: dump the CBOR response
	criticalLog("=== GETASSERTION CBOR RESPONSE ===")
	criticalLog("CBOR encoded (%d bytes): %x", len(encoded), encoded)
	criticalLog("=== END GETASSERTION CBOR RESPONSE ===")

	return encoded, nil
}

// handleGetNextAssertion returns the next credential's assertion in a multi-credential response.
// This implements the CTAP2 authenticatorGetNextAssertion command.
func (a *Authenticator) handleGetNextAssertion() ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Validate we have matching credentials from a previous GetAssertion
	if len(a.matchingCredentials) == 0 {
		return nil, ErrNoCredentials
	}

	// Increment index
	a.currentCredentialIndex++

	// Check if we've exhausted all credentials
	if a.currentCredentialIndex >= len(a.matchingCredentials) {
		a.matchingCredentials = nil
		a.currentCredentialIndex = 0
		a.lastClientDataHash = nil
		return nil, ErrNoCredentials
	}

	// Get the next credential
	credential := a.matchingCredentials[a.currentCredentialIndex]

	// Build a synthetic request for generating the assertion
	request := &GetAssertionRequest{
		RPID:           credential.RPID,
		ClientDataHash: a.lastClientDataHash,
	}

	response, err := a.generateAssertionResponse(credential, request, len(a.matchingCredentials))
	if err != nil {
		return nil, err
	}

	respBytes, err := encodeGetAssertionResponse(response)
	if err != nil {
		return nil, err
	}

	return a.successResponse(respBytes), nil
}

// ClearAssertionState clears the stored assertion state.
// This should be called when the assertion session is complete or timed out.
func (a *Authenticator) ClearAssertionState() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.matchingCredentials = nil
	a.currentCredentialIndex = 0
	a.lastClientDataHash = nil
}

// ValidateGetAssertionRequest performs comprehensive validation on a GetAssertionRequest.
func ValidateGetAssertionRequest(request *GetAssertionRequest) error {
	if request == nil {
		return ErrInvalidParameter
	}

	if request.RPID == "" {
		return ErrGetAssertionMissingRPID
	}

	if len(request.ClientDataHash) != getAssertionClientDataHashSize {
		return ErrGetAssertionInvalidClientDataHash
	}

	// Validate allowList entries
	for _, desc := range request.AllowList {
		if desc.Type != "public-key" {
			return ErrGetAssertionInvalidCredentialDescriptor
		}
		if len(desc.ID) == 0 {
			return ErrGetAssertionInvalidCredentialDescriptor
		}
	}

	return nil
}

// MatchesCredentialID checks if a credential ID matches any in the allowList.
func MatchesCredentialID(credentialID []byte, allowList []CredentialDescriptor) bool {
	for _, desc := range allowList {
		if bytes.Equal(desc.ID, credentialID) {
			return true
		}
	}
	return false
}
