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

package client

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	softwarebackend "github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator/keybackend"
)

// SoftwareAdapter implements AuthenticatorAdapter by delegating to the real
// CTAP2 authenticator with a software key backend. It performs JSON-to-CBOR
// translation between the WebAuthn JSON wire format and the CTAP2 binary
// protocol, then calls authenticator.ProcessCBOR for the actual cryptographic
// operations. This adapter uses "none" attestation and is suitable for testing
// and headless automation.
type SoftwareAdapter struct {
	auth    *authenticator.Authenticator
	storage *authenticator.MemoryStorage
}

// NewSoftwareAdapter creates a new software authenticator adapter backed by the
// real CTAP2 authenticator with a BackendAdapter-wrapped software backend,
// MemoryStorage, and AutoGrantHandler for user presence (auto-approve). PIN is
// disabled for headless operation.
func NewSoftwareAdapter() *SoftwareAdapter {
	credStorage := authenticator.NewMemoryStorage()

	// Create an in-memory software backend and wrap it as a FIDO2 key backend.
	swConfig := &softwarebackend.Config{
		KeyStorage: storage.NewMemory(),
	}
	swBackend, err := softwarebackend.NewBackend(swConfig)
	if err != nil {
		panic(fmt.Sprintf("webauthn/client: failed to create software backend: %v", err))
	}
	kb := keybackend.NewBackendAdapter(swBackend, types.BackendTypeSoftware)

	config := &authenticator.Config{
		Storage:                    credStorage,
		KeyBackend:                 kb,
		UserPresenceHandler:        authenticator.NewAutoGrantHandler(),
		EnablePIN:                  false,
		EnableCredentialManagement: false,
		EnableResidentKey:          true,
		AttestationFormat:          "none",
		SupportedAlgorithms:        []int{authenticator.COSEAlgES256},
	}

	auth, err := authenticator.NewAuthenticator(config)
	if err != nil {
		panic(fmt.Sprintf("webauthn/client: failed to create authenticator: %v", err))
	}

	return &SoftwareAdapter{
		auth:    auth,
		storage: credStorage,
	}
}

// Available always returns true for the software adapter.
func (a *SoftwareAdapter) Available() bool {
	return true
}

// MakeCredential creates a new credential from the server's creation options
// JSON. It translates the WebAuthn JSON into a CTAP2 MakeCredential command,
// calls the real authenticator, and translates the response back to WebAuthn
// JSON for the RP server.
func (a *SoftwareAdapter) MakeCredential(options []byte) ([]byte, error) {
	var opts creationOptions
	if err := json.Unmarshal(options, &opts); err != nil {
		return nil, fmt.Errorf("%w: failed to parse creation options: %w", ErrCTAPOperationFailed, err)
	}

	rpID := opts.PublicKey.RP.ID
	if rpID == "" {
		return nil, fmt.Errorf("%w: missing RP ID in creation options", ErrCTAPOperationFailed)
	}

	challenge, err := base64.RawURLEncoding.DecodeString(opts.PublicKey.Challenge)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidChallenge, err)
	}

	// Build CollectedClientData JSON and compute clientDataHash
	clientData := buildCollectedClientData("webauthn.create", challenge, "https://"+rpID)
	clientDataBytes, err := json.Marshal(clientData)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to marshal client data: %w", ErrCTAPOperationFailed, err)
	}
	clientDataHash := sha256.Sum256(clientDataBytes)

	// Decode user ID from base64url to raw bytes
	userIDBytes, err := base64.RawURLEncoding.DecodeString(opts.PublicKey.User.ID)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode user ID: %w", ErrCTAPOperationFailed, err)
	}

	// Build CTAP2 MakeCredential request (integer-keyed CBOR map)
	reqMap := map[int]interface{}{
		0x01: clientDataHash[:],
		0x02: map[string]interface{}{
			"id":   rpID,
			"name": opts.PublicKey.RP.Name,
		},
		0x03: map[string]interface{}{
			"id":          userIDBytes,
			"name":        opts.PublicKey.User.Name,
			"displayName": opts.PublicKey.User.DisplayName,
		},
		0x04: buildCBORPubKeyCredParams(opts.PublicKey.PubKeyCredParams),
	}

	// Add options (rk) if authenticatorSelection is present
	if sel := opts.PublicKey.AuthenticatorSel; sel != nil {
		optionsMap := map[string]bool{}
		switch sel.ResidentKey {
		case "required", "preferred":
			optionsMap["rk"] = true
		}
		if sel.RequireResidentKey != nil && *sel.RequireResidentKey {
			optionsMap["rk"] = true
		}
		if len(optionsMap) > 0 {
			reqMap[0x07] = optionsMap
		}
	}

	cborData, err := cbor.Marshal(reqMap)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to encode CTAP2 request: %w", ErrCTAPOperationFailed, err)
	}

	// Call the real authenticator
	resp, ctapErr := a.auth.ProcessCBOR(authenticator.CmdMakeCredential, cborData)
	if ctapErr != nil {
		return nil, fmt.Errorf("%w: %w", ErrCTAPOperationFailed, ctapErr)
	}

	// Parse the CTAP2 response: [statusByte][cborPayload]
	if len(resp) < 1 {
		return nil, fmt.Errorf("%w: empty response from authenticator", ErrCTAPOperationFailed)
	}
	if resp[0] != authenticator.StatusOK {
		return nil, fmt.Errorf("%w: authenticator returned status 0x%02x", ErrCTAPOperationFailed, resp[0])
	}

	// Decode the CBOR response payload (integer-keyed map)
	var ctapResp map[int]interface{}
	if err := cbor.Unmarshal(resp[1:], &ctapResp); err != nil {
		return nil, fmt.Errorf("%w: failed to decode CTAP2 response: %w", ErrCTAPOperationFailed, err)
	}

	// Extract fields from CTAP2 response
	fmtVal, _ := ctapResp[0x01].(string)
	authDataRaw, _ := ctapResp[0x02].([]byte)
	attStmt := ctapResp[0x03]
	if attStmt == nil {
		attStmt = map[interface{}]interface{}{}
	}

	// Extract credential ID from authData
	credentialID, err := extractCredentialIDFromAuthData(authDataRaw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCTAPOperationFailed, err)
	}

	// Re-encode the attestation object as string-keyed CBOR (WebAuthn format)
	attObj, err := cbor.Marshal(map[string]interface{}{
		"fmt":      fmtVal,
		"attStmt":  normalizeAttStmt(attStmt),
		"authData": authDataRaw,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: failed to encode attestation object: %w", ErrCTAPOperationFailed, err)
	}

	// Build the WebAuthn JSON attestation response
	credIDB64 := base64.RawURLEncoding.EncodeToString(credentialID)
	response := map[string]interface{}{
		"id":    credIDB64,
		"rawId": credIDB64,
		"type":  "public-key",
		"response": map[string]interface{}{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientDataBytes),
			"attestationObject": base64.RawURLEncoding.EncodeToString(attObj),
		},
	}

	return json.Marshal(response)
}

// GetAssertion gets an assertion for the given assertion options by delegating
// to the real CTAP2 authenticator. It translates the WebAuthn JSON into a
// GetAssertion command and translates the response back.
func (a *SoftwareAdapter) GetAssertion(options []byte) ([]byte, error) {
	var opts assertionOptions
	if err := json.Unmarshal(options, &opts); err != nil {
		return nil, fmt.Errorf("%w: failed to parse assertion options: %w", ErrCTAPOperationFailed, err)
	}

	rpID := opts.PublicKey.RPID
	if rpID == "" {
		return nil, fmt.Errorf("%w: missing RP ID in assertion options", ErrCTAPOperationFailed)
	}

	challenge, err := base64.RawURLEncoding.DecodeString(opts.PublicKey.Challenge)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidChallenge, err)
	}

	// Build CollectedClientData JSON and compute clientDataHash
	clientData := buildCollectedClientData("webauthn.get", challenge, "https://"+rpID)
	clientDataBytes, err := json.Marshal(clientData)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to marshal client data: %w", ErrCTAPOperationFailed, err)
	}
	clientDataHash := sha256.Sum256(clientDataBytes)

	// Build CTAP2 GetAssertion request (integer-keyed CBOR map)
	reqMap := map[int]interface{}{
		0x01: rpID,
		0x02: clientDataHash[:],
	}

	// Add allow list if present
	if len(opts.PublicKey.AllowCredentials) > 0 {
		allowList := make([]map[string]interface{}, 0, len(opts.PublicKey.AllowCredentials))
		for _, cred := range opts.PublicKey.AllowCredentials {
			credIDBytes, decErr := base64.RawURLEncoding.DecodeString(cred.ID)
			if decErr != nil {
				// If it fails as base64url, use it raw (for backward compat)
				credIDBytes = []byte(cred.ID)
			}
			allowList = append(allowList, map[string]interface{}{
				"type": "public-key",
				"id":   credIDBytes,
			})
		}
		reqMap[0x03] = allowList
	}

	cborData, err := cbor.Marshal(reqMap)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to encode CTAP2 request: %w", ErrCTAPOperationFailed, err)
	}

	// Call the real authenticator
	resp, ctapErr := a.auth.ProcessCBOR(authenticator.CmdGetAssertion, cborData)
	if ctapErr != nil {
		return nil, fmt.Errorf("%w: %w", ErrCTAPOperationFailed, ctapErr)
	}

	// Parse the CTAP2 response
	if len(resp) < 1 {
		return nil, fmt.Errorf("%w: empty response from authenticator", ErrCTAPOperationFailed)
	}
	if resp[0] != authenticator.StatusOK {
		return nil, fmt.Errorf("%w: authenticator returned status 0x%02x", ErrCTAPOperationFailed, resp[0])
	}

	// Decode the CBOR response payload
	var ctapResp map[int]interface{}
	if err := cbor.Unmarshal(resp[1:], &ctapResp); err != nil {
		return nil, fmt.Errorf("%w: failed to decode CTAP2 response: %w", ErrCTAPOperationFailed, err)
	}

	// Extract credential ID from the response
	credMap, ok := ctapResp[0x01].(map[interface{}]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: missing credential in assertion response", ErrCTAPOperationFailed)
	}
	credIDBytes, _ := credMap["id"].([]byte)
	if len(credIDBytes) == 0 {
		return nil, fmt.Errorf("%w: empty credential ID in assertion response", ErrCTAPOperationFailed)
	}

	authDataRaw, _ := ctapResp[0x02].([]byte)
	signature, _ := ctapResp[0x03].([]byte)

	// Build the WebAuthn JSON assertion response
	credIDB64 := base64.RawURLEncoding.EncodeToString(credIDBytes)
	response := map[string]interface{}{
		"id":    credIDB64,
		"rawId": credIDB64,
		"type":  "public-key",
		"response": map[string]interface{}{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientDataBytes),
			"authenticatorData": base64.RawURLEncoding.EncodeToString(authDataRaw),
			"signature":         base64.RawURLEncoding.EncodeToString(signature),
		},
	}

	return json.Marshal(response)
}

// CredentialCount returns the number of stored credentials.
func (a *SoftwareAdapter) CredentialCount() int {
	count, err := a.storage.Count()
	if err != nil {
		return 0
	}
	return count
}

// creationOptions represents the JSON structure of PublicKeyCredentialCreationOptions
// as sent by the server.
type creationOptions struct {
	PublicKey struct {
		Challenge          string                  `json:"challenge"`
		RP                 rpEntity                `json:"rp"`
		User               userEntity              `json:"user"`
		PubKeyCredParams   []pubKeyCredParam       `json:"pubKeyCredParams,omitempty"`
		Timeout            int                     `json:"timeout,omitempty"`
		Attestation        string                  `json:"attestation,omitempty"`
		AuthenticatorSel   *authenticatorSelection `json:"authenticatorSelection,omitempty"`
		Extensions         map[string]interface{}  `json:"extensions,omitempty"`
		ExcludeCredentials []credentialDescriptor  `json:"excludeCredentials,omitempty"`
	} `json:"publicKey"`
}

// rpEntity represents a Relying Party entity.
type rpEntity struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// userEntity represents a User entity.
type userEntity struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

// pubKeyCredParam specifies a supported algorithm.
type pubKeyCredParam struct {
	Type string `json:"type"`
	Alg  int    `json:"alg"`
}

// authenticatorSelection specifies RP requirements for the authenticator.
type authenticatorSelection struct {
	AuthenticatorAttachment string `json:"authenticatorAttachment,omitempty"`
	ResidentKey             string `json:"residentKey,omitempty"`
	RequireResidentKey      *bool  `json:"requireResidentKey,omitempty"`
	UserVerification        string `json:"userVerification,omitempty"`
}

// assertionOptions represents the JSON structure of PublicKeyCredentialRequestOptions
// as sent by the server.
type assertionOptions struct {
	PublicKey struct {
		Challenge        string                 `json:"challenge"`
		RPID             string                 `json:"rpId"`
		Timeout          int                    `json:"timeout,omitempty"`
		UserVerification string                 `json:"userVerification,omitempty"`
		AllowCredentials []credentialDescriptor `json:"allowCredentials,omitempty"`
		Extensions       map[string]interface{} `json:"extensions,omitempty"`
	} `json:"publicKey"`
}

// credentialDescriptor identifies a credential in an allow list.
type credentialDescriptor struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// collectedClientData represents the CollectedClientData structure per the
// WebAuthn specification.
type collectedClientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

// buildCollectedClientData creates the CollectedClientData structure.
func buildCollectedClientData(typ string, challenge []byte, origin string) collectedClientData {
	return collectedClientData{
		Type:      typ,
		Challenge: base64.RawURLEncoding.EncodeToString(challenge),
		Origin:    origin,
	}
}

// buildCBORPubKeyCredParams converts JSON pubKeyCredParams to CBOR-friendly
// slice of maps.
func buildCBORPubKeyCredParams(params []pubKeyCredParam) []map[string]interface{} {
	if len(params) == 0 {
		// Default to ES256 if no params specified
		return []map[string]interface{}{
			{"type": "public-key", "alg": -7},
		}
	}
	result := make([]map[string]interface{}, 0, len(params))
	for _, p := range params {
		result = append(result, map[string]interface{}{
			"type": p.Type,
			"alg":  p.Alg,
		})
	}
	return result
}

// extractCredentialIDFromAuthData parses the credential ID from authenticator data.
// AuthData layout: rpIdHash(32) + flags(1) + signCount(4) = 37 bytes
// If AT flag (bit 6) is set: aaguid(16) + credIDLen(2 big-endian) + credentialID
func extractCredentialIDFromAuthData(authData []byte) ([]byte, error) {
	if len(authData) < 37 {
		return nil, fmt.Errorf("authData too short: %d bytes", len(authData))
	}

	flags := authData[32]
	if flags&0x40 == 0 {
		return nil, fmt.Errorf("AT flag not set in authData")
	}

	// After the 37-byte header: aaguid(16) + credIDLen(2) + credentialID
	offset := 37
	if len(authData) < offset+16+2 {
		return nil, fmt.Errorf("authData too short for attested credential data")
	}

	// Skip AAGUID (16 bytes)
	offset += 16

	credIDLen := binary.BigEndian.Uint16(authData[offset : offset+2])
	offset += 2

	if len(authData) < offset+int(credIDLen) {
		return nil, fmt.Errorf("authData too short for credential ID")
	}

	credentialID := make([]byte, credIDLen)
	copy(credentialID, authData[offset:offset+int(credIDLen)])

	return credentialID, nil
}

// normalizeAttStmt converts the attStmt from CBOR-decoded form (which may
// have interface{} keys) to a clean map[string]interface{} for re-encoding.
func normalizeAttStmt(raw interface{}) map[string]interface{} {
	switch v := raw.(type) {
	case map[string]interface{}:
		return v
	case map[interface{}]interface{}:
		result := make(map[string]interface{}, len(v))
		for k, val := range v {
			if key, ok := k.(string); ok {
				result[key] = val
			}
		}
		return result
	default:
		return map[string]interface{}{}
	}
}
