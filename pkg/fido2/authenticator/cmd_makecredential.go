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
	"context"
	"crypto/x509"
	"errors"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// CTAP2 MakeCredential request parameter keys (CBOR map indices)
const (
	makeCredentialKeyClientDataHash        = 0x01
	makeCredentialKeyRP                    = 0x02
	makeCredentialKeyUser                  = 0x03
	makeCredentialKeyPubKeyCredParams      = 0x04
	makeCredentialKeyExcludeList           = 0x05
	makeCredentialKeyExtensions            = 0x06
	makeCredentialKeyOptions               = 0x07
	makeCredentialKeyPINUVAuthParam        = 0x08
	makeCredentialKeyPINUVAuthProtocol     = 0x09
	makeCredentialKeyEnterpriseAttestation = 0x0A
)

// CTAP2 MakeCredential response parameter keys (CBOR map indices)
const (
	makeCredentialResponseKeyFmt      = 0x01
	makeCredentialResponseKeyAuthData = 0x02
	makeCredentialResponseKeyAttStmt  = 0x03
)

// Attestation format constants
const (
	AttestationFormatNone   = "none"
	AttestationFormatPacked = "packed"
)

// ClientDataHash size constant
const ClientDataHashSize = 32

// MakeCredential errors
var (
	// ErrMissingClientDataHash indicates clientDataHash parameter is missing.
	ErrMissingClientDataHash = errors.New("authenticator: missing clientDataHash")

	// ErrInvalidClientDataHash indicates clientDataHash is not 32 bytes.
	ErrInvalidClientDataHash = errors.New("authenticator: clientDataHash must be 32 bytes")

	// ErrMissingRP indicates the rp parameter is missing.
	ErrMissingRP = errors.New("authenticator: missing rp parameter")

	// ErrMissingRPID indicates the rp.id field is missing or empty.
	ErrMissingRPID = errors.New("authenticator: missing rp.id")

	// ErrMissingUser indicates the user parameter is missing.
	ErrMissingUser = errors.New("authenticator: missing user parameter")

	// ErrMissingUserID indicates the user.id field is missing or empty.
	ErrMissingUserID = errors.New("authenticator: missing user.id")

	// ErrMissingPubKeyCredParams indicates pubKeyCredParams is missing or empty.
	ErrMissingPubKeyCredParams = errors.New("authenticator: missing pubKeyCredParams")

	// ErrNoSupportedAlgorithm indicates none of the requested algorithms are supported.
	ErrNoSupportedAlgorithm = errors.New("authenticator: no supported algorithm in pubKeyCredParams")

	// ErrResidentKeyLimitReached indicates max resident credentials has been reached.
	ErrResidentKeyLimitReached = errors.New("authenticator: resident key limit reached")

	// ErrCredentialLimitReached indicates max credentials has been reached.
	ErrCredentialLimitReached = errors.New("authenticator: credential limit reached")
)

// MakeCredentialRequest represents a CTAP2 authenticatorMakeCredential request.
// This structure is populated from the CBOR-encoded request data.
type MakeCredentialRequest struct {
	// ClientDataHash is the SHA-256 hash of the client data (32 bytes, required).
	ClientDataHash []byte

	// RP contains the relying party information (required).
	RP RelyingParty

	// User contains the user entity information (required).
	User User

	// PubKeyCredParams lists the acceptable credential algorithms (required).
	PubKeyCredParams []PublicKeyCredentialParam

	// ExcludeList contains credential IDs to exclude (optional).
	ExcludeList []CredentialDescriptor

	// Extensions contains requested extensions (optional).
	Extensions map[string]interface{}

	// Options contains optional request flags (optional).
	// Common options: "rk" (resident key), "uv" (user verification)
	Options map[string]bool

	// PINUVAuthParam is the PIN/UV protocol authentication parameter (optional).
	PINUVAuthParam []byte

	// PINUVAuthProtocol specifies which PIN/UV protocol is used (optional).
	PINUVAuthProtocol uint8

	// EnterpriseAttestation indicates enterprise attestation mode (optional).
	EnterpriseAttestation uint8
}

// MakeCredentialResponse represents a CTAP2 authenticatorMakeCredential response.
type MakeCredentialResponse struct {
	// Fmt is the attestation statement format identifier.
	// Common values: "none", "packed", "tpm", "android-key"
	Fmt string

	// AuthData is the authenticator data containing the new credential.
	AuthData []byte

	// AttStmt is the attestation statement (may be empty for "none" format).
	AttStmt map[string]interface{}
}

// MakeCredentialOptions contains optional parameters for MakeCredential.
type MakeCredentialOptions struct {
	// ExcludeList contains credential IDs to exclude.
	ExcludeList []CredentialDescriptor

	// Extensions contains requested extensions.
	Extensions map[string]interface{}

	// Options contains optional request flags (rk, uv).
	Options map[string]bool

	// PINUVAuthParam is the PIN/UV authentication parameter.
	PINUVAuthParam []byte

	// PINUVAuthProtocol specifies which PIN/UV protocol is used.
	PINUVAuthProtocol uint8
}

// HandleMakeCredential implements the CTAP2 authenticatorMakeCredential command.
// It decodes the CBOR request, validates parameters, creates a new credential,
// and returns the CBOR-encoded response data (without status byte prefix).
//
// Parameters:
//   - data: CBOR-encoded MakeCredential request (without command byte)
//
// Returns:
//   - CBOR-encoded MakeCredential response on success
//   - Error if the request is invalid or operation fails
func (a *Authenticator) HandleMakeCredential(data []byte) ([]byte, error) {
	// Decode the request
	req, err := DecodeMakeCredentialRequest(data)
	if err != nil {
		return nil, err
	}

	// Validate the request
	if err := a.validateMakeCredentialRequest(req); err != nil {
		return nil, err
	}

	// Check exclude list for existing credentials
	if err := a.checkExcludeList(req.ExcludeList, req.RP.ID); err != nil {
		return nil, err
	}

	// Select algorithm from pubKeyCredParams
	selectedAlgorithm, err := a.selectAlgorithm(req.PubKeyCredParams)
	if err != nil {
		return nil, err
	}

	// Check credential limits
	if err := a.checkCredentialLimits(req.Options); err != nil {
		return nil, err
	}

	// Generate credential ID
	credentialID, err := GenerateCredentialID()
	if err != nil {
		return nil, ErrCryptoError
	}
	debugLog("[MAKECRED] generated credentialID length=%d, hex: %x", len(credentialID), credentialID)

	// Generate credential key pair via backend or legacy path
	privateKeyBytes, publicKeyCOSE, err := a.generateCredentialKeyPair(selectedAlgorithm, credentialID)
	if err != nil {
		return nil, err
	}
	debugLog("[MAKECRED] generated publicKeyCOSE length=%d, hex: %x", len(publicKeyCOSE), publicKeyCOSE)

	// Critical logging for registration - always output to stderr
	criticalLog("=== REGISTRATION CRYPTO DEBUG ===")
	criticalLog("rpId: %s", req.RP.ID)
	criticalLog("credentialID: %x", credentialID)
	criticalLog("publicKeyCOSE (%d bytes): %x", len(publicKeyCOSE), publicKeyCOSE)
	criticalLog("algorithm: %d", selectedAlgorithm)
	criticalLog("=== END REGISTRATION CRYPTO DEBUG ===")

	// Determine if this should be a discoverable credential
	discoverable := a.shouldCreateDiscoverable(req.Options)

	// Generate HMAC secret key if extension requested
	var hmacSecretKey []byte
	if a.shouldGenerateHMACSecret(req.Extensions) {
		hmacSecretKey, err = GenerateHMACSecretKey()
		if err != nil {
			return nil, ErrCryptoError
		}
	}

	// Request user presence
	ctx := context.Background()
	if err := a.requestUserPresence(ctx, req.RP.ID, req.RP.Name, req.User.Name, "register"); err != nil {
		return nil, err
	}

	// Build authenticator data with AT flag (attested credential data)
	flags := FlagUP | FlagAT // User present + Attested credential data
	if a.userVerificationSatisfied(req) {
		flags |= FlagUV
	}

	// Process extension inputs for credential storage (e.g., credProtect level).
	// Extension outputs are intentionally NOT included in authData because many
	// WebAuthn RP implementations do not correctly parse the ED flag and will
	// read the extension bytes as part of the COSE public key, corrupting it.
	extensionOutputs := a.processMakeCredentialExtensions(req.Extensions, hmacSecretKey != nil)

	// Extract credProtect level for credential storage
	var credProtectLevel uint8
	if cp, ok := extensionOutputs["credProtect"]; ok {
		credProtectLevel = cp.(uint8)
	}

	authDataBuilder := NewAuthDataBuilder(req.RP.ID).
		WithFlags(flags).
		WithSignCount(0).
		WithAttestedCredentialData(a.state.AAGUID, credentialID, publicKeyCOSE)

	authData, err := authDataBuilder.Build()
	if err != nil {
		return nil, err
	}
	debugLog("[MAKECRED] authData length=%d bytes", len(authData))
	debugLog("[MAKECRED] authData hex: %x", authData)

	// Store the credential
	if err := a.storeCredential(
		credentialID,
		req.RP,
		req.User,
		privateKeyBytes,
		publicKeyCOSE,
		selectedAlgorithm,
		discoverable,
		hmacSecretKey,
		credProtectLevel,
	); err != nil {
		return nil, err
	}

	// Create attestation statement (using "none" format)
	response := &MakeCredentialResponse{
		Fmt:      AttestationFormatNone,
		AuthData: authData,
		AttStmt:  make(map[string]interface{}),
	}

	// Encode the response
	respBytes, err := EncodeMakeCredentialResponse(response)
	if err != nil {
		return nil, err
	}
	debugLog("[MAKECRED] response CBOR length=%d bytes", len(respBytes))
	debugLog("[MAKECRED] response CBOR hex: %x", respBytes)

	return a.successResponse(respBytes), nil
}

// DecodeMakeCredentialRequest decodes a CBOR-encoded MakeCredential request.
// The input should not include the command byte (0x01).
func DecodeMakeCredentialRequest(data []byte) (*MakeCredentialRequest, error) {
	if len(data) == 0 {
		return nil, ErrInvalidParameter
	}

	var rawMap map[int]interface{}
	if err := cbor.Unmarshal(data, &rawMap); err != nil {
		return nil, ErrInvalidParameter
	}

	req := &MakeCredentialRequest{
		Extensions: make(map[string]interface{}),
		Options:    make(map[string]bool),
	}

	// Parse clientDataHash (0x01, required)
	if clientDataHash, ok := rawMap[makeCredentialKeyClientDataHash]; ok {
		if hash, ok := clientDataHash.([]byte); ok {
			req.ClientDataHash = hash
		} else {
			return nil, ErrInvalidClientDataHash
		}
	} else {
		return nil, ErrMissingClientDataHash
	}

	// Parse rp (0x02, required)
	if rpRaw, ok := rawMap[makeCredentialKeyRP]; ok {
		rp, err := parseMakeCredentialRP(rpRaw)
		if err != nil {
			return nil, err
		}
		req.RP = rp
	} else {
		return nil, ErrMissingRP
	}

	// Parse user (0x03, required)
	if userRaw, ok := rawMap[makeCredentialKeyUser]; ok {
		user, err := parseMakeCredentialUser(userRaw)
		if err != nil {
			return nil, err
		}
		req.User = user
	} else {
		return nil, ErrMissingUser
	}

	// Parse pubKeyCredParams (0x04, required)
	if paramsRaw, ok := rawMap[makeCredentialKeyPubKeyCredParams]; ok {
		params, err := parsePubKeyCredParams(paramsRaw)
		if err != nil {
			return nil, err
		}
		req.PubKeyCredParams = params
	} else {
		return nil, ErrMissingPubKeyCredParams
	}

	// Parse excludeList (0x05, optional)
	if excludeRaw, ok := rawMap[makeCredentialKeyExcludeList]; ok {
		excludeList, err := parseMakeCredentialExcludeList(excludeRaw)
		if err != nil {
			return nil, err
		}
		req.ExcludeList = excludeList
	}

	// Parse extensions (0x06, optional)
	if extRaw, ok := rawMap[makeCredentialKeyExtensions]; ok {
		if extensions, ok := extRaw.(map[string]interface{}); ok {
			req.Extensions = extensions
		} else if extMap, ok := extRaw.(map[interface{}]interface{}); ok {
			req.Extensions = convertMakeCredentialStringKeyMap(extMap)
		}
	}

	// Parse options (0x07, optional)
	if optRaw, ok := rawMap[makeCredentialKeyOptions]; ok {
		options, err := parseMakeCredentialOptions(optRaw)
		if err != nil {
			return nil, err
		}
		req.Options = options
	}

	// Parse pinUvAuthParam (0x08, optional)
	if authParam, ok := rawMap[makeCredentialKeyPINUVAuthParam]; ok {
		if param, ok := authParam.([]byte); ok {
			req.PINUVAuthParam = param
		}
	}

	// Parse pinUvAuthProtocol (0x09, optional)
	if authProtocol, ok := rawMap[makeCredentialKeyPINUVAuthProtocol]; ok {
		if protocol, err := makeCredentialToUint8(authProtocol); err == nil {
			req.PINUVAuthProtocol = protocol
		}
	}

	// Parse enterpriseAttestation (0x0A, optional)
	if eaRaw, ok := rawMap[makeCredentialKeyEnterpriseAttestation]; ok {
		if ea, err := makeCredentialToUint8(eaRaw); err == nil {
			req.EnterpriseAttestation = ea
		}
	}

	return req, nil
}

// EncodeMakeCredentialResponse encodes a MakeCredential response to CBOR.
func EncodeMakeCredentialResponse(resp *MakeCredentialResponse) ([]byte, error) {
	if resp == nil {
		return nil, ErrInvalidParameter
	}

	responseMap := map[int]interface{}{
		makeCredentialResponseKeyFmt:      resp.Fmt,
		makeCredentialResponseKeyAuthData: resp.AuthData,
		makeCredentialResponseKeyAttStmt:  resp.AttStmt,
	}

	// Use canonical CBOR encoding for CTAP2 compliance
	encoded, err := encodeCBOR(responseMap)
	if err != nil {
		return nil, err
	}

	// Debug: dump the CBOR response
	criticalLog("=== MAKECREDENTIAL CBOR RESPONSE ===")
	criticalLog("fmt: %s", resp.Fmt)
	criticalLog("authData (%d bytes): %x", len(resp.AuthData), resp.AuthData)
	criticalLog("attStmt: %+v", resp.AttStmt)
	criticalLog("CBOR encoded (%d bytes): %x", len(encoded), encoded)
	criticalLog("=== END MAKECREDENTIAL CBOR RESPONSE ===")

	return encoded, nil
}

// validateMakeCredentialRequest validates the MakeCredential request parameters.
func (a *Authenticator) validateMakeCredentialRequest(req *MakeCredentialRequest) error {
	// Validate clientDataHash (must be 32 bytes)
	if len(req.ClientDataHash) != ClientDataHashSize {
		return ErrInvalidClientDataHash
	}

	// Validate RP
	if req.RP.ID == "" {
		return ErrMissingRPID
	}

	// Validate User
	if len(req.User.ID) == 0 {
		return ErrMissingUserID
	}

	// Validate pubKeyCredParams
	if len(req.PubKeyCredParams) == 0 {
		return ErrMissingPubKeyCredParams
	}

	return nil
}

// checkExcludeList checks if any credential in the exclude list exists.
// Returns ErrCredentialExcluded if a matching credential is found.
func (a *Authenticator) checkExcludeList(excludeList []CredentialDescriptor, rpID string) error {
	for _, desc := range excludeList {
		cred, err := a.storage.Load(desc.ID)
		if err == nil && cred != nil && cred.RPID == rpID {
			return ErrCredentialExcluded
		}
	}
	return nil
}

// selectAlgorithm selects the first supported algorithm from pubKeyCredParams.
// The order indicates client preference, but we prefer ES256 if available.
func (a *Authenticator) selectAlgorithm(params []PublicKeyCredentialParam) (int, error) {
	// First pass: look for ES256 (most common and recommended)
	for _, param := range params {
		if param.Type != "public-key" {
			continue
		}
		if param.Alg == COSEAlgES256 && a.config.SupportsAlgorithm(COSEAlgES256) {
			return COSEAlgES256, nil
		}
	}

	// Second pass: accept any supported algorithm in client preference order
	for _, param := range params {
		if param.Type != "public-key" {
			continue
		}
		if a.config.SupportsAlgorithm(param.Alg) {
			return param.Alg, nil
		}
	}

	return 0, ErrNoSupportedAlgorithm
}

// checkCredentialLimits verifies credential storage limits are not exceeded.
func (a *Authenticator) checkCredentialLimits(options map[string]bool) error {
	// Check total credential limit
	count, err := a.storage.Count()
	if err != nil {
		return ErrStorageError
	}
	if count >= a.config.MaxCredentials {
		return ErrCredentialLimitReached
	}

	// Check resident key limit if creating discoverable credential
	if options["rk"] {
		discoverableCount, err := a.storage.CountDiscoverable()
		if err != nil {
			return ErrStorageError
		}
		if discoverableCount >= a.config.MaxResidentCredentials {
			return ErrResidentKeyLimitReached
		}
	}

	return nil
}

// shouldCreateDiscoverable determines if a discoverable credential should be created.
func (a *Authenticator) shouldCreateDiscoverable(options map[string]bool) bool {
	if !a.config.EnableResidentKey {
		return false
	}
	// Check if "rk" option is explicitly set
	if rk, ok := options["rk"]; ok {
		return rk
	}
	return false
}

// shouldGenerateHMACSecret determines if an HMAC secret key should be generated.
func (a *Authenticator) shouldGenerateHMACSecret(extensions map[string]interface{}) bool {
	if !a.config.EnableHMACSecret {
		return false
	}
	if hmacSecret, ok := extensions["hmac-secret"]; ok {
		if requested, ok := hmacSecret.(bool); ok && requested {
			return true
		}
	}
	return false
}

// userVerificationSatisfied checks if user verification requirements are met.
func (a *Authenticator) userVerificationSatisfied(req *MakeCredentialRequest) bool {
	// If PIN is set on the authenticator, consider UV satisfied after user presence
	// is confirmed. This is consistent with CTAP2.1 behavior where authenticators
	// with client PIN capability set UV flag when user interaction is performed.
	if a.state.PINSet {
		return true
	}

	// Check if UV was explicitly requested in options
	if uv, ok := req.Options["uv"]; ok && uv {
		// UV was explicitly requested - satisfy it for software authenticator
		// In production with hardware, this would require biometric or PIN
		return true
	}

	return false
}

// processMakeCredentialExtensions processes requested extensions and returns output values.
func (a *Authenticator) processMakeCredentialExtensions(extensions map[string]interface{}, hmacSecretEnabled bool) map[string]interface{} {
	outputs := make(map[string]interface{})

	// Process hmac-secret extension
	if hmacSecretEnabled {
		outputs["hmac-secret"] = true
	}

	// Process credProtect extension
	if credProtect, ok := extensions["credProtect"]; ok {
		if level, err := makeCredentialToUint8(credProtect); err == nil {
			if level >= CredProtectUserVerificationOptional && level <= CredProtectUserVerificationRequired {
				outputs["credProtect"] = level
			}
		}
	}

	return outputs
}

// generateCredentialKeyPair generates a credential key pair using the key backend
// if available, or the legacy crypto.go path. Returns PKCS#8-encoded private key
// bytes (nil for non-exportable backends like TPM2) and COSE-encoded public key.
func (a *Authenticator) generateCredentialKeyPair(algorithm int, credentialID []byte) ([]byte, []byte, error) {
	if a.keyBackend != nil {
		// Key backend path: delegate key generation
		handle, publicKeyCOSE, err := a.keyBackend.GenerateCredentialKey(algorithm, credentialID)
		if err != nil {
			return nil, nil, ErrCryptoError
		}

		// Try to export private key for storage (software backends support this)
		var privateKeyBytes []byte
		if a.keyBackend.Capabilities().SupportsExport {
			privateKeyBytes, err = a.keyBackend.ExportPrivateKey(handle)
			if err != nil {
				return nil, nil, ErrCryptoError
			}
		}
		// For non-exportable backends (TPM2), privateKeyBytes remains nil.
		// The backend.LoadKey + backend.Sign path handles signing at assertion time.

		return privateKeyBytes, publicKeyCOSE, nil
	}

	// Legacy path: generate key via crypto.go
	privateKey, publicKeyCOSE, err := GenerateCredentialKey(algorithm)
	if err != nil {
		return nil, nil, ErrCryptoError
	}

	// Serialize private key to PKCS#8
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, ErrCryptoError
	}

	return privateKeyBytes, publicKeyCOSE, nil
}

// storeCredential persists a newly created credential.
// privateKeyBytes may be nil for non-exportable backends (e.g., TPM2).
func (a *Authenticator) storeCredential(
	credentialID []byte,
	rp RelyingParty,
	user User,
	privateKeyBytes []byte,
	publicKeyCOSE []byte,
	algorithm int,
	discoverable bool,
	hmacSecretKey []byte,
	credProtect uint8,
) error {
	storedCred := &StoredCredential{
		CredentialID:    credentialID,
		RPID:            rp.ID,
		RPName:          rp.Name,
		UserID:          user.ID,
		UserName:        user.Name,
		UserDisplayName: user.DisplayName,
		PrivateKey:      privateKeyBytes,
		PublicKeyCOSE:   publicKeyCOSE,
		Algorithm:       algorithm,
		SignCount:       0,
		Discoverable:    discoverable,
		HMACSecretKey:   hmacSecretKey,
		CredProtect:     credProtect,
		CreatedAt:       time.Now().Unix(),
	}

	if err := a.storage.Store(storedCred); err != nil {
		return ErrStorageError
	}

	return nil
}

// parseMakeCredentialRP parses the rp parameter from raw CBOR data.
func parseMakeCredentialRP(raw interface{}) (RelyingParty, error) {
	var rp RelyingParty

	rpMap, ok := makeCredentialToStringKeyMap(raw)
	if !ok {
		return rp, ErrInvalidParameter
	}

	if id, ok := rpMap["id"].(string); ok {
		rp.ID = id
	} else {
		return rp, ErrMissingRPID
	}

	if name, ok := rpMap["name"].(string); ok {
		rp.Name = name
	}

	if icon, ok := rpMap["icon"].(string); ok {
		rp.Icon = icon
	}

	return rp, nil
}

// parseMakeCredentialUser parses the user parameter from raw CBOR data.
func parseMakeCredentialUser(raw interface{}) (User, error) {
	var user User

	userMap, ok := makeCredentialToStringKeyMap(raw)
	if !ok {
		return user, ErrInvalidParameter
	}

	if id, ok := userMap["id"].([]byte); ok {
		user.ID = id
	} else {
		return user, ErrMissingUserID
	}

	if name, ok := userMap["name"].(string); ok {
		user.Name = name
	}

	if displayName, ok := userMap["displayName"].(string); ok {
		user.DisplayName = displayName
	}

	if icon, ok := userMap["icon"].(string); ok {
		user.Icon = icon
	}

	return user, nil
}

// parsePubKeyCredParams parses the pubKeyCredParams array from raw CBOR data.
func parsePubKeyCredParams(raw interface{}) ([]PublicKeyCredentialParam, error) {
	paramsArray, ok := raw.([]interface{})
	if !ok {
		return nil, ErrInvalidParameter
	}

	if len(paramsArray) == 0 {
		return nil, ErrMissingPubKeyCredParams
	}

	var params []PublicKeyCredentialParam
	for _, item := range paramsArray {
		paramMap, ok := makeCredentialToStringKeyMap(item)
		if !ok {
			continue
		}

		param := PublicKeyCredentialParam{}

		if typ, ok := paramMap["type"].(string); ok {
			param.Type = typ
		} else {
			continue
		}

		if alg, ok := paramMap["alg"]; ok {
			if algInt, err := makeCredentialToInt(alg); err == nil {
				param.Alg = algInt
			} else {
				continue
			}
		} else {
			continue
		}

		params = append(params, param)
	}

	if len(params) == 0 {
		return nil, ErrMissingPubKeyCredParams
	}

	return params, nil
}

// parseMakeCredentialExcludeList parses an array of credential descriptors from raw CBOR data.
func parseMakeCredentialExcludeList(raw interface{}) ([]CredentialDescriptor, error) {
	descriptorArray, ok := raw.([]interface{})
	if !ok {
		return nil, nil
	}

	var descriptors []CredentialDescriptor
	for _, item := range descriptorArray {
		descMap, ok := makeCredentialToStringKeyMap(item)
		if !ok {
			continue
		}

		desc := CredentialDescriptor{}

		if typ, ok := descMap["type"].(string); ok {
			desc.Type = typ
		}

		if id, ok := descMap["id"].([]byte); ok {
			desc.ID = id
		} else {
			continue // ID is required
		}

		if transports, ok := descMap["transports"].([]interface{}); ok {
			for _, t := range transports {
				if transport, ok := t.(string); ok {
					desc.Transports = append(desc.Transports, transport)
				}
			}
		}

		descriptors = append(descriptors, desc)
	}

	return descriptors, nil
}

// parseMakeCredentialOptions parses the options map from raw CBOR data.
func parseMakeCredentialOptions(raw interface{}) (map[string]bool, error) {
	options := make(map[string]bool)

	optMap, ok := makeCredentialToStringKeyMap(raw)
	if !ok {
		return options, nil
	}

	for key, value := range optMap {
		if boolVal, ok := value.(bool); ok {
			options[key] = boolVal
		}
	}

	return options, nil
}

// makeCredentialToStringKeyMap converts a map with interface{} keys to a map with string keys.
func makeCredentialToStringKeyMap(raw interface{}) (map[string]interface{}, bool) {
	switch m := raw.(type) {
	case map[string]interface{}:
		return m, true
	case map[interface{}]interface{}:
		result := make(map[string]interface{})
		for k, v := range m {
			if key, ok := k.(string); ok {
				result[key] = v
			}
		}
		return result, true
	default:
		return nil, false
	}
}

// convertMakeCredentialStringKeyMap converts map[interface{}]interface{} to map[string]interface{}.
func convertMakeCredentialStringKeyMap(m map[interface{}]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for k, v := range m {
		if key, ok := k.(string); ok {
			result[key] = v
		}
	}
	return result
}

// makeCredentialToUint8 converts various integer types to uint8.
func makeCredentialToUint8(v interface{}) (uint8, error) {
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

// makeCredentialToInt converts various integer types to int.
func makeCredentialToInt(v interface{}) (int, error) {
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

// MakeCredential creates a new FIDO2 credential for the specified relying party.
// This is a high-level convenience method that creates the request structure
// and processes it through the standard CTAP2 flow.
//
// Parameters:
//   - clientDataHash: SHA-256 hash of the client data (32 bytes)
//   - rp: Relying party information
//   - user: User entity information
//   - pubKeyCredParams: List of acceptable credential algorithms
//   - opts: Optional parameters (excludeList, extensions, options)
//
// Returns:
//   - MakeCredentialResponse containing the new credential
//   - Error if credential creation fails
func (a *Authenticator) MakeCredential(
	clientDataHash []byte,
	rp RelyingParty,
	user User,
	pubKeyCredParams []PublicKeyCredentialParam,
	opts *MakeCredentialOptions,
) (*MakeCredentialResponse, error) {
	req := &MakeCredentialRequest{
		ClientDataHash:   clientDataHash,
		RP:               rp,
		User:             user,
		PubKeyCredParams: pubKeyCredParams,
		Extensions:       make(map[string]interface{}),
		Options:          make(map[string]bool),
	}

	if opts != nil {
		req.ExcludeList = opts.ExcludeList
		if opts.Extensions != nil {
			req.Extensions = opts.Extensions
		}
		if opts.Options != nil {
			req.Options = opts.Options
		}
		req.PINUVAuthParam = opts.PINUVAuthParam
		req.PINUVAuthProtocol = opts.PINUVAuthProtocol
	}

	// Validate the request
	if err := a.validateMakeCredentialRequest(req); err != nil {
		return nil, err
	}

	// Check exclude list for existing credentials
	if err := a.checkExcludeList(req.ExcludeList, req.RP.ID); err != nil {
		return nil, err
	}

	// Select algorithm from pubKeyCredParams
	selectedAlgorithm, err := a.selectAlgorithm(req.PubKeyCredParams)
	if err != nil {
		return nil, err
	}

	// Check credential limits
	if err := a.checkCredentialLimits(req.Options); err != nil {
		return nil, err
	}

	// Generate credential ID
	credentialID, err := GenerateCredentialID()
	if err != nil {
		return nil, ErrCryptoError
	}
	debugLog("[MAKECRED] generated credentialID length=%d, hex: %x", len(credentialID), credentialID)

	// Generate credential key pair via backend or legacy path
	privateKeyBytes, publicKeyCOSE, err := a.generateCredentialKeyPair(selectedAlgorithm, credentialID)
	if err != nil {
		return nil, err
	}
	debugLog("[MAKECRED] generated publicKeyCOSE length=%d, hex: %x", len(publicKeyCOSE), publicKeyCOSE)

	// Critical logging for registration - always output to stderr
	criticalLog("=== REGISTRATION CRYPTO DEBUG ===")
	criticalLog("rpId: %s", req.RP.ID)
	criticalLog("credentialID: %x", credentialID)
	criticalLog("publicKeyCOSE (%d bytes): %x", len(publicKeyCOSE), publicKeyCOSE)
	criticalLog("algorithm: %d", selectedAlgorithm)
	criticalLog("=== END REGISTRATION CRYPTO DEBUG ===")

	// Determine if this should be a discoverable credential
	discoverable := a.shouldCreateDiscoverable(req.Options)

	// Generate HMAC secret key if extension requested
	var hmacSecretKey []byte
	if a.shouldGenerateHMACSecret(req.Extensions) {
		hmacSecretKey, err = GenerateHMACSecretKey()
		if err != nil {
			return nil, ErrCryptoError
		}
	}

	// Request user presence
	ctx := context.Background()
	if err := a.requestUserPresence(ctx, req.RP.ID, req.RP.Name, req.User.Name, "register"); err != nil {
		return nil, err
	}

	// Build authenticator data with AT flag (attested credential data)
	flags := FlagUP | FlagAT // User present + Attested credential data
	if a.userVerificationSatisfied(req) {
		flags |= FlagUV
	}

	// Process extension inputs for credential storage (e.g., credProtect level).
	// Extension outputs are intentionally NOT included in authData because many
	// WebAuthn RP implementations do not correctly parse the ED flag and will
	// read the extension bytes as part of the COSE public key, corrupting it.
	extensionOutputs := a.processMakeCredentialExtensions(req.Extensions, hmacSecretKey != nil)

	// Extract credProtect level for credential storage
	var credProtectLevel uint8
	if cp, ok := extensionOutputs["credProtect"]; ok {
		credProtectLevel = cp.(uint8)
	}

	authDataBuilder := NewAuthDataBuilder(req.RP.ID).
		WithFlags(flags).
		WithSignCount(0).
		WithAttestedCredentialData(a.state.AAGUID, credentialID, publicKeyCOSE)

	authData, err := authDataBuilder.Build()
	if err != nil {
		return nil, err
	}

	// Store the credential
	if err := a.storeCredential(
		credentialID,
		req.RP,
		req.User,
		privateKeyBytes,
		publicKeyCOSE,
		selectedAlgorithm,
		discoverable,
		hmacSecretKey,
		credProtectLevel,
	); err != nil {
		return nil, err
	}

	// Create attestation statement (using "none" format)
	return &MakeCredentialResponse{
		Fmt:      AttestationFormatNone,
		AuthData: authData,
		AttStmt:  make(map[string]interface{}),
	}, nil
}
