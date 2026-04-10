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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"

	"github.com/fxamacker/cbor/v2"
)

// CTAP2.1 authenticatorConfig command constants.
const (
	// AuthConfigCmdEnableEnterpriseAttestation enables enterprise attestation.
	AuthConfigCmdEnableEnterpriseAttestation = 0x01

	// AuthConfigCmdToggleAlwaysUv toggles the alwaysUv setting.
	AuthConfigCmdToggleAlwaysUv = 0x02

	// AuthConfigCmdSetMinPINLength sets the minimum PIN length.
	AuthConfigCmdSetMinPINLength = 0x03

	// AuthConfigCmdVendorPrototype is the base for vendor-specific subcommands.
	// Vendor subcommands use the range 0x80-0xFF.
	AuthConfigCmdVendorPrototype = 0x80
)

// Vendor SO PIN subcommands (under VendorPrototype).
const (
	// VendorCmdSetSOPIN initializes the SO PIN for the first time.
	VendorCmdSetSOPIN = 0x01

	// VendorCmdChangeSOPIN changes the existing SO PIN.
	VendorCmdChangeSOPIN = 0x02

	// VendorCmdUnlockWithSOPIN unlocks the KeyManager with SO PIN.
	VendorCmdUnlockWithSOPIN = 0x03

	// VendorCmdResetUserPIN resets the user PIN (requires SO unlock).
	VendorCmdResetUserPIN = 0x04

	// VendorCmdReplaceAttestKey replaces the attestation key (requires SO unlock).
	VendorCmdReplaceAttestKey = 0x05

	// VendorCmdGetSOPINRetries returns the SO PIN retry count.
	VendorCmdGetSOPINRetries = 0x06

	// VendorCmdSetRPPolicy sets a per-RP policy (requires SO unlock).
	VendorCmdSetRPPolicy = 0x07

	// VendorCmdGetRPPolicy gets a per-RP policy.
	VendorCmdGetRPPolicy = 0x08

	// VendorCmdDeleteRPPolicy deletes a per-RP policy (requires SO unlock).
	VendorCmdDeleteRPPolicy = 0x09

	// VendorCmdListRPPolicies lists all per-RP policies.
	VendorCmdListRPPolicies = 0x0A

	// VendorCmdSetProfile sets authenticator profile configuration (requires SO unlock).
	VendorCmdSetProfile = 0x0B
)

// authenticatorConfig CBOR request parameter keys.
const (
	configKeySubCommand        = 0x01
	configKeySubCommandParams  = 0x02
	configKeyPinUvAuthProtocol = 0x03
	configKeyPinUvAuthParam    = 0x04
)

// authenticatorConfig vendor subcommand parameter keys.
const (
	vendorParamKeyPin            = "pin"
	vendorParamKeyNewPin         = "newPin"
	vendorParamKeyNewPinHash     = "newPinHash"
	vendorParamKeyAttestCert     = "attestCert"
	vendorParamKeyVendorCmd      = "vendorCmd"
	vendorParamKeyRPID           = "rpId"
	vendorParamKeyUVOverride     = "uvOverride"
	vendorParamKeyUPOverride     = "upOverride"
	vendorParamKeyAttestOverride = "attestationOverride"
	vendorParamKeyEnterprise     = "enterprise"
	vendorParamKeyBlocked        = "blocked"
	vendorParamKeyTransports     = "transports"
	vendorParamKeyEnableEP       = "enableEnterpriseAttestation"
)

// authenticatorConfig response keys.
const (
	configResponseKeyRetries  = 0x01
	configResponseKeyPolicy   = 0x02
	configResponseKeyPolicies = 0x03
)

// Config command errors.
var (
	// ErrConfigNotEnabled indicates authenticatorConfig is not enabled.
	ErrConfigNotEnabled = errors.New("authenticator: config command not enabled")

	// ErrConfigMissingSubCommand indicates subCommand is missing from request.
	ErrConfigMissingSubCommand = errors.New("authenticator: missing subCommand")

	// ErrConfigInvalidVendorCmd indicates an invalid vendor subcommand.
	ErrConfigInvalidVendorCmd = errors.New("authenticator: invalid vendor subcommand")

	// ErrConfigMissingPin indicates the pin parameter is missing.
	ErrConfigMissingPin = errors.New("authenticator: missing pin parameter")

	// ErrConfigMissingNewPin indicates the newPin parameter is missing.
	ErrConfigMissingNewPin = errors.New("authenticator: missing newPin parameter")

	// ErrConfigMissingNewPinHash indicates the newPinHash parameter is missing.
	ErrConfigMissingNewPinHash = errors.New("authenticator: missing newPinHash parameter")

	// ErrConfigInvalidPinHash indicates the newPinHash has invalid length.
	ErrConfigInvalidPinHash = errors.New("authenticator: invalid pin hash length")
)

// configRequest represents a decoded authenticatorConfig request.
type configRequest struct {
	subCommand        uint8
	subCommandParams  map[interface{}]interface{}
	pinUvAuthProtocol uint8
	pinUvAuthParam    []byte
}

// vendorSOPINHandlerFunc is the function signature for vendor SO PIN handlers.
type vendorSOPINHandlerFunc func(a *Authenticator, params map[interface{}]interface{}) ([]byte, error)

// vendorSOPINHandlers provides O(1) dispatch for vendor SO PIN subcommands.
var vendorSOPINHandlers = map[uint8]vendorSOPINHandlerFunc{
	VendorCmdSetSOPIN:         handleVendorSetSOPIN,
	VendorCmdChangeSOPIN:      handleVendorChangeSOPIN,
	VendorCmdUnlockWithSOPIN:  handleVendorUnlockWithSOPIN,
	VendorCmdResetUserPIN:     handleVendorResetUserPIN,
	VendorCmdReplaceAttestKey: handleVendorReplaceAttestKey,
	VendorCmdGetSOPINRetries:  handleVendorGetSOPINRetries,
	VendorCmdSetRPPolicy:      handleVendorSetRPPolicy,
	VendorCmdGetRPPolicy:      handleVendorGetRPPolicy,
	VendorCmdDeleteRPPolicy:   handleVendorDeleteRPPolicy,
	VendorCmdListRPPolicies:   handleVendorListRPPolicies,
	VendorCmdSetProfile:       handleVendorSetProfile,
}

// handleConfig implements the CTAP2.1 authenticatorConfig command (0x0D).
// This command provides device configuration and vendor-specific operations.
func (a *Authenticator) handleConfig(data []byte) ([]byte, error) {
	req, err := decodeConfigRequest(data)
	if err != nil {
		return nil, err
	}

	// Dispatch based on subCommand
	switch req.subCommand {
	case AuthConfigCmdEnableEnterpriseAttestation:
		return a.handleConfigEnableEnterpriseAttestation(req)

	case AuthConfigCmdToggleAlwaysUv:
		return a.handleConfigToggleAlwaysUv(req)

	case AuthConfigCmdSetMinPINLength:
		return a.handleConfigSetMinPINLength(req)

	default:
		// Check if this is a vendor prototype command (0x80+)
		if req.subCommand >= AuthConfigCmdVendorPrototype {
			return a.handleConfigVendorPrototype(req)
		}
		return nil, ErrInvalidSubcommand
	}
}

// decodeConfigRequest decodes a CBOR-encoded authenticatorConfig request.
func decodeConfigRequest(data []byte) (*configRequest, error) {
	if len(data) == 0 {
		return nil, ErrConfigMissingSubCommand
	}

	var raw map[int]interface{}
	if err := cbor.Unmarshal(data, &raw); err != nil {
		return nil, ErrCBORDecodingFailed
	}

	req := &configRequest{}

	// Extract subCommand (required)
	subCmdRaw, ok := raw[configKeySubCommand]
	if !ok {
		return nil, ErrConfigMissingSubCommand
	}
	subCmd, err := toUint8(subCmdRaw)
	if err != nil {
		return nil, ErrInvalidParameter
	}
	req.subCommand = subCmd

	// Extract subCommandParams (optional)
	if paramsRaw, ok := raw[configKeySubCommandParams]; ok {
		params, ok := paramsRaw.(map[interface{}]interface{})
		if !ok {
			return nil, ErrInvalidParameter
		}
		req.subCommandParams = params
	}

	// Extract pinUvAuthProtocol (optional)
	if protoRaw, ok := raw[configKeyPinUvAuthProtocol]; ok {
		proto, err := toUint8(protoRaw)
		if err != nil {
			return nil, ErrInvalidParameter
		}
		req.pinUvAuthProtocol = proto
	}

	// Extract pinUvAuthParam (optional)
	if authRaw, ok := raw[configKeyPinUvAuthParam]; ok {
		auth, ok := authRaw.([]byte)
		if !ok {
			return nil, ErrInvalidParameter
		}
		req.pinUvAuthParam = auth
	}

	return req, nil
}

// handleConfigEnableEnterpriseAttestation enables enterprise attestation feature.
// This requires PIN/UV auth verification.
func (a *Authenticator) handleConfigEnableEnterpriseAttestation(req *configRequest) ([]byte, error) {
	// Verify PIN/UV auth for this operation
	if err := a.verifyConfigPinUvAuth(req, AuthConfigCmdEnableEnterpriseAttestation); err != nil {
		return nil, err
	}

	// Enterprise attestation is a platform feature indicator
	// For this authenticator, we acknowledge the request but do not change behavior
	// since enterprise attestation requires platform-specific integration.
	return a.successResponse(nil), nil
}

// handleConfigToggleAlwaysUv toggles the alwaysUv configuration option.
// When enabled, user verification is required for all operations.
func (a *Authenticator) handleConfigToggleAlwaysUv(req *configRequest) ([]byte, error) {
	// Verify PIN/UV auth for this operation
	if err := a.verifyConfigPinUvAuth(req, AuthConfigCmdToggleAlwaysUv); err != nil {
		return nil, err
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Toggle the alwaysUv setting
	a.config.AlwaysUV = !a.config.AlwaysUV

	// Persist the state change
	if err := a.storage.SaveState(a.state); err != nil {
		return nil, ErrStorageError
	}

	return a.successResponse(nil), nil
}

// handleConfigSetMinPINLength sets the minimum PIN length requirement.
// This operation requires PIN/UV auth verification.
func (a *Authenticator) handleConfigSetMinPINLength(req *configRequest) ([]byte, error) {
	// Verify PIN/UV auth for this operation
	if err := a.verifyConfigPinUvAuth(req, AuthConfigCmdSetMinPINLength); err != nil {
		return nil, err
	}

	// Extract newMinPINLength from subCommandParams
	if req.subCommandParams == nil {
		return nil, ErrInvalidParameter
	}

	newMinLengthRaw, ok := req.subCommandParams["newMinPINLength"]
	if !ok {
		newMinLengthRaw, ok = req.subCommandParams[int64(0x01)]
		if !ok {
			return nil, ErrInvalidParameter
		}
	}

	newMinLength, err := toUint8(newMinLengthRaw)
	if err != nil {
		return nil, ErrInvalidParameter
	}

	// Validate the new minimum length
	if newMinLength < DefaultPINMinLength {
		return nil, ErrPINPolicyViolation
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Update the PIN minimum length
	a.config.PINMinLength = int(newMinLength)

	// Persist the state change
	if err := a.storage.SaveState(a.state); err != nil {
		return nil, ErrStorageError
	}

	return a.successResponse(nil), nil
}

// handleConfigVendorPrototype dispatches vendor-specific subcommands.
// Vendor commands are used for SO PIN management operations.
func (a *Authenticator) handleConfigVendorPrototype(req *configRequest) ([]byte, error) {
	// Extract the vendor subcommand from subCommandParams
	if req.subCommandParams == nil {
		return nil, ErrInvalidParameter
	}

	vendorCmdRaw, ok := req.subCommandParams[vendorParamKeyVendorCmd]
	if !ok {
		// Try integer key
		vendorCmdRaw, ok = req.subCommandParams[int64(0x01)]
		if !ok {
			return nil, ErrConfigInvalidVendorCmd
		}
	}

	vendorCmd, err := toUint8(vendorCmdRaw)
	if err != nil {
		return nil, ErrConfigInvalidVendorCmd
	}

	// Dispatch to vendor handler using map-based lookup
	handler, ok := vendorSOPINHandlers[vendorCmd]
	if !ok {
		return nil, ErrConfigInvalidVendorCmd
	}

	return handler(a, req.subCommandParams)
}

// handleVendorSetSOPIN initializes the SO PIN for the first time.
// This operation does not require pinUvAuthParam since it's the initial setup.
func handleVendorSetSOPIN(a *Authenticator, params map[interface{}]interface{}) ([]byte, error) {
	// Extract SO PIN from params
	pin, err := extractStringParam(params, vendorParamKeyPin)
	if err != nil {
		return nil, ErrConfigMissingPin
	}

	// Verify key manager is available
	if a.keyManager == nil {
		return nil, ErrKeyManagerNoSOPIN
	}

	// Initialize SO PIN
	if err := a.keyManager.InitializeSOPIN(pin); err != nil {
		return nil, err
	}

	// Persist state
	a.mu.Lock()
	defer a.mu.Unlock()

	if err := a.storage.SaveState(a.state); err != nil {
		return nil, ErrStorageError
	}

	return a.successResponse(nil), nil
}

// handleVendorChangeSOPIN changes the existing SO PIN.
// This operation requires the current SO PIN for verification.
func handleVendorChangeSOPIN(a *Authenticator, params map[interface{}]interface{}) ([]byte, error) {
	// Extract current SO PIN
	currentPin, err := extractStringParam(params, vendorParamKeyPin)
	if err != nil {
		return nil, ErrConfigMissingPin
	}

	// Extract new SO PIN
	newPin, err := extractStringParam(params, vendorParamKeyNewPin)
	if err != nil {
		return nil, ErrConfigMissingNewPin
	}

	// Verify key manager is available
	if a.keyManager == nil {
		return nil, ErrKeyManagerNoSOPIN
	}

	// Verify current SO PIN and get SMK
	if a.state.SOPINManager == nil {
		return nil, ErrSOPINNotSet
	}

	currentSMK, err := a.state.SOPINManager.Verify(currentPin)
	if err != nil {
		return nil, err
	}
	defer clearBytes(currentSMK)

	// Change SO PIN
	if err := a.keyManager.ChangeSOPIN(currentSMK, newPin); err != nil {
		return nil, err
	}

	// Persist state
	a.mu.Lock()
	defer a.mu.Unlock()

	if err := a.storage.SaveState(a.state); err != nil {
		return nil, ErrStorageError
	}

	return a.successResponse(nil), nil
}

// handleVendorUnlockWithSOPIN unlocks the KeyManager with SO PIN.
// This makes key material available for subsequent operations.
func handleVendorUnlockWithSOPIN(a *Authenticator, params map[interface{}]interface{}) ([]byte, error) {
	// Extract SO PIN
	pin, err := extractStringParam(params, vendorParamKeyPin)
	if err != nil {
		return nil, ErrConfigMissingPin
	}

	// Verify key manager is available
	if a.keyManager == nil {
		return nil, ErrKeyManagerNoSOPIN
	}

	// Unlock with SO PIN
	if err := a.keyManager.UnlockWithSOPIN(pin); err != nil {
		return nil, err
	}

	return a.successResponse(nil), nil
}

// handleVendorResetUserPIN resets the user PIN when SO is unlocked.
// This operation requires the KeyManager to be SO-unlocked.
func handleVendorResetUserPIN(a *Authenticator, params map[interface{}]interface{}) ([]byte, error) {
	// Verify key manager is SO-unlocked
	if a.keyManager == nil {
		return nil, ErrKeyManagerNoSOPIN
	}

	if !a.keyManager.IsSOUnlocked() {
		return nil, ErrKeyManagerLocked
	}

	// Extract new PIN hash
	newPinHash, err := extractBytesParam(params, vendorParamKeyNewPinHash)
	if err != nil {
		return nil, ErrConfigMissingNewPinHash
	}

	// Validate PIN hash length (must be 16 bytes - left half of SHA-256)
	if len(newPinHash) != PINHashSize {
		return nil, ErrConfigInvalidPinHash
	}

	// Reset user PIN in key manager (re-wraps CMK with new UMK)
	if err := a.keyManager.ResetUserPIN(newPinHash); err != nil {
		return nil, err
	}

	// Update authenticator state
	a.mu.Lock()
	defer a.mu.Unlock()

	// Store the new PIN hash in state
	a.state.PINHash = make([]byte, len(newPinHash))
	copy(a.state.PINHash, newPinHash)
	a.state.PINSet = true
	a.state.ResetPINRetries()

	// Persist state
	if err := a.storage.SaveState(a.state); err != nil {
		return nil, ErrStorageError
	}
	return a.successResponse(nil), nil
}

// handleVendorReplaceAttestKey replaces the attestation key.
// This operation requires the KeyManager to be SO-unlocked.
func handleVendorReplaceAttestKey(a *Authenticator, params map[interface{}]interface{}) ([]byte, error) {
	// Verify key manager is SO-unlocked
	if a.keyManager == nil {
		return nil, ErrKeyManagerNoSOPIN
	}

	if !a.keyManager.IsSOUnlocked() {
		return nil, ErrKeyManagerLocked
	}

	// Generate new attestation key
	attestKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, ErrKeyGenerationFailed
	}

	// Marshal attestation key to PKCS#8
	attestKeyPKCS8, err := x509.MarshalPKCS8PrivateKey(attestKey)
	if err != nil {
		return nil, ErrCryptoError
	}
	defer clearBytes(attestKeyPKCS8)

	// Wrap the new attestation key
	if err := a.keyManager.WrapAttestationKey(attestKeyPKCS8); err != nil {
		return nil, err
	}

	// Optionally extract and store attestation certificate
	if attestCert, err := extractBytesParam(params, vendorParamKeyAttestCert); err == nil && len(attestCert) > 0 {
		// Validate that it's a valid DER-encoded certificate
		if _, err := x509.ParseCertificate(attestCert); err != nil {
			return nil, ErrInvalidParameter
		}
		a.state.AttestationCert = attestCert
	}

	// Persist state
	a.mu.Lock()
	defer a.mu.Unlock()

	if err := a.storage.SaveState(a.state); err != nil {
		return nil, ErrStorageError
	}

	return a.successResponse(nil), nil
}

// handleVendorGetSOPINRetries returns the current SO PIN retry count.
// This operation does not require authentication.
func handleVendorGetSOPINRetries(a *Authenticator, params map[interface{}]interface{}) ([]byte, error) {
	// Check if SO PIN is configured
	if a.state.SOPINManager == nil || !a.state.SOPINManager.IsSet {
		return nil, ErrSOPINNotSet
	}

	// Get retry count
	retries := a.state.SOPINManager.Retries()

	// Build response
	response := map[int]interface{}{
		configResponseKeyRetries: uint8(retries),
	}

	responseData, err := encodeCBOR(response)
	if err != nil {
		return nil, ErrCBOREncodingFailed
	}

	return a.successResponse(responseData), nil
}

// handleVendorSetRPPolicy sets a per-RP policy (requires SO unlock).
func handleVendorSetRPPolicy(a *Authenticator, params map[interface{}]interface{}) ([]byte, error) {
	// Verify SO is unlocked
	if a.keyManager == nil || !a.keyManager.IsSOUnlocked() {
		return nil, ErrKeyManagerLocked
	}

	// Verify RP policy store is configured
	if a.rpPolicyStore == nil {
		return nil, ErrInvalidParameter
	}

	// Extract RPID
	rpID, err := extractStringParam(params, vendorParamKeyRPID)
	if err != nil {
		return nil, ErrRPPolicyInvalidRPID
	}

	policy := &RPPolicy{RPID: rpID}

	// Extract optional fields
	if uvOverride, err := extractStringParam(params, vendorParamKeyUVOverride); err == nil {
		policy.UVOverride = uvOverride
	}
	if attestOverride, err := extractStringParam(params, vendorParamKeyAttestOverride); err == nil {
		policy.AttestationOverride = attestOverride
	}
	if upOverrideRaw, ok := params[vendorParamKeyUPOverride]; ok {
		if upVal, ok := upOverrideRaw.(bool); ok {
			policy.UPOverride = &upVal
		}
	}
	if enterpriseRaw, ok := params[vendorParamKeyEnterprise]; ok {
		if epVal, ok := enterpriseRaw.(bool); ok {
			policy.Enterprise = epVal
		}
	}
	if blockedRaw, ok := params[vendorParamKeyBlocked]; ok {
		if blVal, ok := blockedRaw.(bool); ok {
			policy.Blocked = blVal
		}
	}

	if err := a.rpPolicyStore.SetPolicy(policy); err != nil {
		return nil, err
	}

	return a.successResponse(nil), nil
}

// handleVendorGetRPPolicy retrieves a per-RP policy.
func handleVendorGetRPPolicy(a *Authenticator, params map[interface{}]interface{}) ([]byte, error) {
	if a.rpPolicyStore == nil {
		return nil, ErrInvalidParameter
	}

	rpID, err := extractStringParam(params, vendorParamKeyRPID)
	if err != nil {
		return nil, ErrRPPolicyInvalidRPID
	}

	policy, err := a.rpPolicyStore.GetPolicy(rpID)
	if err != nil {
		return nil, err
	}

	// Encode policy as CBOR response
	policyMap := map[string]interface{}{
		"rpId": policy.RPID,
	}
	if policy.UVOverride != "" {
		policyMap["uvOverride"] = policy.UVOverride
	}
	if policy.UPOverride != nil {
		policyMap["upOverride"] = *policy.UPOverride
	}
	if policy.AttestationOverride != "" {
		policyMap["attestationOverride"] = policy.AttestationOverride
	}
	if policy.Enterprise {
		policyMap["enterprise"] = true
	}
	if policy.Blocked {
		policyMap["blocked"] = true
	}

	response := map[int]interface{}{
		configResponseKeyPolicy: policyMap,
	}

	responseData, err := encodeCBOR(response)
	if err != nil {
		return nil, ErrCBOREncodingFailed
	}

	return a.successResponse(responseData), nil
}

// handleVendorDeleteRPPolicy deletes a per-RP policy (requires SO unlock).
func handleVendorDeleteRPPolicy(a *Authenticator, params map[interface{}]interface{}) ([]byte, error) {
	// Verify SO is unlocked
	if a.keyManager == nil || !a.keyManager.IsSOUnlocked() {
		return nil, ErrKeyManagerLocked
	}

	if a.rpPolicyStore == nil {
		return nil, ErrInvalidParameter
	}

	rpID, err := extractStringParam(params, vendorParamKeyRPID)
	if err != nil {
		return nil, ErrRPPolicyInvalidRPID
	}

	if err := a.rpPolicyStore.DeletePolicy(rpID); err != nil {
		return nil, err
	}

	return a.successResponse(nil), nil
}

// handleVendorListRPPolicies lists all per-RP policies.
func handleVendorListRPPolicies(a *Authenticator, params map[interface{}]interface{}) ([]byte, error) {
	if a.rpPolicyStore == nil {
		return nil, ErrInvalidParameter
	}

	policies, err := a.rpPolicyStore.ListPolicies()
	if err != nil {
		return nil, err
	}

	policyList := make([]map[string]interface{}, 0, len(policies))
	for _, p := range policies {
		pm := map[string]interface{}{
			"rpId": p.RPID,
		}
		if p.UVOverride != "" {
			pm["uvOverride"] = p.UVOverride
		}
		if p.UPOverride != nil {
			pm["upOverride"] = *p.UPOverride
		}
		if p.AttestationOverride != "" {
			pm["attestationOverride"] = p.AttestationOverride
		}
		if p.Enterprise {
			pm["enterprise"] = true
		}
		if p.Blocked {
			pm["blocked"] = true
		}
		policyList = append(policyList, pm)
	}

	response := map[int]interface{}{
		configResponseKeyPolicies: policyList,
	}

	responseData, err := encodeCBOR(response)
	if err != nil {
		return nil, ErrCBOREncodingFailed
	}

	return a.successResponse(responseData), nil
}

// handleVendorSetProfile sets authenticator profile configuration (requires SO unlock).
func handleVendorSetProfile(a *Authenticator, params map[interface{}]interface{}) ([]byte, error) {
	// Verify SO is unlocked
	if a.keyManager == nil || !a.keyManager.IsSOUnlocked() {
		return nil, ErrKeyManagerLocked
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Apply profile settings
	if transportsRaw, ok := params[vendorParamKeyTransports]; ok {
		if transportsList, ok := transportsRaw.([]interface{}); ok {
			transports := make([]string, 0, len(transportsList))
			for _, t := range transportsList {
				if ts, ok := t.(string); ok {
					transports = append(transports, ts)
				}
			}
			if len(transports) > 0 {
				a.config.Transports = transports
			}
		}
	}

	if epRaw, ok := params[vendorParamKeyEnableEP]; ok {
		if epVal, ok := epRaw.(bool); ok {
			a.config.EnableEnterpriseAttestation = epVal
		}
	}

	// Persist state
	if err := a.storage.SaveState(a.state); err != nil {
		return nil, ErrStorageError
	}

	return a.successResponse(nil), nil
}

// verifyConfigPinUvAuth verifies the pinUvAuthParam for config operations.
// Standard CTAP2.1 operations require pinUvAuthParam for authentication.
func (a *Authenticator) verifyConfigPinUvAuth(req *configRequest, subCmd uint8) error {
	// Check if PIN is required
	if !a.config.EnablePIN {
		return nil
	}

	// If PIN is set, require authentication
	if a.IsPINSet() {
		if req.pinUvAuthParam == nil {
			return ErrPINAuthInvalid
		}

		// Verify pinUvAuthProtocol (V1 or V2)
		if req.pinUvAuthProtocol != PINProtocol1 && req.pinUvAuthProtocol != PINProtocol2 {
			return ErrUnsupportedPINProtocol
		}

		// Build the message to verify: 0xFF{32} || subCmd || subCommandParams
		// CTAP2.1 spec: pinUvAuthParam = HMAC-SHA-256(pinUvAuthToken, 0xff{32} || 0x0d || subCommand || subCommandParams)
		msgLen := 32 + 1 + 1
		if req.subCommandParams != nil {
			paramsData, err := encodeCBOR(req.subCommandParams)
			if err != nil {
				return ErrCBOREncodingFailed
			}
			msgLen += len(paramsData)
		}

		msg := make([]byte, 0, msgLen)

		// Append 0xFF repeated 32 times
		for i := 0; i < 32; i++ {
			msg = append(msg, 0xFF)
		}

		// Append command (0x0D for Config)
		msg = append(msg, CmdConfig)

		// Append subCommand
		msg = append(msg, subCmd)

		// Append subCommandParams if present
		if req.subCommandParams != nil {
			paramsData, err := encodeCBOR(req.subCommandParams)
			if err != nil {
				return ErrCBOREncodingFailed
			}
			msg = append(msg, paramsData...)
		}

		// Verify HMAC
		if !a.verifyConfigHMAC(msg, req.pinUvAuthParam) {
			return ErrPINAuthInvalid
		}

		// Verify permissions include authenticatorConfig
		if a.pinState.protocol != nil {
			if a.pinState.protocol.tokenPermissions&PINPermissionAuthenticatorCfg == 0 {
				return ErrOperationDenied
			}
		}
	}

	return nil
}

// verifyConfigHMAC verifies the HMAC for config operations.
func (a *Authenticator) verifyConfigHMAC(message, authParam []byte) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.pinState.protocol == nil || a.pinState.protocol.pinUvAuthToken == nil {
		return false
	}

	mac := hmac.New(sha256.New, a.pinState.protocol.pinUvAuthToken)
	mac.Write(message)
	var expected []byte
	if a.pinState.protocol.activeProtocol == PINProtocol2 {
		expected = mac.Sum(nil) // Full 32 bytes for V2
	} else {
		expected = mac.Sum(nil)[:16] // Truncated 16 bytes for V1
	}

	return hmac.Equal(expected, authParam)
}

// extractStringParam extracts a string parameter from the params map.
func extractStringParam(params map[interface{}]interface{}, key string) (string, error) {
	if params == nil {
		return "", ErrInvalidParameter
	}

	val, ok := params[key]
	if !ok {
		return "", ErrInvalidParameter
	}

	strVal, ok := val.(string)
	if !ok {
		// Try to convert from []byte
		if bytesVal, ok := val.([]byte); ok {
			return string(bytesVal), nil
		}
		return "", ErrInvalidParameter
	}

	return strVal, nil
}

// extractBytesParam extracts a byte slice parameter from the params map.
func extractBytesParam(params map[interface{}]interface{}, key string) ([]byte, error) {
	if params == nil {
		return nil, ErrInvalidParameter
	}

	val, ok := params[key]
	if !ok {
		return nil, ErrInvalidParameter
	}

	bytesVal, ok := val.([]byte)
	if !ok {
		// Try to convert from string
		if strVal, ok := val.(string); ok {
			return []byte(strVal), nil
		}
		return nil, ErrInvalidParameter
	}

	return bytesVal, nil
}

// toUint8 converts various integer types to uint8.
func toUint8(v interface{}) (uint8, error) {
	switch n := v.(type) {
	case int:
		if n < 0 || n > 255 {
			return 0, ErrInvalidParameter
		}
		return uint8(n), nil
	case int8:
		if n < 0 {
			return 0, ErrInvalidParameter
		}
		return uint8(n), nil
	case int16:
		if n < 0 || n > 255 {
			return 0, ErrInvalidParameter
		}
		return uint8(n), nil
	case int32:
		if n < 0 || n > 255 {
			return 0, ErrInvalidParameter
		}
		return uint8(n), nil
	case int64:
		if n < 0 || n > 255 {
			return 0, ErrInvalidParameter
		}
		return uint8(n), nil
	case uint:
		if n > 255 {
			return 0, ErrInvalidParameter
		}
		return uint8(n), nil
	case uint8:
		return n, nil
	case uint16:
		if n > 255 {
			return 0, ErrInvalidParameter
		}
		return uint8(n), nil
	case uint32:
		if n > 255 {
			return 0, ErrInvalidParameter
		}
		return uint8(n), nil
	case uint64:
		if n > 255 {
			return 0, ErrInvalidParameter
		}
		return uint8(n), nil
	default:
		return 0, ErrInvalidParameter
	}
}
