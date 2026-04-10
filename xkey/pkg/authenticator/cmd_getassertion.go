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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

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

// getAssertionRequestCounter tracks request sequence for debugging.
var getAssertionRequestCounter uint64

// debugLog prints debug messages if debugging is enabled.
func debugLog(format string, args ...interface{}) {
	if debugGetAssertion {
		fmt.Printf("[GETASSERTION DEBUG] "+format+"\n", args...)
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

	// InternalPINHash is the raw PIN hash for trusted in-process callers.
	// Not populated from CBOR — only via the Go API.
	InternalPINHash []byte
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

	// Log request details with request number and UP/UV options
	reqNum := atomic.AddUint64(&getAssertionRequestCounter, 1)
	reqStart := time.Now()
	reqTime := reqStart.Format("15:04:05.000")
	up := true  // Default per CTAP2 spec
	uv := false // Default
	if request.Options != nil {
		if v, ok := request.Options["up"]; ok {
			up = v
		}
		if v, ok := request.Options["uv"]; ok {
			uv = v
		}
	}
	if a.logger != nil {
		a.logger.Info("GetAssertion request",
			"request_num", reqNum,
			"time", reqTime,
			"rpid", request.RPID,
			"allowList_count", len(request.AllowList),
			"up", up,
			"uv", uv,
			"extensions", fmt.Sprintf("%v", request.Extensions),
			"has_pinUvAuthParam", len(request.PINUVAuthParam) > 0,
			"data_bytes", len(data),
		)
	}

	// Execute the assertion
	response, err := a.executeGetAssertion(request)
	if err != nil {
		debugLog("executeGetAssertion failed: %v", err)
		if a.logger != nil {
			a.logger.Warn("GetAssertion failed",
				"request_num", reqNum,
				"duration_ms", time.Since(reqStart).Milliseconds(),
				"rpid", request.RPID,
				"error", err.Error(),
			)
		}
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

	// Extract signCount from authData for diagnostics (bytes 33-36, big-endian uint32).
	var signCount uint32
	if len(response.AuthData) >= 37 {
		signCount = uint32(response.AuthData[33])<<24 |
			uint32(response.AuthData[34])<<16 |
			uint32(response.AuthData[35])<<8 |
			uint32(response.AuthData[36])
	}
	// Extract flags byte for diagnostics.
	var flagsByte byte
	if len(response.AuthData) >= 33 {
		flagsByte = response.AuthData[32]
	}

	// Log completion with duration, signCount, and credential info
	if a.logger != nil {
		a.logger.Info("GetAssertion completed",
			"request_num", reqNum,
			"duration_ms", time.Since(reqStart).Milliseconds(),
			"response_bytes", len(successResp),
			"sign_count", signCount,
			"flags", fmt.Sprintf("0x%02x", flagsByte),
			"signature_len", len(response.Signature),
		)
	}

	// Notify listeners (e.g., AutoFillService cooldown).
	if a.onAssertionCompleted != nil {
		a.onAssertionCompleted(request.RPID)
	}

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

	// Check per-RP SO policy overrides
	var rpPolicy *RPPolicy
	if a.rpPolicyStore != nil {
		policy, err := a.rpPolicyStore.GetPolicy(request.RPID)
		if err == nil {
			rpPolicy = policy
		}
	}

	// Block assertion if RP is blocked by SO policy
	if rpPolicy != nil && rpPolicy.Blocked {
		debugLog("assertion blocked by RP policy for RPID=%s", request.RPID)
		return nil, ErrRPBlocked
	}

	// Check credential protection level
	if err := a.checkAssertionCredentialProtection(credential, request); err != nil {
		debugLog("checkAssertionCredentialProtection failed: %v", err)
		return nil, err
	}

	// Generate the assertion for the selected credential
	return a.generateAssertionResponseWithPolicy(credential, request, len(matchingCreds), rpPolicy)
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
	return a.generateAssertionResponseWithPolicy(credential, request, totalCredentials, nil)
}

// generateAssertionResponseWithPolicy creates the assertion response with SO policy overrides.
func (a *Authenticator) generateAssertionResponseWithPolicy(
	credential *StoredCredential,
	request *GetAssertionRequest,
	totalCredentials int,
	rpPolicy *RPPolicy,
) (*GetAssertionResponse, error) {
	debugLog("generateAssertionResponse: starting for credential ID=%x, signCount=%d",
		credential.CredentialID[:8], credential.SignCount)

	// NOTE: signCount increment is deferred until after all validation passes
	// (PIN, UV, UP). This prevents wasted signCount values on denied or
	// failed assertions — important because RPs check signCount monotonicity.

	// Per CTAP2 spec: If pinUvAuthParam is present and valid,
	// user presence is implicitly satisfied through the PIN exchange.
	// Otherwise, explicitly request user presence.
	pinAuthValid := false
	if len(request.PINUVAuthParam) > 0 && request.PINUVAuthProtocol > 0 {
		if !a.VerifyPinUvAuthToken(request.ClientDataHash, request.PINUVAuthParam) {
			debugLog("pinUvAuthParam verification failed")
			return nil, ErrPINAuthInvalid
		}
		pinAuthValid = true
		debugLog("pinUvAuthParam verified")
	}

	// Internal PIN verification for trusted in-process callers (e.g., autofill
	// service). This bypasses the CTAP2 clientPin ECDH ceremony while still
	// verifying the caller knows the correct PIN hash via constant-time compare.
	// Only available through the Go API — never populated from CBOR/USB.
	if !pinAuthValid && len(request.InternalPINHash) > 0 {
		a.mu.RLock()
		pinSetAndMatches := a.isPINSetLocked() && a.verifyPINHashLocked(request.InternalPINHash)
		a.mu.RUnlock()
		if pinSetAndMatches {
			pinAuthValid = true
			a.state.ResetPINRetries()
			debugLog("internal PIN hash verified for trusted caller")
		} else {
			debugLog("internal PIN hash verification failed")
			return nil, ErrPINInvalid
		}
	}

	// Multi-authenticator support: when UV is required (uv=true or alwaysUV) but
	// no pinUvAuthParam was provided, show a user intent dialog before returning
	// StatusPINRequired. This gives users with multiple security keys (e.g.,
	// xKey + YubiKey) the opportunity to decline xKey and use a different device.
	// Without this check, Chrome immediately commits to xKey's PIN flow.
	uvRequestedForIntent := false
	if request.Options != nil {
		if uv, ok := request.Options["uv"]; ok {
			uvRequestedForIntent = uv
		}
	}
	if !pinAuthValid && a.config.EnablePIN && a.IsPINSet() && a.config.EnableUserIntentCheck &&
		(uvRequestedForIntent || a.config.AlwaysUV) {
		if rpPolicy == nil || rpPolicy.UVOverride != "discouraged" {
			backendHandlesUPCheck := a.keyBackend != nil && a.keyBackend.Capabilities().HandlesUserPresence
			if !backendHandlesUPCheck {
				ctx := a.commandContext()
				debugLog("requesting user intent check for RPID=%s before PIN required", request.RPID)
				if a.logger != nil {
					a.logger.Info("user intent check: waiting for approval before PIN required",
						slog.String("rpid", request.RPID),
						slog.String("user", credential.UserName),
					)
				}
				if err := a.requestUserPresence(ctx, request.RPID, "", credential.UserName, "authenticate"); err != nil {
					debugLog("user intent check denied: %v", err)
					if a.logger != nil {
						a.logger.Info("user intent check denied, returning OperationDenied",
							slog.String("rpid", request.RPID),
							slog.String("error", err.Error()),
						)
					}
					return nil, ErrOperationDenied
				}
				debugLog("user intent check approved, returning PIN required")
				if a.logger != nil {
					a.logger.Info("user intent check approved, returning PINRequired for Chrome PIN exchange",
						slog.String("rpid", request.RPID),
					)
				}
			}
			return nil, ErrPINRequired
		}
	}

	if !pinAuthValid {
		// Check SO UV override: if policy forces UV required, demand PIN auth.
		if rpPolicy != nil && rpPolicy.UVOverride == "required" {
			return nil, ErrPINRequired
		}

		// Per CTAP2 spec §6.2.2: require PIN only when the current request
		// explicitly sets uv=true or the authenticator's alwaysUV is enabled.
		// The stored credential RPUVPolicy is intentionally NOT enforced here
		// because Chrome escalates "preferred" to uv=true at the CTAP2 level
		// during MakeCredential, causing deriveRPUVPolicy to store "required"
		// for what was actually a "preferred" WebAuthn request. Enforcing the
		// stored policy would force PIN on every assertion even when the RP
		// only sends "preferred", diverging from spec-compliant authenticators
		// like YubiKey that follow the current request's UV option.
		uvRequested := false
		if request.Options != nil {
			if uv, ok := request.Options["uv"]; ok {
				uvRequested = uv
			}
		}
		if a.config.EnablePIN && a.IsPINSet() && (uvRequested || a.config.AlwaysUV) {
			if rpPolicy == nil || rpPolicy.UVOverride != "discouraged" {
				return nil, ErrPINRequired
			}
		}
	}

	// Check if the key backend handles user presence internally (e.g., phone biometrics).
	// If so, user presence will be satisfied during the Sign operation.
	backendHandlesUP := a.keyBackend != nil && a.keyBackend.Capabilities().HandlesUserPresence

	// Check the 'up' (user presence) option from the request.
	// Per CTAP2 spec: if up=false, this is a silent credential discovery request
	// (e.g., Chrome's conditional UI) and we should NOT prompt for user presence.
	// Default is up=true per CTAP2 spec.
	upRequired := true
	if request.Options != nil {
		if up, ok := request.Options["up"]; ok {
			upRequired = up
		}
	}

	// Apply SO UP override: if policy sets UP to false, allow silent auth
	if rpPolicy != nil && rpPolicy.UPOverride != nil {
		upRequired = *rpPolicy.UPOverride
	}

	// Request user presence if:
	// 1. up=true (or not specified, default is true)
	// 2. PIN auth was not performed (UP required per CTAP2), OR
	// 3. RequireUserPresence is set (hardware-authenticator-like behavior)
	// BUT skip if:
	// - up=false (silent discovery request or SO policy), OR
	// - the key backend handles user presence internally
	if upRequired && (!pinAuthValid || a.config.RequireUserPresence) && !backendHandlesUP {
		debugLog("requesting user presence for RPID=%s, user=%s (pinAuthValid=%v, requireUP=%v, upRequired=%v)",
			request.RPID, credential.UserName, pinAuthValid, a.config.RequireUserPresence, upRequired)
		ctx := a.commandContext()
		if err := a.requestUserPresence(ctx, request.RPID, "", credential.UserName, "authenticate"); err != nil {
			debugLog("requestUserPresence failed: %v", err)
			return nil, err
		}
		debugLog("user presence confirmed successfully")
	} else {
		reason := "PIN verification"
		if !upRequired {
			reason = "up=false (silent discovery)"
		} else if backendHandlesUP {
			reason = "key backend (biometrics)"
		}
		debugLog("UP implicitly satisfied by %s", reason)
	}

	// All validation passed — now increment and persist signCount.
	// This is deferred from the top of the function to avoid wasting signCount
	// values on denied assertions (PIN wrong, user denies touch, etc.).
	credential.SignCount++
	debugLog("incremented signCount to %d", credential.SignCount)
	if err := a.storage.Store(credential); err != nil {
		debugLog("storage.Store failed: %v", err)
		return nil, ErrStorageError
	}
	debugLog("credential stored with signCount=%d", credential.SignCount)

	// Build flags. UP flag reflects whether user presence was actually satisfied.
	var flags AuthDataFlags
	if upRequired {
		flags = FlagUP
	}
	debugLog("initial flags: 0x%02x (UP=%v)", byte(flags), upRequired)

	// Set UV flag when actual user verification was performed in this transaction:
	// 1. Platform provided a valid pinUvAuthParam, OR
	// 2. Key backend handles user verification internally (e.g., phone biometric), OR
	// 3. Trusted in-process caller provided a valid InternalPINHash
	if len(request.PINUVAuthParam) > 0 && request.PINUVAuthProtocol > 0 {
		flags |= FlagUV
		debugLog("UV flag set (pinUvAuthParam provided), flags now: 0x%02x", byte(flags))
	} else if a.keyBackend != nil && a.keyBackend.Capabilities().HandlesUserVerification {
		flags |= FlagUV
		debugLog("UV flag set (key backend handles verification), flags now: 0x%02x", byte(flags))
	} else if pinAuthValid && len(request.InternalPINHash) > 0 {
		flags |= FlagUV
		debugLog("UV flag set (internal PIN hash verified), flags now: 0x%02x", byte(flags))
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

	// Sign using key backend or inline private key.
	debugLog("signing with algorithm=%d", credential.Algorithm)
	var signature []byte
	if a.keyBackend != nil {
		debugLog("using key backend for signing")
		handle, loadErr := a.keyBackend.LoadKey(credential.CredentialID, credential.Algorithm)
		if loadErr != nil {
			debugLog("keyBackend.LoadKey failed: %v", loadErr)
			if a.logger != nil {
				a.logger.Error("key backend LoadKey failed",
					"error", loadErr.Error(),
					"credential_id_prefix", fmt.Sprintf("%x", credential.CredentialID[:8]),
					"algorithm", credential.Algorithm,
					"backend_type", fmt.Sprintf("%T", a.keyBackend))
			}
			return nil, mapKeyBackendError(loadErr)
		}
		signature, err = a.keyBackend.Sign(handle, credential.Algorithm, signData)
		if err != nil {
			debugLog("keyBackend.Sign failed: %v", err)
			if a.logger != nil {
				a.logger.Error("key backend Sign failed",
					"error", err.Error(),
					"credential_id_prefix", fmt.Sprintf("%x", credential.CredentialID[:8]),
					"algorithm", credential.Algorithm,
					"backend_type", fmt.Sprintf("%T", a.keyBackend))
			}
			return nil, mapKeyBackendError(err)
		}
	} else {
		debugLog("parsing private key, length=%d bytes", len(credential.PrivateKey))
		privateKey, parseErr := parseAssertionPrivateKey(credential.PrivateKey)
		if parseErr != nil {
			debugLog("parseAssertionPrivateKey failed: %v", parseErr)
			return nil, ErrCryptoError
		}
		debugLog("private key parsed successfully, type=%T", privateKey)

		signature, err = Sign(privateKey, credential.Algorithm, signData)
		if err != nil {
			debugLog("Sign failed: %v", err)
			return nil, ErrCryptoError
		}
	}
	debugLog("signature created successfully, length=%d bytes", len(signature))
	debugLog("signature hex: %x", signature)

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

	return encoded, nil
}

// handleGetNextAssertion returns the next credential's assertion in a multi-credential response.
// This implements the CTAP2 authenticatorGetNextAssertion command.
func (a *Authenticator) handleGetNextAssertion() ([]byte, error) {
	// Extract state under lock, then release before calling generateAssertionResponse
	// which acquires its own locks (IsPINSet, requestUserPresence, etc.).
	var credential *StoredCredential
	var clientDataHash []byte
	var totalCredentials int

	a.mu.Lock()
	if len(a.matchingCredentials) == 0 {
		a.mu.Unlock()
		return nil, ErrNoCredentials
	}

	a.currentCredentialIndex++

	if a.currentCredentialIndex >= len(a.matchingCredentials) {
		a.matchingCredentials = nil
		a.currentCredentialIndex = 0
		a.lastClientDataHash = nil
		a.mu.Unlock()
		return nil, ErrNoCredentials
	}

	credential = a.matchingCredentials[a.currentCredentialIndex]
	totalCredentials = len(a.matchingCredentials)
	clientDataHash = make([]byte, len(a.lastClientDataHash))
	copy(clientDataHash, a.lastClientDataHash)
	a.mu.Unlock()

	request := &GetAssertionRequest{
		RPID:           credential.RPID,
		ClientDataHash: clientDataHash,
	}

	response, err := a.generateAssertionResponse(credential, request, totalCredentials)
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

// mapKeyBackendError maps key backend errors to appropriate CTAP2 errors.
// This allows the authenticator to return protocol-compliant errors while
// preserving detailed error information in logs.
func mapKeyBackendError(err error) error {
	if err == nil {
		return nil
	}

	errStr := err.Error()

	// Map specific error patterns to CTAP2 errors.
	// We use string matching because the phone package cannot be imported
	// without creating a circular dependency.
	switch {
	case contains(errStr, "key not found"),
		contains(errStr, "not found"),
		contains(errStr, "does not exist"):
		// Key doesn't exist on the backend - this is a credential lookup failure
		return ErrNoCredentials

	case contains(errStr, "user cancelled"),
		contains(errStr, "cancelled"),
		contains(errStr, "denied"):
		// User cancelled the operation on the phone
		return ErrOperationDenied

	case contains(errStr, "biometric"),
		contains(errStr, "verification failed"):
		// Biometric verification failed
		return ErrOperationDenied

	case contains(errStr, "timeout"),
		contains(errStr, "timed out"):
		// Operation timed out
		return ErrOperationDenied

	case contains(errStr, "not connected"),
		contains(errStr, "connection failed"):
		// Connection issue with backend
		return ErrCryptoError

	default:
		// Default to generic crypto error
		return ErrCryptoError
	}
}

// contains is a helper for case-insensitive substring matching.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		len(substr) > 0 && containsLower(s, substr))
}

// containsLower performs case-insensitive contains check.
func containsLower(s, substr string) bool {
	// Simple lowercase comparison for common patterns
	sl := toLower(s)
	subsl := toLower(substr)
	for i := 0; i <= len(sl)-len(subsl); i++ {
		if sl[i:i+len(subsl)] == subsl {
			return true
		}
	}
	return false
}

// toLower converts a string to lowercase (ASCII only for error matching).
func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

// GetAssertionOptions contains optional parameters for the public GetAssertion API.
type GetAssertionOptions struct {
	// Extensions contains requested extension inputs (optional).
	Extensions map[string]interface{}

	// Options contains authenticator option flags (optional).
	// Supported keys: "up" (user presence), "uv" (user verification).
	Options map[string]bool

	// PINUVAuthParam is the PIN/UV authentication parameter (optional).
	PINUVAuthParam []byte

	// PINUVAuthProtocol specifies which PIN/UV protocol is used (optional).
	PINUVAuthProtocol uint8

	// InternalPINHash allows trusted in-process callers to bypass the CTAP2
	// clientPin ECDH ceremony. When set, the authenticator verifies the hash
	// directly against the stored PIN hash using constant-time comparison.
	// This field is NOT accessible via CBOR/USB — only through the Go API.
	// The hash must be the first 16 bytes of SHA-256(rawPIN).
	InternalPINHash []byte
}

// GetAssertion performs a CTAP2 authenticatorGetAssertion operation using Go types.
// It validates the request, finds matching credentials, handles user presence and
// verification, and returns the signed assertion. This is the public Go API equivalent
// of processing a CBOR 0x02 command.
//
// Parameters:
//   - clientDataHash: SHA-256 hash of the client data (32 bytes)
//   - rpID: Relying party identifier
//   - allowList: Credential descriptors to match (nil for discoverable credential flow)
//   - opts: Optional parameters (extensions, options, PIN/UV auth)
//
// Returns:
//   - GetAssertionResponse containing the signed assertion
//   - Error if assertion fails
func (a *Authenticator) GetAssertion(
	clientDataHash []byte,
	rpID string,
	allowList []CredentialDescriptor,
	opts *GetAssertionOptions,
) (*GetAssertionResponse, error) {
	req := &GetAssertionRequest{
		ClientDataHash: clientDataHash,
		RPID:           rpID,
		AllowList:      allowList,
		Extensions:     make(map[string]interface{}),
		Options:        make(map[string]bool),
	}

	if opts != nil {
		if opts.Extensions != nil {
			req.Extensions = opts.Extensions
		}
		if opts.Options != nil {
			req.Options = opts.Options
		}
		req.PINUVAuthParam = opts.PINUVAuthParam
		req.PINUVAuthProtocol = opts.PINUVAuthProtocol
		req.InternalPINHash = opts.InternalPINHash
	}

	// Validate required parameters
	if rpID == "" {
		return nil, ErrGetAssertionMissingRPID
	}
	if len(clientDataHash) != getAssertionClientDataHashSize {
		return nil, ErrGetAssertionInvalidClientDataHash
	}

	return a.executeGetAssertion(req)
}
