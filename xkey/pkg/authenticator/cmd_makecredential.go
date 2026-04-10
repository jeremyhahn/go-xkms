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
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator/keybackend"
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
	AttestationFormatTPM    = "tpm"
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

	// InternalPINHash is the raw PIN hash for trusted in-process callers.
	// Not populated from CBOR — only via the Go API.
	InternalPINHash []byte
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

	// InternalPINHash allows trusted in-process callers to bypass the CTAP2
	// clientPin ECDH ceremony. When set, the authenticator verifies the hash
	// directly against the stored PIN hash using constant-time comparison.
	// This field is NOT accessible via CBOR/USB — only through the Go API.
	InternalPINHash []byte
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
	debugLog("[MAKECRED] decoded request: RP=%s, pinUvAuthParam len=%d, pinUvAuthProtocol=%d",
		req.RP.ID, len(req.PINUVAuthParam), req.PINUVAuthProtocol)

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

	// Check per-RP policy overrides before UV/UP processing.
	var rpPolicy *RPPolicy
	if a.rpPolicyStore != nil {
		policy, err := a.rpPolicyStore.GetPolicy(req.RP.ID)
		if err == nil {
			rpPolicy = policy
		}
		// ErrRPPolicyNotFound is expected when no policy exists
	}

	// Block credential creation if RP is blocked by SO policy
	if rpPolicy != nil && rpPolicy.Blocked {
		if a.logger != nil {
			a.logger.Warn("MakeCredential blocked by RP policy",
				slog.String("rp", req.RP.ID))
		}
		return nil, ErrRPBlocked
	}

	// Per CTAP2 spec section 6.1.2: If pinUvAuthParam is present and valid,
	// user presence is implicitly satisfied through the PIN exchange.
	// If PIN is set but pinUvAuthParam is missing, return PIN_REQUIRED (0x36)
	// so the client knows it must perform PIN verification first.
	if a.logger != nil {
		a.logger.Info("MakeCredential PIN check",
			slog.String("rp", req.RP.ID),
			slog.Int("pinUvAuthParam_len", len(req.PINUVAuthParam)),
			slog.Int("pinUvAuthProtocol", int(req.PINUVAuthProtocol)),
			slog.Bool("enablePIN", a.config.EnablePIN),
			slog.Bool("pinSet", a.IsPINSet()),
		)
	}

	pinAuthValid := false
	if len(req.PINUVAuthParam) > 0 && req.PINUVAuthProtocol > 0 {
		if !a.VerifyPinUvAuthToken(req.ClientDataHash, req.PINUVAuthParam) {
			if a.logger != nil {
				a.logger.Warn("MakeCredential pinUvAuthParam verification failed")
			}
			return nil, ErrPINAuthInvalid
		}
		pinAuthValid = true
		if a.logger != nil {
			a.logger.Info("MakeCredential pinUvAuthParam verified")
		}
	}

	if !pinAuthValid {
		// Apply SO UV override: if policy forces UV required, demand PIN auth
		if rpPolicy != nil && rpPolicy.UVOverride == "required" {
			if a.logger != nil {
				a.logger.Warn("MakeCredential rejected: SO policy requires UV for this RP",
					slog.String("rp", req.RP.ID))
			}
			return nil, ErrPINRequired
		}

		// Multi-authenticator support: when PIN is set but no pinUvAuthParam
		// was provided, show a user intent dialog before returning PINRequired.
		// This gives users with multiple security keys (e.g., xKey + YubiKey)
		// the opportunity to decline xKey and use a different device.
		// Without this check, Chrome immediately commits to xKey's PIN flow.
		if a.config.EnablePIN && a.IsPINSet() && a.config.EnableUserIntentCheck {
			if rpPolicy == nil || rpPolicy.UVOverride != "discouraged" {
				backendHandlesUPCheck := a.keyBackend != nil && a.keyBackend.Capabilities().HandlesUserPresence
				if !backendHandlesUPCheck {
					ctx := a.commandContext()
					debugLog("[MAKECRED] requesting user intent check for RP=%s before PIN required", req.RP.ID)
					if a.logger != nil {
						a.logger.Info("MakeCredential user intent check: waiting for approval before PIN required",
							slog.String("rp", req.RP.ID),
							slog.String("user", req.User.Name),
						)
					}
					if err := a.requestUserPresence(ctx, req.RP.ID, req.RP.Name, req.User.Name, "register"); err != nil {
						debugLog("[MAKECRED] user intent check denied: %v", err)
						if a.logger != nil {
							a.logger.Info("MakeCredential user intent check denied, returning OperationDenied",
								slog.String("rp", req.RP.ID),
								slog.String("error", err.Error()),
							)
						}
						return nil, ErrOperationDenied
					}
					debugLog("[MAKECRED] user intent check approved, returning PIN required")
					if a.logger != nil {
						a.logger.Info("MakeCredential user intent check approved, returning PINRequired for Chrome PIN exchange",
							slog.String("rp", req.RP.ID),
						)
					}
				}
				return nil, ErrPINRequired
			}
		}

		// When PIN is configured and set but EnableUserIntentCheck is off,
		// the client MUST provide pinUvAuthParam. Return PINRequired so
		// Chrome starts the PIN exchange directly.
		if a.config.EnablePIN && a.IsPINSet() {
			if rpPolicy == nil || rpPolicy.UVOverride != "discouraged" {
				if a.logger != nil {
					a.logger.Warn("MakeCredential rejected: PIN set but no pinUvAuthParam provided")
				}
				return nil, ErrPINRequired
			}
		}
	}

	// Check if the key backend handles user presence internally (e.g., phone biometrics).
	backendHandlesUP := a.keyBackend != nil && a.keyBackend.Capabilities().HandlesUserPresence

	// Request user presence BEFORE key generation.
	// This ensures the user approves the operation before the phone prompts for biometrics.
	// For phone backends with HandlesUserPresence=false, this shows the desktop notification
	// first, then the phone prompts for biometric after approval.
	if (!pinAuthValid || a.config.RequireUserPresence) && !backendHandlesUP {
		if a.logger != nil {
			a.logger.Info("MakeCredential requesting user presence",
				slog.Bool("pinAuthValid", pinAuthValid),
				slog.Bool("requireUP", a.config.RequireUserPresence),
			)
		}
		ctx := a.commandContext()
		if err := a.requestUserPresence(ctx, req.RP.ID, req.RP.Name, req.User.Name, "register"); err != nil {
			return nil, err
		}
	} else if a.logger != nil {
		reason := "PIN verification"
		if backendHandlesUP {
			reason = "key backend (biometrics)"
		}
		a.logger.Info("MakeCredential UP implicitly satisfied", slog.String("by", reason))
	}

	// Generate credential ID
	credentialID, err := GenerateCredentialID()
	if err != nil {
		return nil, ErrCryptoError
	}
	debugLog("[MAKECRED] generated credentialID length=%d, hex: %x", len(credentialID), credentialID)

	// Generate credential key pair via backend or legacy path
	// For phone backends, this will trigger biometric verification on the phone
	// AFTER the user has approved via desktop notification above.
	privateKeyBytes, publicKeyCOSE, actualBackendID, err := a.generateCredentialKeyPair(selectedAlgorithm, credentialID)
	if err != nil {
		return nil, err
	}
	debugLog("[MAKECRED] generated publicKeyCOSE length=%d, hex: %x", len(publicKeyCOSE), publicKeyCOSE)

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

	// Build authenticator data with AT flag (attested credential data)
	flags := FlagUP | FlagAT // User present + Attested credential data
	if a.userVerificationSatisfied(req) {
		flags |= FlagUV
	}

	// Process extension inputs and include outputs in authData. Chrome
	// requires the ED flag and credProtect output in MakeCredential
	// responses when the credProtect extension was requested.
	extensionOutputs := a.processMakeCredentialExtensions(req.Extensions, hmacSecretKey != nil)

	// Extract credProtect level for credential storage
	var credProtectLevel uint8
	if cp, ok := extensionOutputs["credProtect"]; ok {
		credProtectLevel = cp.(uint8)
	}

	if a.logger != nil {
		a.logger.Info("MakeCredential AAGUID",
			slog.String("aaguid_hex", fmt.Sprintf("%x", a.state.AAGUID[:])))
	}

	authDataBuilder := NewAuthDataBuilder(req.RP.ID).
		WithFlags(flags).
		WithSignCount(0).
		WithAttestedCredentialData(a.state.AAGUID, credentialID, publicKeyCOSE)

	// Include extension outputs in authData (sets ED flag automatically).
	if len(extensionOutputs) > 0 {
		authDataBuilder.WithExtensions(extensionOutputs)
	}

	authData, err := authDataBuilder.Build()
	if err != nil {
		if a.logger != nil {
			a.logger.Error("MakeCredential authData build failed", "backend", actualBackendID, "error", err)
		}
		return nil, err
	}
	debugLog("[MAKECRED] authData length=%d bytes", len(authData))
	debugLog("[MAKECRED] authData hex: %x", authData)

	// Derive RP policy fields from the request
	rpUVPolicy := deriveRPUVPolicy(req)
	rpRKPolicy := ""
	if rk, ok := req.Options["rk"]; ok && rk {
		rpRKPolicy = "required"
	}

	// Store the credential with RP policy fields
	if err := a.storeCredentialWithPolicy(&storeCredentialParams{
		credentialID:    credentialID,
		rp:              req.RP,
		user:            req.User,
		privateKeyBytes: privateKeyBytes,
		publicKeyCOSE:   publicKeyCOSE,
		algorithm:       selectedAlgorithm,
		discoverable:    discoverable,
		hmacSecretKey:   hmacSecretKey,
		credProtect:     credProtectLevel,
		rpUVPolicy:      rpUVPolicy,
		rpUPPolicy:      true, // MakeCredential always requires UP per CTAP2 spec
		rpRKPolicy:      rpRKPolicy,
		backendID:       actualBackendID,
	}); err != nil {
		if a.logger != nil {
			a.logger.Error("MakeCredential credential storage failed", "backend", actualBackendID, "error", err)
		}
		return nil, err
	}

	// Build attestation statement based on configured format.
	// Check enterprise attestation: only honor if RP is in enterprise allowlist.
	attestationFmt, attStmt := a.buildMakeCredentialAttestation(authData, req.ClientDataHash, req, rpPolicy)

	// Create response
	response := &MakeCredentialResponse{
		Fmt:      attestationFmt,
		AuthData: authData,
		AttStmt:  attStmt,
	}

	// Encode the response
	respBytes, err := EncodeMakeCredentialResponse(response)
	if err != nil {
		return nil, err
	}
	debugLog("[MAKECRED] response CBOR length=%d bytes", len(respBytes))
	debugLog("[MAKECRED] response CBOR hex: %x", respBytes)

	if a.logger != nil {
		a.logger.Info("MakeCredential response built",
			slog.Int("authData_len", len(authData)),
			slog.Int("response_cbor_len", len(respBytes)),
			slog.String("flags", fmt.Sprintf("0x%02X", byte(flags))),
			slog.String("fmt", attestationFmt),
			slog.Int("credentialID_len", len(credentialID)),
			slog.Int("publicKeyCOSE_len", len(publicKeyCOSE)),
		)
	}

	return a.successResponse(respBytes), nil
}

// buildAttestationStatement creates an attestation statement based on the configured format.
// It checks if the key backend implements FIDO2AttestingKeyBackend and uses it for
// attestation if available. Falls back to "none" format if attestation is not supported.
//
// Returns:
//   - attestationFmt: The attestation format string used
//   - attStmt: The attestation statement map (empty for "none" format)
func (a *Authenticator) buildAttestationStatement(authData, clientDataHash []byte) (string, map[string]interface{}) {
	requestedFormat := a.config.AttestationFormat

	// If "none" format is requested, return empty statement
	if requestedFormat == AttestationFormatNone || requestedFormat == "" {
		return AttestationFormatNone, make(map[string]interface{})
	}

	// Check if backend supports attestation
	attestingBackend, canAttest := a.keyBackend.(keybackend.FIDO2AttestingKeyBackend)
	if !canAttest {
		if a.logger != nil {
			a.logger.Warn("Attestation requested but backend does not support it, falling back to none",
				slog.String("requested_format", requestedFormat),
			)
		}
		return AttestationFormatNone, make(map[string]interface{})
	}

	// Get attestation statement from backend
	attStmtData, err := attestingBackend.GetAttestationStatement(requestedFormat, authData, clientDataHash)
	if err != nil {
		if a.logger != nil {
			a.logger.Warn("Failed to get attestation statement, falling back to none",
				slog.String("requested_format", requestedFormat),
				slog.String("error", err.Error()),
			)
		}
		return AttestationFormatNone, make(map[string]interface{})
	}

	// Build attestation statement map based on format
	attStmt := make(map[string]interface{})

	switch requestedFormat {
	case AttestationFormatPacked:
		attStmt["alg"] = attStmtData.Algorithm
		attStmt["sig"] = attStmtData.Signature

		// Add certificate chain if available (x5c)
		if len(attStmtData.CertificateChain) > 0 {
			x5c := make([][]byte, len(attStmtData.CertificateChain))
			for i, cert := range attStmtData.CertificateChain {
				x5c[i] = cert.Raw
			}
			attStmt["x5c"] = x5c
		}

	case AttestationFormatTPM:
		attStmt["alg"] = attStmtData.Algorithm
		attStmt["sig"] = attStmtData.Signature

		// TPM-specific fields: certInfo and pubArea are required
		if len(attStmtData.TPMData) > 0 {
			// TPMData is expected to contain both certInfo and pubArea
			// The backend should encode this appropriately
			// For now, we split based on convention (first half certInfo, second half pubArea)
			// In practice, the backend should return structured data
			attStmt["certInfo"] = attStmtData.TPMData
			// pubArea should be set by the backend; if not available, the RP will reject
		}

		// Add certificate chain if available (x5c) - optional for TPM
		if len(attStmtData.CertificateChain) > 0 {
			x5c := make([][]byte, len(attStmtData.CertificateChain))
			for i, cert := range attStmtData.CertificateChain {
				x5c[i] = cert.Raw
			}
			attStmt["x5c"] = x5c
		}

	default:
		if a.logger != nil {
			a.logger.Warn("Unknown attestation format, falling back to none",
				slog.String("requested_format", requestedFormat),
			)
		}
		return AttestationFormatNone, make(map[string]interface{})
	}

	return requestedFormat, attStmt
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

// userVerificationSatisfied checks if user verification was actually performed
// in this transaction. Per CTAP2 spec, the UV flag should only be set when the
// authenticator has verified the user via PIN token or built-in verification
// during THIS operation -- not merely because a PIN is configured.
func (a *Authenticator) userVerificationSatisfied(req *MakeCredentialRequest) bool {
	// UV is satisfied when:
	// 1. The client provided a valid pinUvAuthParam (platform performed PIN/UV), OR
	// 2. The key backend handles user verification internally (e.g., phone biometric), OR
	// 3. A trusted in-process caller provided a valid InternalPINHash
	if len(req.PINUVAuthParam) > 0 && req.PINUVAuthProtocol > 0 {
		return true
	}

	// Check if the key backend handles user verification (e.g., phone biometric).
	// When the backend performs biometric verification during key operations,
	// that satisfies the UV requirement without needing platform-level PIN/UV.
	if a.keyBackend != nil && a.keyBackend.Capabilities().HandlesUserVerification {
		return true
	}

	// Internal PIN hash verified by trusted in-process caller.
	if len(req.InternalPINHash) > 0 {
		a.mu.RLock()
		pinSetAndMatches := a.isPINSetLocked() && a.verifyPINHashLocked(req.InternalPINHash)
		a.mu.RUnlock()
		if pinSetAndMatches {
			return true
		}
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

// generateCredentialKeyPair generates a key pair and returns:
//   - privateKeyBytes: PKCS#8 encoded private key (nil for hardware backends)
//   - publicKeyCOSE: COSE encoded public key
//   - backendID: the ID of the backend that actually generated the key
//   - error
func (a *Authenticator) generateCredentialKeyPair(algorithm int, credentialID []byte) ([]byte, []byte, types.BackendType, error) {
	if a.keyBackend != nil {
		// Key backend path: delegate key generation
		handle, publicKeyCOSE, err := a.keyBackend.GenerateCredentialKey(algorithm, credentialID)
		if err != nil {
			if a.logger != nil {
				a.logger.Warn("key backend GenerateCredentialKey failed",
					slog.String("backend", string(a.keyBackend.Type())),
					slog.String("error", err.Error()),
					slog.Int("algorithm", algorithm))
			}
			return nil, nil, "", ErrCryptoError
		}

		// Try to export private key for storage (software backends support this).
		// In composite backends, SupportsExport may be true from one backend
		// (e.g., software) while the key was generated on another (e.g., TPM2).
		// Handle ErrExportNotSupported gracefully for hardware-backed keys.
		var privateKeyBytes []byte
		if a.keyBackend.Capabilities().SupportsExport {
			privateKeyBytes, err = a.keyBackend.ExportPrivateKey(handle)
			if err != nil && !errors.Is(err, keybackend.ErrExportNotSupported) {
				return nil, nil, "", ErrCryptoError
			}
		}
		// For non-exportable backends (TPM2, PKCS#11), privateKeyBytes remains nil.
		// The backend.LoadKey + backend.Sign path handles signing at assertion time.

		return privateKeyBytes, publicKeyCOSE, handle.BackendID(), nil
	}

	// Legacy path: generate key via crypto.go
	privateKey, publicKeyCOSE, err := GenerateCredentialKey(algorithm)
	if err != nil {
		return nil, nil, "", ErrCryptoError
	}

	// Serialize private key to PKCS#8
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, "", ErrCryptoError
	}

	return privateKeyBytes, publicKeyCOSE, types.BackendTypeSoftware, nil
}

// storeCredentialParams holds the parameters for credential storage,
// including RP policy fields derived from the original request.
type storeCredentialParams struct {
	credentialID    []byte
	rp              RelyingParty
	user            User
	privateKeyBytes []byte
	publicKeyCOSE   []byte
	algorithm       int
	discoverable    bool
	hmacSecretKey   []byte
	credProtect     uint8
	rpUVPolicy      string
	rpUPPolicy      bool
	rpRKPolicy      string
	rpAttestPref    string
	backendID       types.BackendType
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
	backendID types.BackendType,
) error {
	return a.storeCredentialWithPolicy(&storeCredentialParams{
		credentialID:    credentialID,
		rp:              rp,
		user:            user,
		privateKeyBytes: privateKeyBytes,
		publicKeyCOSE:   publicKeyCOSE,
		algorithm:       algorithm,
		discoverable:    discoverable,
		hmacSecretKey:   hmacSecretKey,
		credProtect:     credProtect,
		rpUPPolicy:      true, // Default per CTAP2 spec
		backendID:       backendID,
	})
}

// storeCredentialWithPolicy persists a credential with RP policy fields.
func (a *Authenticator) storeCredentialWithPolicy(p *storeCredentialParams) error {
	storedCred := &StoredCredential{
		CredentialID:        p.credentialID,
		RPID:                p.rp.ID,
		RPName:              p.rp.Name,
		UserID:              p.user.ID,
		UserName:            p.user.Name,
		UserDisplayName:     p.user.DisplayName,
		PrivateKey:          p.privateKeyBytes,
		PublicKeyCOSE:       p.publicKeyCOSE,
		Algorithm:           p.algorithm,
		SignCount:           0,
		Discoverable:        p.discoverable,
		HMACSecretKey:       p.hmacSecretKey,
		CredProtect:         p.credProtect,
		CreatedAt:           time.Now().Unix(),
		RPUVPolicy:          p.rpUVPolicy,
		RPUPPolicy:          p.rpUPPolicy,
		RPResidentKeyPolicy: p.rpRKPolicy,
		RPAttestationPref:   p.rpAttestPref,
		BackendID:           p.backendID,
	}

	if err := a.storage.Store(storedCred); err != nil {
		return ErrStorageError
	}

	// Notify listeners that a credential was created.
	if a.onCredentialCreated != nil {
		a.onCredentialCreated(storedCred)
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

// deriveRPUVPolicy infers the RP's userVerification requirement from the request.
func deriveRPUVPolicy(req *MakeCredentialRequest) string {
	// UV explicitly requested in options
	if uv, ok := req.Options["uv"]; ok && uv {
		return "required"
	}
	// pinUvAuthParam present implies at least "preferred"
	if len(req.PINUVAuthParam) > 0 && req.PINUVAuthProtocol > 0 {
		return "preferred"
	}
	return "discouraged"
}

// buildMakeCredentialAttestation creates an attestation statement, honoring
// enterprise attestation only when the RP is in the enterprise allowlist.
func (a *Authenticator) buildMakeCredentialAttestation(
	authData, clientDataHash []byte,
	req *MakeCredentialRequest,
	rpPolicy *RPPolicy,
) (string, map[string]interface{}) {
	// Check enterprise attestation request
	if req.EnterpriseAttestation > 0 && a.config.EnableEnterpriseAttestation {
		// Only honor enterprise attestation if RP is in allowlist
		if rpPolicy != nil && rpPolicy.Enterprise {
			// Override attestation format to packed with full cert chain
			originalFormat := a.config.AttestationFormat
			a.config.AttestationFormat = AttestationFormatPacked
			attestationFmt, attStmt := a.buildAttestationStatement(authData, clientDataHash)
			a.config.AttestationFormat = originalFormat
			return attestationFmt, attStmt
		}
	}

	// Check SO attestation override for this RP
	if rpPolicy != nil && rpPolicy.AttestationOverride != "" {
		originalFormat := a.config.AttestationFormat
		a.config.AttestationFormat = rpPolicy.AttestationOverride
		attestationFmt, attStmt := a.buildAttestationStatement(authData, clientDataHash)
		a.config.AttestationFormat = originalFormat
		return attestationFmt, attStmt
	}

	return a.buildAttestationStatement(authData, clientDataHash)
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
		req.InternalPINHash = opts.InternalPINHash
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

	// Per CTAP2 spec section 6.1.2: If pinUvAuthParam is present and valid,
	// user presence is implicitly satisfied through the PIN exchange.
	// Otherwise, explicitly request user presence.
	pinAuthValid := false
	if len(req.PINUVAuthParam) > 0 && req.PINUVAuthProtocol > 0 {
		if !a.VerifyPinUvAuthToken(req.ClientDataHash, req.PINUVAuthParam) {
			return nil, ErrPINAuthInvalid
		}
		pinAuthValid = true
	}

	// Internal PIN verification for trusted in-process callers (e.g., autofill).
	if !pinAuthValid && len(req.InternalPINHash) > 0 {
		a.mu.RLock()
		pinSetAndMatches := a.isPINSetLocked() && a.verifyPINHashLocked(req.InternalPINHash)
		a.mu.RUnlock()
		if pinSetAndMatches {
			pinAuthValid = true
			a.state.ResetPINRetries()
			debugLog("[MAKECRED] internal PIN hash verified for trusted caller")
		} else {
			debugLog("[MAKECRED] internal PIN hash verification failed")
			return nil, ErrPINInvalid
		}
	}

	// Check if the key backend handles user presence internally (e.g., phone biometrics).
	backendHandlesUP := a.keyBackend != nil && a.keyBackend.Capabilities().HandlesUserPresence

	// Request user presence BEFORE key generation.
	// This ensures the user approves the operation before the phone prompts for biometrics.
	if !pinAuthValid && !backendHandlesUP {
		// When PIN is configured and set, the client MUST provide pinUvAuthParam.
		// Falling through to interactive UP here would block indefinitely in
		// non-terminal contexts (e.g., Chrome/UHID).
		if a.config.EnablePIN && a.IsPINSet() {
			return nil, ErrPINRequired
		}
		ctx := a.commandContext()
		if err := a.requestUserPresence(ctx, req.RP.ID, req.RP.Name, req.User.Name, "register"); err != nil {
			return nil, err
		}
	}

	// Generate credential ID
	credentialID, err := GenerateCredentialID()
	if err != nil {
		return nil, ErrCryptoError
	}
	debugLog("[MAKECRED] generated credentialID length=%d, hex: %x", len(credentialID), credentialID)

	// Generate credential key pair via backend or legacy path
	// For phone backends, this will trigger biometric verification on the phone
	// AFTER the user has approved via desktop notification above.
	privateKeyBytes, publicKeyCOSE, actualBackendID, err := a.generateCredentialKeyPair(selectedAlgorithm, credentialID)
	if err != nil {
		return nil, err
	}
	debugLog("[MAKECRED] generated publicKeyCOSE length=%d, hex: %x", len(publicKeyCOSE), publicKeyCOSE)

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

	// Build authenticator data with AT flag (attested credential data)
	flags := FlagUP | FlagAT // User present + Attested credential data
	if a.userVerificationSatisfied(req) {
		flags |= FlagUV
	}

	// Process extension inputs and include outputs in authData. Chrome
	// requires the ED flag and credProtect output in MakeCredential
	// responses when the credProtect extension was requested.
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

	// Include extension outputs in authData (sets ED flag automatically).
	if len(extensionOutputs) > 0 {
		authDataBuilder.WithExtensions(extensionOutputs)
	}

	authData, err := authDataBuilder.Build()
	if err != nil {
		return nil, err
	}

	// Derive RP policy fields
	rpUVPolicyConv := deriveRPUVPolicy(req)
	rpRKPolicyConv := ""
	if rk, ok := req.Options["rk"]; ok && rk {
		rpRKPolicyConv = "required"
	}

	// Store the credential with RP policy fields
	if err := a.storeCredentialWithPolicy(&storeCredentialParams{
		credentialID:    credentialID,
		rp:              req.RP,
		user:            req.User,
		privateKeyBytes: privateKeyBytes,
		publicKeyCOSE:   publicKeyCOSE,
		algorithm:       selectedAlgorithm,
		discoverable:    discoverable,
		hmacSecretKey:   hmacSecretKey,
		credProtect:     credProtectLevel,
		rpUVPolicy:      rpUVPolicyConv,
		rpUPPolicy:      true,
		rpRKPolicy:      rpRKPolicyConv,
		backendID:       actualBackendID,
	}); err != nil {
		return nil, err
	}

	// Build attestation statement based on configured format
	attestationFmt, attStmt := a.buildAttestationStatement(authData, req.ClientDataHash)

	return &MakeCredentialResponse{
		Fmt:      attestationFmt,
		AuthData: authData,
		AttStmt:  attStmt,
	}, nil
}
