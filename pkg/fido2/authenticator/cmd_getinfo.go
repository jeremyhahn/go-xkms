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
	"fmt"
	"log/slog"

	"github.com/jeremyhahn/go-xkms/pkg/fido2/authenticator/keybackend"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// GetInfo response map keys as defined in CTAP2 specification.
const (
	getInfoKeyVersions                         = 0x01
	getInfoKeyExtensions                       = 0x02
	getInfoKeyAAGUID                           = 0x03
	getInfoKeyOptions                          = 0x04
	getInfoKeyMaxMsgSize                       = 0x05
	getInfoKeyPinUvAuthProtocols               = 0x06
	getInfoKeyMaxCredentialCountInList         = 0x07
	getInfoKeyMaxCredentialIdLength            = 0x08
	getInfoKeyTransports                       = 0x09
	getInfoKeyAlgorithms                       = 0x0A
	getInfoKeyMaxSerializedLargeBlobArray      = 0x0B
	getInfoKeyForcePINChange                   = 0x0C
	getInfoKeyMinPINLength                     = 0x0D
	getInfoKeyFirmwareVersion                  = 0x0E
	getInfoKeyMaxCredBlobLength                = 0x0F
	getInfoKeyMaxRPIDsForSetMinPINLength       = 0x10
	getInfoKeyPreferredPlatformUvAttempts      = 0x11
	getInfoKeyUvModality                       = 0x12
	getInfoKeyCertifications                   = 0x13
	getInfoKeyRemainingDiscoverableCredentials = 0x14
	getInfoKeyVendorPrototypeConfigCommands    = 0x15

	// getInfoOptionPolicyTamperLocked is the vendor option ID under which
	// getInfo reports that the SO-signed policy failed integrity verification
	// and user-mode commands are locked. Vendor option IDs are permitted by
	// CTAP 2.1 §6.4 and unknown ones are ignored by clients.
	getInfoOptionPolicyTamperLocked = "policyTamperLocked"
)

// PublicKeyCredentialParameters for algorithm list in GetInfo response.
type publicKeyCredentialParameters struct {
	Type string `cbor:"type"`
	Alg  int    `cbor:"alg"`
}

// Default capabilities for the software authenticator.
const (
	defaultMaxMsgSize            = 2048
	defaultMaxCredentialIDLength = 128
	defaultMaxCredBlobLength     = 32
)

// handleGetInfo implements the CTAP2 authenticatorGetInfo command (0x04).
// This command returns information about the authenticator's capabilities.
// No parameters are required; the data argument is ignored.
func (a *Authenticator) handleGetInfo() ([]byte, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// Build the response map with integer keys per CTAP2 spec
	response := make(map[int]interface{})

	// 0x01: versions - Supported CTAP versions
	response[getInfoKeyVersions] = a.getVersions()

	// 0x02: extensions - Supported extensions
	extensions := a.getExtensions()
	if len(extensions) > 0 {
		response[getInfoKeyExtensions] = extensions
	}

	// 0x03: aaguid - 16-byte Authenticator Attestation GUID
	response[getInfoKeyAAGUID] = a.state.AAGUID[:]

	if a.logger != nil {
		a.logger.Info("GetInfo AAGUID",
			slog.String("aaguid_hex", fmt.Sprintf("%x", a.state.AAGUID[:])))
	}

	// 0x04: options - Map of supported options
	response[getInfoKeyOptions] = a.getOptions()

	// 0x05: maxMsgSize - Maximum message size
	response[getInfoKeyMaxMsgSize] = uint(defaultMaxMsgSize)

	// 0x06: pinUvAuthProtocols - Supported PIN/UV auth protocols
	// CTAP2.1 spec: "If the authenticator supports any version >= 2.1, then
	// pinUvAuthProtocols MUST be present." Only include when PIN is actually
	// enabled, since PIN protocols are the mechanism for pin/UV auth tokens.
	// Prefer protocol 2 (HMAC-SHA-256) over protocol 1 for Chrome compatibility.
	if a.config.EnablePIN {
		response[getInfoKeyPinUvAuthProtocols] = []uint{2, 1}
	}

	// 0x07: maxCredentialCountInList - Max credentials in allow/exclude list
	response[getInfoKeyMaxCredentialCountInList] = uint(a.config.MaxCredentials)

	// 0x08: maxCredentialIdLength - Maximum credential ID length
	response[getInfoKeyMaxCredentialIdLength] = uint(defaultMaxCredentialIDLength)

	// 0x09: transports - Supported transports
	// Use configured transports, falling back to ["usb"] when empty.
	transports := a.config.Transports
	if len(transports) == 0 {
		transports = []string{"usb"}
	}
	response[getInfoKeyTransports] = transports

	// 0x0A: algorithms - Supported algorithms
	response[getInfoKeyAlgorithms] = a.getAlgorithms()

	// 0x0B: maxSerializedLargeBlobArray - required whenever the largeBlobs
	// option is present (CTAP 2.1 §6.4).
	if a.config.EnableLargeBlobs {
		response[getInfoKeyMaxSerializedLargeBlobArray] = uint(a.config.MaxLargeBlobArray)
	}

	// 0x0D: minPINLength - Minimum PIN length
	if a.config.EnablePIN {
		response[getInfoKeyMinPINLength] = uint(a.config.PINMinLength)
	}

	// 0x0E: firmwareVersion - Device firmware version (unsigned integer)
	if a.config.FirmwareVersion > 0 {
		response[getInfoKeyFirmwareVersion] = uint(a.config.FirmwareVersion)
	}

	// 0x14: remainingDiscoverableCredentials - Remaining discoverable credential slots
	remaining, err := a.getRemainingDiscoverableCredentials()
	if err == nil {
		response[getInfoKeyRemainingDiscoverableCredentials] = uint(remaining)
	}

	// 0x15: vendorPrototypeConfigCommands - vendor subcommand IDs reachable
	// through authenticatorConfig's vendorPrototype subcommand. CTAP 2.1 §6.4
	// requires this to be present when that subcommand is supported; without it
	// a client has no way to discover that token initialization exists.
	// handleConfig dispatches the vendorPrototype range unconditionally, so the
	// list is unconditional too.
	response[getInfoKeyVendorPrototypeConfigCommands] = vendorPrototypeConfigCommands()

	// Encode response to CBOR
	data, err := encodeCBOR(response)
	if err != nil {
		return nil, err
	}

	return a.successResponse(data), nil
}

// getVersions returns the list of supported CTAP/FIDO versions.
// Note: U2F_V2 is NOT advertised because CTAPHID INIT sets NMSG capability
// (0x08 = no U2F/CTAP1 support), and Chrome validates consistency between
// transport capabilities and GetInfo versions.
func (a *Authenticator) getVersions() []string {
	versions := []string{"FIDO_2_0"}

	// Add FIDO 2.1 if we support its features AND can mint a pinUvAuthToken.
	// Advertising FIDO_2_1 without a token path causes Chrome to reject the
	// authenticator with "may require a newer or different kind of device".
	if a.supportsPinUvAuthToken() {
		versions = append(versions, "FIDO_2_1_PRE", "FIDO_2_1")
	}

	return versions
}

// getExtensions returns the list of supported extensions.
func (a *Authenticator) getExtensions() []string {
	var extensions []string

	if a.config.EnableHMACSecret {
		extensions = append(extensions, "hmac-secret")
	}

	// credProtect extension is always supported
	extensions = append(extensions, "credProtect")

	// largeBlobKey extension support (future implementation)
	if a.config.EnableLargeBlobs {
		extensions = append(extensions, "largeBlobKey")
	}

	return extensions
}

// getOptions returns the map of authenticator options.
// Per CTAP2.1 Section 6.4, Table 6.3: options at their spec-defined default
// values SHOULD NOT be present. Chrome treats "absent" differently from
// "explicitly false" for capability options.
//
// Spec defaults (omit when at default):
//   - plat: default false (omit)
//   - up: default true (omit)
//   - authnrCfg: absent means unsupported (omit when false)
//   - largeBlobs: absent means unsupported (omit when false)
//   - alwaysUv: default false (omit)
//   - noMcGaPermissionsWithClientPin: default false (omit)
func (a *Authenticator) getOptions() map[string]bool {
	options := make(map[string]bool)

	// rk - Resident key (discoverable credentials) support
	// Only include when true (false is default per spec)
	if a.config.EnableResidentKey {
		options["rk"] = true
	}

	// uv - Built-in user verification (e.g. biometrics).
	// CTAP 2.1 §6.4: uv=true alongside pinUvAuthToken=true promises
	// getPinUvAuthTokenUsingUvWithPermissions, which this authenticator
	// serves only when the key backend can verify a user on demand
	// (keybackend.UserVerifier, ruling 167). A backend that verifies only
	// inside its own key operation (#1145) is the CTAP 2.0 form of built-in
	// UV, so uv=true is advertised for it only when no pinUvAuthToken surface
	// is advertised. Otherwise PIN-based verification reports uv=false
	// (differs from the default of absent).
	if a.userVerifier() != nil ||
		(a.backendHandlesUserVerification() && !a.supportsPinUvAuthToken()) {
		options["uv"] = true
	} else if a.config.EnablePIN {
		options["uv"] = false
	}

	// clientPin - Client PIN support and current state.
	// Always include when PIN is enabled; value indicates PIN set state.
	// Delegates to PINVerifier when available (single source of truth),
	// falls back to internal state.PINSet for standalone/test use.
	if a.config.EnablePIN {
		options["clientPin"] = a.isPINSetLocked()
	}

	// credMgmt - Credential management support (FIDO 2.1)
	// Only advertise when credential management is enabled AND a
	// pinUvAuthToken can be minted. Without one, credMgmt operations cannot be
	// authenticated.
	if a.supportsPinUvAuthToken() {
		options["credMgmt"] = true
	}

	// pinUvAuthToken - Authenticator supports getPinUvAuthTokenUsingPinWithPermissions.
	// CTAP2.1 spec requires this option when FIDO_2_1 is advertised. Chrome
	// validates this strictly and rejects the authenticator if FIDO_2_1 is
	// present but pinUvAuthToken is absent. Only advertise when the PIN path
	// can back it up.
	if a.supportsPinUvAuthToken() {
		options["pinUvAuthToken"] = true
	}

	// makeCredUvNotRqd - UV not required for makeCredential.
	// Only include when true (false is the default).
	// When neither biometrics nor PIN is set, UV genuinely cannot be performed.
	uvAvailable := a.backendHandlesUserVerification() || (a.config.EnablePIN && a.isPINSetLocked())
	if !uvAvailable {
		options["makeCredUvNotRqd"] = true
	}

	// alwaysUv - Always require user verification.
	// Only include when true (false is the default per spec).
	if a.config.AlwaysUV {
		options["alwaysUv"] = true
	}

	// ep - Enterprise attestation support.
	// Only include when enterprise attestation is enabled.
	if a.config.EnableEnterpriseAttestation {
		options["ep"] = true
	}

	// largeBlobs - authenticatorLargeBlobs command support (CTAP 2.1 §6.10).
	// Only include when true (absent means unsupported, per spec default).
	if a.config.EnableLargeBlobs {
		options["largeBlobs"] = true
	}

	// policyTamperLocked - vendor option: the SO-signed policy failed
	// integrity verification and user-mode commands are refused with
	// CTAP2_ERR_INTEGRITY_FAILURE until the SO re-signs it. Present only when
	// locked, so an unlocked device reports nothing and a client that does not
	// know the option ignores it per CTAP 2.1 §6.4. getInfo stays reachable
	// while locked precisely so this state can be read.
	if a.TamperDetected.Load() {
		options[getInfoOptionPolicyTamperLocked] = true
	}

	return options
}

// getAlgorithms returns the list of supported cryptographic algorithms.
func (a *Authenticator) getAlgorithms() []publicKeyCredentialParameters {
	algorithms := make([]publicKeyCredentialParameters, 0, len(a.config.SupportedAlgorithms))

	for _, alg := range a.config.SupportedAlgorithms {
		algorithms = append(algorithms, publicKeyCredentialParameters{
			Type: "public-key",
			Alg:  alg,
		})
	}

	return algorithms
}

// supportsPinUvAuthToken reports whether the authenticator advertises the
// CTAP 2.1 pinUvAuthToken surface: FIDO_2_1, credMgmt and the pinUvAuthToken
// option. authenticatorClientPIN carries every minting subcommand, so the
// surface needs EnablePIN, which Config.SetDefaults forces whenever credential
// management is enabled. A key backend that handles user verification only
// inside its own key operations adds nothing (#1145); one that is a
// keybackend.UserVerifier adds getPinUvAuthTokenUsingUvWithPermissions
// (ruling 167).
func (a *Authenticator) supportsPinUvAuthToken() bool {
	return a.config.EnableCredentialManagement && a.config.EnablePIN
}

// userVerifier returns the key backend's on-demand user verification method,
// or nil when the backend has none (ruling 167).
func (a *Authenticator) userVerifier() keybackend.UserVerifier {
	backend := a.keyBackend
	// NewAuthenticator decorates a non-attesting backend with an
	// AttestingBackend, whose method set hides the inner VerifyUser.
	if attesting, ok := backend.(*keybackend.AttestingBackend); ok {
		backend = attesting.FIDO2KeyBackend
	}
	verifier, ok := backend.(keybackend.UserVerifier)
	if !ok {
		return nil
	}
	return verifier
}

// backendHandlesUserVerification reports whether the key backend verifies the
// user inside every one of its key operations (for example a phone biometric
// gating Sign). For a composite it is true only when every member verifies
// (#1162), so it is a lower bound for any credential: getInfo advertises from
// it, and makeCredential uses it before it knows which member will create the
// key. The UV flag on a response comes from backendHandlesUserVerificationFor.
func (a *Authenticator) backendHandlesUserVerification() bool {
	return a.keyBackend != nil && a.keyBackend.Capabilities().HandlesUserVerification
}

// backendHandlesUserVerificationFor reports whether the backend that owns a
// credential key -- identified by the credential's BackendID -- verified the
// user inside the key operation. makeCredential and getAssertion set the UV
// flag from it when no pinUvAuthParam was given, so a software or TPM
// credential in a composite that also holds a phone never claims the phone's
// verification (#1162).
func (a *Authenticator) backendHandlesUserVerificationFor(backendID xkms.BackendType) bool {
	return a.keyBackend != nil && a.keyBackend.HandlesUserVerificationFor(backendID)
}

// backendHandlesUserPresence reports whether the key backend collects user
// presence inside every one of its key operations. For a composite it is true
// only when every member does (#1162). makeCredential uses it to decide
// whether to skip its own presence check, because that check runs before the
// key exists and so before the creating member is known.
func (a *Authenticator) backendHandlesUserPresence() bool {
	return a.keyBackend != nil && a.keyBackend.Capabilities().HandlesUserPresence
}

// backendHandlesUserPresenceFor reports whether the backend that owns a
// credential key collects user presence inside the key operation.
// getAssertion skips its own presence check only when it does, so a software
// or TPM credential in a composite that also holds a phone still gets a local
// presence check (#1162).
func (a *Authenticator) backendHandlesUserPresenceFor(backendID xkms.BackendType) bool {
	return a.keyBackend != nil && a.keyBackend.HandlesUserPresenceFor(backendID)
}

// getRemainingDiscoverableCredentials returns the number of remaining
// discoverable credential storage slots.
func (a *Authenticator) getRemainingDiscoverableCredentials() (int, error) {
	count, err := a.storage.CountDiscoverable()
	if err != nil {
		return 0, err
	}

	remaining := a.config.MaxResidentCredentials - count
	if remaining < 0 {
		remaining = 0
	}

	return remaining, nil
}
