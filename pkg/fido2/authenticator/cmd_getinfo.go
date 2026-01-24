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
)

// PublicKeyCredentialParameters for algorithm list in GetInfo response.
type publicKeyCredentialParameters struct {
	Type string `cbor:"type"`
	Alg  int    `cbor:"alg"`
}

// Default capabilities for the software authenticator.
const (
	defaultMaxMsgSize            = 1200
	defaultMaxCredentialIDLength = 128
	defaultMaxCredBlobLength     = 32
	defaultPINUvAuthProtocol     = 1
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

	// 0x04: options - Map of supported options
	response[getInfoKeyOptions] = a.getOptions()

	// 0x05: maxMsgSize - Maximum message size
	response[getInfoKeyMaxMsgSize] = uint(defaultMaxMsgSize)

	// 0x06: pinUvAuthProtocols - Supported PIN/UV auth protocols
	response[getInfoKeyPinUvAuthProtocols] = []uint{defaultPINUvAuthProtocol}

	// 0x07: maxCredentialCountInList - Max credentials in allow/exclude list
	response[getInfoKeyMaxCredentialCountInList] = uint(a.config.MaxCredentials)

	// 0x08: maxCredentialIdLength - Maximum credential ID length
	response[getInfoKeyMaxCredentialIdLength] = uint(defaultMaxCredentialIDLength)

	// 0x09: transports - Supported transports
	// "usb" for USB HID devices (vfido2 uses UHID to emulate USB HID)
	response[getInfoKeyTransports] = []string{"usb"}

	// 0x0A: algorithms - Supported algorithms
	response[getInfoKeyAlgorithms] = a.getAlgorithms()

	// 0x0D: minPINLength - Minimum PIN length
	if a.config.EnablePIN {
		response[getInfoKeyMinPINLength] = uint(a.config.PINMinLength)
	}

	// 0x14: remainingDiscoverableCredentials - Remaining discoverable credential slots
	remaining, err := a.getRemainingDiscoverableCredentials()
	if err == nil {
		response[getInfoKeyRemainingDiscoverableCredentials] = uint(remaining)
	}

	// Encode response to CBOR
	data, err := encodeCBOR(response)
	if err != nil {
		return nil, err
	}

	return a.successResponse(data), nil
}

// getVersions returns the list of supported CTAP/FIDO versions.
func (a *Authenticator) getVersions() []string {
	versions := []string{"FIDO_2_0"}

	// Add U2F support (we support basic U2F operations)
	versions = append(versions, "U2F_V2")

	// Add FIDO 2.1 if we support its features
	if a.config.EnableCredentialManagement {
		versions = append(versions, "FIDO_2_1")
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

	return extensions
}

// getOptions returns the map of authenticator options.
func (a *Authenticator) getOptions() map[string]bool {
	options := make(map[string]bool)

	// plat - Platform authenticator (false for software authenticator)
	options["plat"] = false

	// rk - Resident key (discoverable credentials) support
	options["rk"] = a.config.EnableResidentKey

	// up - User presence (always supported)
	options["up"] = true

	// uv - User verification capability
	// We support UV via PIN
	if a.config.EnablePIN {
		options["uv"] = true
	}

	// clientPin - Client PIN support and current state
	if a.config.EnablePIN {
		options["clientPin"] = a.state.PINSet
	}

	// credMgmt - Credential management support (FIDO 2.1)
	if a.config.EnableCredentialManagement {
		options["credMgmt"] = true
	}

	// authnrCfg - Authenticator configuration support
	options["authnrCfg"] = false

	// largeBlobs - Large blob storage (not supported)
	options["largeBlobs"] = false

	// alwaysUv - Always require user verification
	options["alwaysUv"] = false

	// makeCredUvNotRqd - UV not required for makeCredential
	options["makeCredUvNotRqd"] = true

	// noMcGaPermissionsWithClientPin - Permissions check
	options["noMcGaPermissionsWithClientPin"] = false

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
