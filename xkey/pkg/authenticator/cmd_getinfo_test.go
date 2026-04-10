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
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func TestHandleGetInfo(t *testing.T) {
	t.Run("returns valid response", func(t *testing.T) {
		auth := createTestAuthenticator(t)
		defer func() { _ = auth.Close() }()

		response, err := auth.handleGetInfo()
		require.NoError(t, err)
		require.NotNil(t, response)
		require.Equal(t, byte(StatusOK), response[0])
		require.Greater(t, len(response), 1)
	})

	t.Run("response contains required fields", func(t *testing.T) {
		auth := createTestAuthenticator(t)
		defer func() { _ = auth.Close() }()

		response, err := auth.handleGetInfo()
		require.NoError(t, err)

		// Decode CBOR response (skip status byte)
		var info map[int]interface{}
		err = cbor.Unmarshal(response[1:], &info)
		require.NoError(t, err)

		// Check versions (0x01)
		versions, ok := info[getInfoKeyVersions].([]interface{})
		require.True(t, ok)
		require.NotEmpty(t, versions)
		require.Contains(t, interfaceSliceToStringSlice(versions), "FIDO_2_0")

		// Check AAGUID (0x03)
		aaguid, ok := info[getInfoKeyAAGUID].([]byte)
		require.True(t, ok)
		require.Len(t, aaguid, 16)
		require.Equal(t, DefaultAAGUID[:], aaguid)

		// Check options (0x04)
		options, ok := info[getInfoKeyOptions].(map[interface{}]interface{})
		require.True(t, ok)
		require.NotNil(t, options)

		// Check maxMsgSize (0x05)
		maxMsgSize, ok := info[getInfoKeyMaxMsgSize].(uint64)
		require.True(t, ok)
		require.Equal(t, uint64(2048), maxMsgSize)

		// Check pinUvAuthProtocols (0x06)
		protocols, ok := info[getInfoKeyPinUvAuthProtocols].([]interface{})
		require.True(t, ok)
		require.NotEmpty(t, protocols)

		// Check maxCredentialIdLength (0x08)
		maxCredIdLen, ok := info[getInfoKeyMaxCredentialIdLength].(uint64)
		require.True(t, ok)
		require.Equal(t, uint64(defaultMaxCredentialIDLength), maxCredIdLen)

		// Check transports (0x09)
		transports, ok := info[getInfoKeyTransports].([]interface{})
		require.True(t, ok)
		require.Contains(t, interfaceSliceToStringSlice(transports), "usb")

		// Check algorithms (0x0A)
		algorithms, ok := info[getInfoKeyAlgorithms].([]interface{})
		require.True(t, ok)
		require.NotEmpty(t, algorithms)
	})

	t.Run("includes extensions when enabled", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.EnableHMACSecret = true

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		response, err := auth.handleGetInfo()
		require.NoError(t, err)

		var info map[int]interface{}
		err = cbor.Unmarshal(response[1:], &info)
		require.NoError(t, err)

		extensions, ok := info[getInfoKeyExtensions].([]interface{})
		require.True(t, ok)
		extStrings := interfaceSliceToStringSlice(extensions)
		require.Contains(t, extStrings, "hmac-secret")
		require.Contains(t, extStrings, "credProtect")
	})

	t.Run("options reflect configuration", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.EnablePIN = true
		config.EnableResidentKey = true
		config.EnableCredentialManagement = true

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		response, err := auth.handleGetInfo()
		require.NoError(t, err)

		var info map[int]interface{}
		err = cbor.Unmarshal(response[1:], &info)
		require.NoError(t, err)

		options := info[getInfoKeyOptions].(map[interface{}]interface{})

		// CTAP2.1 Section 6.4: default-value options SHOULD NOT be present.
		// plat=false (default) and up=true (default) must be absent.
		_, hasPlat := options["plat"]
		require.False(t, hasPlat, "plat=false is the default and should be absent")
		_, hasUP := options["up"]
		require.False(t, hasUP, "up=true is the default and should be absent")

		// Non-default options that should be present
		require.Equal(t, true, options["rk"])         // Resident key enabled (non-default)
		require.Equal(t, false, options["uv"])        // No built-in UV; PIN-based only
		require.Equal(t, false, options["clientPin"]) // PIN not yet set
		require.Equal(t, true, options["credMgmt"])
		require.Equal(t, true, options["pinUvAuthToken"]) // CTAP2.1 PIN token support

		// Removed default-false options should be absent
		_, hasAuthnrCfg := options["authnrCfg"]
		require.False(t, hasAuthnrCfg, "authnrCfg=false should be absent")
		_, hasLargeBlobs := options["largeBlobs"]
		require.False(t, hasLargeBlobs, "largeBlobs=false should be absent")
		_, hasAlwaysUv := options["alwaysUv"]
		require.False(t, hasAlwaysUv, "alwaysUv=false should be absent")
		_, hasNoMcGa := options["noMcGaPermissionsWithClientPin"]
		require.False(t, hasNoMcGa, "noMcGaPermissionsWithClientPin=false should be absent")
	})

	t.Run("clientPin reflects PIN state", func(t *testing.T) {
		storage := NewMemoryStorage()

		// Pre-set PIN state
		state := NewAuthenticatorState()
		state.AAGUID = DefaultAAGUID
		state.PINSet = true
		err := storage.SaveState(state)
		require.NoError(t, err)

		config := DefaultConfig()
		config.Storage = storage
		config.EnablePIN = true

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		response, err := auth.handleGetInfo()
		require.NoError(t, err)

		var info map[int]interface{}
		err = cbor.Unmarshal(response[1:], &info)
		require.NoError(t, err)

		options := info[getInfoKeyOptions].(map[interface{}]interface{})
		require.Equal(t, true, options["clientPin"])
	})

	t.Run("includes minPINLength when PIN enabled", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.EnablePIN = true
		config.PINMinLength = 6

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		response, err := auth.handleGetInfo()
		require.NoError(t, err)

		var info map[int]interface{}
		err = cbor.Unmarshal(response[1:], &info)
		require.NoError(t, err)

		minPINLen, ok := info[getInfoKeyMinPINLength].(uint64)
		require.True(t, ok)
		require.Equal(t, uint64(6), minPINLen)
	})

	t.Run("includes remaining discoverable credentials", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.MaxResidentCredentials = 10

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		response, err := auth.handleGetInfo()
		require.NoError(t, err)

		var info map[int]interface{}
		err = cbor.Unmarshal(response[1:], &info)
		require.NoError(t, err)

		remaining, ok := info[getInfoKeyRemainingDiscoverableCredentials].(uint64)
		require.True(t, ok)
		require.Equal(t, uint64(10), remaining)
	})

	t.Run("remaining decreases with stored credentials", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.MaxResidentCredentials = 10

		// Store a discoverable credential
		cred := &StoredCredential{
			CredentialID: []byte("test-cred-1"),
			RPID:         "example.com",
			UserID:       []byte("user-1"),
			Discoverable: true,
		}
		err := storage.Store(cred)
		require.NoError(t, err)

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		response, err := auth.handleGetInfo()
		require.NoError(t, err)

		var info map[int]interface{}
		err = cbor.Unmarshal(response[1:], &info)
		require.NoError(t, err)

		remaining, ok := info[getInfoKeyRemainingDiscoverableCredentials].(uint64)
		require.True(t, ok)
		require.Equal(t, uint64(9), remaining) // 10 - 1
	})
}

func TestGetVersions(t *testing.T) {
	t.Run("includes FIDO_2_0 and excludes U2F_V2", func(t *testing.T) {
		auth := createTestAuthenticator(t)
		defer func() { _ = auth.Close() }()

		versions := auth.getVersions()
		require.Contains(t, versions, "FIDO_2_0")
		// U2F_V2 must NOT be advertised because CTAPHID INIT sets NMSG
		// capability (no U2F/CTAP1 support). Chrome validates consistency.
		require.NotContains(t, versions, "U2F_V2")
	})

	t.Run("includes FIDO_2_1_PRE and FIDO_2_1 when credential management enabled", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.EnableCredentialManagement = true

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		versions := auth.getVersions()
		require.Contains(t, versions, "FIDO_2_1_PRE")
		require.Contains(t, versions, "FIDO_2_1")
	})

	t.Run("excludes FIDO_2_1 and FIDO_2_1_PRE when credential management disabled", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.EnableCredentialManagement = false

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		versions := auth.getVersions()
		require.NotContains(t, versions, "FIDO_2_1")
		require.NotContains(t, versions, "FIDO_2_1_PRE")
	})
}

func TestGetExtensions(t *testing.T) {
	t.Run("includes credProtect always", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.EnableHMACSecret = false

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		extensions := auth.getExtensions()
		require.Contains(t, extensions, "credProtect")
	})

	t.Run("includes hmac-secret when enabled", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.EnableHMACSecret = true

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		extensions := auth.getExtensions()
		require.Contains(t, extensions, "hmac-secret")
	})

	t.Run("excludes hmac-secret when disabled", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.EnableHMACSecret = false

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		extensions := auth.getExtensions()
		require.NotContains(t, extensions, "hmac-secret")
	})
}

func TestGetOptions(t *testing.T) {
	t.Run("plat absent for software authenticator (default false omitted)", func(t *testing.T) {
		auth := createTestAuthenticator(t)
		defer func() { _ = auth.Close() }()

		options := auth.getOptions()
		_, hasPlat := options["plat"]
		require.False(t, hasPlat, "plat=false is the spec default and must be absent")
	})

	t.Run("up absent (default true omitted)", func(t *testing.T) {
		auth := createTestAuthenticator(t)
		defer func() { _ = auth.Close() }()

		options := auth.getOptions()
		_, hasUP := options["up"]
		require.False(t, hasUP, "up=true is the spec default and must be absent")
	})

	t.Run("rk present when enabled", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.EnableResidentKey = true

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		options := auth.getOptions()
		require.Equal(t, true, options["rk"])
	})

	t.Run("rk absent when disabled (default false omitted)", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.EnableResidentKey = false

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		options := auth.getOptions()
		_, hasRK := options["rk"]
		require.False(t, hasRK, "rk=false is the spec default and must be absent")
	})

	t.Run("uv absent when PIN disabled", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.EnablePIN = false
		config.EnableCredentialManagement = false // Must also disable to prevent PIN being forced on

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		options := auth.getOptions()
		_, hasUV := options["uv"]
		require.False(t, hasUV)
	})

	t.Run("makeCredUvNotRqd absent when PIN is set (default false omitted)", func(t *testing.T) {
		storage := NewMemoryStorage()

		// Pre-set PIN state to simulate a configured authenticator
		state := NewAuthenticatorState()
		state.AAGUID = DefaultAAGUID
		state.PINSet = true
		err := storage.SaveState(state)
		require.NoError(t, err)

		config := DefaultConfig()
		config.Storage = storage
		config.EnablePIN = true

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		options := auth.getOptions()
		_, hasMakeCredUvNotRqd := options["makeCredUvNotRqd"]
		require.False(t, hasMakeCredUvNotRqd,
			"makeCredUvNotRqd=false is the default and must be absent when UV is available")
	})

	t.Run("makeCredUvNotRqd is true when PIN not set", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.EnablePIN = true // PIN enabled but not yet set

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		options := auth.getOptions()
		require.Equal(t, true, options["makeCredUvNotRqd"])
	})

	t.Run("makeCredUvNotRqd is true when PIN disabled", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.EnablePIN = false
		config.EnableCredentialManagement = false // Must also disable to prevent PIN being forced on

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		options := auth.getOptions()
		require.Equal(t, true, options["makeCredUvNotRqd"])
	})

	t.Run("credMgmt absent when disabled", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.EnableCredentialManagement = false

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		options := auth.getOptions()
		_, hasCredMgmt := options["credMgmt"]
		require.False(t, hasCredMgmt)
	})

	t.Run("unsupported options always absent", func(t *testing.T) {
		auth := createTestAuthenticator(t)
		defer func() { _ = auth.Close() }()

		options := auth.getOptions()
		_, hasAuthnrCfg := options["authnrCfg"]
		require.False(t, hasAuthnrCfg, "authnrCfg absent means unsupported")
		_, hasLargeBlobs := options["largeBlobs"]
		require.False(t, hasLargeBlobs, "largeBlobs absent means unsupported")
		_, hasAlwaysUv := options["alwaysUv"]
		require.False(t, hasAlwaysUv, "alwaysUv=false is default, must be absent")
		_, hasNoMcGa := options["noMcGaPermissionsWithClientPin"]
		require.False(t, hasNoMcGa, "noMcGaPermissionsWithClientPin=false is default")
	})
}

func TestGetAlgorithms(t *testing.T) {
	t.Run("returns supported algorithms", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.SupportedAlgorithms = []int{COSEAlgES256, COSEAlgEdDSA}

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		algorithms := auth.getAlgorithms()
		require.Len(t, algorithms, 2)

		// Check first algorithm
		require.Equal(t, "public-key", algorithms[0].Type)
		require.Equal(t, COSEAlgES256, algorithms[0].Alg)

		// Check second algorithm
		require.Equal(t, "public-key", algorithms[1].Type)
		require.Equal(t, COSEAlgEdDSA, algorithms[1].Alg)
	})

	t.Run("returns default algorithm", func(t *testing.T) {
		auth := createTestAuthenticator(t)
		defer func() { _ = auth.Close() }()

		algorithms := auth.getAlgorithms()
		require.NotEmpty(t, algorithms)
		require.Equal(t, "public-key", algorithms[0].Type)
		require.Equal(t, COSEAlgES256, algorithms[0].Alg)
	})
}

func TestGetRemainingDiscoverableCredentials(t *testing.T) {
	t.Run("returns max when empty", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.MaxResidentCredentials = 25

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		remaining, err := auth.getRemainingDiscoverableCredentials()
		require.NoError(t, err)
		require.Equal(t, 25, remaining)
	})

	t.Run("decreases with stored credentials", func(t *testing.T) {
		storage := NewMemoryStorage()

		// Store some discoverable credentials
		for i := 0; i < 5; i++ {
			cred := &StoredCredential{
				CredentialID: []byte{byte(i)},
				RPID:         "example.com",
				UserID:       []byte{byte(i)},
				Discoverable: true,
			}
			err := storage.Store(cred)
			require.NoError(t, err)
		}

		config := DefaultConfig()
		config.Storage = storage
		config.MaxResidentCredentials = 25

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		remaining, err := auth.getRemainingDiscoverableCredentials()
		require.NoError(t, err)
		require.Equal(t, 20, remaining) // 25 - 5
	})

	t.Run("returns zero when at limit", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.MaxResidentCredentials = 3

		// Store max discoverable credentials
		for i := 0; i < 3; i++ {
			cred := &StoredCredential{
				CredentialID: []byte{byte(i)},
				RPID:         "example.com",
				UserID:       []byte{byte(i)},
				Discoverable: true,
			}
			err := storage.Store(cred)
			require.NoError(t, err)
		}

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		remaining, err := auth.getRemainingDiscoverableCredentials()
		require.NoError(t, err)
		require.Equal(t, 0, remaining)
	})

	t.Run("does not count non-discoverable credentials", func(t *testing.T) {
		storage := NewMemoryStorage()

		// Store non-discoverable credential
		cred := &StoredCredential{
			CredentialID: []byte("non-discoverable"),
			RPID:         "example.com",
			UserID:       []byte("user"),
			Discoverable: false,
		}
		err := storage.Store(cred)
		require.NoError(t, err)

		config := DefaultConfig()
		config.Storage = storage
		config.MaxResidentCredentials = 25

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		remaining, err := auth.getRemainingDiscoverableCredentials()
		require.NoError(t, err)
		require.Equal(t, 25, remaining) // Non-discoverable doesn't count
	})
}

// TestGetInfoPinUvAuthProtocolsV2First tests that GetInfo returns pinUvAuthProtocols
// with protocol 2 listed first (preferred) when PIN is enabled or FIDO_2_1 is advertised.
func TestGetInfoPinUvAuthProtocolsV2First(t *testing.T) {
	t.Run("PIN enabled returns protocols 2 then 1", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.EnablePIN = true

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		response, err := auth.handleGetInfo()
		require.NoError(t, err)

		var info map[int]interface{}
		err = cbor.Unmarshal(response[1:], &info)
		require.NoError(t, err)

		protocols, ok := info[getInfoKeyPinUvAuthProtocols].([]interface{})
		require.True(t, ok, "pinUvAuthProtocols should be present when PIN enabled")
		require.Len(t, protocols, 2, "Should advertise exactly 2 protocols")

		// V2 should be listed first (preferred by Chrome per CTAP2.1).
		first, err := toInt(protocols[0])
		require.NoError(t, err)
		require.Equal(t, PINProtocol2, first,
			"First protocol must be V2 (preferred)")

		second, err := toInt(protocols[1])
		require.NoError(t, err)
		require.Equal(t, PINProtocol1, second,
			"Second protocol must be V1 (fallback)")
	})

	t.Run("credential management forces PIN and includes pinUvAuthProtocols", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.EnablePIN = false                 // Explicitly disabled
		config.EnableCredentialManagement = true // Requires UV, so PIN gets forced on

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		response, err := auth.handleGetInfo()
		require.NoError(t, err)

		var info map[int]interface{}
		err = cbor.Unmarshal(response[1:], &info)
		require.NoError(t, err)

		// SetDefaults forces EnablePIN when EnableCredentialManagement is true,
		// so pinUvAuthProtocols MUST be present
		protocols, ok := info[getInfoKeyPinUvAuthProtocols].([]interface{})
		require.True(t, ok,
			"pinUvAuthProtocols MUST be present when credential management forces PIN on")
		require.Len(t, protocols, 2)

		// Verify FIDO_2_1 is advertised (PIN is now enabled, so UV is available)
		versions, ok := info[getInfoKeyVersions].([]interface{})
		require.True(t, ok)
		versionStrings := interfaceSliceToStringSlice(versions)
		require.Contains(t, versionStrings, "FIDO_2_1")
	})

	t.Run("PIN and FIDO_2_1 both disabled omits pinUvAuthProtocols", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.EnablePIN = false
		config.EnableCredentialManagement = false

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		response, err := auth.handleGetInfo()
		require.NoError(t, err)

		var info map[int]interface{}
		err = cbor.Unmarshal(response[1:], &info)
		require.NoError(t, err)

		_, ok := info[getInfoKeyPinUvAuthProtocols]
		require.False(t, ok,
			"pinUvAuthProtocols should not be present when PIN disabled and no FIDO_2_1")
	})
}

// TestGetInfoChromeCTAP21Compliance verifies all fields Chrome checks when an
// authenticator advertises FIDO_2_1. Chrome is stricter than Firefox about
// CTAP2.1 compliance and will reject authenticators with missing fields.
func TestGetInfoChromeCTAP21Compliance(t *testing.T) {
	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.EnablePIN = true
	config.EnableResidentKey = true
	config.EnableCredentialManagement = true
	config.EnableHMACSecret = true
	config.SupportedAlgorithms = []int{COSEAlgES256}

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	response, err := auth.handleGetInfo()
	require.NoError(t, err)

	var info map[int]interface{}
	err = cbor.Unmarshal(response[1:], &info)
	require.NoError(t, err)

	// Versions must include FIDO_2_0, FIDO_2_1_PRE, and FIDO_2_1
	versions, ok := info[getInfoKeyVersions].([]interface{})
	require.True(t, ok)
	versionStrings := interfaceSliceToStringSlice(versions)
	require.Contains(t, versionStrings, "FIDO_2_0")
	require.Contains(t, versionStrings, "FIDO_2_1_PRE")
	require.Contains(t, versionStrings, "FIDO_2_1")

	// Options must include pinUvAuthToken, clientPin, rk, credMgmt
	options, ok := info[getInfoKeyOptions].(map[interface{}]interface{})
	require.True(t, ok)
	require.Equal(t, true, options["pinUvAuthToken"], "pinUvAuthToken must be true for CTAP2.1")
	_, hasClientPin := options["clientPin"]
	require.True(t, hasClientPin, "clientPin must be present")
	require.Equal(t, true, options["rk"])
	require.Equal(t, true, options["credMgmt"])

	// pinUvAuthProtocols must be present with V2 first
	protocols, ok := info[getInfoKeyPinUvAuthProtocols].([]interface{})
	require.True(t, ok, "pinUvAuthProtocols must be present for CTAP2.1")
	require.GreaterOrEqual(t, len(protocols), 1)
	firstProto, err := toInt(protocols[0])
	require.NoError(t, err)
	require.Equal(t, PINProtocol2, firstProto, "V2 must be first (preferred by Chrome)")

	// Transports must be present
	transports, ok := info[getInfoKeyTransports].([]interface{})
	require.True(t, ok, "transports must be present")
	require.NotEmpty(t, transports)

	// Algorithms must be present
	algorithms, ok := info[getInfoKeyAlgorithms].([]interface{})
	require.True(t, ok, "algorithms must be present")
	require.NotEmpty(t, algorithms)

	// maxMsgSize must be present
	maxMsgSize, ok := info[getInfoKeyMaxMsgSize].(uint64)
	require.True(t, ok, "maxMsgSize must be present")
	require.Greater(t, maxMsgSize, uint64(0))
}

func TestHasUserVerification(t *testing.T) {
	t.Run("true when PIN enabled", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.EnablePIN = true

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		require.True(t, auth.hasUserVerification())
	})

	t.Run("false when PIN disabled and no key backend", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.EnablePIN = false
		config.EnableCredentialManagement = false // Prevent PIN being forced on

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		require.False(t, auth.hasUserVerification())
	})

	t.Run("FIDO_2_1 not advertised without user verification", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.EnablePIN = false
		config.EnableCredentialManagement = false

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		// Manually set credMgmt to true to simulate misconfiguration
		auth.config.EnableCredentialManagement = true

		// Without UV, FIDO_2_1 should NOT be advertised
		versions := auth.getVersions()
		require.Contains(t, versions, "FIDO_2_0")
		require.NotContains(t, versions, "FIDO_2_1",
			"FIDO_2_1 must not be advertised without user verification")
		require.NotContains(t, versions, "FIDO_2_1_PRE")
	})
}

// TestGetInfo_PINSet_CorrectOptions verifies that when PIN is configured and set,
// the GetInfo options correctly report clientPin=true and omit makeCredUvNotRqd.
// This ensures Chrome sees a fully configured authenticator with UV available.
func TestGetInfo_PINSet_CorrectOptions(t *testing.T) {
	storage := NewMemoryStorage()

	// Pre-set PIN state to simulate a fully configured authenticator
	state := NewAuthenticatorState()
	state.AAGUID = DefaultAAGUID
	state.PINSet = true
	state.PINHash = make([]byte, 16) // Simulate a stored PIN hash
	err := storage.SaveState(state)
	require.NoError(t, err)

	config := DefaultConfig()
	config.Storage = storage
	config.EnablePIN = true
	config.EnableResidentKey = true
	config.EnableCredentialManagement = true

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	options := auth.getOptions()

	// clientPin must be true when PIN is set
	clientPinVal, hasClientPin := options["clientPin"]
	require.True(t, hasClientPin,
		"clientPin must be present in options when EnablePIN=true")
	require.True(t, clientPinVal,
		"clientPin must be true when PINSet=true")

	// makeCredUvNotRqd must NOT be present when UV is available via PIN.
	// Its spec default is false, and presence with any value when PIN is set
	// can confuse Chrome.
	_, hasMakeCredUvNotRqd := options["makeCredUvNotRqd"]
	require.False(t, hasMakeCredUvNotRqd,
		"makeCredUvNotRqd must not be present when PIN is set (UV is available)")

	// pinUvAuthToken should be present when credential management is enabled
	// and UV is available (PIN is enabled).
	pinUvAuthTokenVal, hasPinUvAuthToken := options["pinUvAuthToken"]
	require.True(t, hasPinUvAuthToken,
		"pinUvAuthToken must be present when credential management is enabled with UV")
	require.True(t, pinUvAuthTokenVal,
		"pinUvAuthToken must be true")

	// credMgmt should be present and true
	credMgmtVal, hasCredMgmt := options["credMgmt"]
	require.True(t, hasCredMgmt,
		"credMgmt must be present when EnableCredentialManagement=true and UV available")
	require.True(t, credMgmtVal,
		"credMgmt must be true")
}

// TestGetInfo_PINNotSet_CorrectOptions verifies that when PIN is enabled but not
// yet configured, clientPin=false and makeCredUvNotRqd=true. This is the initial
// state before the user sets a PIN. Chrome will prompt the user to set a PIN.
func TestGetInfo_PINNotSet_CorrectOptions(t *testing.T) {
	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.EnablePIN = true
	config.EnableResidentKey = true
	config.EnableCredentialManagement = true

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	options := auth.getOptions()

	// clientPin must be false when PIN is enabled but not yet set.
	// This tells Chrome that PIN support exists but needs initial setup.
	clientPinVal, hasClientPin := options["clientPin"]
	require.True(t, hasClientPin,
		"clientPin must be present in options when EnablePIN=true")
	require.False(t, clientPinVal,
		"clientPin must be false when PINSet=false (PIN not yet configured)")

	// makeCredUvNotRqd must be true when no UV is currently available.
	// PIN is enabled but not set, so UV cannot be performed yet.
	makeCredUvNotRqdVal, hasMakeCredUvNotRqd := options["makeCredUvNotRqd"]
	require.True(t, hasMakeCredUvNotRqd,
		"makeCredUvNotRqd must be present when no UV is available")
	require.True(t, makeCredUvNotRqdVal,
		"makeCredUvNotRqd must be true when PIN is not yet set")
}

// TestGetInfo_PINDisabled_NoClientPin verifies that when PIN support is entirely
// disabled (and no biometric backend is present), the clientPin option is absent
// from the options map and makeCredUvNotRqd is true.
func TestGetInfo_PINDisabled_NoClientPin(t *testing.T) {
	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.EnablePIN = false
	config.EnableCredentialManagement = false // Must disable to prevent SetDefaults forcing PIN on

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	options := auth.getOptions()

	// clientPin must NOT be present when PIN is disabled.
	// Per CTAP2 spec, absent clientPin means no PIN support at all.
	_, hasClientPin := options["clientPin"]
	require.False(t, hasClientPin,
		"clientPin must not be present when EnablePIN=false")

	// makeCredUvNotRqd must be true when no UV method is available.
	// Without PIN and without a biometric backend, UV cannot be performed.
	makeCredUvNotRqdVal, hasMakeCredUvNotRqd := options["makeCredUvNotRqd"]
	require.True(t, hasMakeCredUvNotRqd,
		"makeCredUvNotRqd must be present when no UV is available")
	require.True(t, makeCredUvNotRqdVal,
		"makeCredUvNotRqd must be true when PIN is disabled and no biometric backend")

	// uv must not be present (no built-in UV, no PIN-based UV)
	_, hasUV := options["uv"]
	require.False(t, hasUV,
		"uv must not be present when PIN is disabled and no biometric backend")

	// pinUvAuthToken must not be present (no UV mechanism available)
	_, hasPinUvAuthToken := options["pinUvAuthToken"]
	require.False(t, hasPinUvAuthToken,
		"pinUvAuthToken must not be present when PIN is disabled")

	// credMgmt must not be present (requires UV)
	_, hasCredMgmt := options["credMgmt"]
	require.False(t, hasCredMgmt,
		"credMgmt must not be present when no UV is available")
}

// TestGetInfo_PINSet_NoMakeCredUvNotRqd is a regression test for the Chrome
// "change PIN" bug. When PIN is set and UV is available, makeCredUvNotRqd must
// NOT appear in the options map at all. If makeCredUvNotRqd is incorrectly set
// to true when PIN is available, Chrome gets confused about the authenticator's
// UV capabilities and may prompt the user to change their PIN or show
// "may require a newer or different kind of device".
//
// This test exercises the exact condition through the full CBOR-encoded GetInfo
// response path to catch any serialization-level issues.
func TestGetInfo_PINSet_NoMakeCredUvNotRqd(t *testing.T) {
	storage := NewMemoryStorage()

	// Pre-set PIN state
	state := NewAuthenticatorState()
	state.AAGUID = DefaultAAGUID
	state.PINSet = true
	state.PINHash = make([]byte, 16) // Simulate stored PIN hash
	err := storage.SaveState(state)
	require.NoError(t, err)

	config := DefaultConfig()
	config.Storage = storage
	config.EnablePIN = true
	config.EnableResidentKey = true
	config.EnableCredentialManagement = true

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	// Verify through the direct getOptions() path
	options := auth.getOptions()
	_, hasMakeCredUvNotRqd := options["makeCredUvNotRqd"]
	require.False(t, hasMakeCredUvNotRqd,
		"REGRESSION: makeCredUvNotRqd must not appear when PIN is set; "+
			"its presence causes Chrome to show 'change PIN' or reject the authenticator")

	// Also verify through the full handleGetInfo() CBOR response path
	// to catch any serialization-level issues where the option might leak through.
	response, err := auth.handleGetInfo()
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), response[0],
		"GetInfo must return success status")

	var info map[int]interface{}
	err = cbor.Unmarshal(response[1:], &info)
	require.NoError(t, err)

	cborOptions, ok := info[getInfoKeyOptions].(map[interface{}]interface{})
	require.True(t, ok, "options must be present in GetInfo response")

	// The critical regression check: makeCredUvNotRqd must not be in the
	// CBOR-encoded response when PIN is set.
	_, hasMakeCredUvNotRqdCBOR := cborOptions["makeCredUvNotRqd"]
	require.False(t, hasMakeCredUvNotRqdCBOR,
		"REGRESSION: makeCredUvNotRqd leaked into CBOR GetInfo response despite PIN being set; "+
			"this causes Chrome to prompt 'change PIN' or show confusing UV errors")

	// Verify clientPin is correctly true in the CBOR response
	require.Equal(t, true, cborOptions["clientPin"],
		"clientPin must be true in CBOR response when PIN is set")

	// Verify pinUvAuthToken is present (CTAP2.1 requirement when FIDO_2_1 advertised)
	require.Equal(t, true, cborOptions["pinUvAuthToken"],
		"pinUvAuthToken must be true when credential management is enabled with PIN set")
}

// TestGetInfo_IncludesFirmwareVersion verifies that when Config.FirmwareVersion
// is set to a non-zero value, the GetInfo CBOR response includes key 0x0E
// (firmwareVersion) with the correct unsigned integer value.
func TestGetInfo_IncludesFirmwareVersion(t *testing.T) {
	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.FirmwareVersion = 10203

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	response, err := auth.handleGetInfo()
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), response[0])

	var info map[int]interface{}
	err = cbor.Unmarshal(response[1:], &info)
	require.NoError(t, err)

	// 0x0E: firmwareVersion must be present and match the configured value
	fwVersion, ok := info[getInfoKeyFirmwareVersion].(uint64)
	require.True(t, ok,
		"firmwareVersion (0x0E) must be present when FirmwareVersion > 0")
	require.Equal(t, uint64(10203), fwVersion)
}

// TestGetInfo_OmitsFirmwareVersionWhenZero verifies that when
// Config.FirmwareVersion is 0 (the default), key 0x0E (firmwareVersion)
// is NOT included in the GetInfo CBOR response.
func TestGetInfo_OmitsFirmwareVersionWhenZero(t *testing.T) {
	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.FirmwareVersion = 0

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	response, err := auth.handleGetInfo()
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), response[0])

	var info map[int]interface{}
	err = cbor.Unmarshal(response[1:], &info)
	require.NoError(t, err)

	// 0x0E: firmwareVersion must NOT be present when FirmwareVersion is 0
	_, ok := info[getInfoKeyFirmwareVersion]
	require.False(t, ok,
		"firmwareVersion (0x0E) must not be present when FirmwareVersion is 0")
}

// Helper function to convert []interface{} to []string
func interfaceSliceToStringSlice(slice []interface{}) []string {
	result := make([]string, 0, len(slice))
	for _, v := range slice {
		if s, ok := v.(string); ok {
			result = append(result, s)
		}
	}
	return result
}
