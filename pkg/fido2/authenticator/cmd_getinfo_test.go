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
		require.Equal(t, uint64(defaultMaxMsgSize), maxMsgSize)

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

		// Check specific options
		require.Equal(t, false, options["plat"])      // Software authenticator
		require.Equal(t, true, options["rk"])         // Resident key enabled
		require.Equal(t, true, options["up"])         // User presence always supported
		require.Equal(t, true, options["uv"])         // UV via PIN
		require.Equal(t, false, options["clientPin"]) // PIN not yet set
		require.Equal(t, true, options["credMgmt"])
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
	t.Run("includes FIDO_2_0 and U2F_V2", func(t *testing.T) {
		auth := createTestAuthenticator(t)
		defer func() { _ = auth.Close() }()

		versions := auth.getVersions()
		require.Contains(t, versions, "FIDO_2_0")
		require.Contains(t, versions, "U2F_V2")
	})

	t.Run("includes FIDO_2_1 when credential management enabled", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.EnableCredentialManagement = true

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		versions := auth.getVersions()
		require.Contains(t, versions, "FIDO_2_1")
	})

	t.Run("excludes FIDO_2_1 when credential management disabled", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.EnableCredentialManagement = false

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		versions := auth.getVersions()
		require.NotContains(t, versions, "FIDO_2_1")
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
	t.Run("plat is always false for software authenticator", func(t *testing.T) {
		auth := createTestAuthenticator(t)
		defer func() { _ = auth.Close() }()

		options := auth.getOptions()
		require.Equal(t, false, options["plat"])
	})

	t.Run("up is always true", func(t *testing.T) {
		auth := createTestAuthenticator(t)
		defer func() { _ = auth.Close() }()

		options := auth.getOptions()
		require.Equal(t, true, options["up"])
	})

	t.Run("rk reflects EnableResidentKey", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.EnableResidentKey = false

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		options := auth.getOptions()
		require.Equal(t, false, options["rk"])
	})

	t.Run("uv depends on EnablePIN", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.EnablePIN = false

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		options := auth.getOptions()
		_, hasUV := options["uv"]
		require.False(t, hasUV)
	})

	t.Run("credMgmt reflects EnableCredentialManagement", func(t *testing.T) {
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
