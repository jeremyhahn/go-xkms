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

func TestNewAuthenticator_Success(t *testing.T) {
	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	require.NotNil(t, auth)

	// Verify AAGUID is set
	require.Equal(t, DefaultAAGUID, auth.AAGUID())

	// Clean up
	err = auth.Close()
	require.NoError(t, err)
}

func TestNewAuthenticator_NilConfig(t *testing.T) {
	auth, err := NewAuthenticator(nil)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNilConfig)
	require.Nil(t, auth)
}

func TestNewAuthenticator_NilStorage(t *testing.T) {
	config := DefaultConfig()
	config.Storage = nil

	auth, err := NewAuthenticator(config)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNilStorage)
	require.Nil(t, auth)
}

func TestNewAuthenticator_AppliesDefaults(t *testing.T) {
	storage := NewMemoryStorage()
	config := &Config{
		Storage: storage,
	}

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	require.NotNil(t, auth)

	// Check that defaults were applied
	cfg := auth.Config()
	require.Equal(t, DefaultAAGUID, cfg.AAGUID)
	require.Equal(t, DefaultMaxCredentials, cfg.MaxCredentials)
	require.Equal(t, DefaultMaxResidentCredentials, cfg.MaxResidentCredentials)
	require.Equal(t, DefaultPINMinLength, cfg.PINMinLength)
	require.Equal(t, DefaultPINMaxRetries, cfg.PINMaxRetries)

	err = auth.Close()
	require.NoError(t, err)
}

func TestNewAuthenticator_LoadsExistingState(t *testing.T) {
	storage := NewMemoryStorage()

	// Create initial state with PIN set
	state := NewAuthenticatorState()
	state.AAGUID = DefaultAAGUID
	state.PINSet = true
	state.PINHash = []byte("test-hash")
	err := storage.SaveState(state)
	require.NoError(t, err)

	config := DefaultConfig()
	config.Storage = storage

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	require.NotNil(t, auth)

	// Verify state was loaded
	require.True(t, auth.IsPINSet())

	err = auth.Close()
	require.NoError(t, err)
}

func TestAuthenticator_ProcessCBOR_AfterClose(t *testing.T) {
	auth := createTestAuthenticator(t)
	err := auth.Close()
	require.NoError(t, err)

	response, err := auth.ProcessCBOR(CmdGetInfo, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrAuthenticatorClosed)
	require.Equal(t, byte(StatusOtherError), response[0])
}

func TestAuthenticator_ProcessCBOR_InvalidCommand(t *testing.T) {
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	response, err := auth.ProcessCBOR(0xFF, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidCommand)
	require.Equal(t, byte(StatusInvalidCommand), response[0])
}

func TestAuthenticator_ProcessCBOR_GetInfo(t *testing.T) {
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	response, err := auth.ProcessCBOR(CmdGetInfo, nil)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), response[0])
	require.Greater(t, len(response), 1) // Should have CBOR data
}

func TestAuthenticator_ProcessCBOR_Selection(t *testing.T) {
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	response, err := auth.ProcessCBOR(CmdSelection, nil)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), response[0])
}

func TestAuthenticator_ProcessCBOR_NotImplementedCommands(t *testing.T) {
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	// Note: ClientPIN, Reset, and CredentialManagement are now implemented.
	tests := []struct {
		name string
		cmd  byte
	}{
		{"BioEnrollment", CmdBioEnrollment},
		{"LargeBlobs", CmdLargeBlobs},
		{"Config", CmdConfig},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := auth.ProcessCBOR(tt.cmd, nil)
			require.Error(t, err)
			require.ErrorIs(t, err, ErrNotImplemented)
			require.Equal(t, byte(StatusInvalidCommand), response[0])
		})
	}
}

func TestAuthenticator_Close_Success(t *testing.T) {
	auth := createTestAuthenticator(t)

	err := auth.Close()
	require.NoError(t, err)
}

func TestAuthenticator_Close_MultipleCalls(t *testing.T) {
	auth := createTestAuthenticator(t)

	err := auth.Close()
	require.NoError(t, err)

	err = auth.Close()
	require.NoError(t, err)
}

func TestAuthenticator_Close_OperationsFailAfter(t *testing.T) {
	auth := createTestAuthenticator(t)

	err := auth.Close()
	require.NoError(t, err)

	_, err = auth.ProcessCBOR(CmdGetInfo, nil)
	require.ErrorIs(t, err, ErrAuthenticatorClosed)
}

func TestAuthenticator_State(t *testing.T) {
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	state := auth.State()
	require.NotNil(t, state)
}

func TestAuthenticator_IsPINSet(t *testing.T) {
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	require.False(t, auth.IsPINSet())
}

func TestAuthenticator_PINRetries(t *testing.T) {
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	require.Equal(t, DefaultPINMaxRetries, auth.PINRetries())
}

func TestAuthenticator_Storage(t *testing.T) {
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	storage := auth.Storage()
	require.NotNil(t, storage)
}

func TestErrorToStatus(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected byte
	}{
		{"nil error", nil, StatusOK},
		{"InvalidCommand", ErrInvalidCommand, StatusInvalidCommand},
		{"InvalidParameter", ErrInvalidParameter, StatusInvalidParameter},
		{"CBORDecodingFailed", ErrCBORDecodingFailed, StatusInvalidCBOR},
		{"CredentialNotFound", ErrCredentialNotFound, StatusNoCredentials},
		{"NoCredentials", ErrNoCredentials, StatusNoCredentials},
		{"OperationDenied", ErrOperationDenied, StatusOperationDenied},
		{"PINRequired", ErrPINRequired, StatusPINRequired},
		{"PINInvalid", ErrPINInvalid, StatusPINInvalid},
		{"PINBlocked", ErrPINBlocked, StatusPINBlocked},
		{"PINAuthInvalid", ErrPINAuthInvalid, StatusPINAuthInvalid},
		{"PINNotSet", ErrPINNotSet, StatusPINNotSet},
		{"PINPolicyViolation", ErrPINPolicyViolation, StatusPINPolicyViolation},
		{"InvalidSubcommand", ErrInvalidSubcommand, StatusInvalidSubcommand},
		{"UnsupportedPINProtocol", ErrUnsupportedPINProtocol, StatusInvalidParameter},
		{"UserPresenceRequired", ErrUserPresenceRequired, StatusUPRequired},
		{"UserVerificationRequired", ErrUserVerificationRequired, StatusUVBlocked},
		{"CredentialExcluded", ErrCredentialExcluded, StatusCredentialExcluded},
		{"UnsupportedExtension", ErrUnsupportedExtension, StatusUnsupportedExtension},
		{"StorageClosed", ErrStorageClosed, StatusOtherError},
		{"StorageError", ErrStorageError, StatusOtherError},
		{"NotImplemented", ErrNotImplemented, StatusInvalidCommand},
		{"CredMgmtNotEnabled", ErrCredMgmtNotEnabled, StatusInvalidCommand},
		{"LimitExceeded", ErrLimitExceeded, StatusLimitExceeded},
		{"UnsupportedCryptoAlgorithm", ErrUnsupportedCryptoAlgorithm, StatusUnsupportedAlgorithm},
		{"NoSupportedAlgorithm", ErrNoSupportedAlgorithm, StatusUnsupportedAlgorithm},
		{"MissingClientDataHash", ErrMissingClientDataHash, StatusMissingParameter},
		{"MissingRP", ErrMissingRP, StatusMissingParameter},
		{"MissingRPID", ErrMissingRPID, StatusMissingParameter},
		{"MissingUser", ErrMissingUser, StatusMissingParameter},
		{"MissingUserID", ErrMissingUserID, StatusMissingParameter},
		{"MissingPubKeyCredParams", ErrMissingPubKeyCredParams, StatusMissingParameter},
		{"MissingCredentialID", ErrMissingCredentialID, StatusMissingParameter},
		{"MissingRPIDHash", ErrMissingRPIDHash, StatusMissingParameter},
		{"MissingUserInfo", ErrMissingUserInfo, StatusMissingParameter},
		{"ResidentKeyLimitReached", ErrResidentKeyLimitReached, StatusKeyStoreFull},
		{"CredentialLimitReached", ErrCredentialLimitReached, StatusKeyStoreFull},
		{"NoEnumerationInProgress", ErrNoEnumerationInProgress, StatusNoCredentials},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := errorToStatus(tt.err)
			require.Equal(t, tt.expected, status)
		})
	}
}

// TestDecodeCBOR tests the decodeCBOR helper function.
func TestDecodeCBOR(t *testing.T) {
	t.Run("valid CBOR map", func(t *testing.T) {
		// Create a valid CBOR-encoded map
		input := map[string]interface{}{
			"key1": "value1",
			"key2": 42,
		}
		data, err := cbor.Marshal(input)
		require.NoError(t, err)

		var result map[string]interface{}
		err = decodeCBOR(data, &result)
		require.NoError(t, err)
		require.Equal(t, "value1", result["key1"])
		require.Equal(t, uint64(42), result["key2"])
	})

	t.Run("valid CBOR array", func(t *testing.T) {
		// Create a valid CBOR-encoded array
		input := []int{1, 2, 3, 4, 5}
		data, err := cbor.Marshal(input)
		require.NoError(t, err)

		var result []int
		err = decodeCBOR(data, &result)
		require.NoError(t, err)
		require.Equal(t, []int{1, 2, 3, 4, 5}, result)
	})

	t.Run("valid CBOR integer map keys", func(t *testing.T) {
		// CTAP2 uses integer map keys
		input := map[int]interface{}{
			1: "version",
			2: []byte{1, 2, 3},
			3: true,
		}
		data, err := cbor.Marshal(input)
		require.NoError(t, err)

		var result map[int]interface{}
		err = decodeCBOR(data, &result)
		require.NoError(t, err)
		require.Equal(t, "version", result[1])
		require.Equal(t, []byte{1, 2, 3}, result[2])
		require.Equal(t, true, result[3])
	})

	t.Run("valid CBOR byte string", func(t *testing.T) {
		input := []byte{0xDE, 0xAD, 0xBE, 0xEF}
		data, err := cbor.Marshal(input)
		require.NoError(t, err)

		var result []byte
		err = decodeCBOR(data, &result)
		require.NoError(t, err)
		require.Equal(t, input, result)
	})

	t.Run("valid CBOR nested structure", func(t *testing.T) {
		input := map[string]interface{}{
			"outer": map[string]interface{}{
				"inner": "nested value",
			},
		}
		data, err := cbor.Marshal(input)
		require.NoError(t, err)

		var result map[string]interface{}
		err = decodeCBOR(data, &result)
		require.NoError(t, err)
		require.NotNil(t, result["outer"])
	})

	t.Run("invalid CBOR returns error", func(t *testing.T) {
		// Invalid CBOR data
		invalidData := []byte{0xFF, 0xFF, 0xFF, 0xFF}

		var result map[string]interface{}
		err := decodeCBOR(invalidData, &result)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrCBORDecodingFailed)
	})

	t.Run("truncated CBOR returns error", func(t *testing.T) {
		// Truncated CBOR map header
		truncatedData := []byte{0xBF} // Indefinite map start without end

		var result map[string]interface{}
		err := decodeCBOR(truncatedData, &result)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrCBORDecodingFailed)
	})

	t.Run("empty CBOR data returns error", func(t *testing.T) {
		var result map[string]interface{}
		err := decodeCBOR([]byte{}, &result)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrCBORDecodingFailed)
	})

	t.Run("CBOR type mismatch", func(t *testing.T) {
		// Encode a string, try to decode as map
		input := "just a string"
		data, err := cbor.Marshal(input)
		require.NoError(t, err)

		var result map[string]interface{}
		err = decodeCBOR(data, &result)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrCBORDecodingFailed)
	})
}

// TestEncodeCBOR tests the encodeCBOR helper function.
func TestEncodeCBOR(t *testing.T) {
	t.Run("encode map", func(t *testing.T) {
		input := map[string]interface{}{
			"key": "value",
		}
		data, err := encodeCBOR(input)
		require.NoError(t, err)
		require.NotEmpty(t, data)

		// Verify it can be decoded back
		var result map[string]interface{}
		err = cbor.Unmarshal(data, &result)
		require.NoError(t, err)
		require.Equal(t, "value", result["key"])
	})

	t.Run("encode array", func(t *testing.T) {
		input := []int{1, 2, 3}
		data, err := encodeCBOR(input)
		require.NoError(t, err)
		require.NotEmpty(t, data)
	})

	t.Run("encode integer key map", func(t *testing.T) {
		input := map[int]interface{}{
			1: "value1",
			2: 42,
		}
		data, err := encodeCBOR(input)
		require.NoError(t, err)
		require.NotEmpty(t, data)
	})
}

// createTestAuthenticator is a helper function to create a test authenticator.
func createTestAuthenticator(t *testing.T) *Authenticator {
	t.Helper()
	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	return auth
}
