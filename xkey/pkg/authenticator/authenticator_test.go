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
	"context"
	"crypto/sha256"
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

// TestNewAuthenticator_AAGUIDAlwaysFromConfig verifies that the AAGUID on the
// authenticator always reflects the config value, even when state is loaded
// from storage with a different AAGUID. This ensures configuration changes
// (such as firmware updates or device re-identification) take effect without
// requiring state deletion.
func TestNewAuthenticator_AAGUIDAlwaysFromConfig(t *testing.T) {
	storage := NewMemoryStorage()

	// Phase 1: Create an authenticator with the default AAGUID and persist
	// state to storage via Close.
	config1 := DefaultConfig()
	config1.Storage = storage

	auth1, err := NewAuthenticator(config1)
	require.NoError(t, err)
	require.Equal(t, DefaultAAGUID, auth1.AAGUID(),
		"initial authenticator should use DefaultAAGUID from config")

	err = auth1.Close()
	require.NoError(t, err)

	// Confirm storage now holds state with the original AAGUID.
	savedState, err := storage.LoadState()
	require.NoError(t, err)
	require.Equal(t, DefaultAAGUID, savedState.AAGUID,
		"persisted state should have the original AAGUID")

	// Phase 2: Create a new authenticator with a different AAGUID, reusing
	// the same storage that already contains state with the old AAGUID.
	// NewAuthenticator must override the persisted AAGUID with the config value.
	customAAGUID := [16]byte{
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
	}
	config2 := DefaultConfig()
	config2.Storage = storage
	config2.AAGUID = customAAGUID

	auth2, err := NewAuthenticator(config2)
	require.NoError(t, err)
	require.Equal(t, customAAGUID, auth2.AAGUID(),
		"authenticator should use the new config AAGUID, not the persisted one")
	require.NotEqual(t, DefaultAAGUID, auth2.AAGUID(),
		"AAGUID must differ from the original default")

	err = auth2.Close()
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

	// Note: ClientPIN, Reset, CredentialManagement, and Config are now implemented.
	tests := []struct {
		name string
		cmd  byte
	}{
		{"BioEnrollment", CmdBioEnrollment},
		{"LargeBlobs", CmdLargeBlobs},
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

func TestAuthenticator_SyncPINHash(t *testing.T) {
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	// Initially no PIN is set.
	require.False(t, auth.IsPINSet())

	// Sync a PIN hash (simulates startup PIN propagation from sealed storage).
	pinHash := sha256.Sum256([]byte("123456"))
	auth.SyncPINHash(pinHash[:PINHashSize])

	// PIN should now be set.
	require.True(t, auth.IsPINSet())

	// State should contain the correct hash.
	state := auth.GetState()
	require.Equal(t, pinHash[:PINHashSize], state.PINHash)
	require.True(t, state.PINSet)
	require.Equal(t, DefaultPINMaxRetries, state.PINRetries())

	// State should be persisted — reload from storage and verify.
	loaded, err := auth.Storage().(StatefulCredentialStorage).LoadState()
	require.NoError(t, err)
	require.True(t, loaded.PINSet)
	require.Equal(t, pinHash[:PINHashSize], loaded.PINHash)
}

func TestAuthenticator_SyncPINHash_Idempotent(t *testing.T) {
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	pinHash := sha256.Sum256([]byte("123456"))
	auth.SyncPINHash(pinHash[:PINHashSize])
	require.True(t, auth.IsPINSet())

	// Syncing the same hash again should not fail.
	auth.SyncPINHash(pinHash[:PINHashSize])
	require.True(t, auth.IsPINSet())
	require.Equal(t, pinHash[:PINHashSize], auth.GetState().PINHash)
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
		{"UserPresenceDenied", ErrUserPresenceDenied, StatusOperationDenied},
		{"UserPresenceTimeout", ErrUserPresenceTimeout, StatusUserActionTimeout},
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

// TestErrorToStatus_ContextCanceled verifies that errorToStatus maps
// context.Canceled to StatusKeepaliveCancel (0x2D). This mapping enables
// CTAPHID_CANCEL to abort blocking user presence requests and report the
// correct CTAP2 status code to the host.
func TestErrorToStatus_ContextCanceled(t *testing.T) {
	status := errorToStatus(context.Canceled)
	require.Equal(t, byte(StatusKeepaliveCancel), status,
		"context.Canceled should map to StatusKeepaliveCancel (0x2D)")
}

// TestCommandContext_Default verifies that commandContext() returns a non-nil
// context (context.Background) when no CBOR command is currently executing.
// This ensures internal handlers never receive a nil context.
func TestCommandContext_Default(t *testing.T) {
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	// No command is active, so commandContext should return context.Background.
	ctx := auth.commandContext()
	require.NotNil(t, ctx, "commandContext() must never return nil")

	// Verify it is not already cancelled.
	select {
	case <-ctx.Done():
		t.Fatal("default commandContext should not be cancelled")
	default:
		// Expected: context is not done.
	}
}

// TestProcessCBORWithContext_CanceledContext verifies that calling
// ProcessCBORWithContext with an already-cancelled context causes a blocking
// user presence request (via SocketHandler) to return immediately with
// context.Canceled, which is mapped to StatusKeepaliveCancel (0x2D).
//
// This tests the authenticator-level context propagation path:
// ProcessCBORWithContext stores ctx -> handleGetAssertion -> requestUserPresence
// -> SocketHandler.RequestUserPresence sees cancelled ctx -> returns ctx.Err()
// -> propagates as context.Canceled -> errorToStatus maps to 0x2D.
func TestProcessCBORWithContext_CanceledContext(t *testing.T) {
	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.EnablePIN = true
	config.RequireUserPresence = true

	// Use SocketHandler as UP handler: it blocks until approved, denied,
	// timed out, or context cancelled. With a pre-cancelled context, it
	// returns ctx.Err() immediately.
	socketHandler := NewSocketHandler(nil, nil)
	config.UserPresenceHandler = socketHandler

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	rpID := "example.com"

	// Register a credential directly via storage.
	cred := createAssertionTestCredential(t, auth, rpID, false)

	// Set a PIN so the authenticator is in a realistic state.
	rawPIN := "123456"
	fullHash := sha256.Sum256([]byte(rawPIN))
	pinHash := fullHash[:PINHashSize]
	auth.SyncPINHash(pinHash)
	require.True(t, auth.IsPINSet())

	// Build GetAssertion CBOR request with uv=false so it goes through the
	// regular UP path (not the intent check path which wraps errors).
	clientDataHash := generateTestClientDataHash()
	request := map[int]interface{}{
		getAssertionParamRPID:           rpID,
		getAssertionParamClientDataHash: clientDataHash,
		getAssertionParamAllowList: []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"id":   cred.CredentialID,
			},
		},
		getAssertionParamOptions: map[string]bool{"up": true, "uv": false},
	}

	reqBytes, err := cbor.Marshal(request)
	require.NoError(t, err)

	// Create an already-cancelled context.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Call ProcessCBORWithContext with the cancelled context.
	respBytes, err := auth.ProcessCBORWithContext(ctx, CmdGetAssertion, reqBytes)
	require.Error(t, err)

	// The SocketHandler returns ctx.Err() = context.Canceled, which propagates
	// through requestUserPresence and handleGetAssertion back to
	// ProcessCBORWithContext. errorResponseFromError maps it to 0x2D.
	require.Equal(t, byte(StatusKeepaliveCancel), respBytes[0],
		"cancelled context should produce StatusKeepaliveCancel (0x2D)")
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

// ---------------------------------------------------------------------------
// HasMatchingCredentials tests
// ---------------------------------------------------------------------------

// buildGetAssertionCBOR builds a minimal GetAssertion CBOR payload for the
// given rpID and optional allowList credential IDs.
func buildGetAssertionCBOR(t *testing.T, rpID string, allowListIDs ...[]byte) []byte {
	t.Helper()
	clientDataHash := sha256.Sum256([]byte("test-client-data"))
	params := map[int]interface{}{
		getAssertionParamRPID:           rpID,
		getAssertionParamClientDataHash: clientDataHash[:],
	}
	if len(allowListIDs) > 0 {
		list := make([]interface{}, 0, len(allowListIDs))
		for _, id := range allowListIDs {
			list = append(list, map[string]interface{}{
				"type": "public-key",
				"id":   id,
			})
		}
		params[getAssertionParamAllowList] = list
	}
	data, err := cbor.Marshal(params)
	require.NoError(t, err)
	return data
}

func TestHasMatchingCredentials_WithCredential(t *testing.T) {
	t.Parallel()
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	rpID := "example.com"
	cred := createAssertionTestCredential(t, auth, rpID, true)

	data := buildGetAssertionCBOR(t, rpID, cred.CredentialID)
	hasMatch, parseable, hasPINAuth, gotRPID := auth.HasMatchingCredentials(data)
	require.True(t, parseable, "valid GetAssertion should be parseable")
	require.True(t, hasMatch, "should find stored credential")
	require.False(t, hasPINAuth, "no pinUvAuthParam in request")
	require.Equal(t, rpID, gotRPID, "should return the requested rpID")
}

func TestHasMatchingCredentials_NoCredential(t *testing.T) {
	t.Parallel()
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	// No credentials stored — query for "example.com" should return false.
	data := buildGetAssertionCBOR(t, "example.com")
	hasMatch, parseable, hasPINAuth, _ := auth.HasMatchingCredentials(data)
	require.True(t, parseable, "valid GetAssertion should be parseable")
	require.False(t, hasMatch, "should not find credentials for empty storage")
	require.False(t, hasPINAuth, "no pinUvAuthParam in request")
}

func TestHasMatchingCredentials_InvalidCBOR(t *testing.T) {
	t.Parallel()
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	// Garbage bytes should return not parseable without panic.
	hasMatch, parseable, _, _ := auth.HasMatchingCredentials([]byte{0xFF, 0xFE, 0xFD})
	require.False(t, parseable, "garbage CBOR should not be parseable")
	require.False(t, hasMatch)
}

func TestHasMatchingCredentials_EmptyData(t *testing.T) {
	t.Parallel()
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	hasMatch, parseable, _, _ := auth.HasMatchingCredentials(nil)
	require.False(t, parseable, "nil data should not be parseable")
	require.False(t, hasMatch)

	hasMatch, parseable, _, _ = auth.HasMatchingCredentials([]byte{})
	require.False(t, parseable, "empty data should not be parseable")
	require.False(t, hasMatch)
}

func TestHasMatchingCredentials_WrongRPID(t *testing.T) {
	t.Parallel()
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	// Store credential for "a.com", query for "b.com".
	cred := createAssertionTestCredential(t, auth, "a.com", true)
	data := buildGetAssertionCBOR(t, "b.com", cred.CredentialID)
	hasMatch, parseable, _, _ := auth.HasMatchingCredentials(data)
	require.True(t, parseable, "valid GetAssertion should be parseable")
	require.False(t, hasMatch, "should not match different rpID")
}

func TestHasMatchingCredentials_WithAllowList_Match(t *testing.T) {
	t.Parallel()
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	rpID := "example.com"
	cred := createAssertionTestCredential(t, auth, rpID, false)

	// AllowList with the correct credential ID should match.
	data := buildGetAssertionCBOR(t, rpID, cred.CredentialID)
	hasMatch, parseable, _, _ := auth.HasMatchingCredentials(data)
	require.True(t, parseable, "valid GetAssertion should be parseable")
	require.True(t, hasMatch, "should match with correct allowList ID")
}

func TestHasMatchingCredentials_WithAllowList_NoMatch(t *testing.T) {
	t.Parallel()
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	rpID := "example.com"
	_ = createAssertionTestCredential(t, auth, rpID, false)

	// AllowList with bogus credential ID should NOT match.
	bogusID := make([]byte, 32)
	data := buildGetAssertionCBOR(t, rpID, bogusID)
	hasMatch, parseable, _, _ := auth.HasMatchingCredentials(data)
	require.True(t, parseable, "valid GetAssertion should be parseable")
	require.False(t, hasMatch, "should not match with bogus allowList ID")
}

func TestHasMatchingCredentials_ClosedAuthenticator(t *testing.T) {
	t.Parallel()
	auth := createTestAuthenticator(t)
	cred := createAssertionTestCredential(t, auth, "example.com", true)
	data := buildGetAssertionCBOR(t, "example.com", cred.CredentialID)

	// Close the authenticator first.
	require.NoError(t, auth.Close())
	hasMatch, parseable, _, _ := auth.HasMatchingCredentials(data)
	require.False(t, parseable, "closed authenticator should not be parseable")
	require.False(t, hasMatch)
}

func TestHasMatchingCredentials_WithPINAuth(t *testing.T) {
	t.Parallel()
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	// Build a GetAssertion request with pinUvAuthParam present.
	clientDataHash := sha256.Sum256([]byte("test-client-data"))
	params := map[int]interface{}{
		getAssertionParamRPID:           "example.com",
		getAssertionParamClientDataHash: clientDataHash[:],
		getAssertionParamPINUVAuthParam: make([]byte, 32), // fake PIN auth
	}
	data, err := cbor.Marshal(params)
	require.NoError(t, err)

	hasMatch, parseable, hasPINAuth, gotRPID := auth.HasMatchingCredentials(data)
	require.True(t, parseable, "valid GetAssertion should be parseable")
	require.False(t, hasMatch, "no credentials stored")
	require.True(t, hasPINAuth, "should detect pinUvAuthParam")
	require.Equal(t, "example.com", gotRPID, "should return the requested rpID")
}

// ---------------------------------------------------------------------------
// handleSelection tests
//
// handleSelection always auto-approves. A virtual authenticator is "selected"
// by having it running; requiring touch at the Selection stage would create a
// redundant interaction before the PIN dialog (touch -> PIN -> touch instead of
// just PIN -> touch). The user intent check feature (EnableUserIntentCheck) is
// implemented in MakeCredential/GetAssertion, not Selection.
// ---------------------------------------------------------------------------

// TestHandleSelection_AlwaysAutoApproves verifies that authenticatorSelection
// returns CTAP2 success (StatusOK) without invoking the user presence handler,
// regardless of the EnableUserIntentCheck configuration.
func TestHandleSelection_AlwaysAutoApproves(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                  string
		enableUserIntentCheck bool
	}{
		{"IntentCheckDisabled", false},
		{"IntentCheckEnabled", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			storage := NewMemoryStorage()
			config := DefaultConfig()
			config.Storage = storage
			config.EnableUserIntentCheck = tt.enableUserIntentCheck
			handler := &trackingUPHandler{approve: true}
			config.UserPresenceHandler = handler

			auth, err := NewAuthenticator(config)
			require.NoError(t, err)
			defer func() { _ = auth.Close() }()

			resp, err := auth.ProcessCBOR(CmdSelection, nil)
			require.NoError(t, err)
			require.NotEmpty(t, resp)
			require.Equal(t, byte(StatusOK), resp[0],
				"Selection must return StatusOK regardless of intent check setting")
			require.False(t, handler.called.Load(),
				"user presence handler must NOT be called during Selection")
		})
	}
}

// TestHandleSelection_NeverBlocks verifies that Selection returns immediately
// even when the user presence handler would block. Since handleSelection no
// longer calls the UP handler, a blocking handler must not prevent success.
func TestHandleSelection_NeverBlocks(t *testing.T) {
	t.Parallel()
	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.EnableUserIntentCheck = true
	config.UserPresenceHandler = &blockingUPHandler{}

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	resp, err := auth.ProcessCBOR(CmdSelection, nil)
	require.NoError(t, err)
	require.NotEmpty(t, resp)
	require.Equal(t, byte(StatusOK), resp[0],
		"Selection must succeed even when the UP handler would block")
}

// TestHandleSelection_SuccessResponseFormat verifies the exact response byte
// format: a single StatusOK (0x00) byte with no trailing CBOR payload. This
// matches the CTAP2.1 spec for authenticatorSelection which returns an empty
// success response.
func TestHandleSelection_SuccessResponseFormat(t *testing.T) {
	t.Parallel()
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	resp, err := auth.ProcessCBOR(CmdSelection, nil)
	require.NoError(t, err)
	require.Equal(t, []byte{StatusOK}, resp,
		"Selection response should be a single StatusOK byte with no CBOR payload")
}

// ---------------------------------------------------------------------------
// NeedsPINBeforeTouch tests
// ---------------------------------------------------------------------------

// createTestAuthenticatorWithPINEnabled returns an authenticator with
// EnablePIN=true and no PIN hash set yet. The caller must set a PIN hash
// via SyncPINHash when the test requires IsPINSet() == true.
func createTestAuthenticatorWithPINEnabled(t *testing.T) *Authenticator {
	t.Helper()
	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.EnablePIN = true

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auth.Close() })
	return auth
}

// setPINOnAuthenticator sets a PIN hash on auth using SyncPINHash.
func setPINOnAuthenticator(auth *Authenticator, rawPIN string) {
	full := sha256.Sum256([]byte(rawPIN))
	auth.SyncPINHash(full[:PINHashSize])
}

// buildGetAssertionCBORWithPINAuth builds a GetAssertion CBOR payload that
// includes pinUvAuthParam (key 0x06).
func buildGetAssertionCBORWithPINAuth(t *testing.T) []byte {
	t.Helper()
	clientDataHash := sha256.Sum256([]byte("client-data"))
	params := map[int]interface{}{
		getAssertionParamRPID:           "example.com",
		getAssertionParamClientDataHash: clientDataHash[:],
		getAssertionParamPINUVAuthParam: make([]byte, 32), // non-empty token
	}
	data, err := cbor.Marshal(params)
	require.NoError(t, err)
	return data
}

// buildGetAssertionCBORWithoutPINAuth builds a GetAssertion CBOR payload that
// does NOT include pinUvAuthParam.
func buildGetAssertionCBORWithoutPINAuth(t *testing.T) []byte {
	t.Helper()
	clientDataHash := sha256.Sum256([]byte("client-data"))
	params := map[int]interface{}{
		getAssertionParamRPID:           "example.com",
		getAssertionParamClientDataHash: clientDataHash[:],
	}
	data, err := cbor.Marshal(params)
	require.NoError(t, err)
	return data
}

// buildMakeCredentialCBORWithPINAuth builds a MakeCredential CBOR payload that
// includes pinUvAuthParam (key 0x08).
func buildMakeCredentialCBORWithPINAuth(t *testing.T) []byte {
	t.Helper()
	clientDataHash := sha256.Sum256([]byte("client-data"))
	params := map[int]interface{}{
		makeCredentialKeyClientDataHash: clientDataHash[:],
		makeCredentialKeyRP:             map[string]string{"id": "example.com", "name": "Example"},
		makeCredentialKeyPINUVAuthParam: make([]byte, 32), // non-empty token
	}
	data, err := cbor.Marshal(params)
	require.NoError(t, err)
	return data
}

// buildMakeCredentialCBORWithoutPINAuth builds a MakeCredential CBOR payload
// that does NOT include pinUvAuthParam.
func buildMakeCredentialCBORWithoutPINAuth(t *testing.T) []byte {
	t.Helper()
	clientDataHash := sha256.Sum256([]byte("client-data"))
	params := map[int]interface{}{
		makeCredentialKeyClientDataHash: clientDataHash[:],
		makeCredentialKeyRP:             map[string]string{"id": "example.com", "name": "Example"},
	}
	data, err := cbor.Marshal(params)
	require.NoError(t, err)
	return data
}

// TestNeedsPINBeforeTouch_GetAssertion_NoPINAuth tests the primary trigger
// path: PIN is enabled, PIN is set, and the GetAssertion request carries no
// pinUvAuthParam. The HID layer must send KeepaliveStatusProcessing instead
// of prompting the user to touch, because the authenticator will return
// ErrPINRequired before any touch check occurs.
func TestNeedsPINBeforeTouch_GetAssertion_NoPINAuth(t *testing.T) {
	t.Parallel()
	auth := createTestAuthenticatorWithPINEnabled(t)
	setPINOnAuthenticator(auth, "123456")
	require.True(t, auth.IsPINSet())

	data := buildGetAssertionCBORWithoutPINAuth(t)
	require.True(t, auth.NeedsPINBeforeTouch(CmdGetAssertion, data),
		"should return true: PIN enabled, PIN set, no pinUvAuthParam in GetAssertion")
}

// TestNeedsPINBeforeTouch_GetAssertion_WithPINAuth verifies that a GetAssertion
// request that already carries pinUvAuthParam does not trigger the flag, because
// the authenticator will proceed through PIN verification and then request touch.
func TestNeedsPINBeforeTouch_GetAssertion_WithPINAuth(t *testing.T) {
	t.Parallel()
	auth := createTestAuthenticatorWithPINEnabled(t)
	setPINOnAuthenticator(auth, "123456")
	require.True(t, auth.IsPINSet())

	data := buildGetAssertionCBORWithPINAuth(t)
	require.False(t, auth.NeedsPINBeforeTouch(CmdGetAssertion, data),
		"should return false: pinUvAuthParam is present, no pre-touch PIN prompt needed")
}

// TestNeedsPINBeforeTouch_MakeCredential_NoPINAuth tests the primary trigger
// path for MakeCredential: PIN enabled, PIN set, and no pinUvAuthParam in
// the request body.
func TestNeedsPINBeforeTouch_MakeCredential_NoPINAuth(t *testing.T) {
	t.Parallel()
	auth := createTestAuthenticatorWithPINEnabled(t)
	setPINOnAuthenticator(auth, "123456")
	require.True(t, auth.IsPINSet())

	data := buildMakeCredentialCBORWithoutPINAuth(t)
	require.True(t, auth.NeedsPINBeforeTouch(CmdMakeCredential, data),
		"should return true: PIN enabled, PIN set, no pinUvAuthParam in MakeCredential")
}

// TestNeedsPINBeforeTouch_MakeCredential_WithPINAuth verifies that a
// MakeCredential request that already carries pinUvAuthParam returns false,
// because the browser has already completed the PIN exchange.
func TestNeedsPINBeforeTouch_MakeCredential_WithPINAuth(t *testing.T) {
	t.Parallel()
	auth := createTestAuthenticatorWithPINEnabled(t)
	setPINOnAuthenticator(auth, "123456")
	require.True(t, auth.IsPINSet())

	data := buildMakeCredentialCBORWithPINAuth(t)
	require.False(t, auth.NeedsPINBeforeTouch(CmdMakeCredential, data),
		"should return false: pinUvAuthParam is present, touch prompt is appropriate")
}

// TestNeedsPINBeforeTouch_PINNotEnabled verifies that when PIN is not enabled
// in the configuration the method always returns false, regardless of whether
// a PIN hash is present, because the authenticator will not enforce PIN.
func TestNeedsPINBeforeTouch_PINNotEnabled(t *testing.T) {
	t.Parallel()
	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.EnablePIN = false // PIN feature is off

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auth.Close() })

	data := buildGetAssertionCBORWithoutPINAuth(t)
	require.False(t, auth.NeedsPINBeforeTouch(CmdGetAssertion, data),
		"should return false: PIN feature is not enabled")
}

// TestNeedsPINBeforeTouch_PINNotSet verifies that when PIN is enabled but no
// PIN has been configured yet the method returns false: the authenticator will
// not require PIN (it will instead return ErrPINNotSet or proceed without PIN).
func TestNeedsPINBeforeTouch_PINNotSet(t *testing.T) {
	t.Parallel()
	auth := createTestAuthenticatorWithPINEnabled(t)
	// Deliberately do NOT call setPINOnAuthenticator — IsPINSet() must be false.
	require.False(t, auth.IsPINSet())

	data := buildGetAssertionCBORWithoutPINAuth(t)
	require.False(t, auth.NeedsPINBeforeTouch(CmdGetAssertion, data),
		"should return false: PIN is enabled but no PIN has been set")
}

// TestNeedsPINBeforeTouch_UnknownCommand verifies that commands other than
// GetAssertion and MakeCredential always return false because those commands
// do not have a pinUvAuthParam field in the CTAP2 specification.
func TestNeedsPINBeforeTouch_UnknownCommand(t *testing.T) {
	t.Parallel()
	auth := createTestAuthenticatorWithPINEnabled(t)
	setPINOnAuthenticator(auth, "123456")

	// Build arbitrary valid CBOR — the content is irrelevant for unknown commands.
	data, err := cbor.Marshal(map[int]interface{}{1: "irrelevant"})
	require.NoError(t, err)

	unknownCmds := []struct {
		name string
		cmd  byte
	}{
		{"GetInfo", CmdGetInfo},
		{"ClientPIN", CmdClientPIN},
		{"Reset", CmdReset},
		{"GetNextAssertion", CmdGetNextAssertion},
		{"CredentialManagement", CmdCredentialManagement},
		{"Selection", CmdSelection},
		{"Config", CmdConfig},
		{"UnknownFF", 0xFF},
	}

	for _, tc := range unknownCmds {
		t.Run(tc.name, func(t *testing.T) {
			require.False(t, auth.NeedsPINBeforeTouch(tc.cmd, data),
				"command %s (0x%02X) should return false", tc.name, tc.cmd)
		})
	}
}

// TestNeedsPINBeforeTouch_InvalidCBOR verifies that malformed or non-CBOR data
// causes the method to return false rather than panic. A parse failure means
// the command will fail later in normal processing — there is no valid PIN auth
// state to inspect.
func TestNeedsPINBeforeTouch_InvalidCBOR(t *testing.T) {
	t.Parallel()
	auth := createTestAuthenticatorWithPINEnabled(t)
	setPINOnAuthenticator(auth, "123456")

	invalidPayloads := []struct {
		name string
		data []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"garbage", []byte{0xFF, 0xFE, 0xFD, 0xFC}},
		{"truncated map header", []byte{0xBF}}, // indefinite map without break
	}

	for _, tc := range invalidPayloads {
		t.Run(tc.name, func(t *testing.T) {
			require.False(t, auth.NeedsPINBeforeTouch(CmdGetAssertion, tc.data),
				"invalid CBOR should return false, not panic")
			require.False(t, auth.NeedsPINBeforeTouch(CmdMakeCredential, tc.data),
				"invalid CBOR should return false, not panic")
		})
	}
}
