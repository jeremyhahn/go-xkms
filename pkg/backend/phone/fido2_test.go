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

package phone

import (
	"context"
	"errors"
	"testing"
	"time"

	phoneproto "github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- ListFido2Credentials ---

func TestListFido2Credentials_Success(t *testing.T) {
	expectedCreds := []phoneproto.Fido2CredentialInfo{
		{
			CredentialID:    []byte("cred-1"),
			RpID:            "example.com",
			RpName:          "Example",
			UserID:          []byte("user-1"),
			UserName:        "alice@example.com",
			UserDisplayName: "Alice",
			IsDiscoverable:  true,
			CreatedAt:       time.Now().Unix(),
		},
		{
			CredentialID:    []byte("cred-2"),
			RpID:            "example.com",
			RpName:          "Example",
			UserID:          []byte("user-2"),
			UserName:        "bob@example.com",
			UserDisplayName: "Bob",
			IsDiscoverable:  false,
			CreatedAt:       time.Now().Unix(),
		},
	}

	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			assert.Equal(t, phoneproto.MethodLocalListFido2Credentials, req.Method)
			return mockSuccessResponse(phoneproto.LocalListFido2CredentialsResult{
				Credentials: expectedCreds,
			}), nil
		},
	}

	b := newTestBackend(t, sender)

	creds, err := b.ListFido2Credentials(context.Background(), "example.com")
	require.NoError(t, err)
	require.Len(t, creds, 2)

	assert.Equal(t, []byte("cred-1"), creds[0].CredentialID)
	assert.Equal(t, "example.com", creds[0].RpID)
	assert.Equal(t, "alice@example.com", creds[0].UserName)
	assert.Equal(t, "Alice", creds[0].UserDisplayName)
	assert.True(t, creds[0].IsDiscoverable)

	assert.Equal(t, []byte("cred-2"), creds[1].CredentialID)
	assert.Equal(t, "bob@example.com", creds[1].UserName)
	assert.False(t, creds[1].IsDiscoverable)
}

func TestListFido2Credentials_BackendClosed(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)
	_ = b.Close()

	creds, err := b.ListFido2Credentials(context.Background(), "example.com")
	assert.Nil(t, creds)
	assert.Equal(t, ErrBackendClosed, err)
}

func TestListFido2Credentials_EmptyRpID(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	creds, err := b.ListFido2Credentials(context.Background(), "")
	assert.Nil(t, creds)
	assert.Equal(t, ErrInvalidRpID, err)
}

func TestListFido2Credentials_EmptyResult(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockSuccessResponse(phoneproto.LocalListFido2CredentialsResult{
				Credentials: []phoneproto.Fido2CredentialInfo{},
			}), nil
		},
	}

	b := newTestBackend(t, sender)

	creds, err := b.ListFido2Credentials(context.Background(), "no-creds.example.com")
	require.NoError(t, err)
	require.NotNil(t, creds)
	assert.Empty(t, creds)
}

func TestListFido2Credentials_RPCError(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockErrorResponse(phoneproto.ErrorCodeInternalError, "internal error"), nil
		},
	}

	b := newTestBackend(t, sender)

	creds, err := b.ListFido2Credentials(context.Background(), "example.com")
	assert.Nil(t, creds)
	assert.Equal(t, ErrInvalidResponse, err)
}

func TestListFido2Credentials_TransportError(t *testing.T) {
	transportErr := errors.New("connection refused")
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return nil, transportErr
		},
	}

	b := newTestBackend(t, sender)

	creds, err := b.ListFido2Credentials(context.Background(), "example.com")
	assert.Nil(t, creds)
	assert.Equal(t, transportErr, err)
}

func TestListFido2Credentials_InvalidDecodeResult(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockInvalidResultResponse(), nil
		},
	}

	b := newTestBackend(t, sender)

	creds, err := b.ListFido2Credentials(context.Background(), "example.com")
	assert.Nil(t, creds)
	assert.Equal(t, ErrInvalidResponse, err)
}

// --- SignFido2Assertion ---

func TestSignFido2Assertion_Success(t *testing.T) {
	expectedAuthData := []byte("authenticator-data-bytes")
	expectedSignature := []byte("signature-bytes")
	expectedUserHandle := []byte("user-handle")

	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			assert.Equal(t, phoneproto.MethodLocalSignFido2Assertion, req.Method)
			return mockSuccessResponse(phoneproto.LocalSignFido2AssertionResult{
				AuthenticatorData: expectedAuthData,
				Signature:         expectedSignature,
				UserHandle:        expectedUserHandle,
				SignCount:         42,
			}), nil
		},
	}

	b := newTestBackend(t, sender)

	params := &phoneproto.LocalSignFido2AssertionParams{
		CredentialID:             []byte("cred-id-123"),
		ClientDataHash:           []byte("client-data-hash-32-bytes-long!!"),
		RpID:                     "example.com",
		UserVerificationRequired: true,
	}

	result, err := b.SignFido2Assertion(context.Background(), params)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, expectedAuthData, result.AuthenticatorData)
	assert.Equal(t, expectedSignature, result.Signature)
	assert.Equal(t, expectedUserHandle, result.UserHandle)
	assert.Equal(t, int64(42), result.SignCount)
}

func TestSignFido2Assertion_BackendClosed(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)
	_ = b.Close()

	params := &phoneproto.LocalSignFido2AssertionParams{
		CredentialID:   []byte("cred-id"),
		ClientDataHash: []byte("hash"),
		RpID:           "example.com",
	}

	result, err := b.SignFido2Assertion(context.Background(), params)
	assert.Nil(t, result)
	assert.Equal(t, ErrBackendClosed, err)
}

func TestSignFido2Assertion_NilParams(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	result, err := b.SignFido2Assertion(context.Background(), nil)
	assert.Nil(t, result)
	assert.Equal(t, ErrInvalidConfig, err)
}

func TestSignFido2Assertion_EmptyCredentialID(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	params := &phoneproto.LocalSignFido2AssertionParams{
		CredentialID:   nil,
		ClientDataHash: []byte("hash"),
		RpID:           "example.com",
	}

	result, err := b.SignFido2Assertion(context.Background(), params)
	assert.Nil(t, result)
	assert.Equal(t, ErrInvalidCredentialID, err)
}

func TestSignFido2Assertion_EmptyClientDataHash(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	params := &phoneproto.LocalSignFido2AssertionParams{
		CredentialID:   []byte("cred-id"),
		ClientDataHash: nil,
		RpID:           "example.com",
	}

	result, err := b.SignFido2Assertion(context.Background(), params)
	assert.Nil(t, result)
	assert.Equal(t, ErrInvalidClientDataHash, err)
}

func TestSignFido2Assertion_EmptyRpID(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	params := &phoneproto.LocalSignFido2AssertionParams{
		CredentialID:   []byte("cred-id"),
		ClientDataHash: []byte("hash"),
		RpID:           "",
	}

	result, err := b.SignFido2Assertion(context.Background(), params)
	assert.Nil(t, result)
	assert.Equal(t, ErrInvalidRpID, err)
}

func TestSignFido2Assertion_RPCError(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockErrorResponse(phoneproto.ErrorCodeUserCancelled, "user cancelled"), nil
		},
	}

	b := newTestBackend(t, sender)

	params := &phoneproto.LocalSignFido2AssertionParams{
		CredentialID:   []byte("cred-id"),
		ClientDataHash: []byte("hash"),
		RpID:           "example.com",
	}

	result, err := b.SignFido2Assertion(context.Background(), params)
	assert.Nil(t, result)
	assert.Equal(t, ErrUserCancelled, err)
}

func TestSignFido2Assertion_TransportError(t *testing.T) {
	transportErr := errors.New("bluetooth disconnected")
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return nil, transportErr
		},
	}

	b := newTestBackend(t, sender)

	params := &phoneproto.LocalSignFido2AssertionParams{
		CredentialID:   []byte("cred-id"),
		ClientDataHash: []byte("hash"),
		RpID:           "example.com",
	}

	result, err := b.SignFido2Assertion(context.Background(), params)
	assert.Nil(t, result)
	assert.Equal(t, transportErr, err)
}

func TestSignFido2Assertion_InvalidDecodeResult(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockInvalidResultResponse(), nil
		},
	}

	b := newTestBackend(t, sender)

	params := &phoneproto.LocalSignFido2AssertionParams{
		CredentialID:   []byte("cred-id"),
		ClientDataHash: []byte("hash"),
		RpID:           "example.com",
	}

	result, err := b.SignFido2Assertion(context.Background(), params)
	assert.Nil(t, result)
	assert.Equal(t, ErrInvalidResponse, err)
}

func TestSignFido2Assertion_BiometricFailed(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockErrorResponse(phoneproto.ErrorCodeBiometricFailed, "biometric failed"), nil
		},
	}

	b := newTestBackend(t, sender)

	params := &phoneproto.LocalSignFido2AssertionParams{
		CredentialID:             []byte("cred-id"),
		ClientDataHash:           []byte("hash"),
		RpID:                     "example.com",
		UserVerificationRequired: true,
	}

	result, err := b.SignFido2Assertion(context.Background(), params)
	assert.Nil(t, result)
	assert.Equal(t, ErrBiometricFailed, err)
}

// --- GetFido2CredentialInfo ---

func TestGetFido2CredentialInfo_Success(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			assert.Equal(t, phoneproto.MethodLocalGetKeyInfo, req.Method)
			return mockSuccessResponse(phoneproto.LocalGetKeyInfoResult{
				KeyInfo: phoneproto.KeyInfo{
					KeyID:     "fido2-key-1",
					Algorithm: "ES256",
					KeyType:   "fido2",
				},
				RpID:            "example.com",
				RpName:          "Example Corp",
				UserID:          "user-123",
				UserName:        "alice@example.com",
				UserDisplayName: "Alice Doe",
				IsDiscoverable:  true,
				SignCount:       17,
			}), nil
		},
	}

	b := newTestBackend(t, sender)

	result, err := b.GetFido2CredentialInfo(context.Background(), "fido2-key-1")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "fido2-key-1", result.KeyID)
	assert.Equal(t, "ES256", result.Algorithm)
	assert.Equal(t, "fido2", result.KeyType)
	assert.Equal(t, "example.com", result.RpID)
	assert.Equal(t, "Example Corp", result.RpName)
	assert.Equal(t, "user-123", result.UserID)
	assert.Equal(t, "alice@example.com", result.UserName)
	assert.Equal(t, "Alice Doe", result.UserDisplayName)
	assert.True(t, result.IsDiscoverable)
	assert.Equal(t, int64(17), result.SignCount)
}

func TestGetFido2CredentialInfo_BackendClosed(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)
	_ = b.Close()

	result, err := b.GetFido2CredentialInfo(context.Background(), "fido2-key-1")
	assert.Nil(t, result)
	assert.Equal(t, ErrBackendClosed, err)
}

func TestGetFido2CredentialInfo_EmptyKeyID(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	result, err := b.GetFido2CredentialInfo(context.Background(), "")
	assert.Nil(t, result)
	assert.Equal(t, ErrEmptyKeyID, err)
}

func TestGetFido2CredentialInfo_RPCError(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockErrorResponse(phoneproto.ErrorCodeKeyNotFound, "key not found"), nil
		},
	}

	b := newTestBackend(t, sender)

	result, err := b.GetFido2CredentialInfo(context.Background(), "nonexistent-key")
	assert.Nil(t, result)
	assert.Equal(t, ErrKeyNotFound, err)
}

func TestGetFido2CredentialInfo_TransportError(t *testing.T) {
	transportErr := errors.New("connection timeout")
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return nil, transportErr
		},
	}

	b := newTestBackend(t, sender)

	result, err := b.GetFido2CredentialInfo(context.Background(), "fido2-key-1")
	assert.Nil(t, result)
	assert.Equal(t, transportErr, err)
}

func TestGetFido2CredentialInfo_InvalidDecodeResult(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockInvalidResultResponse(), nil
		},
	}

	b := newTestBackend(t, sender)

	result, err := b.GetFido2CredentialInfo(context.Background(), "fido2-key-1")
	assert.Nil(t, result)
	assert.Equal(t, ErrInvalidResponse, err)
}

func TestGetFido2CredentialInfo_NonFido2Key(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockSuccessResponse(phoneproto.LocalGetKeyInfoResult{
				KeyInfo: phoneproto.KeyInfo{
					KeyID:     "signing-key-1",
					Algorithm: "ES256",
					KeyType:   "signing",
				},
			}), nil
		},
	}

	b := newTestBackend(t, sender)

	result, err := b.GetFido2CredentialInfo(context.Background(), "signing-key-1")
	require.NoError(t, err)
	require.NotNil(t, result)

	// The method returns whatever the phone returns; FIDO2 fields will be zero-valued
	// for non-FIDO2 keys.
	assert.Equal(t, "signing-key-1", result.KeyID)
	assert.Equal(t, "signing", result.KeyType)
	assert.Empty(t, result.RpID)
	assert.Empty(t, result.UserName)
	assert.False(t, result.IsDiscoverable)
	assert.Equal(t, int64(0), result.SignCount)
}

// --- Validation ordering ---

func TestSignFido2Assertion_ClosedCheckBeforeParamValidation(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)
	_ = b.Close()

	// Even with nil params, closed check takes priority.
	result, err := b.SignFido2Assertion(context.Background(), nil)
	assert.Nil(t, result)
	assert.Equal(t, ErrBackendClosed, err)
}

func TestListFido2Credentials_ClosedCheckBeforeRpIDValidation(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)
	_ = b.Close()

	// Even with empty rpID, closed check takes priority.
	creds, err := b.ListFido2Credentials(context.Background(), "")
	assert.Nil(t, creds)
	assert.Equal(t, ErrBackendClosed, err)
}

func TestGetFido2CredentialInfo_ClosedCheckBeforeKeyIDValidation(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)
	_ = b.Close()

	// Even with empty keyID, closed check takes priority.
	result, err := b.GetFido2CredentialInfo(context.Background(), "")
	assert.Nil(t, result)
	assert.Equal(t, ErrBackendClosed, err)
}
