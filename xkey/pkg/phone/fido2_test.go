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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestBackend creates a PhoneKeyBackend with a mockPipeTransport for testing.
// The backend is NOT connected (no Noise handshake performed).
func newTestBackend(t *testing.T) (*PhoneKeyBackend, *mockPipeTransport) {
	t.Helper()

	transport, _ := newPipeTransports()
	cfg := testPhoneKeyBackendConfig()
	cfg.OperationTimeout = 2 * time.Second

	backend, err := NewPhoneKeyBackendWithTransport(cfg, transport)
	require.NoError(t, err)
	require.NotNil(t, backend)

	return backend, transport
}

// newClosedBackend creates a PhoneKeyBackend that has already been closed.
func newClosedBackend(t *testing.T) *PhoneKeyBackend {
	t.Helper()

	backend, _ := newTestBackend(t)
	err := backend.Close()
	require.NoError(t, err)

	return backend
}

// newFailingConnectBackend creates a PhoneKeyBackend whose transport will fail
// on Receive, causing the Noise handshake to fail during Connect.
func newFailingConnectBackend(t *testing.T) *PhoneKeyBackend {
	t.Helper()

	transport, _ := newPipeTransports()
	transport.recvErr = errMockRecv

	cfg := testPhoneKeyBackendConfig()
	cfg.OperationTimeout = 2 * time.Second

	backend, err := NewPhoneKeyBackendWithTransport(cfg, transport)
	require.NoError(t, err)
	require.NotNil(t, backend)

	return backend
}

// ---------------------------------------------------------------------------
// ListFido2Credentials tests
// ---------------------------------------------------------------------------

func TestListFido2Credentials_BackendClosed(t *testing.T) {
	t.Parallel()

	backend := newClosedBackend(t)

	result, err := backend.ListFido2Credentials(context.Background(), "example.com")

	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrBackendClosed)
}

func TestListFido2Credentials_EmptyRpID(t *testing.T) {
	t.Parallel()

	backend, _ := newTestBackend(t)
	defer backend.Close()

	result, err := backend.ListFido2Credentials(context.Background(), "")

	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrInvalidRpID)
}

func TestListFido2Credentials_NotConnected_ConnectFails(t *testing.T) {
	t.Parallel()

	backend := newFailingConnectBackend(t)
	defer backend.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	result, err := backend.ListFido2Credentials(ctx, "example.com")

	assert.Nil(t, result)
	assert.Error(t, err)
	// The error should be from the failed handshake, wrapped as ErrNoiseHandshakeFailed.
	assert.ErrorIs(t, err, ErrNoiseHandshakeFailed)
}

// ---------------------------------------------------------------------------
// SignFido2Assertion tests
// ---------------------------------------------------------------------------

func TestSignFido2Assertion_BackendClosed(t *testing.T) {
	t.Parallel()

	backend := newClosedBackend(t)

	params := &LocalSignFido2AssertionParams{
		CredentialID:   []byte("test-cred-id"),
		ClientDataHash: []byte("test-client-data-hash"),
		RpID:           "example.com",
	}

	result, err := backend.SignFido2Assertion(context.Background(), params)

	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrBackendClosed)
}

func TestSignFido2Assertion_NilParams(t *testing.T) {
	t.Parallel()

	backend, _ := newTestBackend(t)
	defer backend.Close()

	result, err := backend.SignFido2Assertion(context.Background(), nil)

	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrInvalidCredentialID)
}

func TestSignFido2Assertion_EmptyCredentialID(t *testing.T) {
	t.Parallel()

	backend, _ := newTestBackend(t)
	defer backend.Close()

	params := &LocalSignFido2AssertionParams{
		CredentialID:   []byte{},
		ClientDataHash: []byte("test-client-data-hash"),
		RpID:           "example.com",
	}

	result, err := backend.SignFido2Assertion(context.Background(), params)

	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrInvalidCredentialID)
}

func TestSignFido2Assertion_EmptyClientDataHash(t *testing.T) {
	t.Parallel()

	backend, _ := newTestBackend(t)
	defer backend.Close()

	params := &LocalSignFido2AssertionParams{
		CredentialID:   []byte("test-cred-id"),
		ClientDataHash: []byte{},
		RpID:           "example.com",
	}

	result, err := backend.SignFido2Assertion(context.Background(), params)

	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrInvalidClientDataHash)
}

func TestSignFido2Assertion_EmptyRpID(t *testing.T) {
	t.Parallel()

	backend, _ := newTestBackend(t)
	defer backend.Close()

	params := &LocalSignFido2AssertionParams{
		CredentialID:   []byte("test-cred-id"),
		ClientDataHash: []byte("test-client-data-hash"),
		RpID:           "",
	}

	result, err := backend.SignFido2Assertion(context.Background(), params)

	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrInvalidRpID)
}

func TestSignFido2Assertion_NotConnected_ConnectFails(t *testing.T) {
	t.Parallel()

	backend := newFailingConnectBackend(t)
	defer backend.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	params := &LocalSignFido2AssertionParams{
		CredentialID:   []byte("test-cred-id"),
		ClientDataHash: []byte("test-client-data-hash"),
		RpID:           "example.com",
	}

	result, err := backend.SignFido2Assertion(ctx, params)

	assert.Nil(t, result)
	assert.Error(t, err)
	// The error should be from the failed handshake, wrapped as ErrNoiseHandshakeFailed.
	assert.ErrorIs(t, err, ErrNoiseHandshakeFailed)
}

// ---------------------------------------------------------------------------
// Validation ordering tests - verify validation checks execute in the
// documented order: closed -> param validation -> connect check.
// ---------------------------------------------------------------------------

func TestSignFido2Assertion_ClosedTakesPrecedenceOverNilParams(t *testing.T) {
	t.Parallel()

	backend := newClosedBackend(t)

	// Even with nil params, closed check should fire first.
	result, err := backend.SignFido2Assertion(context.Background(), nil)

	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrBackendClosed)
}

func TestListFido2Credentials_ClosedTakesPrecedenceOverEmptyRpID(t *testing.T) {
	t.Parallel()

	backend := newClosedBackend(t)

	// Even with empty rpID, closed check should fire first.
	result, err := backend.ListFido2Credentials(context.Background(), "")

	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrBackendClosed)
}
