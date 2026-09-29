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

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/correlation"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// scrubMarker is a distinctive string standing in for internal detail (a
// storage path, a library message) that must never reach a client.
const scrubMarker = "SCRUB-MARKER-/var/lib/xkms/secret-path-1118"

// errScrubMarker is an unclassified service error carrying scrubMarker.
var errScrubMarker = errors.New("storage backend failed at " + scrubMarker)

// newScrubMCPServer returns an MCP server over a single mock backend named
// "mock" whose ListKeys returns listErr, logging into the returned buffer.
func newScrubMCPServer(t *testing.T, listErr error) (*Server, *bytes.Buffer) {
	t.Helper()
	xkms.Reset()
	t.Cleanup(xkms.Reset)

	ks := xkmsmocks.NewMockKeyStore()
	ks.ListKeysFunc = func() ([]*types.KeyAttributes, error) { return nil, listErr }
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"mock": ks},
		DefaultBackend: "mock",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)

	var logs bytes.Buffer
	server, err := NewServer(&Config{
		XKMSService:   svc,
		Authenticator: auth.NewNoOpAuthenticator(),
		Logger:        slog.New(slog.NewTextHandler(&logs, nil)),
	})
	require.NoError(t, err)
	return server, &logs
}

// listKeysParams is the params object for xkms.listKeys on backend "mock".
var listKeysParams = json.RawMessage(`{"backend":"mock"}`)

// TestInvokeMethod_InternalErrorWithheldAndLogged drives an unclassified
// service error through InvokeMethod: the client-facing rendering carries
// the fixed internal message and no trace of the marker, while the server
// log carries the marker with the method, tool and request ID.
func TestInvokeMethod_InternalErrorWithheldAndLogged(t *testing.T) {
	server, logs := newScrubMCPServer(t, errScrubMarker)
	ctx := correlation.WithCorrelationID(context.Background(), "req-1118")

	_, err := server.InvokeMethod(ctx, "xkms.listKeys", listKeysParams)
	require.Error(t, err)
	require.ErrorIs(t, err, errScrubMarker, "the full error stays available server-side")

	code, message := ClientError(err)
	assert.Equal(t, ErrCodeInternalError, code)
	assert.Equal(t, ErrInternal.Error(), message)
	assert.NotContains(t, message, scrubMarker)

	logged := logs.String()
	assert.Contains(t, logged, withheldErrorLogMessage)
	assert.Contains(t, logged, scrubMarker)
	assert.Contains(t, logged, "method=xkms.listKeys")
	assert.Contains(t, logged, "tool=xkms_listKeys")
	assert.Contains(t, logged, "request_id=req-1118")
}

// TestInvokeMethod_ClientFaultKeepsMessage verifies a classified client
// fault reaches the client with its own message and is not logged as
// withheld.
func TestInvokeMethod_ClientFaultKeepsMessage(t *testing.T) {
	server, logs := newScrubMCPServer(t, fmt.Errorf("key signing-key: %w", xkms.ErrKeyNotFound))

	_, err := server.InvokeMethod(context.Background(), "xkms.listKeys", listKeysParams)
	require.Error(t, err)

	code, message := ClientError(err)
	assert.Equal(t, sdkssh.JSONRPCCodeNotFound, code)
	assert.Contains(t, message, xkms.ErrKeyNotFound.Error())
	assert.Contains(t, message, "signing-key")
	assert.NotContains(t, logs.String(), withheldErrorLogMessage)
}

// TestClientError_Classification pins which errors keep their text and
// which are withheld.
func TestClientError_Classification(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		wantCode    int
		wantMessage string
	}{
		{
			name:        "unclassified internal is withheld",
			err:         mapKeyOpError(errScrubMarker),
			wantCode:    ErrCodeInternalError,
			wantMessage: ErrInternal.Error(),
		},
		{
			name:        "an error nobody classified is withheld",
			err:         errScrubMarker,
			wantCode:    ErrCodeInternalError,
			wantMessage: ErrInternal.Error(),
		},
		{
			name:        "a wrapped unclassified KeyOpError is withheld",
			err:         fmt.Errorf("dispatch: %w", &KeyOpError{Code: ErrCodeInternalError, Err: errScrubMarker}),
			wantCode:    ErrCodeInternalError,
			wantMessage: ErrInternal.Error(),
		},
		{
			name:        "invalid params keeps its text",
			err:         mapKeyOpError(&xkms.ErrValidation{Sentinel: xkms.ErrInvalidHashFunction, Detail: "hash is required"}),
			wantCode:    ErrCodeInvalidParams,
			wantMessage: (&xkms.ErrValidation{Sentinel: xkms.ErrInvalidHashFunction, Detail: "hash is required"}).Error(),
		},
		{
			name:        "not found keeps its text",
			err:         mapKeyOpError(xkms.ErrKeyNotFound),
			wantCode:    sdkssh.JSONRPCCodeNotFound,
			wantMessage: xkms.ErrKeyNotFound.Error(),
		},
		{
			name:        "method not found keeps its text",
			err:         mapKeyOpError(xkms.ErrOperationNotSupported),
			wantCode:    ErrCodeMethodNotFound,
			wantMessage: xkms.ErrOperationNotSupported.Error(),
		},
		{
			name:        "a classified condition on the internal floor keeps its text",
			err:         mapTenantError(seal.ErrSealed, "unseal tenant"),
			wantCode:    ErrCodeInternalError,
			wantMessage: "unseal tenant: " + seal.ErrSealed.Error(),
		},
		{
			name:        "a sentinel-table internal entry keeps its text",
			err:         mapKeyOpError(xkms.ErrNotInitialized),
			wantCode:    ErrCodeInternalError,
			wantMessage: xkms.ErrNotInitialized.Error(),
		},
		{
			name:        "barrier not configured keeps its text",
			err:         errBarrierNotConfigured(),
			wantCode:    ErrCodeInternalError,
			wantMessage: ErrBarrierNotConfigured.Error(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, message := ClientError(tt.err)
			assert.Equal(t, tt.wantCode, code)
			assert.Equal(t, tt.wantMessage, message)
			assert.NotContains(t, message, scrubMarker)
		})
	}
}

// TestKeyOpError_Internal verifies only an unclassified error on the
// internal code is withheld.
func TestKeyOpError_Internal(t *testing.T) {
	assert.True(t, (&KeyOpError{Code: ErrCodeInternalError, Err: errScrubMarker}).Internal())
	assert.False(t, classified(ErrCodeInternalError, seal.ErrSealed).Internal())
	assert.False(t, (&KeyOpError{Code: ErrCodeInvalidParams, Err: errScrubMarker}).Internal())
}

// TestLogWithheldError_NilLoggerUsesDefault verifies a Server built without
// NewServer (no logger) still logs a withheld error instead of panicking.
func TestLogWithheldError_NilLoggerUsesDefault(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	(&Server{}).logWithheldError(context.Background(), "xkms.listKeys", errScrubMarker)

	assert.Contains(t, logs.String(), scrubMarker)
	assert.Contains(t, logs.String(), "method=xkms.listKeys")
	assert.NotContains(t, logs.String(), "request_id=")
}
