// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package audit

import (
	"errors"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/fido2/authenticator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _ authenticator.AuditLogger = (*FIDO2Logger)(nil)

// newFIDO2TestStore returns an in-memory BackendStore and a FIDO2Logger
// writing through it.
func newFIDO2TestStore(t *testing.T) (*BackendStore, *FIDO2Logger) {
	t.Helper()
	store, err := NewBackendStore(xkms.NewStorageMemory(), 100, nil)
	require.NoError(t, err)
	return store, NewFIDO2Logger(store)
}

func TestFIDO2Logger_LogCredentialCreated(t *testing.T) {
	store, logger := newFIDO2TestStore(t)

	require.NoError(t, logger.LogCredentialCreated("c0ffee"))

	results := store.Query(QueryFilter{})
	require.Len(t, results, 1)
	assert.Equal(t, OpFIDO2CredentialCreated, results[0].Operation)
	assert.Equal(t, "fido2", results[0].Backend)
	assert.Equal(t, "c0ffee", results[0].KeyID)
	assert.True(t, results[0].Success)
}

func TestFIDO2Logger_LogPINSeeded(t *testing.T) {
	store, logger := newFIDO2TestStore(t)

	require.NoError(t, logger.LogPINSeeded())

	results := store.Query(QueryFilter{})
	require.Len(t, results, 1)
	assert.Equal(t, OpPINSeeded, results[0].Operation)
	assert.Equal(t, "fido2", results[0].Backend)
	assert.True(t, results[0].Success)
}

// TestFIDO2Logger_WriteFailureIsReturned verifies both events are
// SeveritySecurity: a failed write reaches the authenticator as an error so
// it refuses the operation.
func TestFIDO2Logger_WriteFailureIsReturned(t *testing.T) {
	writeErr := errors.New("audit sink unavailable")
	calls := map[string]func(*FIDO2Logger) error{
		"credential created": func(l *FIDO2Logger) error { return l.LogCredentialCreated("c0ffee") },
		"pin seeded":         func(l *FIDO2Logger) error { return l.LogPINSeeded() },
	}

	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			store, logger := newFIDO2TestStore(t)
			store.slog = &fakeEntryLogger{logErr: writeErr}

			err := call(logger)

			require.ErrorIs(t, err, writeErr)
			var writeFailed *ErrAuditWriteFailed
			require.ErrorAs(t, err, &writeFailed)
		})
	}
}
