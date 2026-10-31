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

//go:build pkcs11

package hardware_test

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage/hardware"
	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeSearchFinalizer records the sessions C_FindObjectsFinal is called on and
// answers with err.
type fakeSearchFinalizer struct {
	err      error
	sessions []pkcs11.SessionHandle
}

func (f *fakeSearchFinalizer) FindObjectsFinal(session pkcs11.SessionHandle) error {
	f.sessions = append(f.sessions, session)
	return f.err
}

var errTestInit = errors.New("test: C_FindObjectsInit failed")

func TestClearFailedPKCS11Search_FinalizesAndReturnsInitError(t *testing.T) {
	for name, finalErr := range map[string]error{
		"final succeeds":          nil,
		"no search was open":      pkcs11.Error(pkcs11.CKR_OPERATION_NOT_INITIALIZED),
		"wrapped not-initialized": &wrappedErr{err: pkcs11.Error(pkcs11.CKR_OPERATION_NOT_INITIALIZED)},
	} {
		t.Run(name, func(t *testing.T) {
			fake := &fakeSearchFinalizer{err: finalErr}

			err := hardware.ClearFailedPKCS11Search(fake, 7, errTestInit)

			assert.Equal(t, errTestInit, err, "only the Init failure is reported")
			assert.Equal(t, []pkcs11.SessionHandle{7}, fake.sessions, "the session's search must be finalized once")
		})
	}
}

func TestClearFailedPKCS11Search_JoinsFinalFailure(t *testing.T) {
	finalErr := pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	fake := &fakeSearchFinalizer{err: finalErr}

	err := hardware.ClearFailedPKCS11Search(fake, 3, errTestInit)

	require.ErrorIs(t, err, errTestInit, "the Init failure must not be masked")
	require.ErrorIs(t, err, finalErr, "the Final failure must not be discarded")
	assert.Equal(t, []pkcs11.SessionHandle{3}, fake.sessions)
}

// wrappedErr wraps err, as an errs.Wrapped from a caller's own layer would.
type wrappedErr struct{ err error }

func (w *wrappedErr) Error() string { return "test: " + w.err.Error() }
func (w *wrappedErr) Unwrap() error { return w.err }
