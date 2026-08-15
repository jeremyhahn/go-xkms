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

package xkms

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// These tests exercise the Error()/Unwrap() implementations of typed errors
// that are otherwise only constructed by production code paths requiring
// live hardware/network dependencies (WebAuthn ceremonies, qrdb cluster
// client failures, role resolution). Constructing the error values directly
// and asserting on their string/Unwrap contract is meaningful: it locks in
// the error message format relied upon by callers doing errors.Is/As, and
// catches accidental signature drift.

func TestErrWebAuthnCeremony_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("attestation parse failed")
	err := &ErrWebAuthnCeremony{Operation: "finish registration", Err: inner}

	assert.Equal(t, "keystore: webauthn finish registration: attestation parse failed", err.Error())
	assert.Same(t, inner, err.Unwrap())
	assert.ErrorIs(t, err, inner)
}

func TestErrUnknownRole_Error(t *testing.T) {
	err := &ErrUnknownRole{Role: "superadmin"}
	assert.Equal(t, `keystore: unknown role "superadmin"`, err.Error())
}
