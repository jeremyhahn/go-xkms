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

package pinadapter

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// GetError.Error() / PutError.Error() message formatting
// =============================================================================
//
// These are exercised end-to-end via TestGet_BackendErrorWrappedInGetError and
// TestPut_BackendErrorWrappedInPutError, but those tests only assert via
// errors.As/errors.Is and never call Error() directly, so the message-building
// statement in each method was never executed. Call Error() directly here to
// pin down the exact wire format callers/log lines depend on.

func TestGetError_Error_FormatsKeyAndCause(t *testing.T) {
	e := &GetError{Key: "session/abc", Err: errors.New("disk gone")}

	got := e.Error()

	assert.Equal(t, "pinadapter: get session/abc: disk gone", got)
}

func TestPutError_Error_FormatsKeyAndCause(t *testing.T) {
	e := &PutError{Key: "session/abc", Err: errors.New("read-only fs")}

	got := e.Error()

	assert.Equal(t, "pinadapter: put session/abc: read-only fs", got)
}
