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

package main

import (
	"errors"
	"strings"
	"testing"
)

// TestWrappedDetailError_ErrorWithCause proves the "<sentinel>: <detail>:
// <cause>" rendering: every existing caller that constructs a
// WrappedDetailError with a non-nil Err (init.go's CSR read/parse failures,
// init_factor_persister.go's persist failures) only ever exercises this
// through errors.Is/errors.As, never Error() itself, so a nil-pointer
// dereference on e.Err or a dropped segment would not have been caught.
func TestWrappedDetailError_ErrorWithCause(t *testing.T) {
	cause := errors.New("permission denied")
	err := &WrappedDetailError{Sentinel: ErrCSRReadFailed, Detail: "/etc/xkms/officer.csr", Err: cause}

	msg := err.Error()
	if !strings.Contains(msg, ErrCSRReadFailed.Error()) {
		t.Errorf("Error() = %q, want it to contain the sentinel %q", msg, ErrCSRReadFailed.Error())
	}
	if !strings.Contains(msg, "/etc/xkms/officer.csr") {
		t.Errorf("Error() = %q, want it to contain the detail", msg)
	}
	if !strings.Contains(msg, cause.Error()) {
		t.Errorf("Error() = %q, want it to contain the cause %q", msg, cause.Error())
	}
}

// TestWrappedDetailError_ErrorWithoutCause proves a WrappedDetailError
// constructed with no underlying cause (Err left nil, as
// parseOfficerFlag's malformed-input errors do) still renders a complete
// message rather than panicking on a nil e.Err or leaving a trailing
// "<nil>" segment.
func TestWrappedDetailError_ErrorWithoutCause(t *testing.T) {
	err := &WrappedDetailError{Sentinel: ErrEmptyCSRPath, Detail: `"admin1:"`}

	msg := err.Error()
	if !strings.Contains(msg, ErrEmptyCSRPath.Error()) {
		t.Errorf("Error() = %q, want it to contain the sentinel %q", msg, ErrEmptyCSRPath.Error())
	}
	if !strings.Contains(msg, `"admin1:"`) {
		t.Errorf("Error() = %q, want it to contain the detail", msg)
	}
	if strings.Contains(msg, "<nil>") {
		t.Errorf("Error() = %q, must not render a nil cause as \"<nil>\"", msg)
	}
}

// TestWrappedDetailError_Unwrap proves errors.Is/errors.As reach both the
// sentinel and the cause through Unwrap, and that a nil cause does not add a
// spurious nil entry to the unwrapped chain.
func TestWrappedDetailError_Unwrap(t *testing.T) {
	cause := errors.New("disk full")
	withCause := &WrappedDetailError{Sentinel: ErrCABundleWriteFailed, Detail: "/data/ca.pem", Err: cause}
	if !errors.Is(withCause, ErrCABundleWriteFailed) {
		t.Error("errors.Is must see the sentinel through Unwrap")
	}
	if !errors.Is(withCause, cause) {
		t.Error("errors.Is must see the cause through Unwrap")
	}

	withoutCause := &WrappedDetailError{Sentinel: ErrEmptyCSRPath, Detail: "x"}
	unwrapped := withoutCause.Unwrap()
	if len(unwrapped) != 1 || unwrapped[0] != ErrEmptyCSRPath {
		t.Errorf("Unwrap() with no cause = %v, want exactly [Sentinel]", unwrapped)
	}
}
