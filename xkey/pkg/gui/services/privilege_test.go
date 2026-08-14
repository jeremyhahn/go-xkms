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

package services

import (
	"os/user"
	"testing"
)

// asUnprivileged forces the privilege seams to report a non-root user for the
// duration of the test. This lets the unprivileged branches be exercised
// deterministically even when the test binary runs as root.
func asUnprivileged(t *testing.T) {
	t.Helper()
	origUID, origUser := geteuid, currentUser
	geteuid = func() int { return 1000 }
	currentUser = func() (*user.User, error) {
		return &user.User{Uid: "1000", Gid: "1000", Username: "xkeytest", HomeDir: "/home/xkeytest"}, nil
	}
	t.Cleanup(func() {
		geteuid, currentUser = origUID, origUser
	})
}

// asPrivileged forces the privilege seams to report root for the duration of
// the test. Only the privilege decision is faked; no privileged operation is
// actually performed against the host.
func asPrivileged(t *testing.T) {
	t.Helper()
	origUID, origUser := geteuid, currentUser
	geteuid = func() int { return 0 }
	currentUser = func() (*user.User, error) {
		return &user.User{Uid: "0", Gid: "0", Username: "root", HomeDir: "/root"}, nil
	}
	t.Cleanup(func() {
		geteuid, currentUser = origUID, origUser
	})
}

// TestAdminService_IsAdmin_PrivilegeSeam verifies IsAdmin tracks the reported
// user identity in both directions, and fails closed when the user cannot be
// resolved.
func TestAdminService_IsAdmin_PrivilegeSeam(t *testing.T) {
	svc := NewAdminService()

	asUnprivileged(t)
	if svc.IsAdmin() {
		t.Error("IsAdmin() = true for uid 1000, want false")
	}

	asPrivileged(t)
	if !svc.IsAdmin() {
		t.Error("IsAdmin() = false for uid 0, want true")
	}
}

// TestAdminService_IsAdmin_LookupFailure verifies IsAdmin fails closed when
// the current user cannot be determined.
func TestAdminService_IsAdmin_LookupFailure(t *testing.T) {
	orig := currentUser
	currentUser = func() (*user.User, error) { return nil, user.UnknownUserError("nobody") }
	t.Cleanup(func() { currentUser = orig })

	svc := NewAdminService()
	if svc.IsAdmin() {
		t.Error("IsAdmin() = true when the current user is unresolvable, want false (fail closed)")
	}
}
