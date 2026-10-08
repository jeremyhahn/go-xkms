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

package webauthn

import (
	"context"
	"errors"
	"testing"
)

// ----- InvalidUserHandleError.Error() -----

// TestInvalidUserHandleError_Error covers the Error() formatting branches:
// a populated receiver and the defensive nil-receiver guard. Both are
// reachable from any caller that stores the typed error in an interface
// and later calls .Error() (e.g. logging), which the round-trip test in
// qrdb_userstore_test.go never exercises.
func TestInvalidUserHandleError_Error(t *testing.T) {
	cases := []struct {
		name string
		err  *InvalidUserHandleError
		want string
	}{
		{
			name: "seven bytes",
			err:  &InvalidUserHandleError{Length: 7},
			want: "webauthn: invalid user handle: expected 8 bytes, got 7",
		},
		{
			name: "nil receiver",
			err:  nil,
			want: "webauthn: invalid user handle",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

// ----- qrdbUserStore: malformed handle / empty email branches -----

func TestQRDBAdapter_GetByID_MalformedHandle(t *testing.T) {
	us, _, _ := newTestAdapter(t)
	// Non-empty but not 8 bytes: exercises the UserIDFromHandle error
	// branch distinct from the "len(userID)==0" early return.
	_, err := us.GetByID(context.Background(), []byte{1, 2, 3})
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("GetByID(malformed handle) = %v, want ErrUserNotFound", err)
	}
}

func TestQRDBAdapter_GetByEmail_EmptyEmail(t *testing.T) {
	us, _, _ := newTestAdapter(t)
	_, err := us.GetByEmail(context.Background(), "")
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("GetByEmail(\"\") = %v, want ErrUserNotFound", err)
	}
}

func TestQRDBAdapter_UserSave_MalformedHandle(t *testing.T) {
	us, _, _ := newTestAdapter(t)
	user := NewDefaultUser([]byte{1, 2, 3}, "bad@example.com", "Bad Handle")
	var ihe *InvalidUserHandleError
	if err := us.Save(context.Background(), user); !errors.As(err, &ihe) {
		t.Fatalf("Save(malformed handle) = %v, want *InvalidUserHandleError", err)
	}
}

func TestQRDBAdapter_UserDelete_MalformedHandle(t *testing.T) {
	us, _, _ := newTestAdapter(t)
	var ihe *InvalidUserHandleError
	if err := us.Delete(context.Background(), []byte{9, 9}); !errors.As(err, &ihe) {
		t.Fatalf("Delete(malformed handle) = %v, want *InvalidUserHandleError", err)
	}
}
