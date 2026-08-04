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
	"encoding/json"
	"errors"
	"testing"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// marshalStringsForTest is a small helper that JSON-encodes a credential id
// index the same way qrdbBackend does internally, so gap tests can seed a
// KV directly without depending on unexported marshal helpers.
func marshalStringsForTest(t *testing.T, ids []string) []byte {
	t.Helper()
	blob, err := json.Marshal(ids)
	if err != nil {
		t.Fatalf("marshal string index: %v", err)
	}
	return blob
}

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
	us, _, _, _ := newTestAdapter(t)
	// Non-empty but not 8 bytes: exercises the UserIDFromHandle error
	// branch distinct from the "len(userID)==0" early return.
	_, err := us.GetByID(context.Background(), []byte{1, 2, 3})
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("GetByID(malformed handle) = %v, want ErrUserNotFound", err)
	}
}

func TestQRDBAdapter_GetByEmail_EmptyEmail(t *testing.T) {
	us, _, _, _ := newTestAdapter(t)
	_, err := us.GetByEmail(context.Background(), "")
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("GetByEmail(\"\") = %v, want ErrUserNotFound", err)
	}
}

func TestQRDBAdapter_UserSave_MalformedHandle(t *testing.T) {
	us, _, _, _ := newTestAdapter(t)
	user := NewDefaultUser([]byte{1, 2, 3}, "bad@example.com", "Bad Handle")
	var ihe *InvalidUserHandleError
	if err := us.Save(context.Background(), user); !errors.As(err, &ihe) {
		t.Fatalf("Save(malformed handle) = %v, want *InvalidUserHandleError", err)
	}
}

func TestQRDBAdapter_UserDelete_MalformedHandle(t *testing.T) {
	us, _, _, _ := newTestAdapter(t)
	var ihe *InvalidUserHandleError
	if err := us.Delete(context.Background(), []byte{9, 9}); !errors.As(err, &ihe) {
		t.Fatalf("Delete(malformed handle) = %v, want *InvalidUserHandleError", err)
	}
}

func TestQRDBAdapter_CredSave_MalformedUserHandle(t *testing.T) {
	_, cs, _, _ := newTestAdapter(t)
	cred := &Credential{ID: []byte("c1"), UserID: []byte{1}}
	var ihe *InvalidUserHandleError
	if err := cs.Save(context.Background(), cred); !errors.As(err, &ihe) {
		t.Fatalf("Save(malformed user handle) = %v, want *InvalidUserHandleError", err)
	}
}

func TestQRDBAdapter_CredGetByUserID_MalformedHandle(t *testing.T) {
	_, cs, _, _ := newTestAdapter(t)
	var ihe *InvalidUserHandleError
	if _, err := cs.GetByUserID(context.Background(), []byte{1}); !errors.As(err, &ihe) {
		t.Fatalf("GetByUserID(malformed handle) = %v, want *InvalidUserHandleError", err)
	}
}

func TestQRDBAdapter_CredDeleteByUserID_MalformedHandle(t *testing.T) {
	_, cs, _, _ := newTestAdapter(t)
	var ihe *InvalidUserHandleError
	if err := cs.DeleteByUserID(context.Background(), []byte{1}); !errors.As(err, &ihe) {
		t.Fatalf("DeleteByUserID(malformed handle) = %v, want *InvalidUserHandleError", err)
	}
}

// TestQRDBAdapter_CredDelete_MalformedUserIDInRecord covers the decode
// branch inside qrdbCredentialStore.Delete that runs AFTER the credential
// blob is successfully fetched: the stored record itself carries a
// corrupt (non-8-byte) UserID, which can only happen if the KV entry was
// written outside the adapter (e.g. a hand-rolled migration). The
// credential is seeded directly into the KV to simulate that.
func TestQRDBAdapter_CredDelete_MalformedUserIDInRecord(t *testing.T) {
	ctx := context.Background()
	kv := newFakeKV()
	cred := &Credential{ID: []byte("bad-user"), UserID: []byte{1, 2, 3}}
	blob, err := json.Marshal(cred)
	if err != nil {
		t.Fatalf("marshal credential: %v", err)
	}
	if err := kv.Put(ctx, credKey(credIDToString(cred.ID)), blob); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, cs := newFaultyAdapter(t, newFakeUserClient(), kv)
	var ihe *InvalidUserHandleError
	if err := cs.Delete(ctx, cred.ID); !errors.As(err, &ihe) {
		t.Fatalf("Delete(corrupt user id) = %v, want *InvalidUserHandleError", err)
	}
}

// ----- qrdbCredentialStore.GetByUserID: per-credential fetch branches -----

func TestQRDBAdapter_CredGetByUserID_MalformedIndexSegment(t *testing.T) {
	ctx := context.Background()
	kv := newFakeKV()
	// Seed an index entry that is not valid base64url, forcing
	// credIDFromString to fail inside the GetByUserID loop.
	if err := kv.Put(ctx, userCredSetKey(7), []byte(`["not base64url!!"]`)); err != nil {
		t.Fatalf("seed index: %v", err)
	}
	_, cs := newFaultyAdapter(t, newFakeUserClient(), kv)
	if _, err := cs.GetByUserID(ctx, HandleFromUserID(7)); err == nil {
		t.Fatal("expected decode error for malformed index segment")
	}
}

func TestQRDBAdapter_CredGetByUserID_SkipsGhostEntry(t *testing.T) {
	ctx := context.Background()
	kv := newFakeKV()
	// The index references a credential id with no stored blob; the not-found
	// per-entry error must be swallowed (continue), not propagated.
	ghost := credIDToString([]byte("ghost-cred"))
	if err := kv.Put(ctx, userCredSetKey(11), marshalStringsForTest(t, []string{ghost})); err != nil {
		t.Fatalf("seed index: %v", err)
	}
	_, cs := newFaultyAdapter(t, newFakeUserClient(), kv)
	creds, err := cs.GetByUserID(ctx, HandleFromUserID(11))
	if err != nil {
		t.Fatalf("GetByUserID: %v", err)
	}
	if len(creds) != 0 {
		t.Fatalf("expected ghost entry skipped, got %d creds", len(creds))
	}
}

func TestQRDBAdapter_CredGetByUserID_NonNotFoundEntryError(t *testing.T) {
	ctx := context.Background()
	real := newFakeKV()
	segID := credIDToString([]byte("real-cred"))
	if err := real.Put(ctx, userCredSetKey(13), marshalStringsForTest(t, []string{segID})); err != nil {
		t.Fatalf("seed index: %v", err)
	}
	// Fault ONLY the individual credential key, leaving the index lookup
	// (a different key) untouched, so the loop reaches the per-credential
	// GetByCredentialID call and receives a real (non-not-found) error.
	kv := &faultyKV{
		inner:             real,
		getErr:            errKVFault,
		getFaultKeyPrefix: credKey(segID),
	}
	_, cs := newFaultyAdapter(t, newFakeUserClient(), kv)
	if _, err := cs.GetByUserID(ctx, HandleFromUserID(13)); !errors.Is(err, errKVFault) {
		t.Fatalf("GetByUserID = %v, want wrapped errKVFault", err)
	}
}

// ----- qrdbCredentialStore.GetByCredentialID: empty-blob branch -----

func TestQRDBAdapter_GetByCredentialID_EmptyBlob(t *testing.T) {
	ctx := context.Background()
	kv := newFakeKV()
	// A key that exists but holds a zero-length value must be treated as
	// not-found, not as a successfully decoded (zero-value) credential.
	if err := kv.Put(ctx, credKey(credIDToString([]byte("empty"))), []byte{}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, cs := newFaultyAdapter(t, newFakeUserClient(), kv)
	_, err := cs.GetByCredentialID(ctx, []byte("empty"))
	if !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("GetByCredentialID(empty blob) = %v, want ErrCredentialNotFound", err)
	}
}

// ----- qrdbCredentialStore.Delete: non-not-found fetch error -----

func TestQRDBAdapter_CredDelete_FetchError(t *testing.T) {
	ctx := context.Background()
	real := newFakeKV()
	segID := credIDToString([]byte("fetch-fail"))
	if err := real.Put(ctx, credKey(segID), []byte(`{}`)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	kv := &faultyKV{inner: real, getErr: errKVFault, getFaultKeyPrefix: credKey(segID)}
	_, cs := newFaultyAdapter(t, newFakeUserClient(), kv)
	err := cs.Delete(ctx, []byte("fetch-fail"))
	if errors.Is(err, ErrCredentialNotFound) {
		t.Fatal("a real transport fault must not be classified as not-found")
	}
	if !errors.Is(err, errKVFault) {
		t.Fatalf("Delete = %v, want wrapped errKVFault", err)
	}
}

// ----- qrdbCredentialStore.Delete: kv.Delete failure on credential key -----

func TestQRDBAdapter_CredDelete_KVDeleteError(t *testing.T) {
	ctx := context.Background()
	real := newFakeKV()
	_, seedCS := newFaultyAdapter(t, newFakeUserClient(), real)
	cred := &Credential{ID: []byte("del-fail"), UserID: HandleFromUserID(21)}
	if err := seedCS.Save(ctx, cred); err != nil {
		t.Fatalf("seed: %v", err)
	}
	kv := &faultyKV{inner: real, deleteErr: errKVFault}
	_, cs := newFaultyAdapter(t, newFakeUserClient(), kv)
	if err := cs.Delete(ctx, cred.ID); !errors.Is(err, errKVFault) {
		t.Fatalf("Delete = %v, want wrapped errKVFault", err)
	}
}

// ----- materialize: per-credential fetch and decode errors -----

func TestQRDBAdapter_Materialize_CredentialFetchError(t *testing.T) {
	ctx := context.Background()
	inner := newFakeUserClient()
	realKV := newFakeKV()
	u, err := inner.CreateUser(ctx, &qrdbtransport.CreateUserRequest{Username: "materr@example.com", TenantID: "system"})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	segID := credIDToString([]byte("mat-cred"))
	if err := realKV.Put(ctx, userCredSetKey(u.ID), marshalStringsForTest(t, []string{segID})); err != nil {
		t.Fatalf("seed index: %v", err)
	}
	kv := &faultyKV{inner: realKV, getErr: errKVFault, getFaultKeyPrefix: credKey(segID)}
	us, _ := newFaultyAdapter(t, inner, kv)
	if _, err := us.GetByID(ctx, HandleFromUserID(u.ID)); !errors.Is(err, errKVFault) {
		t.Fatalf("GetByID = %v, want wrapped errKVFault from materialize", err)
	}
}

func TestQRDBAdapter_Materialize_CredentialDecodeError(t *testing.T) {
	ctx := context.Background()
	inner := newFakeUserClient()
	kv := newFakeKV()
	u, err := inner.CreateUser(ctx, &qrdbtransport.CreateUserRequest{Username: "matdecode@example.com", TenantID: "system"})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	segID := credIDToString([]byte("corrupt-cred"))
	if err := kv.Put(ctx, userCredSetKey(u.ID), marshalStringsForTest(t, []string{segID})); err != nil {
		t.Fatalf("seed index: %v", err)
	}
	if err := kv.Put(ctx, credKey(segID), []byte("{not-json")); err != nil {
		t.Fatalf("seed corrupt blob: %v", err)
	}
	us, _ := newFaultyAdapter(t, inner, kv)
	if _, err := us.GetByID(ctx, HandleFromUserID(u.ID)); err == nil {
		t.Fatal("expected decode error for corrupt credential blob during materialize")
	}
}

// ----- listUserCredIDs: empty (but present) index blob -----

func TestQRDBAdapter_ListUserCredIDs_EmptyBlob(t *testing.T) {
	ctx := context.Background()
	kv := newFakeKV()
	if err := kv.Put(ctx, userCredSetKey(31), []byte{}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, cs := newFaultyAdapter(t, newFakeUserClient(), kv)
	creds, err := cs.GetByUserID(ctx, HandleFromUserID(31))
	if err != nil {
		t.Fatalf("GetByUserID: %v", err)
	}
	if len(creds) != 0 {
		t.Fatalf("expected no credentials for empty index blob, got %d", len(creds))
	}
}
