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
	"crypto/rand"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// QRDBUserStoreOptions configures the adapter pair at construction time.
type QRDBUserStoreOptions struct {
	// Users is the qrdb user client, used for create/get/list of users.
	Users qrdbtransport.UserClient

	// DAOFactory is the injected go-qrdb DAO factory the credential store
	// builds its DAO from. Its default store must support atomic
	// conditional writes: credential creation is a create-if-absent and a
	// counter update a CompareAndSwap, so a credential ID can be claimed
	// by exactly one account (go-xkms#1295).
	DAOFactory *qrdbsdk.DAOFactory

	// TenantID is the tenant scope for user creation and lookup. Use
	// the system tenant ("system") for daemon-internal use, or a
	// per-tenant id for multi-tenant deployments. Required.
	TenantID string
}

// qrdbUserStore implements xkms's UserStore over qrdb's user records. A
// user's credentials are read from, and deleted through, the credential
// store it was built with.
type qrdbUserStore struct {
	users    qrdbtransport.UserClient
	creds    CredentialStore
	tenantID string
}

// NewQRDBUserStoreAdapter constructs the (UserStore, CredentialStore) pair
// xkms's WebAuthn relying party runs on: users are go-qrdb's user records,
// and credentials are go-qrdb DAO entities built from the injected factory.
// The user store reads a user's credentials through the returned credential
// store, so the two must be used as a pair.
func NewQRDBUserStoreAdapter(opts QRDBUserStoreOptions) (UserStore, CredentialStore, error) {
	if opts.Users == nil {
		return nil, nil, &QRDBAdapterConfigError{Field: "Users"}
	}
	if opts.DAOFactory == nil {
		return nil, nil, &QRDBAdapterConfigError{Field: "DAOFactory"}
	}
	if opts.TenantID == "" {
		return nil, nil, &QRDBAdapterConfigError{Field: "TenantID"}
	}
	creds, err := newCredentialStore(opts.DAOFactory)
	if err != nil {
		return nil, nil, WrapError("build credential store", err)
	}
	users := &qrdbUserStore{users: opts.Users, creds: creds, tenantID: opts.TenantID}
	return users, creds, nil
}

// ----- handle <-> qrdb user id encoding -----
//
// qrdb's canonical user identifier is a uint64 stored/indexed as an
// 8-byte big-endian key. The WebAuthn user handle is the byte form of
// that id, encoded as a fixed 8-byte big-endian value so it matches
// qrdb's on-disk key encoding (see also GenerateUserID in types.go,
// which produces 8-byte big-endian handles for email-derived ids).

// HandleFromUserID encodes a qrdb uint64 user id as the fixed 8-byte
// big-endian WebAuthn user handle. This is the single source of truth
// for the qrdb-id-to-handle encoding across xkms.
func HandleFromUserID(id uint64) []byte {
	h := make([]byte, 8)
	binary.BigEndian.PutUint64(h, id)
	return h
}

// UserIDFromHandle decodes an 8-byte big-endian WebAuthn user handle
// back into the qrdb uint64 user id. A handle of any other length is
// rejected with an *InvalidUserHandleError.
func UserIDFromHandle(handle []byte) (uint64, error) {
	if len(handle) != 8 {
		return 0, &InvalidUserHandleError{Length: len(handle)}
	}
	return binary.BigEndian.Uint64(handle), nil
}

// GetByID retrieves the user by webauthn handle. The handle is the
// 8-byte big-endian form of the qrdb uint64 user id.
func (s *qrdbUserStore) GetByID(ctx context.Context, userID []byte) (User, error) {
	if len(userID) == 0 {
		return nil, ErrUserNotFound
	}
	id, err := UserIDFromHandle(userID)
	if err != nil {
		return nil, ErrUserNotFound
	}
	u, err := s.users.GetUser(ctx, id)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return s.materialize(ctx, u)
}

// GetByEmail looks up a user by the canonical tenant-scoped email login key.
//
// It used to resolve through the USERNAME index, on the assumption that the
// xkms email and the qrdb username were the same string. They were not for any
// user created through a path that set them independently, and the mismatch
// surfaced as a WebAuthn login that verified correctly and then failed to
// resolve a principal (go-xkms #185, go-quicbaas #359).
func (s *qrdbUserStore) GetByEmail(ctx context.Context, email string) (User, error) {
	if email == "" {
		return nil, ErrUserNotFound
	}
	u, err := s.users.GetUserByEmail(ctx, s.tenantID, email)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return s.materialize(ctx, u)
}

// Create creates a new user in the configured tenant.
//
// The email and display name are fields OF the qrdb record. They used to be
// kept beside it — the display name in an xkms-owned KV blob, because qrdb had
// no Name field — which made this store a second source of truth for an
// identity qrdb already owned. Both now live in the record itself.
//
// The record's Username is its decimal qrdb user ID. A failure to assign it
// is a *QRDBUsernameAssignError, after which the half-created record has been
// deleted unless its RollbackErr says otherwise.
func (s *qrdbUserStore) Create(ctx context.Context, email, displayName string) (User, error) {
	if email == "" {
		return nil, &QRDBAdapterConfigError{Field: "email"}
	}
	// qrdb's Username is the certificate CN, so it carries the qrdb user ID,
	// never the email (owner ruling 166, go-xkms#1468): the email stays in
	// Email, the tenant-unique login key. qrdb assigns the ID at create and
	// refuses an empty Username, so the record is created under a random,
	// PII-free placeholder and then renamed to its ID.
	u, err := s.users.CreateUser(ctx, &qrdbtransport.CreateUserRequest{
		Username: pendingUsernamePrefix + rand.Text(),
		Email:    email,
		Name:     displayName,
		TenantID: s.tenantID,
	})
	if err != nil {
		return nil, WrapError("qrdb create user", err)
	}
	renamed, err := s.users.UpdateUser(ctx, &qrdbtransport.UpdateUserRequest{
		ID:       u.ID,
		Username: strconv.FormatUint(u.ID, 10),
	})
	if err != nil {
		// A record left under its placeholder would hold the email as a
		// login key with no usable Username, so it is removed.
		return nil, &QRDBUsernameAssignError{
			UserID:      u.ID,
			Err:         err,
			RollbackErr: s.users.DeleteUser(ctx, u.ID),
		}
	}
	return s.materialize(ctx, renamed)
}

// Save stores per-user state. xkms's User abstraction carries in-memory
// session-data and credential lists; the credential store owns persistence of
// credentials, so Save is a near no-op for the user record. A display-name
// change is an update to the qrdb record, not a write to a parallel key.
func (s *qrdbUserStore) Save(ctx context.Context, user User) error {
	if user == nil {
		return &QRDBAdapterConfigError{Field: "user"}
	}
	dn := user.DisplayName()
	if dn == "" {
		return nil
	}
	id, err := UserIDFromHandle(user.WebAuthnID())
	if err != nil {
		return err
	}
	if _, uErr := s.users.UpdateUser(ctx, &qrdbtransport.UpdateUserRequest{
		ID:   id,
		Name: dn,
	}); uErr != nil {
		return WrapError("qrdb update display name", uErr)
	}
	return nil
}

// Delete removes the user and then the user's credentials. The user record
// is gone first; a failure deleting the credentials still reaches the
// caller, since an orphaned credential would go on referencing a user that
// no longer exists.
func (s *qrdbUserStore) Delete(ctx context.Context, userID []byte) error {
	id, err := UserIDFromHandle(userID)
	if err != nil {
		return err
	}
	if dErr := s.users.DeleteUser(ctx, id); dErr != nil {
		if isUserNotFound(dErr) {
			return ErrUserNotFound
		}
		return WrapError("qrdb delete user", dErr)
	}
	if dErr := s.creds.DeleteByUserID(ctx, userID); dErr != nil {
		return WrapError("delete user credentials", dErr)
	}
	return nil
}

// materialize hydrates a qrdb User into the xkms DefaultUser shape, with
// its credentials read from the credential store.
func (s *qrdbUserStore) materialize(ctx context.Context, u *qrdbtransport.User) (*DefaultUser, error) {
	// The WebAuthn name is the canonical EMAIL login key, and the display name
	// is the record's own Name. Both used to come from elsewhere — the name from
	// u.Username, the display name from an xkms KV blob — which is what let the
	// two drift.
	user := NewDefaultUser(HandleFromUserID(u.ID), u.Email, u.Name)
	// Account standing is qrdb's, carried verbatim: the service refuses a
	// login or enrolment the record's lifecycle or auth-method policy does
	// not allow (go-xkms#1298). A record with no lifecycle is not treated as
	// active — only qrdbsdk.LifecycleActive authenticates.
	user.SetLifecycle(qrdbsdk.Lifecycle(u.Lifecycle))
	user.SetAuthMethods(u.AuthMethods)

	// A read failure is returned, never skipped: a user handed back with
	// silently FEWER credentials than they have would make the
	// authentication that follows judge a valid passkey unknown.
	creds, err := s.creds.GetByUserID(ctx, user.WebAuthnID())
	if err != nil {
		return nil, err
	}
	user.SetCredentials(creds)
	return user, nil
}

// mapNotFound converts a qrdb not-found error into the xkms sentinel.
func mapNotFound(err error) error {
	if isUserNotFound(err) {
		return ErrUserNotFound
	}
	return WrapError("qrdb user lookup", err)
}

// isUserNotFound reports whether err means the user record is absent.
//
// Classification is typed, and fails CLOSED: anything not recognised is a
// failure to answer, never an answer of "absent" (#183). A user reported
// absent on the strength of a transport failure makes the registration
// ceremony CREATE a duplicate account, and lets a consumer's rollback guard
// delete a credential it did not create.
//
// What a missing user looks like depends on the transport (go-qrdb#286,
// measured on the SDK this module pins): REST returns
// *transport.UserNotFoundError; gRPC, MCP and the embedded transport return
// *transport.KeyNotFoundError; the embedded DAO path is IsDAONotFound. QUIC
// carries the service's message opaquely inside *transport.RequestError
// (go-qrdb#289 keeps that one open), so for it, and only for it, the message
// is matched against the two canonical forms the user service emits, by
// exact prefix. "connection not found", "tenant not found: x" or "host not
// found: dial tcp" start with none of them.
func isUserNotFound(err error) bool {
	if err == nil {
		return false
	}
	var userNotFound *qrdbtransport.UserNotFoundError
	if errors.As(err, &userNotFound) {
		return true
	}
	var keyNotFound *qrdbtransport.KeyNotFoundError
	if errors.As(err, &keyNotFound) {
		return true
	}
	if qrdbsdk.IsDAONotFound(err) {
		return true
	}
	var request *qrdbtransport.RequestError
	if errors.As(err, &request) && request.Err != nil {
		return isCanonicalUserNotFoundMessage(request.Err.Error())
	}
	return false
}

// userNotFoundCanonicalPrefixes are the message forms qrdb's user service
// emits for a missing user: the pre-0.16.3 "user not found: <id>" and the
// typed error's own "user: not found: <lookup>". They are matched by exact
// prefix, and only on the opaque transport path above.
var userNotFoundCanonicalPrefixes = []string{
	"user not found: ",
	"user: not found: ",
}

// isCanonicalUserNotFoundMessage reports whether msg is, by exact prefix,
// one of the user service's own not-found messages.
func isCanonicalUserNotFoundMessage(msg string) bool {
	for _, prefix := range userNotFoundCanonicalPrefixes {
		if strings.HasPrefix(msg, prefix) {
			return true
		}
	}
	return false
}

// QRDBAdapterConfigError is returned when the adapter is constructed
// with missing or invalid configuration.
type QRDBAdapterConfigError struct {
	Field string
}

// Error implements error.
func (e *QRDBAdapterConfigError) Error() string {
	if e == nil || e.Field == "" {
		return "webauthn: qrdb adapter: invalid configuration"
	}
	return "webauthn: qrdb adapter: missing or invalid field: " + e.Field
}

// InvalidUserHandleError is returned when a WebAuthn user handle cannot
// be decoded into a qrdb uint64 user id. The handle must be exactly
// 8 bytes (big-endian uint64).
type InvalidUserHandleError struct {
	// Length is the actual byte length of the offending handle.
	Length int
}

// Error implements error.
func (e *InvalidUserHandleError) Error() string {
	if e == nil {
		return "webauthn: invalid user handle"
	}
	return "webauthn: invalid user handle: expected 8 bytes, got " + strconv.Itoa(e.Length)
}

// pendingUsernamePrefix marks the placeholder Username a WebAuthn user is
// created under before Create renames it to its qrdb user ID.
const pendingUsernamePrefix = "webauthn-pending-"

// QRDBUsernameAssignError is returned by the qrdb user store's Create when
// the new record could not be renamed to its qrdb user ID. The record is
// deleted on that failure; RollbackErr is the deletion's error, nil when the
// record is gone.
type QRDBUsernameAssignError struct {
	// UserID is the qrdb user ID of the record that was created.
	UserID uint64
	// Err is the qrdb error from the rename.
	Err error
	// RollbackErr is the qrdb error from deleting the record, or nil.
	RollbackErr error
}

// Error implements error.
func (e *QRDBUsernameAssignError) Error() string {
	msg := "webauthn: qrdb adapter: assign username to user " + strconv.FormatUint(e.UserID, 10) + ": " + e.Err.Error()
	if e.RollbackErr != nil {
		msg += "; delete of the created user failed: " + e.RollbackErr.Error()
	}
	return msg
}

// Unwrap returns the rename error and, when set, the rollback error.
func (e *QRDBUsernameAssignError) Unwrap() []error {
	if e.RollbackErr == nil {
		return []error{e.Err}
	}
	return []error{e.Err, e.RollbackErr}
}

// Compile-time interface assertion.
var _ UserStore = (*qrdbUserStore)(nil)
