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
	"encoding/binary"
	"encoding/json"
	"errors"
	"strconv"
	"sync"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// QRDBUserStoreOptions configures the adapter pair at construction time.
type QRDBUserStoreOptions struct {
	// Users is the qrdb user client, used for create/get/list of users.
	Users qrdbtransport.UserClient

	// KV is the qrdb KV client used for credential storage. The
	// credential namespace lives under "__xkms:webauthn/" and is
	// internal to xkms.
	KV qrdbtransport.KVClient

	// TenantID is the tenant scope for user creation and lookup. Use
	// the system tenant ("system") for daemon-internal use, or a
	// per-tenant id for multi-tenant deployments. Required.
	TenantID string
}

// qrdbBackend is the shared internal state used by both store
// adapters. Splitting the surface into two structs avoids the method
// name clash on Save/Delete between UserStore and CredentialStore.
type qrdbBackend struct {
	users    qrdbtransport.UserClient
	kv       qrdbtransport.KVClient
	tenantID string

	// mu serialises the read-modify-write pattern used when adding /
	// removing a credential from the user-credential index. Inner
	// stores are themselves concurrency-safe via Raft; this lock only
	// covers cross-key consistency.
	mu sync.Mutex
}

// qrdbUserStore implements xkms's UserStore over qrdb.
type qrdbUserStore struct{ b *qrdbBackend }

// qrdbCredentialStore implements xkms's CredentialStore over qrdb.
type qrdbCredentialStore struct{ b *qrdbBackend }

// NewQRDBUserStoreAdapter constructs a (UserStore, CredentialStore) pair
// wiring xkms's webauthn stores onto qrdb's user + KV surfaces. The two
// returned stores share state and must be used as a pair.
func NewQRDBUserStoreAdapter(opts QRDBUserStoreOptions) (UserStore, CredentialStore, error) {
	if opts.Users == nil {
		return nil, nil, &QRDBAdapterConfigError{Field: "Users"}
	}
	if opts.KV == nil {
		return nil, nil, &QRDBAdapterConfigError{Field: "KV"}
	}
	if opts.TenantID == "" {
		return nil, nil, &QRDBAdapterConfigError{Field: "TenantID"}
	}
	b := &qrdbBackend{
		users:    opts.Users,
		kv:       opts.KV,
		tenantID: opts.TenantID,
	}
	return &qrdbUserStore{b: b}, &qrdbCredentialStore{b: b}, nil
}

// ----- handle <-> qrdb user id encoding -----
//
// qrdb's canonical user identifier is a uint64 stored/indexed as an
// 8-byte big-endian key. The WebAuthn user handle is the byte form of
// that id, encoded as a fixed 8-byte big-endian value so it matches
// qrdb's on-disk key encoding (see also GenerateUserID in types.go,
// which produces 8-byte big-endian handles for email-derived ids).
//
// Persisted xkms KV key segments embed the id as base-10 decimal
// (strconv.FormatUint) for readability, e.g.
// "__xkms:webauthn/users/42/credentials".

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

// ----- UserStore -----

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
	u, err := s.b.users.GetUser(ctx, id)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return s.b.materialize(ctx, u)
}

// GetByEmail looks up a user by username (xkms email == qrdb username).
func (s *qrdbUserStore) GetByEmail(ctx context.Context, email string) (User, error) {
	if email == "" {
		return nil, ErrUserNotFound
	}
	u, err := s.b.users.GetUserByUsername(ctx, s.b.tenantID, email)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return s.b.materialize(ctx, u)
}

// Create creates a new user in the configured tenant. The xkms display
// name is stashed alongside the credential set under
// __xkms:webauthn/users/<id>/displayName.
func (s *qrdbUserStore) Create(ctx context.Context, email, displayName string) (User, error) {
	if email == "" {
		return nil, &QRDBAdapterConfigError{Field: "email"}
	}
	u, err := s.b.users.CreateUser(ctx, &qrdbtransport.CreateUserRequest{
		Username: email,
		TenantID: s.b.tenantID,
	})
	if err != nil {
		return nil, WrapError("qrdb create user", err)
	}
	if displayName != "" {
		if pErr := s.b.kv.Put(ctx, displayNameKey(u.ID), []byte(displayName)); pErr != nil {
			return nil, WrapError("persist display name", pErr)
		}
	}
	return s.b.materialize(ctx, u)
}

// Save stores per-user state. xkms's User abstraction carries
// in-memory session-data and credential lists; the credential store
// owns persistence of credentials, so Save is a near no-op for the
// user record. Display-name updates are written to KV.
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
	return s.b.kv.Put(ctx, displayNameKey(id), []byte(dn))
}

// Delete removes the user and the credential side-channel entries.
func (s *qrdbUserStore) Delete(ctx context.Context, userID []byte) error {
	id, err := UserIDFromHandle(userID)
	if err != nil {
		return err
	}
	if dErr := s.b.users.DeleteUser(ctx, id); dErr != nil {
		return WrapError("qrdb delete user", dErr)
	}
	_ = s.b.kv.Delete(ctx, displayNameKey(id))
	credIDs, _ := s.b.listUserCredIDs(ctx, id)
	for _, c := range credIDs {
		_ = s.b.kv.Delete(ctx, credKey(c))
	}
	_ = s.b.kv.Delete(ctx, userCredSetKey(id))
	return nil
}

// ----- CredentialStore -----

// Save stores a credential and adds it to the user's credential index.
func (s *qrdbCredentialStore) Save(ctx context.Context, cred *Credential) error {
	if cred == nil {
		return &QRDBAdapterConfigError{Field: "cred"}
	}
	if len(cred.ID) == 0 {
		return ErrInvalidCredential
	}
	id, err := UserIDFromHandle(cred.UserID)
	if err != nil {
		return err
	}
	s.b.mu.Lock()
	defer s.b.mu.Unlock()

	blob, err := json.Marshal(cred)
	if err != nil {
		return WrapError("encode credential", err)
	}
	if err := s.b.kv.Put(ctx, credKey(string(cred.ID)), blob); err != nil {
		return WrapError("persist credential", err)
	}
	ids, _ := s.b.listUserCredIDs(ctx, id)
	for _, existing := range ids {
		if existing == string(cred.ID) {
			return nil
		}
	}
	ids = append(ids, string(cred.ID))
	idsBlob, err := json.Marshal(ids)
	if err != nil {
		return WrapError("encode cred index", err)
	}
	if err := s.b.kv.Put(ctx, userCredSetKey(id), idsBlob); err != nil {
		return WrapError("persist cred index", err)
	}
	return nil
}

// GetByUserID returns all credentials for a user.
func (s *qrdbCredentialStore) GetByUserID(ctx context.Context, userID []byte) ([]*Credential, error) {
	id, err := UserIDFromHandle(userID)
	if err != nil {
		return nil, err
	}
	ids, err := s.b.listUserCredIDs(ctx, id)
	if err != nil {
		return nil, err
	}
	creds := make([]*Credential, 0, len(ids))
	for _, cid := range ids {
		c, err := s.GetByCredentialID(ctx, []byte(cid))
		if err != nil {
			if errors.Is(err, ErrCredentialNotFound) {
				continue
			}
			return nil, err
		}
		creds = append(creds, c)
	}
	return creds, nil
}

// GetByCredentialID retrieves a credential by its id.
func (s *qrdbCredentialStore) GetByCredentialID(ctx context.Context, credID []byte) (*Credential, error) {
	blob, err := s.b.kv.Get(ctx, credKey(string(credID)))
	if err != nil {
		return nil, mapNotFoundCred(err)
	}
	if len(blob) == 0 {
		return nil, ErrCredentialNotFound
	}
	var cred Credential
	if err := json.Unmarshal(blob, &cred); err != nil {
		return nil, WrapError("decode credential", err)
	}
	return &cred, nil
}

// Update overwrites an existing credential record.
func (s *qrdbCredentialStore) Update(ctx context.Context, cred *Credential) error {
	if cred == nil {
		return &QRDBAdapterConfigError{Field: "cred"}
	}
	if _, err := s.GetByCredentialID(ctx, cred.ID); err != nil {
		return err
	}
	blob, err := json.Marshal(cred)
	if err != nil {
		return WrapError("encode credential", err)
	}
	return s.b.kv.Put(ctx, credKey(string(cred.ID)), blob)
}

// Delete removes a credential record (and detaches it from the user
// index).
func (s *qrdbCredentialStore) Delete(ctx context.Context, credID []byte) error {
	s.b.mu.Lock()
	defer s.b.mu.Unlock()

	idStr := string(credID)
	cred, err := s.GetByCredentialID(ctx, credID)
	if err != nil {
		if errors.Is(err, ErrCredentialNotFound) {
			return ErrCredentialNotFound
		}
		return err
	}
	userID, err := UserIDFromHandle(cred.UserID)
	if err != nil {
		return err
	}
	if err := s.b.kv.Delete(ctx, credKey(idStr)); err != nil {
		return WrapError("delete credential", err)
	}
	ids, _ := s.b.listUserCredIDs(ctx, userID)
	out := ids[:0]
	for _, id := range ids {
		if id == idStr {
			continue
		}
		out = append(out, id)
	}
	if len(out) == 0 {
		return s.b.kv.Delete(ctx, userCredSetKey(userID))
	}
	blob, err := json.Marshal(out)
	if err != nil {
		return WrapError("encode cred index", err)
	}
	return s.b.kv.Put(ctx, userCredSetKey(userID), blob)
}

// DeleteByUserID removes all credentials for a user.
func (s *qrdbCredentialStore) DeleteByUserID(ctx context.Context, userID []byte) error {
	id, err := UserIDFromHandle(userID)
	if err != nil {
		return err
	}
	s.b.mu.Lock()
	defer s.b.mu.Unlock()

	ids, err := s.b.listUserCredIDs(ctx, id)
	if err != nil {
		return err
	}
	for _, cid := range ids {
		_ = s.b.kv.Delete(ctx, credKey(cid))
	}
	return s.b.kv.Delete(ctx, userCredSetKey(id))
}

// ----- shared helpers -----

// materialize hydrates a qrdb User into the xkms DefaultUser shape, plus
// fetching display-name and credentials from KV.
func (b *qrdbBackend) materialize(ctx context.Context, u *qrdbtransport.User) (*DefaultUser, error) {
	dn := ""
	if blob, err := b.kv.Get(ctx, displayNameKey(u.ID)); err == nil && len(blob) > 0 {
		dn = string(blob)
	}
	user := NewDefaultUser(HandleFromUserID(u.ID), u.Username, dn)

	// Load credentials via the cred-set index.
	ids, err := b.listUserCredIDs(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	creds := make([]*Credential, 0, len(ids))
	for _, id := range ids {
		blob, err := b.kv.Get(ctx, credKey(id))
		if err != nil {
			if isQRDBNotFound(err) {
				continue
			}
			return nil, WrapError("read credential", err)
		}
		var c Credential
		if err := json.Unmarshal(blob, &c); err != nil {
			return nil, WrapError("decode credential", err)
		}
		creds = append(creds, &c)
	}
	user.SetCredentials(creds)
	return user, nil
}

// listUserCredIDs returns the credential id list for the given qrdb user
// id. When the user has no credentials yet the returned slice is empty.
func (b *qrdbBackend) listUserCredIDs(ctx context.Context, userID uint64) ([]string, error) {
	blob, err := b.kv.Get(ctx, userCredSetKey(userID))
	if err != nil {
		if isQRDBNotFound(err) {
			return nil, nil
		}
		return nil, WrapError("read cred index", err)
	}
	if len(blob) == 0 {
		return nil, nil
	}
	var ids []string
	if err := json.Unmarshal(blob, &ids); err != nil {
		return nil, WrapError("decode cred index", err)
	}
	return ids, nil
}

func credKey(credID string) string {
	return "__xkms:webauthn/credentials/" + credID
}

// userIDSegment renders a qrdb uint64 user id as the base-10 KV key
// segment used in the persisted webauthn namespace.
func userIDSegment(userID uint64) string {
	return strconv.FormatUint(userID, 10)
}

func userCredSetKey(userID uint64) string {
	return "__xkms:webauthn/users/" + userIDSegment(userID) + "/credentials"
}

func displayNameKey(userID uint64) string {
	return "__xkms:webauthn/users/" + userIDSegment(userID) + "/displayName"
}

// mapNotFound converts a qrdb not-found error into the xkms sentinel.
func mapNotFound(err error) error {
	if isQRDBNotFound(err) {
		return ErrUserNotFound
	}
	return WrapError("qrdb user lookup", err)
}

// mapNotFoundCred converts a qrdb not-found error into the xkms
// credential-not-found sentinel.
func mapNotFoundCred(err error) error {
	if isQRDBNotFound(err) {
		return ErrCredentialNotFound
	}
	return WrapError("qrdb credential lookup", err)
}

// isQRDBNotFound reports whether the given error is a qrdb not-found.
// We detect by error string match because qrdb's typed errors live in
// the SDK and cross-cutting probes against the embedded transport
// surface a wrapped variant. The check is deliberately permissive.
func isQRDBNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, needle := range []string{"not found", "ErrCodeNotFound", "no rows"} {
		if containsFold(msg, needle) {
			return true
		}
	}
	return false
}

// containsFold reports case-insensitive substring containment without
// allocating a lowered copy of the input.
func containsFold(haystack, needle string) bool {
	if len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			h := haystack[i+j]
			n := needle[j]
			if h >= 'A' && h <= 'Z' {
				h += 'a' - 'A'
			}
			if n >= 'A' && n <= 'Z' {
				n += 'a' - 'A'
			}
			if h != n {
				match = false
				break
			}
		}
		if match {
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

// formatUserIDForTest is a small helper used by tests to convert a
// numeric qrdb id into the matching xkms []byte handle. Production
// callers obtain the id directly from qrdbtransport.User.ID and encode
// it with HandleFromUserID. The handle is the fixed 8-byte big-endian
// form of the uint64 id.
func formatUserIDForTest(n uint64) []byte {
	return HandleFromUserID(n)
}

// Compile-time interface assertions.
var (
	_ UserStore       = (*qrdbUserStore)(nil)
	_ CredentialStore = (*qrdbCredentialStore)(nil)
)
