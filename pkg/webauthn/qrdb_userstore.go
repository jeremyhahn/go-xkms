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
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strconv"
	"sync"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
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
	u, err := s.b.users.GetUserByEmail(ctx, s.b.tenantID, email)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return s.b.materialize(ctx, u)
}

// Create creates a new user in the configured tenant.
//
// The email and display name are fields OF the qrdb record. They used to be
// kept beside it — the display name in an xkms-owned KV blob, because qrdb had
// no Name field — which made this store a second source of truth for an
// identity qrdb already owned. Both now live in the record itself.
func (s *qrdbUserStore) Create(ctx context.Context, email, displayName string) (User, error) {
	if email == "" {
		return nil, &QRDBAdapterConfigError{Field: "email"}
	}
	u, err := s.b.users.CreateUser(ctx, &qrdbtransport.CreateUserRequest{
		Username: email,
		Email:    email,
		Name:     displayName,
		TenantID: s.b.tenantID,
	})
	if err != nil {
		return nil, WrapError("qrdb create user", err)
	}
	return s.b.materialize(ctx, u)
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
	if _, uErr := s.b.users.UpdateUser(ctx, &qrdbtransport.UpdateUserRequest{
		ID:   id,
		Name: dn,
	}); uErr != nil {
		return WrapError("qrdb update display name", uErr)
	}
	return nil
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
	credSeg := credIDToString(cred.ID)
	if err := s.b.kv.Put(ctx, credKey(credSeg), blob); err != nil {
		return WrapError("persist credential", err)
	}
	ids, _ := s.b.listUserCredIDs(ctx, id)
	for _, existing := range ids {
		if existing == credSeg {
			return nil
		}
	}
	ids = append(ids, credSeg)
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
		rawID, decErr := credIDFromString(cid)
		if decErr != nil {
			return nil, decErr
		}
		c, err := s.GetByCredentialID(ctx, rawID)
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
	blob, err := s.b.kv.Get(ctx, credKey(credIDToString(credID)))
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
	return s.b.kv.Put(ctx, credKey(credIDToString(cred.ID)), blob)
}

// Delete removes a credential record (and detaches it from the user
// index).
func (s *qrdbCredentialStore) Delete(ctx context.Context, credID []byte) error {
	s.b.mu.Lock()
	defer s.b.mu.Unlock()

	idStr := credIDToString(credID)
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
	// The WebAuthn name is the canonical EMAIL login key, and the display name
	// is the record's own Name. Both used to come from elsewhere — the name from
	// u.Username, the display name from an xkms KV blob — which is what let the
	// two drift.
	user := NewDefaultUser(HandleFromUserID(u.ID), u.Email, u.Name)

	// Load credentials via the cred-set index.
	ids, err := b.listUserCredIDs(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	creds := make([]*Credential, 0, len(ids))
	for _, id := range ids {
		blob, err := b.kv.Get(ctx, credKey(id))
		if err != nil {
			// Only a genuinely absent credential is skipped. Anything else is
			// returned: a transport failure swallowed here would hand the
			// caller a user with silently FEWER credentials than they have,
			// and the authentication that follows would judge a valid passkey
			// unknown.
			if isKVNotFound(err) {
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
		// An absent index means the user has no credentials yet. A transport
		// failure does not, and must not read as "this user has none".
		if isKVNotFound(err) {
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

// credIDToString renders a raw WebAuthn credential id (arbitrary
// authenticator-assigned bytes) as its canonical persistence form: a
// base64url-without-padding string. This is the single lossless encoding
// used for BOTH the credential KV key segment and the per-user credential
// index entries.
//
// The raw credential id is NOT valid UTF-8 in the general case, so it must
// never be embedded directly in a Go string that is later JSON-marshalled:
// encoding/json replaces every invalid UTF-8 byte with U+FFFD, which
// silently corrupts the id and detaches the credential from its user index
// (the credential persists, but BeginLogin reports ErrNoCredentials).
// base64url keeps the round-trip exact and produces an ASCII-safe KV key.
func credIDToString(credID []byte) string {
	return base64.RawURLEncoding.EncodeToString(credID)
}

// credIDFromString reverses credIDToString, recovering the raw credential
// id bytes from the canonical base64url segment. A malformed segment (one
// that was never produced by credIDToString) surfaces a typed decode error
// rather than a silent mismatch.
func credIDFromString(s string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, WrapError("decode credential id segment", err)
	}
	return raw, nil
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

// mapNotFound converts a qrdb not-found error into the xkms sentinel.
func mapNotFound(err error) error {
	if isUserNotFound(err) {
		return ErrUserNotFound
	}
	return WrapError("qrdb user lookup", err)
}

// mapNotFoundCred converts a qrdb key-not-found error into the xkms
// credential-not-found sentinel.
func mapNotFoundCred(err error) error {
	if isKVNotFound(err) {
		return ErrCredentialNotFound
	}
	return WrapError("qrdb credential lookup", err)
}

// isKVNotFound reports whether err is the key-value store's not-found.
//
// Classification is TYPED and the default is closed: anything this does not
// positively recognise is an error, not an absent key. That ordering matters
// because every caller treats "not found" as a benign, expected outcome — a
// transport failure classified as not-found silently becomes "this credential
// does not exist", in the authentication path.
//
// The KV transports report a missing key as *transport.KeyNotFoundError; the
// qrdb SDK matches it with errors.As in its own kvstore adapter, coordination
// and guarded-swap paths, so this is the contract rather than an inference from
// message text.
func isKVNotFound(err error) bool {
	if err == nil {
		return false
	}
	var keyNotFound *qrdbtransport.KeyNotFoundError
	return errors.As(err, &keyNotFound)
}

// isUserNotFound reports whether err means the user record is absent.
//
// Unlike isKVNotFound this still falls back to matching the message text, and
// therefore still fails OPEN: an unrecognised transport failure is reported as
// "no such user".
//
// It is left that way deliberately. The typed check below is the contract we
// want, but UserClient.GetUser and GetUserByEmail — the two methods this
// classifies — document no not-found error at all, while the neighbouring
// GetUserByUsername documents ErrNotFound. Their implementations live outside
// this repository and this package's tests use hand-written fakes, so what a
// real missing user produces cannot be observed from here. Inverting the
// default without that answer would turn every genuine not-found into an
// error and break registration, which is worse than what is here now.
//
// Note also that qrdbsdk.ErrNotFound is an ErrorCode constant, not a sentinel
// error — errors.Is cannot match it, so IsDAONotFound is the only typed probe
// the SDK offers here. That is recorded on go-qrdb#286 too.
//
// Tracked upstream as go-qrdb#286. When that confirms the contract, delete the
// text fallback and leave the typed check.
func isUserNotFound(err error) bool {
	if err == nil {
		return false
	}
	if qrdbsdk.IsDAONotFound(err) {
		return true
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
