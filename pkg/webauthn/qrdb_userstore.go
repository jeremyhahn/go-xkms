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
	"fmt"
	"strconv"
	"strings"
	"time"

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

	// CallContext derives the context every user-client call runs on from
	// the caller's. The ceremony endpoints are public, so a request carries
	// no identity go-qrdb's authorization accepts: an embedded node passes
	// its service principal (node.ServiceContext) here, as the datastore
	// does. Nil runs the calls on the caller's context.
	CallContext func(ctx context.Context) (context.Context, error)

	// KV is the qrdb KV client the pending-enrolment claims live in. It must
	// implement transport.GuardedKVClient: a claim is taken with PutIfAbsent,
	// an expired one taken over with CompareAndSwap and a claim consumed with
	// CompareAndDelete, so concurrent registrations of one email elect
	// exactly one winner. Required.
	KV qrdbtransport.KVClient

	// EnrolmentClaimTTL bounds how long a claim holds an email's pending
	// record before another registration may take it over. It must not
	// outlive the registration session, so a taken-over claim's session
	// is already expired. Zero means DefaultEnrolmentClaimTTL.
	EnrolmentClaimTTL time.Duration
}

// qrdbUserStore implements xkms's UserStore over qrdb's user records. A
// user's credentials are read from, and deleted through, the credential
// store it was built with.
type qrdbUserStore struct {
	users    qrdbtransport.UserClient
	creds    CredentialStore
	kv       qrdbtransport.GuardedKVClient
	claimTTL time.Duration
	tenantID string
	bind     func(ctx context.Context) (context.Context, error)
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
	if opts.KV == nil {
		return nil, nil, &QRDBAdapterConfigError{Field: "KV"}
	}
	kv, ok := opts.KV.(qrdbtransport.GuardedKVClient)
	if !ok {
		return nil, nil, &QRDBGuardedKVUnsupportedError{ClientType: fmt.Sprintf("%T", opts.KV)}
	}
	claimTTL := opts.EnrolmentClaimTTL
	if claimTTL <= 0 {
		claimTTL = DefaultEnrolmentClaimTTL
	}
	creds, err := newCredentialStore(opts.DAOFactory)
	if err != nil {
		return nil, nil, WrapError("build credential store", err)
	}
	users := &qrdbUserStore{
		users:    opts.Users,
		creds:    creds,
		kv:       kv,
		claimTTL: claimTTL,
		tenantID: opts.TenantID,
		bind:     opts.CallContext,
	}
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
	ctx, err = s.callContext(ctx)
	if err != nil {
		return nil, err
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
	ctx, err := s.callContext(ctx)
	if err != nil {
		return nil, err
	}
	u, err := s.users.GetUserByEmail(ctx, s.tenantID, email)
	if err != nil {
		return nil, mapNotFound(err)
	}
	user, err := s.materialize(ctx, u)
	if err != nil {
		return nil, err
	}
	if isPendingUsername(u.Username) && len(user.Credentials()) == 0 {
		// A Create whose rename failed left this record. It is no account
		// yet, and the next Create for the email finishes it.
		return nil, ErrUserNotFound
	}
	return user, nil
}

// Create creates a new user in the configured tenant.
//
// The email and display name are fields OF the qrdb record. They used to be
// kept beside it — the display name in an xkms-owned KV blob, because qrdb had
// no Name field — which made this store a second source of truth for an
// identity qrdb already owned. Both now live in the record itself.
//
// The record's Username is its decimal qrdb user ID. A failure to assign it
// is a *QRDBUsernameAssignError. The record is left under its placeholder,
// since the service principal holds no users:delete, and the next Create for
// the same email and tenant finishes the rename. A placeholder that already
// holds a credential is never taken over: that Create is a
// *QRDBPendingUserClaimedError.
func (s *qrdbUserStore) Create(ctx context.Context, email, displayName string) (User, error) {
	if email == "" {
		return nil, &QRDBAdapterConfigError{Field: "email"}
	}
	ctx, err := s.callContext(ctx)
	if err != nil {
		return nil, err
	}
	existing, err := s.users.GetUserByEmail(ctx, s.tenantID, email)
	switch {
	case err == nil:
		return s.claimExisting(ctx, existing)
	case !isUserNotFound(err):
		return nil, WrapError("qrdb user lookup", err)
	}
	// qrdb's Username is the certificate CN, so it carries the qrdb user ID,
	// never the email (owner ruling 166, go-xkms#1468): the email stays in
	// Email, the tenant-unique login key. qrdb assigns the ID at create and
	// refuses an empty Username, so the record is created under a random,
	// PII-free placeholder and then renamed to its ID. An existing account
	// for the email is refused here by qrdb.
	u, err := s.users.CreateUser(ctx, &qrdbtransport.CreateUserRequest{
		Username: pendingUsernamePrefix + rand.Text(),
		Email:    email,
		Name:     displayName,
		TenantID: s.tenantID,
	})
	if err != nil {
		// A concurrent registration may have created the record first; it
		// is then contended through its claim like any existing record.
		if existing, lookupErr := s.users.GetUserByEmail(ctx, s.tenantID, email); lookupErr == nil {
			return s.claimExisting(ctx, existing)
		}
		return nil, WrapError("qrdb create user", err)
	}
	claim, err := s.acquireClaim(ctx, u.ID, true)
	if err != nil {
		return nil, err
	}
	return s.claimedUser(ctx, u.ID, claim)
}

// claimExisting contends for the enrolment of a record that already exists
// for the email. A credential-free placeholder is open to a claim. A renamed,
// credential-free record is mid-enrolment, and only an expired claim on it can
// be taken over. A record that holds a credential is never handed out.
func (s *qrdbUserStore) claimExisting(ctx context.Context, u *qrdbtransport.User) (User, error) {
	pending := isPendingUsername(u.Username)
	creds, err := s.creds.GetByUserID(ctx, HandleFromUserID(u.ID))
	if err != nil {
		return nil, err
	}
	if len(creds) > 0 {
		if pending {
			return nil, &QRDBPendingUserClaimedError{UserID: u.ID}
		}
		return nil, ErrRegistrationRefused
	}
	claim, err := s.acquireClaim(ctx, u.ID, pending)
	if err != nil {
		return nil, err
	}
	if pending {
		return s.claimedUser(ctx, u.ID, claim)
	}
	user, err := s.materialize(ctx, u)
	if err != nil {
		return nil, errors.Join(err, s.releaseClaim(ctx, claim))
	}
	return &claimedUser{User: user, claim: claim.token}, nil
}

// claimedUser renames the claimed placeholder to its ID and returns it
// carrying the claim. A failed rename releases the claim, so the placeholder
// stays recoverable by the next registration.
func (s *qrdbUserStore) claimedUser(ctx context.Context, id uint64, claim *enrolmentClaim) (User, error) {
	user, err := s.assignUsername(ctx, id)
	if err != nil {
		return nil, errors.Join(err, s.releaseClaim(ctx, claim))
	}
	return &claimedUser{User: user, claim: claim.token}, nil
}

// acquireClaim takes the enrolment claim on record id. When allowAbsent is
// set, an absent claim is taken with PutIfAbsent. A live claim refuses with
// EnrolmentInProgressError. An expired or unreadable one is taken over with
// a CompareAndSwap on its exact value, which only one contender can win.
func (s *qrdbUserStore) acquireClaim(ctx context.Context, id uint64, allowAbsent bool) (*enrolmentClaim, error) {
	claim := &enrolmentClaim{userID: id, key: s.claimKey(id), token: rand.Text()}
	claim.value = encodeEnrolmentClaim(claim.token, time.Now().Add(s.claimTTL))
	if allowAbsent {
		stored, err := s.kv.PutIfAbsent(ctx, claim.key, claim.value)
		if err != nil {
			return nil, WrapError("put enrolment claim", err)
		}
		if stored {
			return claim, nil
		}
	}
	current, found, err := s.readClaim(ctx, claim.key)
	switch {
	case err != nil:
		return nil, err
	case !found && allowAbsent:
		// The claim was settled after the PutIfAbsent lost to it: its
		// holder has just saved a credential, and this registration lost.
		return nil, &EnrolmentInProgressError{UserID: id}
	case !found:
		// A renamed record that nobody is enrolling is an existing account.
		return nil, ErrRegistrationRefused
	}
	if _, expires, ok := decodeEnrolmentClaim(current); ok && time.Now().Before(expires) {
		return nil, &EnrolmentInProgressError{UserID: id}
	}
	swapped, err := s.kv.CompareAndSwap(ctx, claim.key, current, claim.value)
	if err != nil {
		return nil, WrapError("take over enrolment claim", err)
	}
	if !swapped {
		return nil, &EnrolmentInProgressError{UserID: id}
	}
	return claim, nil
}

// releaseClaim gives up a claim this store holds, only if it still holds
// it. The claim is left expired rather than deleted: an expired claim marks
// a credential-free account a later registration may recover, while an
// absent claim on a renamed account means an account nobody is enrolling.
func (s *qrdbUserStore) releaseClaim(ctx context.Context, claim *enrolmentClaim) error {
	expired := encodeEnrolmentClaim(claim.token, time.Unix(0, 0))
	if _, err := s.kv.CompareAndSwap(ctx, claim.key, claim.value, expired); err != nil {
		return WrapError("release enrolment claim", err)
	}
	return nil
}

// consumeEnrolmentClaim marks the claim a finishing enrolment holds as
// consumed, with a CompareAndSwap on the exact claim it read. The consumed
// claim carries a fresh expiry and stays held until settleEnrolmentClaim, so
// no other registration can take the account while the credential is saved.
// A claim that is absent, expired, already consumed or another
// registration's fails with EnrolmentClaimLostError, and the enrolment must
// then add nothing.
//
// The consumed claim still expires, and a save can outlast it. So the
// consume also wins the account's enrolment credential marker with
// PutIfAbsent: a marker with no expiry that no path takes over. A marker
// already held fails with EnrolmentCredentialMarkedError, and the claim is
// released. This is what keeps the unauthenticated path to at most one
// credential per account, whatever the timing.
func (s *qrdbUserStore) consumeEnrolmentClaim(ctx context.Context, user User, token string) error {
	ctx, claim, err := s.liveClaim(ctx, user, token)
	if err != nil {
		return err
	}
	consumed := encodeEnrolmentClaim(consumedClaimPrefix+token, time.Now().Add(s.claimTTL))
	swapped, err := s.kv.CompareAndSwap(ctx, claim.key, claim.value, consumed)
	if err != nil {
		return WrapError("consume enrolment claim", err)
	}
	if !swapped {
		return &EnrolmentClaimLostError{UserID: claim.userID}
	}
	// The claim expires; the credential marker never does. Winning it is
	// what lets this finish write the account's one public-enrolment
	// credential, however long the save then takes.
	stored, err := s.kv.PutIfAbsent(ctx, s.credentialMarkerKey(claim.userID), []byte(token))
	if err != nil {
		return errors.Join(WrapError("put enrolment credential marker", err), s.releaseConsumed(ctx, claim, consumed))
	}
	if !stored {
		return errors.Join(&EnrolmentCredentialMarkedError{UserID: claim.userID}, s.releaseConsumed(ctx, claim, consumed))
	}
	return nil
}

// releaseConsumed hands back a claim this finish consumed but will not use.
func (s *qrdbUserStore) releaseConsumed(ctx context.Context, claim *enrolmentClaim, consumed []byte) error {
	claim.value = consumed
	return s.releaseClaim(ctx, claim)
}

// settleEnrolmentClaim ends a consumed claim once the credential save has
// run. A saved credential deletes the claim: the account now holds a
// credential and is never taken again; a claim that expired during the save
// is not an error, since the credential marker holds the account. A failed
// save deletes the credential marker and releases the claim, so a retry or a
// new registration of the email can recover the account.
func (s *qrdbUserStore) settleEnrolmentClaim(ctx context.Context, user User, token string, saved bool) error {
	if !saved {
		if err := s.dropCredentialMarker(ctx, user, token); err != nil {
			return err
		}
	}
	ctx, claim, err := s.liveClaim(ctx, user, consumedClaimPrefix+token)
	var lost *EnrolmentClaimLostError
	if saved && errors.As(err, &lost) {
		// The claim expired while the credential was saving. The credential
		// marker, not the claim, holds the account: nothing is left to settle.
		return nil
	}
	if err != nil {
		return err
	}
	if !saved {
		claim.token = token
		return s.releaseClaim(ctx, claim)
	}
	if _, err := s.kv.CompareAndDelete(ctx, claim.key, claim.value); err != nil {
		return WrapError("settle enrolment claim", err)
	}
	return nil
}

// dropCredentialMarker removes the credential marker this finish won with
// token, once its credential save has failed: no credential was written, so
// the account may enrol again. A marker another finish holds is left alone.
func (s *qrdbUserStore) dropCredentialMarker(ctx context.Context, user User, token string) error {
	id, err := UserIDFromHandle(user.WebAuthnID())
	if err != nil {
		return err
	}
	ctx, err = s.callContext(ctx)
	if err != nil {
		return err
	}
	if _, err := s.kv.CompareAndDelete(ctx, s.credentialMarkerKey(id), []byte(token)); err != nil {
		return WrapError("delete enrolment credential marker", err)
	}
	return nil
}

// enrolmentRecoverable reports whether user's record carries a released or
// expired enrolment claim: a public enrolment that never saved its
// credential, which the next Create for the email may take over. An account
// whose enrolment credential marker is held is never recoverable.
func (s *qrdbUserStore) enrolmentRecoverable(ctx context.Context, user User) (bool, error) {
	id, err := UserIDFromHandle(user.WebAuthnID())
	if err != nil {
		return false, err
	}
	ctx, err = s.callContext(ctx)
	if err != nil {
		return false, err
	}
	_, marked, err := s.readClaim(ctx, s.credentialMarkerKey(id))
	if err != nil || marked {
		return false, err
	}
	current, found, err := s.readClaim(ctx, s.claimKey(id))
	if err != nil || !found {
		return false, err
	}
	_, expires, ok := decodeEnrolmentClaim(current)
	return !ok || !time.Now().Before(expires), nil
}

// liveClaim binds the call context and reads the claim on user's record. It
// fails with EnrolmentClaimLostError unless the claim is unexpired and
// carries token.
func (s *qrdbUserStore) liveClaim(ctx context.Context, user User, token string) (context.Context, *enrolmentClaim, error) {
	id, err := UserIDFromHandle(user.WebAuthnID())
	if err != nil {
		return nil, nil, err
	}
	ctx, err = s.callContext(ctx)
	if err != nil {
		return nil, nil, err
	}
	key := s.claimKey(id)
	current, found, err := s.readClaim(ctx, key)
	if err != nil {
		return nil, nil, err
	}
	held, expires, ok := decodeEnrolmentClaim(current)
	if !found || !ok || held != token || !time.Now().Before(expires) {
		return nil, nil, &EnrolmentClaimLostError{UserID: id}
	}
	return ctx, &enrolmentClaim{userID: id, key: key, value: current, token: token}, nil
}

// readClaim returns the enrolment claim stored under key; found is false
// when there is none.
func (s *qrdbUserStore) readClaim(ctx context.Context, key string) (value []byte, found bool, err error) {
	value, err = s.kv.Get(ctx, key)
	var notFound *qrdbtransport.KeyNotFoundError
	if errors.As(err, &notFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, WrapError("get enrolment claim", err)
	}
	return value, true, nil
}

// claimKey is the KV key of the enrolment claim on record id.
func (s *qrdbUserStore) claimKey(id uint64) string {
	return enrolmentClaimPrefix + s.tenantID + "/" + strconv.FormatUint(id, 10)
}

// credentialMarkerKey is the KV key of the marker a finishing public
// enrolment wins before it writes the account's credential.
func (s *qrdbUserStore) credentialMarkerKey(id uint64) string {
	return enrolmentCredentialPrefix + s.tenantID + "/" + strconv.FormatUint(id, 10)
}

// enrolmentClaim is a claim this store took: its key, the exact value it
// wrote, and the token the registration session carries.
type enrolmentClaim struct {
	userID uint64
	key    string
	value  []byte
	token  string
}

// encodeEnrolmentClaim lays a claim out as its expiry in Unix nanoseconds,
// big-endian, followed by its token.
func encodeEnrolmentClaim(token string, expires time.Time) []byte {
	value := binary.BigEndian.AppendUint64(make([]byte, 0, 8+len(token)), uint64(expires.UnixNano()))
	return append(value, token...)
}

// decodeEnrolmentClaim reverses encodeEnrolmentClaim; ok is false for a
// value too short to hold a token.
func decodeEnrolmentClaim(value []byte) (token string, expires time.Time, ok bool) {
	if len(value) <= 8 {
		return "", time.Time{}, false
	}
	return string(value[8:]), time.Unix(0, int64(binary.BigEndian.Uint64(value))), true
}

// enrolmentClaimant is a user handed to exactly one registration under an
// enrolment claim. Its registration session carries the claim's token, and
// finishing that registration consumes the claim.
type enrolmentClaimant interface {
	EnrolmentClaim() string
}

// enrolmentClaimConsumer is a user store whose Create hands out claimed
// users; a finishing enrolment consumes its claim through it before the
// credential save and settles it after, and a new registration asks it
// whether an existing record is an enrolment it may recover.
type enrolmentClaimConsumer interface {
	enrolmentRecoverable(ctx context.Context, user User) (bool, error)
	consumeEnrolmentClaim(ctx context.Context, user User, token string) error
	settleEnrolmentClaim(ctx context.Context, user User, token string, saved bool) error
}

// claimedUser is the user Create returns: the record and the claim it was
// won under.
type claimedUser struct {
	User
	claim string
}

// EnrolmentClaim implements enrolmentClaimant.
func (u *claimedUser) EnrolmentClaim() string {
	return u.claim
}

// assignUsername renames the record to its decimal qrdb user ID.
func (s *qrdbUserStore) assignUsername(ctx context.Context, id uint64) (User, error) {
	renamed, err := s.users.UpdateUser(ctx, &qrdbtransport.UpdateUserRequest{
		ID:       id,
		Username: strconv.FormatUint(id, 10),
	})
	if err != nil {
		return nil, &QRDBUsernameAssignError{UserID: id, Err: err}
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
	ctx, err = s.callContext(ctx)
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
	ctx, err = s.callContext(ctx)
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
	// Deleting the account is the administrator's way to clear a credential
	// marker whose finish died before its save: the email enrols afresh.
	var notFound *qrdbtransport.KeyNotFoundError
	if dErr := s.kv.Delete(ctx, s.credentialMarkerKey(id)); dErr != nil && !errors.As(dErr, &notFound) {
		return WrapError("delete enrolment credential marker", dErr)
	}
	return nil
}

// callContext returns the context a user-client call runs on: the caller's,
// bound by the CallContext option when one is set.
func (s *qrdbUserStore) callContext(ctx context.Context) (context.Context, error) {
	if s.bind == nil {
		return ctx, nil
	}
	bound, err := s.bind(ctx)
	if err != nil {
		return nil, &QRDBCallContextError{Err: err}
	}
	return bound, nil
}

// QRDBCallContextError reports that the CallContext option could not derive
// the context a qrdb user-client call runs on, e.g. an embedded node with no
// service principal. The call is refused before it reaches go-qrdb.
type QRDBCallContextError struct {
	Err error
}

func (e *QRDBCallContextError) Error() string {
	return "webauthn: derive qrdb call context: " + e.Err.Error()
}

// Unwrap exposes the binder's error for errors.Is/errors.As.
func (e *QRDBCallContextError) Unwrap() error { return e.Err }

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

// enrolmentClaimPrefix is the KV prefix of the enrolment claims, keyed
// <prefix><tenant>/<qrdb user ID>.
const enrolmentClaimPrefix = "webauthn/enrolment-claims/"

// consumedClaimPrefix marks the token of a claim whose enrolment is saving
// its credential; no session carries a token with this prefix.
const consumedClaimPrefix = "consumed:"

// enrolmentCredentialPrefix is the KV prefix of the enrolment credential
// markers, keyed <prefix><tenant>/<qrdb user ID>. A marker has no expiry:
// once a public enrolment has won it and saved its credential, no other
// unauthenticated enrolment can write a credential for that account.
const enrolmentCredentialPrefix = "webauthn/enrolment-credential/"

// DefaultEnrolmentClaimTTL is the enrolment claim lifetime when
// QRDBUserStoreOptions.EnrolmentClaimTTL is zero: Config's default
// ceremony Timeout.
const DefaultEnrolmentClaimTTL = 60 * time.Second

// isPendingUsername reports whether username is a Create placeholder.
func isPendingUsername(username string) bool {
	return strings.HasPrefix(username, pendingUsernamePrefix)
}

// QRDBUsernameAssignError is returned by the qrdb user store's Create when
// the record could not be renamed to its qrdb user ID. The record stays
// under its placeholder; the next Create for the same email and tenant
// finishes the rename.
type QRDBUsernameAssignError struct {
	// UserID is the qrdb user ID of the record left under its placeholder.
	UserID uint64
	// Err is the qrdb error from the rename.
	Err error
}

// Error implements error.
func (e *QRDBUsernameAssignError) Error() string {
	return "webauthn: qrdb adapter: assign username to user " + strconv.FormatUint(e.UserID, 10) + ": " + e.Err.Error()
}

// Unwrap returns the rename error.
func (e *QRDBUsernameAssignError) Unwrap() error { return e.Err }

// QRDBPendingUserClaimedError is returned by the qrdb user store's Create
// when the email's record is still under its placeholder but already holds
// a credential. Such a record is never renamed and handed to a new
// registration.
type QRDBPendingUserClaimedError struct {
	// UserID is the qrdb user ID of the placeholder record.
	UserID uint64
}

// Error implements error.
func (e *QRDBPendingUserClaimedError) Error() string {
	return "webauthn: qrdb adapter: placeholder user " + strconv.FormatUint(e.UserID, 10) + " already holds a credential"
}

// QRDBGuardedKVUnsupportedError is returned by NewQRDBUserStoreAdapter when
// the KV client lacks the conditional-write verbs
// (transport.GuardedKVClient). An enrolment claim is decided by them, so the
// store fails to build rather than run a check-then-write that two
// registrations can interleave inside.
type QRDBGuardedKVUnsupportedError struct {
	// ClientType is the Go type of the KV client supplied.
	ClientType string
}

// Error implements error.
func (e *QRDBGuardedKVUnsupportedError) Error() string {
	return "webauthn: qrdb adapter: kv client " + e.ClientType +
		" does not implement transport.GuardedKVClient; enrolment claims are unavailable on this transport"
}

// EnrolmentInProgressError is returned by the qrdb user store's Create when
// another registration holds the live enrolment claim on the email's
// record. No registration session is issued.
type EnrolmentInProgressError struct {
	// UserID is the qrdb user ID of the record being enrolled.
	UserID uint64
}

// Error implements error.
func (e *EnrolmentInProgressError) Error() string {
	return "webauthn: qrdb adapter: an enrolment of user " + strconv.FormatUint(e.UserID, 10) + " is already in progress"
}

// EnrolmentClaimLostError is returned when a finishing enrolment no longer
// holds its claim: the claim expired, was taken over or was already
// consumed. No credential is added.
type EnrolmentClaimLostError struct {
	// UserID is the qrdb user ID of the record being enrolled.
	UserID uint64
}

// Error implements error.
func (e *EnrolmentClaimLostError) Error() string {
	return "webauthn: qrdb adapter: the enrolment claim on user " + strconv.FormatUint(e.UserID, 10) + " is no longer held"
}

// EnrolmentCredentialMarkedError is returned when a finishing public
// enrolment finds the account's enrolment credential marker already held:
// another enrolment has written, or is writing, the account's credential.
// No credential is added.
type EnrolmentCredentialMarkedError struct {
	// UserID is the qrdb user ID of the record being enrolled.
	UserID uint64
}

// Error implements error.
func (e *EnrolmentCredentialMarkedError) Error() string {
	return "webauthn: qrdb adapter: user " + strconv.FormatUint(e.UserID, 10) + " already has a public-enrolment credential"
}

// Compile-time interface assertion.
var _ UserStore = (*qrdbUserStore)(nil)
