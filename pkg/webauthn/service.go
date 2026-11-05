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
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// verificationError classifies an error returned by go-webauthn credential
// validation. A protocol-level verification failure (a forged or invalid
// attestation/assertion) is mapped to ErrVerificationFailed so transports
// return 401; any other error (for example a storage fault surfaced through a
// validation callback) is wrapped unchanged and remains a 500.
func verificationError(op string, err error) error {
	var protoErr *protocol.Error
	if errors.As(err, &protoErr) {
		return NewVerificationError(op, err)
	}
	return WrapError(op, err)
}

// sessionClaimError classifies a failed single-use session claim. A session
// that cannot be claimed — missing, expired, or already consumed by a
// concurrent finish — is an authentication failure, never a partial success:
// there is no ceremony state left to validate the response against, so the
// request must not authenticate. Classifying it as a verification failure also
// keeps transports returning 401 rather than leaking store state.
func sessionClaimError(op string, err error) error {
	return NewVerificationError(op, err)
}

// Service provides WebAuthn registration and authentication operations.
type Service struct {
	webauthn    *webauthn.WebAuthn
	config      *Config
	users       UserStore
	sessions    SessionStore
	creds       CredentialStore
	jwtGen      JWTGenerator // optional
	logger      *slog.Logger
	auditLogger qrdbsdk.NodeAuditLogger // optional
	configured  bool

	// decoyKey keys the decoy login ceremonies (decoy.go). It is drawn
	// once per process and never leaves memory.
	decoyKey []byte
}

// ServiceParams contains dependencies for creating a WebAuthn service.
type ServiceParams struct {
	// Config is the WebAuthn configuration (required).
	Config *Config

	// UserStore is the user persistence layer (required).
	UserStore UserStore

	// SessionStore is the session persistence layer (required).
	SessionStore SessionStore

	// CredentialStore is the credential persistence layer (required).
	CredentialStore CredentialStore

	// JWTGenerator is an optional token generator for post-auth tokens.
	// If nil, the service returns the base64-encoded user ID after auth.
	JWTGenerator JWTGenerator

	// Logger is an optional logger for the service.
	// If nil, uses slog.Default().
	Logger *slog.Logger

	// AuditLogger receives the service's security audit events (a login
	// with a possibly cloned credential, see CloneWarningAuditAction). Nil
	// records none; the warning is still logged through Logger.
	AuditLogger qrdbsdk.NodeAuditLogger
}

// NewService creates a new WebAuthn service with the provided dependencies.
func NewService(params ServiceParams) (*Service, error) {
	if params.Config == nil {
		return nil, &errs.Message{Msg: "config is required"}
	}
	if params.UserStore == nil {
		return nil, &errs.Message{Msg: "user store is required"}
	}
	if params.SessionStore == nil {
		return nil, &errs.Message{Msg: "session store is required"}
	}
	if params.CredentialStore == nil {
		return nil, &errs.Message{Msg: "credential store is required"}
	}

	// Set defaults and validate
	params.Config.SetDefaults()
	if err := params.Config.Validate(); err != nil {
		return nil, &errs.Wrapped{Msg: "invalid config", Err: err}
	}

	// Create the go-webauthn instance
	wa, err := webauthn.New(params.Config.ToWebAuthnConfig())
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create webauthn instance", Err: err}
	}

	logger := params.Logger
	if logger == nil {
		logger = slog.Default()
	}

	decoyKey, err := newDecoyKey()
	if err != nil {
		return nil, err
	}

	return &Service{
		webauthn:    wa,
		config:      params.Config,
		users:       params.UserStore,
		sessions:    params.SessionStore,
		creds:       params.CredentialStore,
		jwtGen:      params.JWTGenerator,
		logger:      logger,
		auditLogger: params.AuditLogger,
		configured:  true,
		decoyKey:    decoyKey,
	}, nil
}

// BeginRegistration starts the public (unauthenticated) WebAuthn
// registration ceremony for email. Returns the registration options to be
// sent to the client and a session ID.
//
// An unauthenticated caller may only ever enroll the FIRST passkey of an
// account that DID NOT EXIST before this call: the implicit Create below is
// precisely what "public registration" means — an email nobody has seen
// before becomes an account — and that is the only case in which reaching
// this entry point with no proof of anything is safe. When the relying
// party has open sign-up turned off, that branch is withheld and an unknown
// email is refused with ErrRegistrationRefused, the same answer every other
// refusal gets so it does not reveal whether the account exists
// (go-xkms#1296).
//
// An account that already exists — whether it holds credentials or was
// provisioned through CreateUser with none yet — is always refused here,
// full stop. A held credential means BeginAddCredential and an authenticated
// session are required (go-xkms#1294). Zero credentials on a
// PREVIOUSLY-EXISTING account means the account is either pending
// activation (CreateUser mints an invitation for exactly this — see
// pkg/xkms's BeginInviteRegistration, which calls BeginInviteRegistration
// below instead of this method) or was created through some other path this
// service does not know how to authorize; either way, enrolling its first
// credential through this unauthenticated entry point is the hole
// go-xkms#1294 part B closes. Before that ruling this method enrolled such
// an account's first passkey with no proof of possession at all.
func (s *Service) BeginRegistration(ctx context.Context, email, displayName string) (*protocol.CredentialCreation, string, error) {
	if !s.configured {
		return nil, "", ErrNotConfigured
	}

	if existing, err := s.users.GetByEmail(ctx, email); err == nil {
		// The account already exists: whatever its credential count, this
		// unauthenticated entry point never enrolls its first credential,
		// unless the record is a public enrolment that never saved one.
		recoverable, err := s.enrolmentRecoverable(ctx, existing)
		if err != nil {
			return nil, "", err
		}
		if !recoverable {
			return nil, "", ErrRegistrationRefused
		}
	} else if !IsUserNotFound(err) {
		return nil, "", WrapError("get user by email", err)
	}

	if !s.config.PublicRegistrationAllowed() {
		return nil, "", ErrRegistrationRefused
	}
	user, err := s.users.Create(ctx, email, displayName)
	if err != nil {
		return nil, "", WrapError("create user", err)
	}

	// A brand-new account cannot hold a credential, but the credential store
	// is still consulted rather than assumed empty: a storage fault here
	// must surface as an error, not be silently treated as "no credentials".
	existingCreds, err := s.creds.GetByUserID(ctx, user.WebAuthnID())
	if err != nil {
		return nil, "", WrapError("get credentials", err)
	}

	// beginRegistrationFor also checks account standing — which is how
	// public registration created accounts as active from the start.
	return s.beginRegistrationFor(ctx, user, existingCreds)
}

// BeginInviteRegistration opens a WebAuthn registration ceremony for a
// PENDING account, authorized by an out-of-band invitation the caller has
// already validated (pkg/xkms's BeginInviteRegistration looks up the
// invitation and resolves email from the account it names — never from
// caller input — before calling this).
//
// This is the ONLY unauthenticated entry point that may enroll the first
// credential of an account that already existed before the call
// (go-xkms#1294 part B). It refuses everything except an account whose
// Lifecycle is exactly LifecyclePending and holds no credential yet: an
// active account (already activated, nothing pending to enroll), a
// suspended/locked/disabled/deleting one, or a pending one that somehow
// already holds a credential, all get the same ErrRegistrationRefused a
// public BeginRegistration refusal carries, so this cannot be used to add a
// second credential or to re-run activation.
func (s *Service) BeginInviteRegistration(ctx context.Context, email string) (*protocol.CredentialCreation, string, error) {
	if !s.configured {
		return nil, "", ErrNotConfigured
	}
	user, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		if IsUserNotFound(err) {
			return nil, "", ErrRegistrationRefused
		}
		return nil, "", WrapError("get user by email", err)
	}
	if user.Lifecycle() != qrdbsdk.LifecyclePending {
		return nil, "", ErrRegistrationRefused
	}
	existingCreds, err := s.creds.GetByUserID(ctx, user.WebAuthnID())
	if err != nil {
		return nil, "", WrapError("get credentials", err)
	}
	if len(existingCreds) > 0 {
		return nil, "", ErrRegistrationRefused
	}

	return s.runBeginRegistration(ctx, user, nil)
}

// BeginAddCredential starts a registration ceremony that adds a passkey to
// the account an authenticated session belongs to. The account is taken from
// the session, never from the request, so a session can only ever add a
// passkey to its own account. It fails with ErrSessionAccountMismatch when
// acct does not name an existing account whose email matches.
func (s *Service) BeginAddCredential(ctx context.Context, acct SessionAccount) (*protocol.CredentialCreation, string, error) {
	if !s.configured {
		return nil, "", ErrNotConfigured
	}
	if len(acct.UserID) == 0 || acct.Email == "" {
		return nil, "", ErrSessionAccountMismatch
	}

	user, err := s.users.GetByID(ctx, acct.UserID)
	if err != nil {
		if IsUserNotFound(err) {
			return nil, "", ErrSessionAccountMismatch
		}
		return nil, "", WrapError("get user", err)
	}
	// The handle alone is not enough: a session minted by another
	// authentication method could carry a subject that happens to decode to
	// a valid handle. The email login key must name the same account.
	if user.Email() != acct.Email {
		return nil, "", ErrSessionAccountMismatch
	}

	existingCreds, err := s.creds.GetByUserID(ctx, user.WebAuthnID())
	if err != nil {
		return nil, "", WrapError("get credentials", err)
	}
	return s.beginRegistrationFor(ctx, user, existingCreds)
}

// beginRegistrationFor runs the registration ceremony for an already
// resolved account, excluding the credentials it already holds. An account
// that is not active is refused with ErrRegistrationRefused, the same answer
// every other refused enrolment gets, so the refusal does not reveal the
// account's state (go-xkms#1298).
func (s *Service) beginRegistrationFor(ctx context.Context, user User, existingCreds []*Credential) (*protocol.CredentialCreation, string, error) {
	if err := checkLifecycle(user); err != nil {
		s.logStandingRefusal("begin registration", err)
		return nil, "", ErrRegistrationRefused
	}
	return s.runBeginRegistration(ctx, user, existingCreds)
}

// runBeginRegistration starts the go-webauthn ceremony for an already
// resolved, already standing-checked account, excluding the credentials it
// already holds, and persists the resulting session. It carries no lifecycle
// or credential-count policy of its own — every caller decides that before
// reaching here — because BeginInviteRegistration's policy (pending, zero
// credentials) and beginRegistrationFor's (active) are deliberately
// different gates in front of the identical ceremony mechanics.
func (s *Service) runBeginRegistration(ctx context.Context, user User, existingCreds []*Credential) (*protocol.CredentialCreation, string, error) {
	excludeList := make([]protocol.CredentialDescriptor, len(existingCreds))
	for i, cred := range existingCreds {
		excludeList[i] = protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: cred.ID,
			Transport:    cred.Transport,
		}
	}

	opts := []webauthn.RegistrationOption{webauthn.WithExclusions(excludeList)}
	if claimant, ok := user.(enrolmentClaimant); ok {
		opts = append(opts, withEnrolmentChallenge(claimant.EnrolmentClaim()))
	}
	options, session, err := s.webauthn.BeginRegistration(user, opts...)
	if err != nil {
		return nil, "", WrapError("begin registration", err)
	}

	sessionID, err := s.sessions.Save(ctx, session)
	if err != nil {
		return nil, "", WrapError("save session", err)
	}

	return options, sessionID, nil
}

// FinishRegistration completes the WebAuthn registration ceremony.
// Returns a token (JWT if configured, otherwise base64 user ID) and the user.
func (s *Service) FinishRegistration(ctx context.Context, sessionID string, response *protocol.ParsedCredentialCreationData) (string, User, error) {
	user, err := s.finishRegistrationUser(ctx, sessionID, response)
	if err != nil {
		return "", nil, err
	}

	token, err := s.generateToken(ctx, user)
	if err != nil {
		return "", nil, WrapError("generate token", err)
	}

	return token, user, nil
}

// FinishRegistrationPair completes the registration ceremony and returns an
// access/refresh token pair. The refresh token is empty when the configured
// generator does not implement TokenPairGenerator.
func (s *Service) FinishRegistrationPair(ctx context.Context, sessionID string, response *protocol.ParsedCredentialCreationData) (*TokenPair, User, error) {
	user, err := s.finishRegistrationUser(ctx, sessionID, response)
	if err != nil {
		return nil, nil, err
	}

	pair, err := s.mintTokens(ctx, user)
	if err != nil {
		return nil, nil, WrapError("generate token", err)
	}

	return pair, user, nil
}

// finishRegistrationUser runs the registration ceremony through credential
// storage, returning the enrolled user. Token minting is the caller's choice.
// The account must still be active: it may have left that state since the
// ceremony began.
func (s *Service) finishRegistrationUser(ctx context.Context, sessionID string, response *protocol.ParsedCredentialCreationData) (User, error) {
	return s.runFinishRegistration(ctx, sessionID, response, func(user User) error {
		if err := checkLifecycle(user); err != nil {
			s.logStandingRefusal("finish registration", err)
			return ErrRegistrationRefused
		}
		return nil
	})
}

// FinishInviteRegistration completes an invite-authorized WebAuthn
// registration ceremony. It binds the credential to the account the
// ceremony's session names, which must still be LifecyclePending: an
// invitation authorizes enrolling the FIRST credential of a pending account,
// nothing else, so a session whose account already activated or left
// pending some other way is refused exactly like any other invalid
// registration (ErrRegistrationRefused).
//
// This does NOT activate the account or redeem the invitation — the account
// is deliberately left pending, with its first credential now bound, so a
// failure in the caller's activation step (pkg/xkms's
// FinishInviteRegistration) leaves the invitation intact and the token
// retryable rather than a redeemed invite pointing at a still-pending
// account with no way back in.
func (s *Service) FinishInviteRegistration(ctx context.Context, sessionID string, response *protocol.ParsedCredentialCreationData) (User, error) {
	return s.runFinishRegistration(ctx, sessionID, response, func(user User) error {
		if user.Lifecycle() != qrdbsdk.LifecyclePending {
			return ErrRegistrationRefused
		}
		return nil
	})
}

// runFinishRegistration claims the ceremony session, resolves the account it
// names, and — only once accept approves that account — validates the
// authenticator response and persists the resulting credential. accept
// encodes the ONE thing that differs between an ordinary registration finish
// (the account must still be active) and an invite-authorized one (the
// account must still be pending): everything else about completing a
// WebAuthn registration ceremony is identical, and duplicating it per caller
// is how the two could silently drift.
func (s *Service) runFinishRegistration(ctx context.Context, sessionID string, response *protocol.ParsedCredentialCreationData, accept func(User) error) (User, error) {
	if !s.configured {
		return nil, ErrNotConfigured
	}

	// Claim the session BEFORE anything is validated. Take is get-and-delete in
	// one atomic step, so two concurrent finish requests for one ceremony
	// cannot both proceed: the loser has nothing to validate against.
	session, err := s.sessions.Take(ctx, sessionID)
	if err != nil {
		return nil, sessionClaimError("take registration session", err)
	}

	// Get user
	user, err := s.users.GetByID(ctx, session.UserID)
	if err != nil {
		return nil, WrapError("get user", err)
	}

	if err := accept(user); err != nil {
		return nil, err
	}

	// Finish registration
	credential, err := s.webauthn.CreateCredential(user, *session, response)
	if err != nil {
		return nil, verificationError("create credential", err)
	}

	var enrolment enrolmentClaimConsumer
	token, enrolling := enrolmentClaimToken(session)
	if enrolling {
		if enrolment, err = s.consumeEnrolment(ctx, user, token); err != nil {
			return nil, err
		}
	}

	// Convert and store credential
	cred := FromWebAuthnCredential(user.WebAuthnID(), credential)
	saveErr := s.creds.Save(ctx, cred)
	if enrolling {
		if err := enrolment.settleEnrolmentClaim(ctx, user, token, outcomeOfCredentialSave(saveErr)); err != nil {
			return nil, errors.Join(saveErr, err)
		}
	}
	if saveErr != nil {
		return nil, WrapError("save credential", saveErr)
	}

	// Add credential to user
	user.AddCredential(cred)
	if err := s.users.Save(ctx, user); err != nil {
		return nil, WrapError("save user", err)
	}

	return user, nil
}

// enrolmentChallengePrefix marks the challenge of a session a public
// enrolment began under a claim; the claim's token follows it. The session
// is server-side, so a client cannot forge the marker.
const enrolmentChallengePrefix = "xkms-enrolment-claim:"

// withEnrolmentChallenge sets the registration challenge to the enrolment
// marker and the claim's token, so the session carries the claim to finish.
// The token is crypto/rand, so the challenge stays unpredictable.
func withEnrolmentChallenge(token string) webauthn.RegistrationOption {
	return func(cco *protocol.PublicKeyCredentialCreationOptions) error {
		cco.Challenge = protocol.URLEncodedBase64(enrolmentChallengePrefix + token)
		return nil
	}
}

// enrolmentClaimToken returns the claim token a public-enrolment session
// carries in its challenge.
func enrolmentClaimToken(session *webauthn.SessionData) (string, bool) {
	challenge, err := base64.RawURLEncoding.DecodeString(session.Challenge)
	if err != nil {
		return "", false
	}
	return strings.CutPrefix(string(challenge), enrolmentChallengePrefix)
}

// enrolmentRecoverable reports whether user is a public enrolment whose
// claim was released or expired before a credential was saved.
func (s *Service) enrolmentRecoverable(ctx context.Context, user User) (bool, error) {
	consumer, ok := s.users.(enrolmentClaimConsumer)
	if !ok {
		return false, nil
	}
	return consumer.enrolmentRecoverable(ctx, user)
}

// consumeEnrolment consumes a public enrolment's claim before its credential
// is added, and returns the store that settles it once the save has run. The
// unauthenticated path never adds a credential to a user that already holds
// one, whatever the claim says.
func (s *Service) consumeEnrolment(ctx context.Context, user User, token string) (enrolmentClaimConsumer, error) {
	existing, err := s.creds.GetByUserID(ctx, user.WebAuthnID())
	if err != nil {
		return nil, WrapError("get credentials", err)
	}
	if len(existing) > 0 {
		return nil, ErrRegistrationRefused
	}
	consumer, ok := s.users.(enrolmentClaimConsumer)
	if !ok {
		return nil, ErrRegistrationRefused
	}
	if err := consumer.consumeEnrolmentClaim(ctx, user, token); err != nil {
		return nil, err
	}
	return consumer, nil
}

// BeginLogin starts the WebAuthn authentication ceremony.
// If userID is nil, returns options for discoverable credentials (passkeys).
func (s *Service) BeginLogin(ctx context.Context, userID []byte) (*protocol.CredentialAssertion, string, error) {
	if !s.configured {
		return nil, "", ErrNotConfigured
	}

	var options *protocol.CredentialAssertion
	var session *webauthn.SessionData
	var err error

	if userID == nil {
		// Discoverable credentials flow
		options, session, err = s.webauthn.BeginDiscoverableLogin()
	} else {
		// User-identified flow
		user, userErr := s.users.GetByID(ctx, userID)
		if userErr != nil {
			return nil, "", WrapError("get user", userErr)
		}
		// An account that may not log in answers exactly like one that
		// does not exist (go-xkms#1298).
		if standingErr := CheckAccountStanding(user); standingErr != nil {
			s.logStandingRefusal("begin login", standingErr)
			return nil, "", WrapError("get user", ErrUserNotFound)
		}

		// Check if user has credentials
		creds, credErr := s.creds.GetByUserID(ctx, userID)
		if credErr != nil {
			return nil, "", WrapError("get credentials", credErr)
		}
		if len(creds) == 0 {
			return nil, "", ErrNoCredentials
		}

		options, session, err = s.webauthn.BeginLogin(user)
	}

	if err != nil {
		return nil, "", WrapError("begin login", err)
	}

	return s.saveLoginSession(ctx, options, session)
}

// BeginLoginForEmail starts a user-identified authentication ceremony for
// the account email names. It never reveals whether that account exists:
// an unknown email, or an account with no credentials, is answered with a
// well-formed decoy ceremony (see beginDecoyLogin) instead of an error, so
// the response is shaped exactly like a real one (go-xkms#1296).
func (s *Service) BeginLoginForEmail(ctx context.Context, email string) (*protocol.CredentialAssertion, string, error) {
	if !s.configured {
		return nil, "", ErrNotConfigured
	}
	if email == "" {
		return nil, "", NewError("begin login", ErrInvalidRequest)
	}
	user, err := s.users.GetByEmail(ctx, email)
	return s.beginLoginOrDecoy(ctx, user, err, decoySubject(decoyKindEmail, []byte(email)))
}

// BeginLoginForHandle is BeginLoginForEmail for a caller that addresses the
// account by its WebAuthn user handle. An unknown handle, or an account with
// no credentials, is answered with a decoy ceremony.
func (s *Service) BeginLoginForHandle(ctx context.Context, userID []byte) (*protocol.CredentialAssertion, string, error) {
	if !s.configured {
		return nil, "", ErrNotConfigured
	}
	if len(userID) == 0 {
		return nil, "", NewError("begin login", ErrInvalidRequest)
	}
	user, err := s.users.GetByID(ctx, userID)
	return s.beginLoginOrDecoy(ctx, user, err, decoySubject(decoyKindHandle, userID))
}

// beginLoginOrDecoy starts the real ceremony for a resolved account in good
// standing (CheckAccountStanding) holding credentials, and the decoy ceremony
// for subject otherwise. lookupErr is the account lookup's error; only "not
// found" is answered with a decoy. An account that may not log in — not
// active, or with WebAuthn withdrawn from its auth-method policy — is
// answered with the decoy an unknown account gets, so begin does not reveal
// its state (go-xkms#1298).
func (s *Service) beginLoginOrDecoy(ctx context.Context, user User, lookupErr error, subject []byte) (*protocol.CredentialAssertion, string, error) {
	if lookupErr != nil {
		if !IsUserNotFound(lookupErr) {
			return nil, "", WrapError("get user", lookupErr)
		}
		return s.beginDecoyLogin(ctx, subject)
	}
	if err := CheckAccountStanding(user); err != nil {
		s.logStandingRefusal("begin login", err)
		return s.beginDecoyLogin(ctx, subject)
	}

	creds, err := s.creds.GetByUserID(ctx, user.WebAuthnID())
	if err != nil {
		return nil, "", WrapError("get credentials", err)
	}
	if len(creds) == 0 {
		return s.beginDecoyLogin(ctx, subject)
	}

	options, session, err := s.webauthn.BeginLogin(user)
	if err != nil {
		return nil, "", WrapError("begin login", err)
	}
	return s.saveLoginSession(ctx, options, session)
}

// beginDecoyLogin runs a real go-webauthn login ceremony against a decoy
// account derived from subject (see decoyUser), and stores its session like
// any other. The options are therefore built by the same code as a real
// ceremony, the session ID comes from the same store, and a finish against
// it fails verification exactly like a wrong assertion: the decoy handle
// resolves to no account.
func (s *Service) beginDecoyLogin(ctx context.Context, subject []byte) (*protocol.CredentialAssertion, string, error) {
	user, err := s.decoyUser(subject)
	if err != nil {
		return nil, "", WrapError("derive decoy account", err)
	}
	options, session, err := s.webauthn.BeginLogin(user)
	if err != nil {
		return nil, "", WrapError("begin login", err)
	}
	return s.saveLoginSession(ctx, options, session)
}

// saveLoginSession stores a login ceremony's session and returns its ID
// alongside the options.
func (s *Service) saveLoginSession(ctx context.Context, options *protocol.CredentialAssertion, session *webauthn.SessionData) (*protocol.CredentialAssertion, string, error) {
	sessionID, err := s.sessions.Save(ctx, session)
	if err != nil {
		return nil, "", WrapError("save session", err)
	}
	return options, sessionID, nil
}

// FinishLogin completes the WebAuthn authentication ceremony.
// userID is advisory only: the session created by BeginLogin already
// records whether the ceremony is discoverable or user-identified, and that
// record always takes precedence, so userID may be nil for either flow.
// Returns a token (JWT if configured, otherwise base64 user ID) and the user.
func (s *Service) FinishLogin(ctx context.Context, sessionID string, userID []byte, response *protocol.ParsedCredentialAssertionData) (string, User, error) {
	if !s.configured {
		return "", nil, ErrNotConfigured
	}

	user, err := s.finishLoginUser(ctx, sessionID, response)
	if err != nil {
		return "", nil, err
	}

	// Generate token
	token, err := s.generateToken(ctx, user)
	if err != nil {
		return "", nil, WrapError("generate token", err)
	}

	return token, user, nil
}

// FinishLoginPair completes the login ceremony and returns an access/refresh
// token pair. The refresh token is empty when the configured generator does
// not implement TokenPairGenerator. userID is advisory only; see FinishLogin.
func (s *Service) FinishLoginPair(ctx context.Context, sessionID string, userID []byte, response *protocol.ParsedCredentialAssertionData) (*TokenPair, User, error) {
	user, err := s.finishLoginUser(ctx, sessionID, response)
	if err != nil {
		return nil, nil, err
	}

	pair, err := s.mintTokens(ctx, user)
	if err != nil {
		return nil, nil, WrapError("generate token", err)
	}

	return pair, user, nil
}

// finishLoginUser runs the login ceremony through credential-counter update,
// returning the authenticated user. Token minting is the caller's choice.
func (s *Service) finishLoginUser(ctx context.Context, sessionID string, response *protocol.ParsedCredentialAssertionData) (User, error) {
	if !s.configured {
		return nil, ErrNotConfigured
	}

	// Claim the session BEFORE validating the assertion. Take is get-and-delete
	// in one atomic step, so a replayed assertion racing the genuine one finds
	// no session to authenticate against. Reading the session first and
	// deleting it after validation let both requests succeed, and the
	// authenticator sign counter does not catch it: go-webauthn only sets
	// CloneWarning, and passkeys frequently report a counter of 0.
	session, err := s.sessions.Take(ctx, sessionID)
	if err != nil {
		return nil, sessionClaimError("take login session", err)
	}

	var user User
	var credential *webauthn.Credential

	// The session records which ceremony was started: BeginLogin stores the
	// user handle, BeginDiscoverableLogin leaves it empty. Always defer to
	// the session rather than the caller-supplied userID, which transports
	// derive from a client-controlled header. A discoverable session must
	// stay discoverable even when the caller re-derives a handle from an
	// already-resolved factor — go-webauthn's ValidateLogin rejects any
	// non-empty handle against an empty session.UserID with "ID mismatch for
	// User and Session", so honoring the caller's handle here would make
	// every discoverable login unreachable. Conversely, a session begun
	// identified must stay identified: ValidatePasskeyLogin rejects a
	// non-empty session.UserID with "session was not initiated as a
	// client-side discoverable login".
	userID := session.UserID

	if len(userID) == 0 {
		// Discoverable credentials flow - find user by credential
		credential, err = s.webauthn.ValidateDiscoverableLogin(
			s.discoverableUserHandler(ctx),
			*session,
			response,
		)
		if err != nil {
			return nil, verificationError("validate discoverable login", err)
		}

		// Get user from credential
		cred, credErr := s.creds.GetByCredentialID(ctx, credential.ID)
		if credErr != nil {
			return nil, WrapError("get credential", credErr)
		}
		user, err = s.users.GetByID(ctx, cred.UserID)
		if err != nil {
			return nil, WrapError("get user", err)
		}
	} else {
		// User-identified flow. A session whose handle names no account
		// is a decoy ceremony (beginDecoyLogin) or an account deleted
		// mid-ceremony; either way the assertion cannot verify, and it
		// fails exactly like a wrong assertion so a decoy is not revealed.
		user, err = s.users.GetByID(ctx, userID)
		if err != nil {
			if IsUserNotFound(err) {
				return nil, NewVerificationError("get user", err)
			}
			return nil, WrapError("get user", err)
		}

		credential, err = s.webauthn.ValidateLogin(user, *session, response)
		if err != nil {
			return nil, verificationError("validate login", err)
		}
	}

	// A valid assertion does not authenticate an account that may not log
	// in: one that is not active, or has withdrawn WebAuthn from its
	// auth-method policy. Begin already answers such an account with a decoy;
	// this catches the discoverable flow, which names no account at begin,
	// and an account whose standing changed mid-ceremony. The refusal is the
	// bare verification failure, carrying no detail that would reveal the
	// account's state (go-xkms#1298).
	if standingErr := CheckAccountStanding(user); standingErr != nil {
		s.logStandingRefusal("finish login", standingErr)
		return nil, NewVerificationError("validate login", nil)
	}

	// Update credential sign counter
	cred, err := s.creds.GetByCredentialID(ctx, credential.ID)
	if err != nil {
		return nil, WrapError("get credential for update", err)
	}
	if credential.Authenticator.CloneWarning {
		if err := s.reportCloneWarning(ctx, user, cred, response.Response.AuthenticatorData.Counter); err != nil {
			return nil, err
		}
	}
	cred.Authenticator.SignCount = credential.Authenticator.SignCount
	cred.Authenticator.CloneWarning = credential.Authenticator.CloneWarning
	cred.LastUsedAt = time.Now().UTC()

	if err := s.creds.Update(ctx, cred); err != nil {
		return nil, WrapError("update credential", err)
	}

	// Update user's credential
	user.UpdateCredential(cred)
	if err := s.users.Save(ctx, user); err != nil {
		return nil, WrapError("save user", err)
	}

	return user, nil
}

// logStandingRefusal records, for the operator, why a ceremony was refused
// for an account not in good standing. The client only ever sees the
// ceremony's generic refusal.
func (s *Service) logStandingRefusal(op string, err error) {
	s.logger.Warn("webauthn: ceremony refused for account not in good standing",
		"op", op,
		"error", err)
}

// IsRegistered checks if a user has any registered credentials.
func (s *Service) IsRegistered(ctx context.Context, userID []byte) (bool, error) {
	if !s.configured {
		return false, ErrNotConfigured
	}

	if userID == nil {
		return false, nil
	}

	creds, err := s.creds.GetByUserID(ctx, userID)
	if err != nil {
		return false, WrapError("get credentials", err)
	}

	return len(creds) > 0, nil
}

// GetUser retrieves a user by their WebAuthn ID.
func (s *Service) GetUser(ctx context.Context, userID []byte) (User, error) {
	if !s.configured {
		return nil, ErrNotConfigured
	}

	return s.users.GetByID(ctx, userID)
}

// GetUserByEmail retrieves a user by their email address.
func (s *Service) GetUserByEmail(ctx context.Context, email string) (User, error) {
	if !s.configured {
		return nil, ErrNotConfigured
	}

	return s.users.GetByEmail(ctx, email)
}

// GetCredentials retrieves all credentials for a user.
func (s *Service) GetCredentials(ctx context.Context, userID []byte) ([]*Credential, error) {
	if !s.configured {
		return nil, ErrNotConfigured
	}

	return s.creds.GetByUserID(ctx, userID)
}

// DeleteCredential removes a credential.
func (s *Service) DeleteCredential(ctx context.Context, credID []byte) error {
	if !s.configured {
		return ErrNotConfigured
	}

	return s.creds.Delete(ctx, credID)
}

// DeleteUser removes a user and all their credentials.
func (s *Service) DeleteUser(ctx context.Context, userID []byte) error {
	if !s.configured {
		return ErrNotConfigured
	}

	// Delete all credentials first
	if err := s.creds.DeleteByUserID(ctx, userID); err != nil {
		return WrapError("delete user credentials", err)
	}

	// Delete user
	return s.users.Delete(ctx, userID)
}

// Config returns the service configuration.
func (s *Service) Config() *Config {
	return s.config
}

// generateToken creates a token for the authenticated user.
func (s *Service) generateToken(ctx context.Context, user User) (string, error) {
	if s.jwtGen != nil {
		return s.jwtGen.GenerateToken(ctx, user)
	}
	// Default: return base64-encoded user ID
	return base64.RawURLEncoding.EncodeToString(user.WebAuthnID()), nil
}

// TokenPair carries the access token and, when the configured generator
// supports rotation, the refresh token minted at ceremony completion.
type TokenPair struct {
	// AccessToken is the bearer token for subsequent API requests.
	AccessToken string

	// RefreshToken renews the access token without a new hardware ceremony.
	// Empty when the generator does not implement TokenPairGenerator.
	RefreshToken string
}

// mintTokens mints the richest token shape the configured generator
// supports: an access/refresh pair via TokenPairGenerator, otherwise the
// single access token via JWTGenerator (or the base64 user-ID fallback).
func (s *Service) mintTokens(ctx context.Context, user User) (*TokenPair, error) {
	if pg, ok := s.jwtGen.(TokenPairGenerator); ok {
		access, refresh, err := pg.GenerateTokenPair(ctx, user)
		if err != nil {
			return nil, err
		}
		return &TokenPair{AccessToken: access, RefreshToken: refresh}, nil
	}

	access, err := s.generateToken(ctx, user)
	if err != nil {
		return nil, err
	}
	return &TokenPair{AccessToken: access}, nil
}

// discoverableUserHandler returns a handler for discoverable credential login.
func (s *Service) discoverableUserHandler(ctx context.Context) func(rawID, userHandle []byte) (webauthn.User, error) {
	return func(rawID, userHandle []byte) (webauthn.User, error) {
		// Try to find user by user handle
		user, err := s.users.GetByID(ctx, userHandle)
		if err != nil {
			return nil, err
		}
		return user, nil
	}
}
