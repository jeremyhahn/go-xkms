package tpm2

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

var (
	// ErrPlatformPolicySession is returned when the platform policy session
	// creation fails.
	ErrPlatformPolicySession = errors.New("tpm2: failed to create platform policy session")

	// ErrPlatformPolicyDigestCompute is returned when the platform policy digest
	// computation fails.
	ErrPlatformPolicyDigestCompute = errors.New("tpm2: failed to compute platform policy digest")
)

// Creates an unsalted, unauthenticated HMAC session with the TPM. If
// session encryption is enabled in the platform configuration file,
// the TPM <-> CPU bus is encrypted using AES-128 CFB.
func (tpm *TPM2) HMAC(auth []byte) tpm2.Session {
	if tpm.config.EncryptSession {
		tpm.logger.Debug("tpm: creating unauthenticated, unsalted, encrypted HMAC session")
		return tpm2.HMAC(
			tpm2.TPMAlgSHA256,
			16,
			tpm2.Auth(auth),
			// AESEncryption uses the session to encrypt the first parameter sent to/from
			// the TPM.
			// Note that only commands whose first command/response parameter is a 2B can
			// support session encryption.
			// EncryptIn specifies a decrypt session.
			// EncryptOut specifies an encrypt session.
			// EncryptInOut specifies a decrypt+encrypt session
			tpm2.AESEncryption(
				128,
				tpm2.EncryptInOut))
	}
	tpm.logger.Debug("tpm: creating unauthenticated, unsalted, UNencrypted HMAC session")

	return tpm2.HMAC(
		tpm2.TPMAlgSHA256,
		16,
		tpm2.Password(auth))
}

// Creates an authenticated, unsalted HMAC session with the TPM. If session
// encryption is enabled in the platform configuration file, the TPM <-> CPU
// bus is encrypted using AES-128 CFB.
func (tpm *TPM2) HMACSession(auth []byte) (s tpm2.Session, close func() error, err error) {
	if tpm.config.EncryptSession {
		tpm.logger.Debug("tpm: creating encrypted HMAC session")
		if tpm.debugSecrets {
			tpm.logger.Debug("tpm: HMAC session auth", slog.String("auth", string(auth)))
		}
		return tpm2.HMACSession(
			tpm.transport,
			tpm2.TPMAlgSHA256,
			16,
			tpm2.Auth(auth),
			tpm2.AESEncryption(
				128,
				tpm2.EncryptInOut))
	}
	tpm.logger.Debug("tpm: creating UNencrypted HMAC session")
	if tpm.debugSecrets {
		tpm.logger.Debug("tpm: HMAC session auth", slog.String("auth", string(auth)))
	}
	return tpm2.HMACSession(
		tpm.transport,
		tpm2.TPMAlgSHA256,
		16,
		tpm2.Auth(auth))
}

// Creates an authenticated, salted HMAC session with the TPM. If session
// encryption is enabled in the platform configuration file, the TPM <-> CPU
// bus is encrypted using AES-128 CFB.
func (tpm *TPM2) HMACSaltedSession(
	handle tpm2.TPMHandle,
	pub tpm2.TPMTPublic,
	auth []byte) (s tpm2.Session, close func() error, err error) {

	if tpm.config.EncryptSession {
		tpm.logger.Debug("tpm: creating salted, encrypted HMAC session with primary key",
			slog.String("handle", fmt.Sprintf("0x%x", handle)))
		if tpm.debugSecrets {
			tpm.logger.Debug("tpm: HMAC session auth", slog.String("auth", string(auth)))
		}
		return tpm2.HMACSession(
			tpm.transport,
			tpm2.TPMAlgSHA256,
			16,
			tpm2.Auth(auth),
			tpm2.AESEncryption(
				128,
				tpm2.EncryptInOut),
			tpm2.Salted(handle, pub))
	}
	tpm.logger.Debug("tpm: creating salted, UNencrypted HMAC session with key",
		slog.String("handle", fmt.Sprintf("0x%x", handle)))
	if tpm.debugSecrets {
		tpm.logger.Debug("tpm: HMAC session auth", slog.String("auth", string(auth)))
	}
	return tpm2.HMACSession(
		tpm.transport,
		tpm2.TPMAlgSHA256,
		16,
		[]tpm2.AuthOption{tpm2.Auth(auth)}...)
}

// PlatformPolicySession creates a PolicyOR session supporting both PCR-based
// automatic unlock and password-based PIN fallback. The session satisfies
// the platform policy digest (PolicyOR of PolicyPCR + PolicyAuthValue).
//
// When auth is nil, the session executes the PCR branch (PolicyPCR followed
// by PolicyOR). When auth is non-nil, the session executes the password
// branch (PolicyAuthValue followed by PolicyOR), binding the auth value to
// the session so the HMAC computation includes it (per TPM 2.0 Part 1,
// Section 19.6: HMAC key = sessionKey || authValue).
//
// Both branch digests are derived from the live platform PCR. This is the
// right behaviour for an object whose recorded policy pin is unknown -- every
// object created before pins existed, and every non-sealed platform-policy key
// -- and it is what makes the PCR branch fail once the platform state moves.
// Callers holding an object's pin build the session through
// platformPolicySession so the PIN branch survives a platform change.
//
// The resulting policy digest is cached in tpm.policyDigest.
func (tpm *TPM2) PlatformPolicySession(auth []byte) (tpm2.Session, func() error, error) {
	return tpm.platformPolicySession(auth, nil)
}

// platformPolicySession is the single implementation behind
// PlatformPolicySession. It differs only in where the PolicyPCR branch digest
// comes from.
//
// A policy session has to reach the exact PolicyOR digest that was attached to
// the key as its AuthPolicy, and that digest covers BOTH branch digests --
// including the branch the session does not take. The rule this function
// follows is: a branch digest the session actually demonstrates is computed
// from what was demonstrated; a branch digest the session merely names as an
// operand of TPM2_PolicyOR comes from the key's pin.
//
//   - PCR branch (auth == nil): the session runs TPM2_PolicyPCR against live
//     PCRs, so branch 1 is computed from the live platform PCR whether or not
//     a pin exists. If the platform state moved, the session digest no longer
//     equals the key's AuthPolicy and the TPM refuses the authorization with
//     TPM_RC_POLICY_FAIL. That is the platform binding and it is deliberately
//     untouched.
//
//   - Password branch (auth != nil): the session never demonstrates any PCR
//     state, so branch 1 is a pure operand. Recomputing it from live PCRs --
//     the historical behaviour -- made the OR digest change whenever the PCRs
//     moved, which locked out the PIN branch in exactly the situation a
//     recovery PIN exists for. With a pin, branch 1 is rebuilt from the PCR
//     digest recorded when the key was created, so a correct PIN still opens
//     it after a platform change.
//
// This applies to both kinds of platform-policy key: a sealed object, whose pin
// is recorded beside its blobs, and a persistent SRK, whose pin is recorded
// under its handle. pin may be nil, in which case the historical live-PCR
// behaviour is used for both branches.
func (tpm *TPM2) platformPolicySession(
	auth []byte,
	pin *store.PlatformPolicyPin) (tpm2.Session, func() error, error) {

	usePCRBranch := auth == nil

	hashAlgID, err := ParsePCRBankAlgID(tpm.config.PlatformPCRBank)
	if err != nil {
		return nil, nil, &errs.Detail{Err: ErrPlatformPolicySession, Detail: fmt.Sprintf("%v", err)}
	}

	// Branch digests for PolicyOR. pcrDigest is only read from the TPM when
	// the branch digests are derived from live PCRs; the pinned password
	// branch needs no PCR read at all.
	var pcrDigest, branch1Digest, branch2Digest []byte
	pinned := !usePCRBranch && pin != nil
	if pinned {
		branch1Digest, branch2Digest, err = platformPolicyBranchDigests(
			tpm2.TPMAlgID(pin.PCRBank), uint(pin.PCRIndex), pin.PCRDigest)
		if err != nil {
			return nil, nil, &errs.Detail{Err: ErrPlatformPolicySession, Detail: fmt.Sprintf("%v", err)}
		}
		if tpm2.TPMAlgID(pin.PCRBank) != hashAlgID {
			tpm.logger.Warn("tpm: platform policy pin was recorded in a different PCR bank",
				slog.String("pin_bank", fmt.Sprintf("0x%x", pin.PCRBank)),
				slog.String("configured_bank", fmt.Sprintf("0x%x", hashAlgID)))
		}
	} else {
		pcrDigest, err = tpm.PlatformPolicyDigestHash()
		if err != nil {
			return nil, nil, &errs.Detail{Err: ErrPlatformPolicySession, Detail: fmt.Sprintf("%v", err)}
		}
		branch1Digest, branch2Digest, err = platformPolicyBranchDigests(
			hashAlgID, tpm.config.PlatformPCR, pcrDigest)
		if err != nil {
			return nil, nil, &errs.Detail{Err: ErrPlatformPolicySession, Detail: fmt.Sprintf("%v", err)}
		}
	}

	// Create the real policy session.
	// When using the password branch (PolicyAuthValue), the auth value must
	// be bound to the session so that the HMAC computation includes it.
	// Per TPM 2.0 Part 1, Section 19.6: HMAC key = sessionKey || authValue.
	var sessionOpts []tpm2.AuthOption
	if !usePCRBranch && len(auth) > 0 {
		sessionOpts = append(sessionOpts, tpm2.Auth(auth))
	}
	session, closer, err := tpm2.PolicySession(
		tpm.transport, hashAlgID, 16, sessionOpts...)
	if err != nil {
		return nil, nil, &errs.Detail{Err: ErrPlatformPolicySession, Detail: fmt.Sprintf("%v", err)}
	}

	if usePCRBranch {
		// Execute PolicyPCR in the live session
		_, err = tpm2.PolicyPCR{
			PolicySession: session.Handle(),
			PcrDigest: tpm2.TPM2BDigest{
				Buffer: pcrDigest,
			},
			Pcrs: platformPolicyPCRSelection(hashAlgID, tpm.config.PlatformPCR),
		}.Execute(tpm.transport)
		if err != nil {
			if closeErr := closer(); closeErr != nil {
				tpm.logger.Error("failed to close session after PolicyPCR error",
					slog.String("error", closeErr.Error()))
			}
			return nil, nil, &errs.Detail{Err: ErrPlatformPolicySession, Detail: fmt.Sprintf("PolicyPCR execute: %v", err)}
		}
		tpm.logger.Debug("tpm: PlatformPolicySession - PCR branch executed")
	} else {
		// Execute PolicyAuthValue in the live session
		_, err = tpm2.PolicyAuthValue{
			PolicySession: session.Handle(),
		}.Execute(tpm.transport)
		if err != nil {
			if closeErr := closer(); closeErr != nil {
				tpm.logger.Error("failed to close session after PolicyAuthValue error",
					slog.String("error", closeErr.Error()))
			}
			return nil, nil, &errs.Detail{Err: ErrPlatformPolicySession, Detail: fmt.Sprintf("PolicyAuthValue execute: %v", err)}
		}
		tpm.logger.Debug("tpm: PlatformPolicySession - password branch executed")
	}

	// Execute PolicyOR with both branch digests to complete the session policy
	_, err = tpm2.PolicyOr{
		PolicySession: session.Handle(),
		PHashList: tpm2.TPMLDigest{
			Digests: []tpm2.TPM2BDigest{
				{Buffer: branch1Digest},
				{Buffer: branch2Digest},
			},
		},
	}.Execute(tpm.transport)
	if err != nil {
		if closeErr := closer(); closeErr != nil {
			tpm.logger.Error("failed to close session after PolicyOR error",
				slog.String("error", closeErr.Error()))
		}
		return nil, nil, &errs.Detail{Err: ErrPlatformPolicySession, Detail: fmt.Sprintf("PolicyOR execute: %v", err)}
	}

	// Get the final session policy digest for caching
	pgd, pgdErr := tpm2.PolicyGetDigest{
		PolicySession: session.Handle(),
	}.Execute(tpm.transport)
	if pgdErr == nil {
		tpm.policyDigest = pgd.PolicyDigest
		tpm.logger.Info("tpm: PlatformPolicySession - final session policy digest",
			slog.Bool("pcr_branch", usePCRBranch),
			slog.Bool("pinned_pcr_branch_digest", pinned),
			slog.String("session_digest", fmt.Sprintf("%x", pgd.PolicyDigest.Buffer)),
			slog.String("branch1_pcr", fmt.Sprintf("%x", branch1Digest)),
			slog.String("branch2_auth", fmt.Sprintf("%x", branch2Digest)))
	}

	return session, closer, nil
}

// Creates a one-time use TPM nonce session
func (tpm *TPM2) NonceSession(hierarchyAuth types.Password) (tpm2.Session, func() error, error) {

	var auth []byte
	if hierarchyAuth != nil {
		auth = hierarchyAuth.Bytes()
	}

	session, closer, err := tpm2.PolicySession(
		tpm.transport, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		tpm.logger.Error("failed to create nonce policy session", slog.String("error", err.Error()))
		return nil, nil, err
	}

	_, err = tpm2.PolicySecret{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Auth:   tpm2.PasswordAuth(auth),
		},
		NonceTPM:      session.NonceTPM(),
		PolicySession: session.Handle(),
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("failed to execute PolicySecret", slog.String("error", err.Error()))
		// Clean up session before returning error
		if closeErr := closer(); closeErr != nil {
			tpm.logger.Error("Failed to close session after PolicySecret error", slog.String("error", closeErr.Error()))
		}
		return nil, nil, err
	}

	return session, closer, nil
}

// Returns an authorization session for a key based on the provided parent
// key attributes and platform configuration file.
//
// Session selection logic for the parent key:
//   - Password != nil AND PlatformPolicy = true: PlatformPolicySession(password)
//     (password branch of PolicyOR for auto-unseal-capable keys)
//   - Password == nil AND PlatformPolicy = true: PlatformPolicySession(nil)
//     (PCR branch of PolicyOR for automatic unlock)
//   - Password != nil AND PlatformPolicy = false: PasswordAuth(password)
//     (default password-only, no auto-unseal)
//   - Neither: empty password auth
//
// When PlatformPolicy is false and encryption is enabled, a salted HMAC
// session is created using the parent key. This function returns a session
// closer function that needs to be called to close the session when complete.
func (tpm *TPM2) CreateSession(
	keyAttrs *types.KeyAttributes) (tpm2.Session, func() error, error) {

	var session tpm2.Session
	var err error
	var parentAuth []byte

	closer := func() error { return nil }

	if keyAttrs.Parent == nil {
		return tpm.CreateKeySession(keyAttrs)
	}

	parentHandle := keyAttrs.Parent.TPMAttributes.Handle

	if keyAttrs.Parent.PlatformPolicy {

		// Determine whether the parent has a meaningful (non-empty) auth value.
		// A nil Password or a Password with zero-length bytes means "no auth" and
		// should use the PCR branch for automatic unlock. After a restart the
		// cached SRK attributes carry no password (config file has empty string),
		// so selecting the password branch with empty auth would produce
		// TPM_RC_BAD_AUTH because the actual SRK UserAuth is the user PIN set
		// during initial setup.
		var parentAuth []byte
		if keyAttrs.Parent.Password != nil {
			parentAuth = keyAttrs.Parent.Password.Bytes()
		}

		if len(parentAuth) > 0 {
			// Password + PlatformPolicy: use compound policy password branch.
			// The parent's auth value must be passed so the session HMAC
			// includes it (TPM 2.0 Part 1, Section 19.6).
			//
			// The parent is a persistent primary key, so its pin is read from
			// the platform backend -- the one CreateSRK recorded it in. It is
			// deliberately not read from a caller-supplied key store: the SRK
			// is platform state and has exactly one writer and one reader.
			//
			// Without this the PIN branch of a platform-policy SRK could only
			// be satisfied while the measurements were unchanged, and TPM2_Load
			// of any child failed on the parent before the child's own PIN
			// branch was ever reached.
			pin, pinErr := tpm.loadPlatformPolicyPin(
				primaryPolicyPinAttrs(keyAttrs.Parent), nil)
			if pinErr != nil {
				return nil, closer, pinErr
			}
			session, closer, err = tpm.platformPolicySession(parentAuth, pin)
			if err != nil {
				return session, closer, err
			}
			tpm.logger.Debug("tpm: created platform policy session (password branch)",
				slog.String("cn", keyAttrs.CN))
			return session, closer, nil
		}

		// PlatformPolicy without password: use compound policy PCR branch
		session, closer, err = tpm.PlatformPolicySession(nil)
		if err != nil {
			return session, closer, err
		}
		tpm.logger.Debug("tpm: created platform policy session (PCR branch)",
			slog.String("cn", keyAttrs.CN))
		return session, closer, nil
	}

	// No PlatformPolicy: extract password for standard auth
	if keyAttrs.Parent.Password != nil {
		parentAuth = keyAttrs.Parent.Password.Bytes()
	}

	_, parentPub, err := tpm.ReadHandle(parentHandle)
	if err != nil {
		return session, closer, err
	}

	if tpm.config.EncryptSession {

		// Create salted (encrypted) session using parent key
		session, closer, err = tpm.HMACSaltedSession(
			parentHandle,
			parentPub,
			parentAuth)
		if err != nil {
			tpm.logger.Error("failed to create salted session", slog.String("error", err.Error()))
			return session, closer, err
		}
		return session, closer, nil
	}

	session = tpm2.PasswordAuth(parentAuth)
	return session, closer, nil
}

// loadPlatformPolicyPin returns the platform policy pin recorded beside the
// object's key blobs, or nil when the object carries none.
//
// A missing record is the pre-pin on-disk form: every object created before
// pins existed, and every platform-policy key that is not a sealed object.
// Those are answered with a nil pin so the caller reproduces the historical
// live-PCR behaviour; nothing is migrated or re-created behind the caller's
// back. Any other failure -- including a record that exists but cannot be
// decoded -- is returned, because silently authorizing with a policy the
// object was not created with would only turn a clear error into an obscure
// TPM authorization failure.
//
// backend may be nil, in which case the platform backend is used.
func (tpm *TPM2) loadPlatformPolicyPin(
	keyAttrs *types.KeyAttributes,
	backend store.KeyBackend) (*store.PlatformPolicyPin, error) {

	// No attributes to look a record up by is the same answer as no record:
	// nothing was ever written for such a key either.
	if keyAttrs == nil {
		return nil, nil
	}

	if backend == nil {
		backend = tpm.backend
	}
	if backend == nil {
		return nil, nil
	}

	record, err := backend.Get(keyAttrs, store.FSEXT_PLATFORM_POLICY)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) || errors.Is(err, fs.ErrNotExist) {
			tpm.logger.Debug("tpm: no platform policy pin recorded for key",
				slog.String("cn", keyAttrs.CN))
			return nil, nil
		}
		return nil, err
	}

	pin, err := store.UnmarshalPlatformPolicyPin(record)
	if err != nil {
		tpm.logger.Error("tpm: failed to decode platform policy pin",
			slog.String("cn", keyAttrs.CN),
			slog.String("error", err.Error()))
		return nil, err
	}

	tpm.logger.Debug("tpm: loaded platform policy pin",
		slog.String("cn", keyAttrs.CN),
		slog.Uint64("pcr", uint64(pin.PCRIndex)),
		slog.String("pcr_digest", fmt.Sprintf("%x", pin.PCRDigest)))

	return pin, nil
}

// Returns an authorization session for a child key based on the provided
// key attributes.
//
// Session selection logic:
//   - Password != nil AND PlatformPolicy = true: PlatformPolicySession(password)
//     (password branch of PolicyOR for auto-unseal-capable keys)
//   - Password == nil AND PlatformPolicy = true: PlatformPolicySession(nil)
//     (PCR branch of PolicyOR for automatic unlock)
//   - Password != nil AND PlatformPolicy = false: PasswordAuth(password)
//     (default password-only, no auto-unseal)
//   - Neither: empty password auth
//
// The key's platform policy pin, when it has one, is resolved from the
// platform backend. Callers holding a different backend -- the seal and unseal
// paths take one as a parameter -- use createKeySession directly.
//
// This function returns a session closer function that needs to be called
// to close the session when complete.
func (tpm *TPM2) CreateKeySession(
	keyAttrs *types.KeyAttributes) (tpm2.Session, func() error, error) {

	return tpm.createKeySession(keyAttrs, nil)
}

// createKeySession is the implementation behind CreateKeySession, resolving
// the key's platform policy pin from the supplied backend. backend may be nil,
// in which case the platform backend is used.
//
// The pin is only consulted for the password branch, which is the only branch
// that needs it (see platformPolicySession) -- so keys that never carry one
// cost no extra storage lookup.
func (tpm *TPM2) createKeySession(
	keyAttrs *types.KeyAttributes,
	backend store.KeyBackend) (tpm2.Session, func() error, error) {

	var session tpm2.Session
	var closer func() error
	var err error

	// Callers register their closer in a defer before inspecting the error,
	// so every return path -- including the failures -- has to hand back a
	// callable closer.
	noopCloser := func() error { return nil }

	if keyAttrs.PlatformPolicy {

		// Determine whether the key has a meaningful (non-empty) auth value.
		// See CreateSession for the full rationale on why empty auth must be
		// treated as nil to avoid TPM_RC_BAD_AUTH after restart.
		var keyAuth []byte
		if keyAttrs.Password != nil {
			keyAuth = keyAttrs.Password.Bytes()
		}

		if len(keyAuth) > 0 {
			// Password + PlatformPolicy: use platform policy password branch.
			// The key's auth value must be passed so the session HMAC
			// includes it (TPM 2.0 Part 1, Section 19.6).
			pin, pinErr := tpm.loadPlatformPolicyPin(keyAttrs, backend)
			if pinErr != nil {
				return nil, noopCloser, pinErr
			}
			session, closer, err = tpm.platformPolicySession(keyAuth, pin)
			if err != nil {
				if closer == nil {
					closer = noopCloser
				}
				return session, closer, err
			}
		} else {
			// PlatformPolicy without password: use platform policy PCR branch
			session, closer, err = tpm.PlatformPolicySession(nil)
			if err != nil {
				if closer == nil {
					closer = noopCloser
				}
				return session, closer, err
			}
		}
	} else {

		if keyAttrs.Password != nil {
			// Check if password is valid (error passwords return error from String())
			_, err = keyAttrs.Password.String()
			if err != nil {
				// noopCloser, not nil: UnsealKey registers its deferred
				// closer call before inspecting this error, so returning a nil
				// closer here panicked inside the deferred function instead of
				// reporting the bad password. A panic unwinding through the
				// unseal path skips the transient-object flushes below it.
				return nil, noopCloser, err
			}
			keyAuth := keyAttrs.Password.Bytes()
			session = tpm2.PasswordAuth(keyAuth)
		} else {
			session = tpm2.PasswordAuth(nil)
		}
	}

	if closer == nil {
		closer = func() error { return nil }
	}

	return session, closer, nil
}

// Loads the requested TPMAlgKeyedHash encrypted public and private
// blobs from blob storage. The returned handle must be closed when
// finished to prevent memory leaks / exhaustion.
//
// When session is nil, the ParentHandle authorization session is built by
// TPM2.CreateSession using the exact same selection logic used at key
// creation time (see CreateSession's doc comment): a PolicyOR session when
// the parent uses PlatformPolicy, a salted/encrypted HMAC session when
// tpm.config.EncryptSession is enabled, or a zero-round-trip PasswordAuth
// pseudo-session otherwise. Building an ad hoc, always-real HMAC session
// here (independent of that selection logic, as this function used to do
// via TPM2.HMAC) unconditionally issues a TPM2_StartAuthSession command
// even when EncryptSession is disabled and the parent has no policy --
// unlike key creation, which in that configuration never talks to the TPM
// for the auth session at all. On TPM/kernel combinations where
// TPM2_StartAuthSession is unusable through the resource manager device,
// that asymmetry made key generation succeed while every subsequent
// LoadKeyPair call (delete, sign, ECDH, attestation, unseal) failed.
func (tpm *TPM2) LoadKeyPair(
	keyAttrs *types.KeyAttributes,
	session *tpm2.Session,
	backend store.KeyBackend) (*tpm2.LoadResponse, error) {

	if keyAttrs.Parent == nil {
		return nil, store.ErrInvalidParentAttributes
	}

	// Use custom backend if provided, otherwise use the
	// default platform backend passed in during instantiation
	if backend == nil {
		backend = tpm.backend
	}

	// Load the public and private area blobs
	tpm.logger.Debug("tpm: LoadKeyPair - loading blobs",
		slog.String("cn", keyAttrs.CN),
		slog.String("keyType", fmt.Sprintf("%v", keyAttrs.KeyType)))
	priv, err := backend.Get(keyAttrs, store.FSEXT_PRIVATE_BLOB)
	if err != nil {
		// Log at debug level - this is expected during fresh initialization
		// when the key doesn't exist yet
		tpm.logger.Debug("tpm: LoadKeyPair - failed to load private blob",
			slog.String("error", err.Error()),
			slog.String("cn", keyAttrs.CN))
		return nil, err
	}
	tpm.logger.Debug("tpm: LoadKeyPair - loaded private blob", slog.Int("bytes", len(priv)))
	pub, err := backend.Get(keyAttrs, store.FSEXT_PUBLIC_BLOB)
	if err != nil {
		// Log at debug level - this is expected during fresh initialization
		// when the key doesn't exist yet
		tpm.logger.Debug("tpm: LoadKeyPair - failed to load public blob",
			slog.String("error", err.Error()),
			slog.String("cn", keyAttrs.CN))
		return nil, err
	}
	tpm.logger.Debug("tpm: LoadKeyPair - loaded public blob", slog.Int("bytes", len(pub)))

	// Create the ParentHandle authorization session if the caller did not
	// supply one. CreateSession authorizes the *parent* (using the
	// parent's own PlatformPolicy/Password), which is the correct entity
	// to authorize for TPM2_Load -- the child key's own auth value plays
	// no role in loading it.
	closer := func() error { return nil }
	if session == nil {
		sess, sessCloser, err := tpm.CreateSession(keyAttrs)
		if err != nil {
			return nil, err
		}
		session = &sess
		if sessCloser != nil {
			closer = sessCloser
		}
	}
	defer func() {
		if err := closer(); err != nil {
			tpm.logger.Error("tpm: LoadKeyPair - failed to close parent session",
				slog.String("error", err.Error()))
		}
	}()

	parentHandle := keyAttrs.Parent.TPMAttributes.Handle
	parentName := keyAttrs.Parent.TPMAttributes.Name

	// Ensure the parent Name is populated. After an app restart the cached
	// SRK attributes may only contain the persistent handle without the Name
	// (built from config, not from TPM2_ReadPublic). TPM2_Load requires a
	// valid Name for the ParentHandle parameter -- without it the go-tpm
	// marshaller returns "missing Name for 'ParentHandle' parameter".
	if len(parentName.Buffer) == 0 {
		tpm.logger.Debug("tpm: LoadKeyPair - parent Name empty, reading from TPM",
			slog.String("parent_handle", fmt.Sprintf("0x%x", parentHandle)))
		resolvedName, _, readErr := tpm.ReadHandle(parentHandle)
		if readErr != nil {
			return nil, readErr
		}
		parentName = resolvedName
		keyAttrs.Parent.TPMAttributes.Name = resolvedName
	}

	tpm.logger.Debug("tpm: loading key pair",
		slog.String("parent_handle", fmt.Sprintf("0x%x", parentHandle)))

	tpm.logger.Debug("tpm: loading key pair",
		slog.String("parent_name", fmt.Sprintf("0x%s", Encode(parentName.Buffer))))

	// Load the public and private areas into the TPM
	loadResponse, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: parentHandle,
			Name:   parentName,
			Auth:   *session,
		},
		InPrivate: tpm2.TPM2BPrivate{
			Buffer: priv,
		},
		InPublic: tpm2.BytesAs2B[tpm2.TPMTPublic](pub),
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("failed to load key pair",
			slog.String("cn", keyAttrs.CN),
			slog.String("error", err.Error()))
		return nil, err
	}
	// defer tpm.Flush(loadResponse.ObjectHandle)

	tpm.logger.Debug("tpm: loaded key pair", slog.String("handle", fmt.Sprintf("0x%x", loadResponse.ObjectHandle)))

	return loadResponse, nil
}

// LoadKeyPairFromBlobs loads a key pair from provided public and private blobs
// instead of reading from backend storage. This enables loading keys from in-memory
// data (e.g., blobs loaded from EFI partition files during boot).
//
// This is similar to LoadKeyPair but uses provided blobs instead of reading from storage.
//
// When session is nil, the ParentHandle authorization session is built by
// TPM2.CreateSession -- see LoadKeyPair's doc comment for the rationale;
// this function had the identical always-real-HMAC-session defect.
func (tpm *TPM2) LoadKeyPairFromBlobs(
	keyAttrs *types.KeyAttributes,
	session *tpm2.Session,
	tpmPublic, tpmPrivate []byte) (*tpm2.LoadResponse, error) {

	if keyAttrs.Parent == nil {
		return nil, store.ErrInvalidParentAttributes
	}

	closer := func() error { return nil }
	if session == nil {
		sess, sessCloser, err := tpm.CreateSession(keyAttrs)
		if err != nil {
			return nil, err
		}
		session = &sess
		if sessCloser != nil {
			closer = sessCloser
		}
	}
	defer func() {
		if err := closer(); err != nil {
			tpm.logger.Error("tpm: LoadKeyPairFromBlobs - failed to close parent session",
				slog.String("error", err.Error()))
		}
	}()

	parentHandle := keyAttrs.Parent.TPMAttributes.Handle
	parentName := keyAttrs.Parent.TPMAttributes.Name

	// Ensure the parent Name is populated. After an app restart the cached
	// SRK attributes may only contain the persistent handle without the Name
	// (built from config, not from TPM2_ReadPublic). TPM2_Load requires a
	// valid Name for the ParentHandle parameter -- without it the go-tpm
	// marshaller returns "missing Name for 'ParentHandle' parameter".
	if len(parentName.Buffer) == 0 {
		tpm.logger.Debug("tpm: LoadKeyPairFromBlobs - parent Name empty, reading from TPM",
			slog.String("parent_handle", fmt.Sprintf("0x%x", parentHandle)))
		resolvedName, _, readErr := tpm.ReadHandle(parentHandle)
		if readErr != nil {
			return nil, readErr
		}
		parentName = resolvedName
		keyAttrs.Parent.TPMAttributes.Name = resolvedName
	}

	tpm.logger.Debug("tpm: loading key pair from blobs",
		slog.String("parent_handle", fmt.Sprintf("0x%x", parentHandle)))

	tpm.logger.Debug("tpm: loading key pair from blobs",
		slog.String("parent_name", fmt.Sprintf("0x%s", Encode(parentName.Buffer))))

	// Load the public and private areas into the TPM
	loadResponse, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: parentHandle,
			Name:   parentName,
			Auth:   *session,
		},
		InPrivate: tpm2.TPM2BPrivate{
			Buffer: tpmPrivate,
		},
		InPublic: tpm2.BytesAs2B[tpm2.TPMTPublic](tpmPublic),
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("failed to load key pair from blobs",
			slog.String("cn", keyAttrs.CN),
			slog.String("error", err.Error()))
		return nil, err
	}

	tpm.logger.Debug("tpm: loaded key pair from blobs", slog.String("handle", fmt.Sprintf("0x%x", loadResponse.ObjectHandle)))

	return loadResponse, nil
}

// Saves the requested TPMAlgKeyedHash encrypted public and private
// blobs to the blob store.
func (tpm *TPM2) SaveKeyPair(
	keyAttrs *types.KeyAttributes,
	outPrivate tpm2.TPM2BPrivate,
	outPublic tpm2.TPM2B[tpm2.TPMTPublic, *tpm2.TPMTPublic],
	backend store.KeyBackend,
	overwrite bool) error {

	tpm.logger.Debug("tpm: saving key pair", slog.String("cn", keyAttrs.CN))

	if backend == nil {
		backend = tpm.backend
	}
	err := backend.Save(keyAttrs, outPrivate.Buffer, store.FSEXT_PRIVATE_BLOB, overwrite)
	if err != nil {
		return err
	}
	err = backend.Save(keyAttrs, outPublic.Bytes(), store.FSEXT_PUBLIC_BLOB, overwrite)
	if err != nil {
		return err
	}
	return nil
}

// Deletes the requested encrypted public and private blobs from
// the blob store.
func (tpm *TPM2) DeleteKeyPair(
	keyAttrs *types.KeyAttributes,
	backend store.KeyBackend) error {

	tpm.logger.Debug("tpm: deleting key pair", slog.String("cn", keyAttrs.CN))
	if backend == nil {
		backend = tpm.backend
	}
	err := backend.Delete(keyAttrs)
	if err != nil {
		return err
	}
	return nil
}

// // Saves a key to an encrypted context file only readable by this TPM
// func (tpm *TPM2) saveContext(keyAttrs *types.KeyAttributes) error {
// 	response, err := tpm2.ContextSave{
// 		SaveHandle: keyAttrs.TPMAttributes.Handle,
// 	}.Execute(tpm.transport)
// 	if err != nil {
// 		tpm.logger.Error("failed to save context", slog.String("error", err.Error()))
// 		return err
// 	}
// 	err = tpm.backend.Save(
// 		keyAttrs, response.Context.ContextBlob.Buffer, store.FSEXT_TPM_CONTEXT)
// 	if err != nil {
// 		tpm.logger.Error("failed to save context to backend", slog.String("error", err.Error()))
// 		return err
// 	}
// 	return nil
// }

// // Loads an encrypted context file only readable by this TPM
// func (tpm *TPM2) loadContext(keyAttrs *types.KeyAttributes) ([]byte, error) {
// 	ctx, err := tpm.backend.Get(keyAttrs, store.FSEXT_TPM_CONTEXT)
// 	if err != nil {
// 		tpm.logger.Error("failed to load context", slog.String("error", err.Error()))
// 		return nil, err
// 	}
// 	return ctx, nil
// }
