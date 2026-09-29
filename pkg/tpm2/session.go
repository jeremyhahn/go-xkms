package tpm2

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
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

	// ErrSaltKey is returned when no key could be resolved or created to salt
	// an authorization session against.
	ErrSaltKey = errors.New("tpm2: failed to resolve the session salt key")

	// ErrSaltedSession is returned when a salted HMAC session could not be
	// started.
	ErrSaltedSession = errors.New("tpm2: failed to start salted session")
)

// sessionNonceSize is the nonceCaller size of every session this package
// starts.
const sessionNonceSize = 16

// sessionAESKeyBits is the AES key size used for session parameter
// encryption (AES-128-CFB, the size every TPM 2.0 implements).
const sessionAESKeyBits = 128

// paramEncryption names the parameter a session encrypts on the TPM bus.
// The TPM can only encrypt a command's or response's first parameter, and
// only when that parameter is a TPM2B; setting the decrypt or encrypt
// attribute on a session for a command that has no such parameter is refused
// with TPM_RC_ATTRIBUTES (TCG TPM 2.0 Part 1, section 21). Each secret-bearing
// command therefore names the one direction its secret travels in.
type paramEncryption uint8

const (
	// encryptNone carries no parameter encryption: the command's parameters
	// hold no secret.
	encryptNone paramEncryption = iota

	// encryptIn encrypts the command's first parameter on its way into the
	// TPM (the session's decrypt attribute): TPM2B_SENSITIVE_CREATE,
	// TPM2B_AUTH, TPM2B_MAX_NV_BUFFER and the like.
	encryptIn

	// encryptOut encrypts the response's first parameter on its way out of
	// the TPM (the session's encrypt attribute): unsealed data, NV contents,
	// decrypted plaintext, shared secrets and activated credentials.
	encryptOut
)

// paramEncryptionOptions maps each encrypting direction to the go-tpm
// session option that sets the matching session attribute.
var paramEncryptionOptions = map[paramEncryption]tpm2.AuthOption{
	encryptIn:  tpm2.AESEncryption(sessionAESKeyBits, tpm2.EncryptIn),
	encryptOut: tpm2.AESEncryption(sessionAESKeyBits, tpm2.EncryptOut),
}

// noopCloser is the closer handed back with a session that needs no flush.
func noopCloser() error { return nil }

// saltKeyFunc resolves the loaded key a session is salted against, together
// with a release function the caller runs once the session has started.
type saltKeyFunc func() (tpm2.TPMHandle, tpm2.TPMTPublic, func() error, error)

// saltKey returns the loaded key a session is salted against, together with
// a release function the caller runs once the session has started.
//
// The salt is what keeps a bus observer out: the session key is derived from
// a random salt encrypted to this key (TCG TPM 2.0 Part 1, section 19.6.13),
// so the captured traffic of a salted session neither reveals the parameters
// it encrypts nor lets the auth value behind its HMAC be brute forced offline.
//
// The persistent Endorsement Key is used whenever it is resident. It is only
// read here -- TPM2_ReadPublic -- and never modified. Before it exists (between
// TPM2_Clear and CreateEK during provisioning, or on a TPM whose EK was never
// persisted) the ephemeral NULL-hierarchy key of nullSaltKey is used instead.
func (tpm *TPM2) saltKey() (tpm2.TPMHandle, tpm2.TPMTPublic, func() error, error) {
	if tpm.config.EK != nil && tpm.config.EK.Handle != 0 {
		ekHandle := tpm2.TPMHandle(tpm.config.EK.Handle)
		_, ekPub, err := tpm.ReadHandle(ekHandle)
		if err == nil {
			return ekHandle, ekPub, noopCloser, nil
		}
		if !isAbsentHandle(err) {
			return 0, tpm2.TPMTPublic{}, noopCloser, &errs.Joined{Lead: ErrSaltKey, Detail: "read EK public", Cause: err}
		}
	}
	return nullSaltKey(tpm.transport)()
}

// nullSaltKey returns a saltKeyFunc that creates an ephemeral ECC P-256
// storage key in the NULL hierarchy of the TPM behind t, from go-tpm's TCG
// SRK template, and whose release function flushes it. The NULL hierarchy
// needs no authorization, so creating the key discloses nothing, and it
// touches no persistent object: neither the EK nor any SRK. The salt key is
// only needed by TPM2_StartAuthSession, so releasing it immediately
// afterwards does not affect the session.
func nullSaltKey(t transport.TPM) saltKeyFunc {
	return func() (tpm2.TPMHandle, tpm2.TPMTPublic, func() error, error) {
		primary, err := tpm2.CreatePrimary{
			PrimaryHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHNull,
				Auth:   tpm2.PasswordAuth(nil),
			},
			InPublic: tpm2.New2B(tpm2.ECCSRKTemplate),
		}.Execute(t)
		if err != nil {
			return 0, tpm2.TPMTPublic{}, noopCloser, &errs.Joined{Lead: ErrSaltKey, Detail: "create NULL hierarchy salt key", Cause: err}
		}
		release := func() error {
			_, err := tpm2.FlushContext{FlushHandle: primary.ObjectHandle}.Execute(t)
			return err
		}
		pub, err := primary.OutPublic.Contents()
		if err != nil {
			return 0, tpm2.TPMTPublic{}, noopCloser, &errs.Joined{
				Lead:   ErrSaltKey,
				Detail: "NULL hierarchy salt key public",
				Cause:  errors.Join(err, release()),
			}
		}
		return primary.ObjectHandle, *pub, release, nil
	}
}

// isAbsentHandle reports whether err is the TPM's answer to reading an
// unpopulated persistent handle: TPM_RC_HANDLE, or TPM_RC_VALUE on TPMs that
// report a handle outside the populated range that way.
func isAbsentHandle(err error) bool {
	return errors.Is(err, tpmRCHandle) || errors.Is(err, tpm2.TPMRC(0x184))
}

// startHMACSession starts a reusable HMAC session on t, salted against the
// loaded key at saltHandle and encrypting the parameter dir names. opts carry
// the auth value and binding. The session's closer flushes it.
func startHMACSession(
	t transport.TPM,
	saltHandle tpm2.TPMHandle,
	saltPub tpm2.TPMTPublic,
	dir paramEncryption,
	opts ...tpm2.AuthOption) (tpm2.Session, func() error, error) {

	sessionOpts := append([]tpm2.AuthOption{tpm2.Salted(saltHandle, saltPub)}, opts...)
	if encryption, ok := paramEncryptionOptions[dir]; ok {
		sessionOpts = append(sessionOpts, encryption)
	}
	session, closer, err := tpm2.HMACSession(
		t, tpm2.TPMAlgSHA256, sessionNonceSize, sessionOpts...)
	if err != nil {
		return nil, noopCloser, &errs.Joined{Lead: ErrSaltedSession, Cause: err}
	}
	return session, closer, nil
}

// startSaltedSession starts a reusable HMAC session on t, salted against the
// key saltKey resolves and encrypting the parameter dir names. opts carry the
// auth value and binding. The session's closer flushes it.
//
// The salt key is released as soon as the session has started. The session
// no longer needs it, so a release failure does not fail the command the
// session serves: it is reported by the session's closer, the teardown
// channel every caller already handles, alongside any failure to flush the
// session itself.
func startSaltedSession(
	t transport.TPM,
	saltKey saltKeyFunc,
	dir paramEncryption,
	opts ...tpm2.AuthOption) (tpm2.Session, func() error, error) {

	saltHandle, saltPub, release, err := saltKey()
	if err != nil {
		return nil, noopCloser, err
	}
	session, closer, err := startHMACSession(t, saltHandle, saltPub, dir, opts...)
	releaseErr := release()
	if releaseErr != nil {
		releaseErr = &errs.Joined{Lead: ErrSaltKey, Detail: "release salt key", Cause: releaseErr}
	}
	if err != nil {
		return nil, noopCloser, errors.Join(err, releaseErr)
	}
	if releaseErr == nil {
		return session, closer, nil
	}
	return session, func() error { return errors.Join(releaseErr, closer()) }, nil
}

// startHierarchySession returns the authorization for hierarchy on t, whose
// authorization value is auth, encrypting the parameter dir names and salted
// against the key saltKey resolves.
//
// A non-empty hierarchy auth -- the SO PIN -- is proven through a salted HMAC
// session bound to the hierarchy. The binding matters for the commands that
// change the hierarchy's own authorization (TPM2_HierarchyChangeAuth,
// TPM2_Clear): the TPM computes their response HMAC with the new value, and a
// bound session authorizing its bind entity leaves the authValue out of the
// HMAC key altogether (TCG TPM 2.0 Part 1, section 19.6.5), so the response
// verifies under the session key alone. An empty auth with nothing to encrypt
// has no secret to protect and is answered with a zero-round-trip empty
// password session.
func startHierarchySession(
	t transport.TPM,
	saltKey saltKeyFunc,
	hierarchy tpm2.TPMHandle,
	auth []byte,
	dir paramEncryption) (tpm2.Session, func() error, error) {

	if len(auth) == 0 && dir == encryptNone {
		return tpm2.PasswordAuth(nil), noopCloser, nil
	}
	return startSaltedSession(t, saltKey, dir,
		tpm2.Auth(auth),
		tpm2.Bound(hierarchy, tpm2.HandleName(hierarchy), auth))
}

// saltedSession starts a reusable HMAC session salted against the key saltKey
// resolves, encrypting the parameter dir names. opts carry the auth value and binding.
// The session's closer flushes it.
func (tpm *TPM2) saltedSession(
	dir paramEncryption,
	opts ...tpm2.AuthOption) (tpm2.Session, func() error, error) {

	return startSaltedSession(tpm.transport, tpm.saltKey, dir, opts...)
}

// encryptionSession starts a salted session that authorizes nothing and
// exists only to encrypt one parameter of the command it is attached to, as
// an extra session after the command's authorization sessions. It carries
// the secret of a command whose authorization is a policy or password
// session and so cannot encrypt it -- a policy session answering the PCR
// branch does not know the authValue the TPM mixes into an authorization
// session's encryption key (TCG TPM 2.0 Part 1, section 21.1).
func (tpm *TPM2) encryptionSession(dir paramEncryption) (tpm2.Session, func() error, error) {
	return tpm.saltedSession(dir)
}

// objectAuthSession returns the authorization for an object or NV index whose
// authValue is auth, encrypting the parameter dir names.
//
// An auth value never crosses the bus: a non-empty auth is proven through a
// salted HMAC session, whose HMAC key the salt keeps out of reach of an
// offline brute force. An empty auth with nothing to encrypt has no secret to
// protect and is answered with a zero-round-trip empty password session.
func (tpm *TPM2) objectAuthSession(auth []byte, dir paramEncryption) (tpm2.Session, func() error, error) {
	if len(auth) == 0 && dir == encryptNone {
		return tpm2.PasswordAuth(nil), noopCloser, nil
	}
	return tpm.saltedSession(dir, tpm2.Auth(auth))
}

// hierarchyAuthSession returns the authorization for a hierarchy whose
// authorization value is auth, encrypting the parameter dir names (see
// startHierarchySession). A salted session is salted against the key saltKey
// resolves.
func (tpm *TPM2) hierarchyAuthSession(
	hierarchy tpm2.TPMHandle,
	auth []byte,
	dir paramEncryption) (tpm2.Session, func() error, error) {

	return startHierarchySession(tpm.transport, tpm.saltKey, hierarchy, auth, dir)
}

// HierarchyAuthSession returns the authorization for hierarchy on the raw
// transport t, proving its authorization value auth -- the SO PIN for the
// owner hierarchy -- without auth ever crossing the TPM bus: a non-empty auth
// is proven through an HMAC session bound to the hierarchy and salted against
// an ephemeral NULL-hierarchy key (see startHierarchySession). The session
// encrypts no parameter. An empty auth is answered with the empty password
// session, which has nothing to protect.
//
// It serves code that drives go-tpm on a transport of its own rather than
// through a TPM2; a TPM2 salts its sessions against the Endorsement Key
// instead. The caller must invoke the returned closer to flush the session.
func HierarchyAuthSession(
	t transport.TPM,
	hierarchy tpm2.TPMHandle,
	auth []byte) (tpm2.Session, func() error, error) {

	return startHierarchySession(t, nullSaltKey(t), hierarchy, auth, encryptNone)
}

// CommandEncryptionSession starts a session on the raw transport t that
// authorizes nothing and encrypts the first parameter of the command it is
// attached to, as an extra session after the command's authorization: the
// sensitive area of a TPM2_Create, for example. It is salted against an
// ephemeral NULL-hierarchy key (see nullSaltKey), so the parameter cannot be
// recovered from the bus. The caller must invoke the returned closer to
// flush the session.
func CommandEncryptionSession(t transport.TPM) (tpm2.Session, func() error, error) {
	return startSaltedSession(t, nullSaltKey(t), encryptIn)
}

// ResponseEncryptionSession starts a session on the raw transport t that
// authorizes nothing and encrypts the first parameter of the response to the
// command it is attached to, as an extra session after the command's
// authorization: the data a TPM2_Unseal returns, for example. It is salted
// against an ephemeral NULL-hierarchy key (see nullSaltKey), so the parameter
// cannot be recovered from the bus. The caller must invoke the returned
// closer to flush the session.
func ResponseEncryptionSession(t transport.TPM) (tpm2.Session, func() error, error) {
	return startSaltedSession(t, nullSaltKey(t), encryptOut)
}

// withHierarchyAuth runs execute with an authorization handle for hierarchy
// whose session proves auth and encrypts the parameter dir names (see
// hierarchyAuthSession). The session is flushed once execute returns.
func (tpm *TPM2) withHierarchyAuth(
	hierarchy tpm2.TPMHandle,
	auth []byte,
	dir paramEncryption,
	execute func(tpm2.AuthHandle) error) error {

	session, closer, err := tpm.hierarchyAuthSession(hierarchy, auth, dir)
	if err != nil {
		return err
	}
	defer tpm.closeSession(closer, "hierarchy authorization")
	return execute(tpm2.AuthHandle{
		Handle: hierarchy,
		Auth:   session,
	})
}

// policySecret executes TPM2_PolicySecret in policySession, proving knowledge
// of the hierarchy's authorization value through hierarchyAuthSession.
func (tpm *TPM2) policySecret(
	hierarchy tpm2.TPMHandle,
	auth []byte,
	policySession tpm2.Session) error {

	return tpm.withHierarchyAuth(hierarchy, auth, encryptNone, func(authHandle tpm2.AuthHandle) error {
		_, err := tpm2.PolicySecret{
			AuthHandle:    authHandle,
			NonceTPM:      policySession.NonceTPM(),
			PolicySession: policySession.Handle(),
		}.Execute(tpm.transport)
		return err
	})
}

// closeSession runs a session closer, logging rather than returning its
// failure: it is called on paths that already carry the command's result.
func (tpm *TPM2) closeSession(closer func() error, what string) {
	if err := closer(); err != nil {
		tpm.logger.Error("tpm: failed to close session",
			slog.String("session", what),
			slog.String("error", err.Error()))
	}
}

// HMACSession starts a reusable HMAC session carrying auth, salted against
// the Endorsement Key (see saltKey), so neither the auth value nor anything
// derived from it can be recovered from the TPM bus. The caller must invoke
// the returned closer to flush the session.
func (tpm *TPM2) HMACSession(auth []byte) (s tpm2.Session, close func() error, err error) {
	return tpm.saltedSession(encryptNone, tpm2.Auth(auth))
}

// HMACSaltedSession starts a reusable HMAC session carrying auth, salted
// against the loaded key at handle whose public area is pub. The key must be
// a loaded RSA or ECC decryption key. The caller must invoke the returned
// closer to flush the session.
func (tpm *TPM2) HMACSaltedSession(
	handle tpm2.TPMHandle,
	pub tpm2.TPMTPublic,
	auth []byte) (s tpm2.Session, close func() error, err error) {

	tpm.logger.Debug("tpm: creating salted HMAC session",
		slog.String("salt_handle", fmt.Sprintf("0x%x", handle)))
	return startHMACSession(tpm.transport, handle, pub, encryptNone, tpm2.Auth(auth))
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
	//
	// The password branch (PolicyAuthValue) makes the session HMAC key
	// sessionKey || authValue (TPM 2.0 Part 1, Section 19.6), so the auth
	// value is handed to the session -- and the session is salted. Unsalted,
	// the session key is empty and the HMAC key is the auth value alone: a
	// single captured command lets an observer brute force the PIN offline.
	// The PCR branch proves no secret and needs no salt.
	var sessionOpts []tpm2.AuthOption
	releaseSaltKey := noopCloser
	if !usePCRBranch && len(auth) > 0 {
		saltHandle, saltPub, release, saltErr := tpm.saltKey()
		if saltErr != nil {
			return nil, nil, &errs.Joined{Lead: ErrPlatformPolicySession, Cause: saltErr}
		}
		releaseSaltKey = release
		sessionOpts = append(sessionOpts,
			tpm2.Auth(auth),
			tpm2.Salted(saltHandle, saltPub))
	}
	session, closer, err := tpm2.PolicySession(
		tpm.transport, hashAlgID, sessionNonceSize, sessionOpts...)
	tpm.closeSession(releaseSaltKey, "salt key")
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

// NonceSession returns a policy session that has executed TPM2_PolicySecret
// against the Endorsement hierarchy, proving hierarchyAuth through a salted
// HMAC session (see hierarchyAuthSession). The caller must invoke the returned
// closer to flush the policy session.
func (tpm *TPM2) NonceSession(hierarchyAuth types.Password) (tpm2.Session, func() error, error) {

	var auth []byte
	if hierarchyAuth != nil {
		auth = hierarchyAuth.Bytes()
	}

	session, closer, err := tpm2.PolicySession(
		tpm.transport, tpm2.TPMAlgSHA256, sessionNonceSize)
	if err != nil {
		tpm.logger.Error("failed to create nonce policy session", slog.String("error", err.Error()))
		return nil, nil, err
	}

	if err := tpm.policySecret(tpm2.TPMRHEndorsement, auth, session); err != nil {
		tpm.logger.Error("failed to execute PolicySecret", slog.String("error", err.Error()))
		tpm.closeSession(closer, "nonce policy")
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
//   - Password != nil AND PlatformPolicy = false: salted HMAC session
//     proving the password (default password-only, no auto-unseal)
//   - Neither: empty password auth
//
// Every session that proves a non-empty auth value is salted (see saltKey),
// so the value never crosses the TPM bus and cannot be brute forced from a
// capture. The session only authorizes: a command whose parameters carry a
// secret attaches an encryptionSession for it. This function returns a
// session closer function that needs to be called to close the session when
// complete.
func (tpm *TPM2) CreateSession(
	keyAttrs *types.KeyAttributes) (tpm2.Session, func() error, error) {

	var session tpm2.Session
	var err error
	var parentAuth []byte

	closer := func() error { return nil }

	if keyAttrs.Parent == nil {
		return tpm.CreateKeySession(keyAttrs)
	}

	if keyAttrs.Parent.TPMPolicy == types.TPMPolicyPlatform {

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

	// No PlatformPolicy: the parent's auth value, proven through a salted
	// HMAC session when it has one.
	if keyAttrs.Parent.Password != nil {
		parentAuth = keyAttrs.Parent.Password.Bytes()
	}
	return tpm.objectAuthSession(parentAuth, encryptNone)
}

// devidKeySession answers the USER-role authorization for an IDevID or IAK.
// A non-empty authValue is the password path Template H-0 keeps open
// (userWithAuth SET, section 7.2.4) and is used whenever it exists. With no
// authValue and PlatformPolicy set, the key is used through the platform
// Delegation Policy the Owner wrote into its Policy NV Index at
// provisioning, so the session fails once the platform state moves. With
// neither, the empty authValue is presented as no auth value at all, for the
// reason CreateSession documents.
func (tpm *TPM2) devidKeySession(
	kind DevIDKeyKind,
	keyAttrs *types.KeyAttributes) (tpm2.Session, func() error, error) {

	var keyAuth []byte
	if keyAttrs.Password != nil {
		if _, err := keyAttrs.Password.String(); err != nil {
			return nil, noopCloser, err
		}
		keyAuth = keyAttrs.Password.Bytes()
	}
	if len(keyAuth) == 0 && keyAttrs.TPMPolicy == types.TPMPolicyPlatform {
		return tpm.devidPlatformDelegatedSession(kind, keyAttrs)
	}
	return tpm.objectAuthSession(keyAuth, encryptNone)
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
//   - Password != nil AND PlatformPolicy = false: salted HMAC session
//     proving the password (default password-only, no auto-unseal)
//   - Neither: empty password auth
//
// As with CreateSession, the session only authorizes and every non-empty
// auth value is proven through a salted session.
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
	// callable closer (noopCloser).

	// An IDevID or IAK carries the TCG IDevID/IAK Key Policy as its
	// authPolicy, not the platform policy, so a platform-policy session
	// could never satisfy it. Its USER role is authorized by the authValue
	// (TCG "TPM 2.0 Keys for Device Identity and Attestation" v1.00 r12,
	// section 7.2.4), or -- when the configuration asks for platform binding
	// and no authValue is set -- by the platform Delegation Policy through
	// the key's Policy NV Index (section 7.3).
	if kind, isDevID := devidKeyKindOf(keyAttrs.KeyType); isDevID {
		session, closer, err = tpm.devidKeySession(kind, keyAttrs)
		if err != nil {
			if closer == nil {
				closer = noopCloser
			}
			return session, closer, err
		}
	} else if keyAttrs.TPMPolicy == types.TPMPolicyPlatform {

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

		var keyAuth []byte
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
			keyAuth = keyAttrs.Password.Bytes()
		}
		session, closer, err = tpm.objectAuthSession(keyAuth, encryptNone)
		if err != nil {
			return nil, noopCloser, err
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
// the parent uses PlatformPolicy, a salted HMAC session when the parent has
// an auth value, or a zero-round-trip empty PasswordAuth otherwise. Load and
// creation therefore issue the same session commands, so a TPM that can
// create a key under a parent can also load it.
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
