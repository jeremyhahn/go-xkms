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

package tpm2

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/google/go-tpm/tpm2"
)

var (
	// ErrAuthFailed is returned when TPM auth verification fails because
	// the provided auth value does not match the key's UserAuth.
	ErrAuthFailed = errors.New("tpm2: auth verification failed")

	// ErrAuthChangeKeyNotFound is returned when the persistent handle
	// does not exist during an auth verification or change operation.
	ErrAuthChangeKeyNotFound = errors.New("tpm2: key not found at handle for auth change")

	// ErrAuthChangeRecreate is returned when the primary key cannot be
	// recreated with the new auth value during a ChangeAuth operation.
	ErrAuthChangeRecreate = errors.New("tpm2: failed to recreate primary key with new auth")

	// ErrAuthProbeRejected is returned when the TPM rejects the auth-probe
	// Create command for a reason other than an authorization failure (for
	// example TPM_RC_ATTRIBUTES from a malformed child template). This is a
	// programming/spec error in the probe itself, never a wrong-PIN signal,
	// and must NOT be collapsed into ErrAuthFailed by callers.
	ErrAuthProbeRejected = errors.New("tpm2: auth probe rejected by TPM (not an auth failure)")

	// ErrAuthSessionFlushFailed is returned (joined into a logged error, never
	// swallowed) when the auth-probe HMAC session could not be flushed from
	// the TPM after exhausting all retry attempts. This indicates a leaked
	// TPM2_StartAuthSession handle: it permanently occupies one of the TPM's
	// limited session-context slots (TCG TPM 2.0 Part 1, Section 19) until
	// the resource manager's client connection is closed. Repeated
	// occurrences are the precursor to TPM_RC_SESSION_MEMORY, which then
	// fails every subsequent auth-verifying operation regardless of whether
	// the presented auth value is correct.
	ErrAuthSessionFlushFailed = errors.New("tpm2: failed to flush auth-probe session")
)

const (
	// flushRetryAttempts bounds the number of TPM2_FlushContext attempts made
	// to reclaim a single auth-probe session before giving up. This absorbs
	// transient resource-manager contention on the shared TPM device (for
	// example a concurrent command returning EBUSY on /dev/tpmrm0) without
	// retrying indefinitely against a genuinely unresponsive TPM.
	flushRetryAttempts = 3

	// flushRetryDelay is the pause between successive flush retries.
	flushRetryDelay = 20 * time.Millisecond
)

// authProbeTemplate builds the child object template used by VerifyAuth to
// exercise the parent key's authorization. The TPM evaluates parent auth on
// TPM2_Create before it creates the child, so any valid child template forces
// the auth check. The template MUST be spec-consistent: a keyed-hash object
// with Scheme=Null and FixedTPM|FixedParent|UserWithAuth (the previous value)
// is rejected with TPM_RC_ATTRIBUTES before auth is ever evaluated, which
// masks both correct and incorrect PINs. A keyed-hash HMAC(SHA256) object with
// SensitiveDataOrigin set (TPM generates the key material, so no caller
// sensitive data is required) is valid and lets the TPM reach the auth check.
func authProbeTemplate() tpm2.TPM2BPublic {
	return tpm2.New2B(tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgKeyedHash,
			&tpm2.TPMSKeyedHashParms{
				Scheme: tpm2.TPMTKeyedHashScheme{
					Scheme: tpm2.TPMAlgHMAC,
					Details: tpm2.NewTPMUSchemeKeyedHash(
						tpm2.TPMAlgHMAC,
						&tpm2.TPMSSchemeHMAC{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
			},
		),
	})
}

// VerifyAuth verifies the auth value on a persistent key at the given handle.
// The TPM validates the auth by executing a Create command with the key as
// parent. If the auth value is incorrect, the TPM returns an auth failure.
//
// A correct auth value returns nil. An incorrect auth value returns
// ErrAuthFailed (the TPM reported TPM_RC_BAD_AUTH / TPM_RC_AUTH_FAIL). Any
// other TPM rejection is wrapped in ErrAuthProbeRejected so callers can tell a
// genuine wrong-PIN apart from a probe/transport fault.
//
// Session lifecycle: the auth-probe session is a real, caller-owned, salted
// HMAC session (started via TPM2_StartAuthSession up front, see
// TPM2.HMACSession) rather than a go-tpm one-shot, just-in-time session. The
// salt keeps the probed auth value from being recovered from the bus. This is a
// deliberate choice, not a style preference: go-tpm's one-shot session is
// only flushed on the TPM's own initiative on success (when the command's
// session attributes carry ContinueSession=false, TCG TPM 2.0 Part 1 Section
// 19.7.1) or by go-tpm's CleanupFailure on the specific path where the TPM
// itself returns a response header error (tpm2/reflect.go, execute()). Every
// other failure between session start and that point -- a marshalling error,
// or a transport fault such as "write /dev/tpmrm0: device or resource busy"
// -- returns before CleanupFailure ever runs, permanently leaking the
// already-started session handle. Repeated leaks exhaust the TPM's session
// slots (TPM_RC_SESSION_MEMORY), after which every future VerifyAuth call
// fails regardless of whether the presented PIN is correct -- a permanent,
// process-lifetime PIN-verification outage. Owning the session explicitly
// here means its flush is unconditional and lives entirely in our own defer,
// independent of which path the probe command takes to return.
func (tpm *TPM2) VerifyAuth(handle tpm2.TPMHandle, authValue []byte) error {
	if tpm.transport == nil {
		return ErrTransportNotInitialized
	}

	// Read the public area to confirm the handle exists.
	name, _, err := tpm.ReadHandle(handle)
	if err != nil {
		return errors.Join(ErrAuthChangeKeyNotFound, err)
	}

	// Start a real HMAC session carrying the provided auth value. Unlike a
	// go-tpm one-shot session, this issues TPM2_StartAuthSession
	// immediately, so the session handle is known to us -- and therefore
	// flushable by us -- before the probe command ever executes.
	session, closeSession, err := tpm.HMACSession(authValue)
	if err != nil {
		return errors.Join(ErrAuthProbeRejected, &errs.Wrapped{Msg: "start auth-probe session", Err: err})
	}
	defer func() {
		if flushErr := flushSessionWithRetry(closeSession); flushErr != nil {
			tpm.logger.Error("tpm: VerifyAuth - failed to flush auth-probe session",
				slog.String("handle", fmt.Sprintf("0x%x", handle)),
				slog.String("error", flushErr.Error()))
		}
	}()

	// Create a minimal keyed-hash child under this handle. The TPM requires
	// correct parent auth for the Create command. If the auth is wrong, the
	// TPM returns TPM_RC_BAD_AUTH or TPM_RC_AUTH_FAIL. Whatever this command
	// does -- succeed, fail on auth, or fail for any other reason including a
	// transport-level fault -- the deferred flush above always runs and owns
	// reclaiming the session; it does not depend on this call's outcome.
	_, err = tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: handle,
			Name:   name,
			Auth:   session,
		},
		InPublic: authProbeTemplate(),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{},
		},
	}.Execute(tpm.transport)
	if err != nil {
		if isTPMAuthError(err) {
			return ErrAuthFailed
		}
		// Not an auth failure: a malformed probe, transport fault, or other
		// TPM rejection. Surface it distinctly so it is never mistaken for a
		// wrong PIN.
		return errors.Join(ErrAuthProbeRejected, err)
	}

	// Auth verified successfully. The ephemeral child is not persisted
	// and will be garbage collected by the TPM.
	return nil
}

// flushSessionWithRetry invokes close (a TPM2_FlushContext issued against the
// auth-probe session) up to flushRetryAttempts times, pausing flushRetryDelay
// between attempts. The retry absorbs the same transient resource-manager
// contention that can cause the probe command itself to fail (for example
// "device or resource busy" on a shared /dev/tpmrm0), so a session is never
// abandoned solely because a single flush attempt lost a race for the
// device. All attempts failing returns ErrAuthSessionFlushFailed joined with
// the last underlying error; callers must log this rather than discard it,
// since it identifies a leaked TPM session slot.
func flushSessionWithRetry(close func() error) error {
	var lastErr error
	for attempt := 0; attempt < flushRetryAttempts; attempt++ {
		err := close()
		if err == nil {
			return nil
		}
		lastErr = err
		if attempt < flushRetryAttempts-1 {
			time.Sleep(flushRetryDelay)
		}
	}
	return errors.Join(ErrAuthSessionFlushFailed, lastErr)
}

// ChangeAuth changes the auth value on a persistent primary key. For primary
// keys, this recreates the key with the same template (deterministic key
// material) and new auth, then evicts the old key and re-persists at the
// same handle.
func (tpm *TPM2) ChangeAuth(handle tpm2.TPMHandle, currentAuth, newAuth []byte) error {
	if tpm.transport == nil {
		return ErrTransportNotInitialized
	}

	// Verify the current auth before proceeding.
	if err := tpm.VerifyAuth(handle, currentAuth); err != nil {
		return err
	}

	// Read the public area to get the key template for recreation.
	name, pub, err := tpm.ReadHandle(handle)
	if err != nil {
		return errors.Join(ErrAuthChangeKeyNotFound, err)
	}

	// Determine the hierarchy from the persistent handle range.
	// Handles in 0x81000000-0x817FFFFF are owner hierarchy.
	// Handles in 0x81800000-0x81FFFFFF are platform hierarchy.
	hierarchy := tpm2.TPMRHOwner
	if uint32(handle) >= 0x81800000 {
		hierarchy = tpm2.TPMRHPlatform
	}

	// Evict the current persistent key.
	err = tpm.evictControl(hierarchy, nil, tpm2.NamedHandle{
		Handle: handle,
		Name:   name,
	}, handle)
	if err != nil {
		return errors.Join(ErrAuthChangeRecreate, &errs.Wrapped{Msg: fmt.Sprintf("evict old handle 0x%x", handle), Err: err})
	}

	// Recreate the primary with the same template but new auth.
	// Using the same template ensures deterministic key material
	// (same hierarchy seed + same template = same key). The new auth value
	// is encrypted on its way into the TPM (see createPrimary).
	primaryKey, err := tpm.createPrimary(hierarchy, nil, tpm2.CreatePrimary{
		InPublic: tpm2.New2B(pub),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: newAuth,
				},
			},
		},
	})
	if err != nil {
		return errors.Join(ErrAuthChangeRecreate, &errs.Wrapped{Msg: "recreate primary", Err: err})
	}
	defer tpm.Flush(primaryKey.ObjectHandle)

	// Persist the recreated key at the same handle.
	err = tpm.evictControl(hierarchy, nil, tpm2.NamedHandle{
		Handle: primaryKey.ObjectHandle,
		Name:   primaryKey.Name,
	}, handle)
	if err != nil {
		return errors.Join(ErrAuthChangeRecreate, &errs.Wrapped{Msg: fmt.Sprintf("persist new key at 0x%x", handle), Err: err})
	}

	tpm.logger.Info("auth changed for persistent handle",
		slog.String("handle", fmt.Sprintf("0x%x", handle)))

	return nil
}

// isTPMResponseCode reports whether err carries the TPM response code code,
// either as a typed value or, failing that, by name in err's message.
//
// A format-1 response carries handle, session, or parameter index bits
// alongside the base response value (TCG TPM 2.0 Library Part 2, section
// 6.6.3), so the code a real TPM returns for, say, a session-1 auth failure
// is not the bare TPMRCBadAuth constant but that constant with the session
// bits added on top. tpm2.TPMRC implements error's optional Is(error) bool
// method by stripping exactly those bits before comparing (see
// TPMRC.isFmt1Error in the go-tpm package this project already depends on),
// so errors.Is(err, code) -- which calls that method once it unwraps err
// down to the TPMRC go-tpm attached -- is the canonical classification. A
// hand-rolled mask over the raw code has to reimplement that stripping
// itself and get every one of session, parameter, and handle formats right;
// getting it wrong silently degrades the typed path to unreachable and the
// predicate then only works by accident, through the string fallback below.
//
// fallback names substrings recognised in err's message when the wrapping
// chain exposes no typed TPMRC, for robustness across go-tpm versions.
func isTPMResponseCode(err error, code tpm2.TPMRC, fallback ...string) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, code) {
		return true
	}
	s := err.Error()
	for _, sub := range fallback {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// isTPMAuthError checks whether a TPM error indicates an authentication
// failure. The TPM returns specific response codes for auth failures:
//   - TPM_RC_BAD_AUTH (0x022) - authorization value is incorrect
//   - TPM_RC_AUTH_FAIL (0x09A) - authorization failed (DA counter incremented)
//   - TPM_RC_LOCKOUT (0x921) - DA lockout is active
//
// Each is classified through isTPMResponseCode, so the typed comparison
// normalizes format-1 session/parameter bits instead of assuming they are
// zero. This is the broad predicate -- "the caller supplied the wrong
// secret" -- used for PIN retry; isTPMBadAuth (tpm.go) shares this same
// primitive but recognizes only the narrower non-DA TPM_RC_BAD_AUTH form.
func isTPMAuthError(err error) bool {
	return isTPMResponseCode(err, tpm2.TPMRCBadAuth,
		"bad_auth", "BAD_AUTH", "TPM_RC_BAD_AUTH") ||
		isTPMResponseCode(err, tpm2.TPMRCAuthFail,
			"auth_fail", "AUTH_FAIL", "TPM_RC_AUTH_FAIL") ||
		isTPMResponseCode(err, tpm2.TPMRCLockout)
}
