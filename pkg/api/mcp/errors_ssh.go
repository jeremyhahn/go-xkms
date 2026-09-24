// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package mcp

import (
	"errors"

	pkgauthorized "github.com/jeremyhahn/go-xkms/pkg/ssh/authorized"
	pkgkeys "github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	pkgknownhosts "github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// mapSSHError converts an error returned by the SSH sub-system (handlers_ssh.go,
// via s.sshClient or a handler's own params/parsing checks) into a *KeyOpError
// carrying the JSON-RPC error code InvokeMethod/mcpToolHandler should report --
// the same role mapKeyOpError (errors_keyops.go) plays for the xkms.* key/crypto
// methods. Before this function existed, ssh.* handlers returned these errors
// unwrapped, so mcpToolHandler's `errors.As(err, &keyErr)` never matched and
// EVERY ssh.* failure -- not-found, duplicate, mismatch, bad input, whatever --
// reached the caller as the same generic "xkms: internal error" (wire.CodeInternal),
// with the actual detail discarded.
//
// # The classification, and its one real limitation
//
// The mapping keeps to the eight JSON-RPC codes pkg/api/mcp/types.go already
// declares (see keyOpSentinelCodes' own doc comment on why that set is fixed
// at eight rather than one member per gRPC-style condition): unresolvable
// participants (not-found), non-idempotent conflicts (duplicate), and
// integrity failures (host-key mismatch) all become ErrCodeInvalidParams,
// exactly where wireCodeToRPCCode (pkg/api/transport/mcp/status.go) already
// buckets wire.CodeNotFound for every OTHER method family, since xkms's
// JSON-RPC vocabulary has no dedicated NotFound or AlreadyExists member.
//
// This means a caller cannot tell *pkg/ssh/known_hosts.NotFoundError,
// *pkg/ssh/known_hosts.DuplicateError and *pkg/ssh/known_hosts.MismatchError
// apart from RPCError.Code alone -- go-xkms#792 traced this all the way to
// the wire and confirmed it, rather than assuming it. The three remain
// distinguishable by MESSAGE (each Error() names its own condition, see the
// struct doc comments below), and the message always survives the round trip
// unmodified; what is lost is only the CODE-level classification, and losing
// it here is a documented, existing limitation of the shared vocabulary
// (see wireCodeToRPCCode's doc comment), not something this function
// introduces on its own. sdk/go/client/ssh's MCP client (mcp.go) reflects
// this honestly: it reconstructs a *sdkssh.InvalidRequestError for the
// ErrCodeInvalidParams bucket rather than guessing which of the three
// conditions produced it.
//
// Everything else keeps its own distinct code: authentication/authorization
// failures, the SSH sub-system being unconfigured (ErrSSHNotConfigured),
// malformed request parameters, and genuine storage/serialization faults.
func mapSSHError(err error) error {
	if err == nil {
		return nil
	}

	// Already classified by a lower layer (checkSSHClient, or a future
	// handler that wants a specific code) -- pass through unchanged so a
	// double-map never happens.
	var existing *KeyOpError
	if errors.As(err, &existing) {
		return existing
	}

	if errors.Is(err, ErrSSHNotConfigured) {
		// The whole sub-system is absent from this deployment, not merely
		// one operation on it -- distinct from the per-capability
		// ErrCodeMethodNotFound mapKeyOpError uses for
		// xkms.ErrOperationNotSupported.
		return &KeyOpError{Code: ErrCodeServiceUnavailable, Err: err}
	}

	if code, ok := sshHandlerLayerCode(err); ok {
		return &KeyOpError{Code: code, Err: err}
	}

	if code, ok := sshNotFoundDuplicateOrMismatchCode(err); ok {
		return &KeyOpError{Code: code, Err: err}
	}

	if code, ok := sshValidationCode(err); ok {
		return &KeyOpError{Code: code, Err: err}
	}

	if code, ok := sshStorageCode(err); ok {
		return &KeyOpError{Code: code, Err: err}
	}

	return &KeyOpError{Code: ErrCodeInternalError, Err: err}
}

// sshHandlerLayerCode classifies the handlers_ssh.go-local error types: bad
// request params, and the not-found result handleSSHAuthorizedKeysVerify
// returns itself (not from a Store).
func sshHandlerLayerCode(err error) (int, bool) {
	var invalidParams *SSHInvalidParamsError
	if errors.As(err, &invalidParams) {
		return ErrCodeInvalidParams, true
	}
	var notFound *SSHNotFoundError
	if errors.As(err, &notFound) {
		return ErrCodeInvalidParams, true
	}
	return 0, false
}

// sshNotFoundDuplicateOrMismatchCode classifies the three domain conditions
// this function's doc comment says are indistinguishable by code alone: a
// missing resource, a non-idempotent conflict, and a host-key integrity
// failure. All three, from all three SSH store packages, land on
// ErrCodeInvalidParams.
func sshNotFoundDuplicateOrMismatchCode(err error) (int, bool) {
	var keyNotFound *pkgkeys.KeyNotFoundError
	if errors.As(err, &keyNotFound) {
		return ErrCodeInvalidParams, true
	}
	var hostNotFound *pkgknownhosts.NotFoundError
	if errors.As(err, &hostNotFound) {
		return ErrCodeInvalidParams, true
	}
	var authNotFound *pkgauthorized.NotFoundError
	if errors.As(err, &authNotFound) {
		return ErrCodeInvalidParams, true
	}
	var hostDuplicate *pkgknownhosts.DuplicateError
	if errors.As(err, &hostDuplicate) {
		return ErrCodeInvalidParams, true
	}
	var authDuplicate *pkgauthorized.DuplicateError
	if errors.As(err, &authDuplicate) {
		return ErrCodeInvalidParams, true
	}
	var mismatch *pkgknownhosts.MismatchError
	if errors.As(err, &mismatch) {
		return ErrCodeInvalidParams, true
	}
	return 0, false
}

// sshValidationCode classifies caller-input errors that are not one of the
// not-found/duplicate/mismatch trio: malformed or unsupported values the
// caller supplied. All become ErrCodeInvalidParams, the same bucket
// mapKeyOpError uses for *xkms.ErrValidation.
func sshValidationCode(err error) (int, bool) {
	for _, matches := range []func(error) bool{
		isType[*pkgkeys.NilInputError],
		isType[*pkgkeys.UnsupportedAlgorithmError],
		isType[*pkgkeys.InvalidKeySizeError],
		isType[*pkgkeys.PassphraseRequiredError],
		isType[*pkgkeys.PEMParseError],
		isType[*pkgknownhosts.NilInputError],
		isType[*pkgknownhosts.NoPublicKeyError],
		isType[*pkgknownhosts.LegacyPinError],
		isType[*pkgknownhosts.RejectedError],
		isType[*pkgknownhosts.InvalidHostError],
		isType[*pkgknownhosts.PublicKeyRequiredError],
		isType[*pkgknownhosts.InvalidFingerprintError],
		isType[*pkgauthorized.NilInputError],
		isType[*pkgauthorized.MalformedLineError],
		isType[*pkgauthorized.InvalidNameError],
		isType[*pkgauthorized.UnsupportedVersionError],
		isType[*sdkssh.NilInputError],
		isType[*sdkssh.InvalidScopeError],
		isType[*sdkssh.InvalidAlgorithmError],
		isType[*sdkssh.MissingPublicKeyError],
		isType[*sdkssh.InvalidPublicKeyError],
		isType[*sdkssh.BackendUnavailableError],
	} {
		if matches(err) {
			return ErrCodeInvalidParams, true
		}
	}
	return 0, false
}

// sshStorageCode classifies the genuine internal faults: a storage backend
// or (de)serialization failure, and the programming-error signals
// (ClosedSignerError). These are the same floor mapKeyOpError uses for
// anything it does not otherwise recognize.
func sshStorageCode(err error) (int, bool) {
	for _, matches := range []func(error) bool{
		isType[*pkgkeys.KeyMaterialError],
		isType[*pkgkeys.StorageError],
		isType[*pkgkeys.SerializationError],
		isType[*pkgkeys.ClosedSignerError],
		isType[*pkgknownhosts.StorageError],
		isType[*pkgknownhosts.SerializationError],
		isType[*pkgauthorized.StorageError],
		isType[*pkgauthorized.SerializationError],
		isType[*sdkssh.NotImplementedError],
	} {
		if matches(err) {
			return ErrCodeInternalError, true
		}
	}
	return 0, false
}

// isType reports whether err's chain contains a *T, via errors.As. It exists
// so the classification tables above can list one type per line instead of
// one `var`/`errors.As` pair per type.
func isType[T error](err error) bool {
	var target T
	return errors.As(err, &target)
}
