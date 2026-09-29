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

package rest

import (
	"errors"
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/api/apierrors"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/aead"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// keyOpSentinelStatus maps the service-layer sentinels raised by the
// hardware-capability key operations (AttestKey, DeriveKeyECDH,
// ExportKeyMaterial, WrapKeyByID, UnwrapKeyByID) onto HTTP status codes. It is
// an ordered slice rather than a map because a single error can satisfy
// errors.Is for more than one entry: xkms.ErrOperationWrap deliberately
// exposes both its sentinel and its cause. The first match wins, so the most
// specific sentinel is listed first. This mirrors
// pkg/api/grpc/errors_keyops.go's keyOpSentinelCodes so both transports report
// the same capability boundaries under their own status vocabularies.
var keyOpSentinelStatus = []struct {
	sentinel error
	status   int
}{
	// A digest this service refuses (SHA-1 and the other collision-broken
	// names) or cannot resolve is a fault in the request, not in the server.
	// ResolveOAEPHash reports the weak-hash refusal as ErrOperationWrap rather
	// than ErrValidation, so without these two entries it fell through to the
	// catch-all and a caller that named a bad digest was told the server had
	// failed.
	{xkms.ErrWeakOAEPHash, http.StatusBadRequest},
	{xkms.ErrInvalidHashFunction, http.StatusBadRequest},
	// A malformed certificate, an empty chain, or sealed data missing its
	// payload is a fault in the request (go-xkms#1228).
	{xkms.ErrInvalidEncodingPEM, http.StatusBadRequest},
	{xkms.ErrInvalidCertificate, http.StatusBadRequest},
	{xkms.ErrEmptyChain, http.StatusBadRequest},
	{xkms.ErrInvalidSealedData, http.StatusBadRequest},
	{xkms.ErrNilData, http.StatusBadRequest},
	{xkms.ErrOperationNotSupported, http.StatusNotImplemented},
	{xkms.ErrExportKeyMaterialFailed, http.StatusPreconditionFailed},
	{xkms.ErrBackendNotFound, http.StatusNotFound},
	{xkms.ErrKeyNotFound, http.StatusNotFound},
	{xkms.ErrCertNotFound, http.StatusNotFound},
	{xkms.ErrCertChainNotFound, http.StatusNotFound},
	{xkms.ErrNotInitialized, http.StatusServiceUnavailable},

	// WrapKey, UnwrapKey, GetImportParameters and ImportKey now route through
	// the service layer (go-xkms#1216) rather than calling
	// backend.ImportBackend / backend.ExportBackend directly, so a
	// backend-layer capability or policy sentinel reaches here wrapped in the
	// service's own xkms.ErrOperationWrap. These mirror the same sentinels
	// mapErrorToStatusCode classifies for the handlers that still call the
	// backend methods directly (ExportKey, CopyKey), so both paths report the
	// same capability boundary under the same status code regardless of which
	// one a given RPC happens to take.
	{backend.ErrExportNotSupported, http.StatusNotImplemented},
	{backend.ErrImportNotSupported, http.StatusNotImplemented},
	{backend.ErrAsymmetricKeyExportNotAllowed, http.StatusBadRequest},
	{backend.ErrKeyNotExportable, http.StatusForbidden},

	// A caller-supplied nonce against a backend whose remote encryption
	// service manages its own nonces (AWS KMS, GCP KMS, Vault Transit, the
	// paired phone) is a malformed request, not a capability the backend
	// categorically lacks (go-xkms#1223).
	{backend.ErrCallerNonceNotSupported, http.StatusBadRequest},

	// aead.ErrNonceReuse and aead.ErrNonceTrackerFull reach here wrapped in
	// pkg/xkms's ErrKeyOperation from Encrypt's and WrapKeyByID's AEAD nonce
	// guard. A reused nonce is the caller's request repeating a value that
	// must never repeat -- 409, matching gRPC's codes.AlreadyExists and
	// apierrors.AEADSentinelClasses' ClassAlreadyExists -- and a full guard
	// is a resource limit reached, not a permanent refusal -- 503, matching
	// codes.ResourceExhausted (go-xkms#1223).
	{aead.ErrNonceReuse, http.StatusConflict},
	{aead.ErrNonceTrackerFull, http.StatusServiceUnavailable},
}

// mapKeyOpError converts an error returned by the xkms service layer's key
// and crypto operations into an HTTP status response. Validation failures
// report the offending field verbatim so callers see the same wire-level
// field name they sent; a malformed backend name is a 400; capability
// boundaries (a backend that cannot attest, or cannot export) become 501 or
// 412; unresolved backends and keys become 404. A clustered not-leader
// condition is surfaced as 421, exactly as handleError does for the rest of
// the package.
//
// An error none of those match is classified by mapErrorToStatusCode, the
// package's table for the backend-layer sentinels a service operation wraps
// rather than replaces: ExportKey and CopyKey report a backend's
// ErrKeyNotExportable (403) or ErrExportNotSupported (501) as the cause of an
// operation failure, and CopyKey an existing destination key as
// storage.ErrAlreadyExists (409). Anything that table does not know is a 500.
func mapKeyOpError(w http.ResponseWriter, err error) {
	if nl, ok := xkms.AsNotLeader(err); ok {
		writeNotLeader(w, nl)
		return
	}

	var role *xkms.ErrRoleLookup
	if errors.As(err, &role) {
		writeError(w, role, http.StatusNotFound)
		return
	}

	// A key or certificate ID that does not parse -- including one naming
	// another tenant's namespace ("tenant-b/web") -- is malformed input. It
	// is matched before ErrValidation, which the parse failure may wrap, so
	// the response names the key ID as the field at fault.
	var keyID *xkms.ErrKeyIDParse
	if errors.As(err, &keyID) {
		writeError(w, keyID, http.StatusBadRequest)
		return
	}

	var validation *xkms.ErrValidation
	if errors.As(err, &validation) {
		writeErrorWithMessage(w, validation, keyOpValidationMessage(validation), http.StatusBadRequest)
		return
	}

	var backendName *xkms.ErrBackendNameValidation
	if errors.As(err, &backendName) {
		writeError(w, backendName, http.StatusBadRequest)
		return
	}

	for _, entry := range keyOpSentinelStatus {
		if errors.Is(err, entry.sentinel) {
			writeError(w, err, entry.status)
			return
		}
	}

	// A TPM2 key or seal routed to a tenant's TPM scope surfaces the TPM
	// policy service's errors (an unknown named policy, a tenant whose TPM
	// mode is none, a name reserved for the service's own objects), which
	// the package table does not know.
	status := mapErrorToStatusCode(err)
	if class, ok := apierrors.TPMPolicyClassOf(err); ok && status == http.StatusInternalServerError {
		status = classToHTTPStatus[class]
	}
	writeError(w, err, status)
}

// keyOpValidationMessage renders a service-layer validation error for the
// wire. The Detail carries the caller-facing message ("key_id is required");
// the sentinel is only used when a validation error carries no detail. This
// mirrors pkg/api/grpc/errors_keyops.go's validationMessage.
func keyOpValidationMessage(err *xkms.ErrValidation) string {
	if err.Detail != "" {
		return err.Detail
	}
	return err.Sentinel.Error()
}
