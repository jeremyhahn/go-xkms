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

// Package apierrors holds the sentinel-to-class tables that classify a
// service-layer error the same way regardless of which transport (gRPC or
// MCP) is reporting it.
//
// Each transport owns its own wire vocabulary -- gRPC's codes.Code, MCP's
// JSON-RPC ErrCode -- and neither can be cast to the other: gRPC has
// seventeen codes, JSON-RPC's reserved range covers far fewer, and the two
// numberings share nothing. Class is the layer in between: a small,
// transport-agnostic vocabulary broad enough to describe every condition a
// sentinel table in this package classifies. A transport package supplies
// its own Class -> local-code map (a handful of entries, mechanical and
// total) and calls ClassOf against one of this package's tables, so the
// judgment of "which sentinel means what" is written down exactly once and
// read by both transports (go-xkms#912) instead of being re-derived, and
// possibly re-diverged, per transport.
//
// This package intentionally does not try to classify every error family in
// pkg/api/grpc and pkg/api/mcp. It holds only the families whose gRPC
// classification is itself a plain sentinel -> code table (import/export
// capability sentinels, PIV, the barrier/Shamir domain): a mechanical,
// message-preserving refactor of that table into Sentinel -> Class loses
// nothing. Families whose gRPC classification hand-picks a caller-facing
// message per case (password) or has no sentinel table at all (CA, TLS
// certificate storage) are classified locally in pkg/api/mcp instead, with a
// comment explaining why sharing a table would cost more than it returns.
package apierrors

import "errors"

// Class is a transport-agnostic classification of a service-layer error. It
// mirrors the outcomes gRPC's codes.Code and MCP's JSON-RPC vocabulary can
// both express, so any transport's local code table can be built from it
// with a total, one-line-per-entry translation.
type Class int

const (
	// ClassInternal is the floor every unclassified error falls to: a fault
	// in the server rather than in the request or its preconditions.
	ClassInternal Class = iota

	// ClassInvalidArgument reports a malformed or out-of-vocabulary request
	// field.
	ClassInvalidArgument

	// ClassNotFound reports a named resource (key, backend, slot, share)
	// that does not exist.
	ClassNotFound

	// ClassAlreadyExists reports a resource the caller tried to create a
	// second time, or a state transition that has already happened.
	ClassAlreadyExists

	// ClassPermissionDenied reports a caller that is authenticated but not
	// entitled to the resource it named.
	ClassPermissionDenied

	// ClassFailedPrecondition reports a request that is well-formed but
	// cannot be served in the server's current state (sealed, locked,
	// quorum incomplete).
	ClassFailedPrecondition

	// ClassUnavailable reports a capability that is not wired up at all
	// (no CA configured, no barrier strategy registered), as opposed to one
	// that is wired but currently refusing the request.
	ClassUnavailable

	// ClassUnimplemented reports a capability boundary: the backend this
	// request resolved to does not support the requested operation at all.
	ClassUnimplemented

	// ClassUnauthenticated reports a credential (passphrase, PIN, recovery
	// share) that failed verification.
	ClassUnauthenticated

	// ClassDataLoss reports corruption: a root key, share, or token that
	// failed an integrity check.
	ClassDataLoss

	// ClassDeadlineExceeded reports a time-bounded state (a quorum ceremony)
	// that expired before it completed.
	ClassDeadlineExceeded
)

// SentinelClass pairs one sentinel error with the Class it classifies to.
type SentinelClass struct {
	// Sentinel is matched against a candidate error with errors.Is.
	Sentinel error
	// Class is the classification Sentinel carries.
	Class Class
}

// ClassOf reports the Class the first entry of table matching err (via
// errors.Is) carries. Order matters, exactly as it does in the tables this
// package exports: a single error can satisfy errors.Is for more than one
// entry, so the first, most specific match wins. The second return is false
// when err is nil or matches no entry, so a caller can distinguish "no
// classification" from ClassInternal, which is also a legitimate entry.
func ClassOf(table []SentinelClass, err error) (Class, bool) {
	if err == nil {
		return ClassInternal, false
	}
	for _, entry := range table {
		if errors.Is(err, entry.Sentinel) {
			return entry.Class, true
		}
	}
	return ClassInternal, false
}
