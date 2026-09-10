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

package storage

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/storage/qrdb"
)

// qrdb.Backend cannot state this itself: pkg/storage imports pkg/storage/qrdb
// (constructors.go), so the assertion has to live on this side of that edge or
// it would be an import cycle. It is the same reason qrdb carries its own
// ErrNotFound sentinel and has it injected by SetNotFoundError.
var _ CompareAndDeleter = (*qrdb.Backend)(nil)

// CompareAndDeleter is an OPTIONAL capability a Backend may implement: an
// atomic guarded delete. It is a separate interface rather than a Backend
// method for exactly the reason CompareAndSwapper is — so a backend that cannot
// provide the guarantee is not forced to pretend it can — and a caller that
// needs it type-asserts for it.
//
// The distinction matters more here than for a swap. A backend that cannot
// scope a delete to the record a guard names, or that has no way to evaluate
// the guard where writes serialize, cannot be given a stand-in implementation:
// there is no safe degradation, only a delete that reports success for
// something narrower or wider than what was asked. Absence of the capability is
// the honest signal, and it is visible at the call site on the first assertion
// rather than in production.
//
// Backends that implement it today: engineBackend (and therefore NewFile,
// NewPebble, NewMemory), qrdb.Backend, mocks.MockCertStorage, and the wrappers
// PrefixBackend, file.FileStorage, luks.Backend and sealed.Backend, each of
// which forwards to the backend it wraps and reports
// ErrCompareAndDeleteUnsupported when that backend lacks it. All of them are
// held to this contract by the shared suite in pkg/storage/storagetest.
//
// pkcs11/module's remote state backend implements it over the PKCS11StateCAD
// RPC: the guard is evaluated by xkmsd's pkcs11state.Store on its own backend,
// where the writes of every host sharing that token serialise, and never
// emulated on the client. It is held to the same suite.
//
// seal.BarrierBackend also implements it, overriding the method it would
// otherwise promote from go-qrdb's barrier so that an absent key becomes the
// refusal this contract requires: the barrier recognises only go-qrdb's own
// ErrSecretNotFound, and an xkms backend reports a missing key as ErrNotFound.
// It is held to the same suite as the rest.
//
// Backends that deliberately do NOT implement it, with the expansion tracked:
//
//   - hardware.HardwareBackendAdapter (#143): its delete addresses a
//     certificate id rather than a record, so it cannot be scoped to the one key
//     a guarded release names; honouring the request would destroy the sibling
//     certificate or chain and report success.
//
// qrdb.Backend implements the capability but the embedded constructors cannot
// yet execute it (go-qrdb #175, an upstream apply-loop gap); it reports that as
// an error rather than emulating it.
type CompareAndDeleter interface {
	// CompareAndDelete atomically removes key only when its stored value still
	// equals expected. It returns deleted=true when this call removed the key,
	// and deleted=false with a NIL ERROR when the key was absent or held a
	// different value -- in that case the store is unchanged. A non-nil error
	// means the outcome is unknown and the caller must not assume either way.
	//
	// Note the deliberate asymmetry with Backend.Delete, which reports an absent
	// key as ErrNotFound: here an absent key is an ordinary refusal, not a
	// failure. A caller cannot distinguish "someone else released it first" from
	// "it was never there", and both leave the store in the state it wanted.
	//
	// This is the release half of the pair PutIfAbsent opens, and the halves are
	// not independent: a guarded create is only as strong as its release. With
	// PutIfAbsent to acquire and a plain Delete to release, two releasers can
	// both read holder A, the first deletes, B legitimately claims the
	// now-absent key, and the second executes its unguarded delete and removes
	// B's value -- B having acquired the key under the guarantee PutIfAbsent
	// advertises. Re-reading before the delete does not close this, because the
	// window is BETWEEN the read and the delete. Only a delete conditioned on
	// the value the caller last observed, evaluated where the store serializes
	// writes, closes it.
	//
	// expected is compared as raw bytes and nil is NOT a wildcard: it is
	// equivalent to an empty slice, so it matches a stored empty value and
	// nothing else. (This differs from CompareAndSwapper.CompareAndSwap, where a
	// nil expected means "require the key to be ABSENT". The verbs differ
	// because a swap can meaningfully create, and a delete cannot.)
	//
	// expected IS AN ORDINARY HEAP SLICE and carries no memory-protection
	// guarantee, including from sealed.Backend, which protects the value it
	// decrypts but cannot protect one the caller already holds. The signature is
	// go-quicraft's seal.StorageBackend contract, which the barrier boundary
	// must satisfy, so it is fixed here; an enclave-typed parameter would move
	// the exposure one frame rather than remove it, because the caller has
	// already materialized the bytes. Making the whole chain enclave-aware is
	// tracked upstream as go-quicraft #46 (hardening, not a defect).
	//
	// GUARD ON A MARKER OR A CIPHERTEXT, NEVER ON SECRET KEY MATERIAL. Both
	// real consumers already do: the barrier's guarded release guards on the
	// ciphertext it read, and go-qrdb's custodian on a per-attempt claim token.
	// A guard value only has to be unforgeable and comparable, which a marker
	// is, so routing a secret here buys nothing and exposes it on the heap.
	//
	// ATOMICITY IS PER IMPLEMENTATION, and each one documents what it actually
	// provides on its own method rather than inheriting a promise from here:
	//
	//   - engineBackend and mocks.MockCertStorage serialize the
	//     compare-then-delete under a local lock. Their store has a single
	//     in-process writer, so the guarantee is genuine.
	//   - PrefixBackend, file.FileStorage, luks.Backend and sealed.Backend add
	//     no writer of their own and inherit the guarantee of the backend they
	//     wrap, whatever that is. sealed.Backend additionally unseals into
	//     locked memory and compares there, never on the heap.
	//   - qrdb.Backend evaluates the comparison inside the cluster, so the
	//     guarantee holds across nodes.
	//
	// An implementation that HAS the capability may still report a particular
	// call as unavailable -- qrdb's embedded constructors do. There is no safe
	// fallback in that case either: degrading to a read followed by an unguarded
	// delete reintroduces precisely the window the operation exists to close, so
	// it MUST return an error rather than a plausible-looking deleted=true. A
	// caller must therefore handle the error, and must not read a failure as
	// "the value differed" -- that is what deleted=false means and an error does
	// not.
	CompareAndDelete(ctx context.Context, key string, expected []byte) (deleted bool, err error)
}
