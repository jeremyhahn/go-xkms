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

package sealed

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

var _ storage.CompareAndDeleter = (*Backend)(nil)

// unsealAndCompare decrypts sealed DIRECTLY INTO LOCKED MEMORY and compares the
// result against expected there, so the plaintext never exists on the Go heap.
//
// The comparison is why this backend decrypts at all, and the decrypted value is
// the material the barrier exists to protect. Sealer.Unseal cannot be used for
// it: that returns a []byte, so the plaintext is already on the heap by the time
// it could be moved anywhere safer, where it can be paged to swap or captured in
// a core dump. Wiping afterwards does not undo that — the exposure is the
// existence of the copy, not how long it lives. So the destination is chosen
// FIRST and the decryption is aimed at it.
//
//   - PlaintextLen sizes the region exactly. An upper bound would not do: the
//     locked region cannot grow, and a destination one byte short pushes the
//     decryption onto the heap.
//   - The region is admitted through enclave.ProcessAllocator, the one
//     locked-memory budget the process shares, so a request past that budget
//     is refused as ErrGuardEnclaveFailed (wrapping enclave.ErrBudgetExhausted)
//     before any locked memory is requested, rather than competing with every
//     other library for the same RLIMIT_MEMLOCK ceiling.
//   - NewSized maps locked pages that stay WRITABLE, which is what makes
//     filling them possible; enclaves built from existing material are frozen
//     read-only and could not be decrypted into.
//   - compareInEnclave does the fill and the compare inside one borrow, and
//     Destroy is deferred, so the pages are wiped and returned on every path.
func unsealAndCompare(
	ctx context.Context,
	u types.UnsealerInto,
	sealed *types.SealedData,
	expected []byte,
) (matched bool, err error) {
	n, err := u.PlaintextLen(sealed)
	if err != nil {
		return false, &errs.Joined{Lead: ErrUnsealFailed, Cause: err}
	}

	if n == 0 {
		// go-enclave refuses a zero-length region, and an empty plaintext holds
		// no secret to protect. It still has to be DECRYPTED rather than assumed:
		// skipping the unseal would skip the AEAD tag check, so a corrupt or
		// tampered envelope would silently "match" an empty guard. Authenticate,
		// then compare by length so nil and empty stay equivalent.
		if _, err := u.UnsealInto(ctx, nil, sealed, nil); err != nil {
			return false, &errs.Joined{Lead: ErrUnsealFailed, Cause: err}
		}
		return len(expected) == 0, nil
	}

	alloc, err := enclave.ProcessAllocator()
	if err != nil {
		return false, &errs.Joined{Lead: ErrGuardEnclaveFailed, Cause: err}
	}
	enc, err := alloc.NewSized(n)
	if err != nil {
		return false, &errs.Joined{Lead: ErrGuardEnclaveFailed, Cause: err}
	}
	defer func() {
		// A guard that could not be wiped is not a trustworthy answer, so the
		// result is withdrawn along with the comparison's own error, if any.
		if destroyErr := enc.Destroy(); destroyErr != nil {
			matched = false
			err = errors.Join(err, &errs.Joined{Lead: ErrGuardEnclaveFailed, Cause: destroyErr})
		}
	}()

	return compareInEnclave(ctx, enc, u, sealed, expected)
}

// compareInEnclave fills enc by decrypting into its locked pages and compares
// the plaintext against expected within the same borrow.
//
// It takes the enclave as a parameter rather than building one so that the two
// failures worth pinning can be reproduced deterministically in a test: an
// enclave that cannot be read, and one too small to hold the plaintext.
//
// THE ALIASING CHECK IS THE POINT. Open appends, so a destination without the
// capacity does not fail — it allocates a new slice on the heap, decrypts into
// that, and returns it. Every subsequent line would work perfectly on plaintext
// sitting in ordinary memory, which is the exact outcome this path exists to
// prevent, and nothing else would reveal it. Comparing the result's first
// element address against the borrowed buffer's is what tells them apart.
//
// It goes through WithBytes rather than Open/EqualTo because WithBytes surfaces
// ErrEnclaveDestroyed. Allocator.NewSized documents that it can return a
// successful but already-destroyed enclave when WipeAll races publication, and
// an unreadable enclave must be an ERROR: deleted=false is a load-bearing claim
// that the guard was evaluated and lost, and a caller acts on it by giving up a
// claim it still holds.
func compareInEnclave(
	ctx context.Context,
	enc *enclave.MemoryEnclave,
	u types.UnsealerInto,
	sealed *types.SealedData,
	expected []byte,
) (bool, error) {
	matched := false

	// Captured separately so the two failure classes stay distinguishable after
	// the borrow. Everything WithBytes returns arrives at one place, but a
	// corrupt envelope failing its AEAD tag check is NOT a locked-memory
	// failure: the enclave was readable and did its job. Reporting it as one
	// would tell an operator to look at RLIMIT_MEMLOCK for what is actually
	// damaged or tampered data, and would classify the same fault differently
	// here than on the empty-plaintext path above.
	var unsealErr error

	if err := enc.WithBytes(func(buf []byte) error {
		out, err := u.UnsealInto(ctx, buf[:0], sealed, nil)
		if err != nil {
			unsealErr = err
			return err
		}
		if len(out) == 0 || len(buf) == 0 || &out[0] != &buf[0] {
			return ErrGuardEscapedEnclave
		}
		matched = subtle.ConstantTimeCompare(out, expected) == 1
		return nil
	}); err != nil {
		if unsealErr != nil {
			return false, &errs.Joined{Lead: ErrUnsealFailed, Cause: unsealErr}
		}
		return false, &errs.Joined{Lead: ErrGuardEnclaveFailed, Cause: err}
	}
	return matched, nil
}

// CompareAndDelete removes key only when the value stored there still unseals
// to expected. The atomicity guarantee is inherited unchanged from the inner
// backend; this type adds no writer of its own.
//
// IT GUARDS ON THE STORED ENVELOPE, NOT ON A FRESH SEAL OF expected. Sealing is
// randomised — sealing the same plaintext twice yields different bytes — so a
// guard built by re-sealing expected would refuse EVERY release, turning every
// release into a silent no-op, which is worse than the race the guard exists to
// fix. Reading the stored envelope, unsealing to compare in plaintext, and then
// guarding the delete on those exact bytes keeps the guarantee intact: any write
// landing in between replaces the envelope, so the inner guard still refuses.
//
// This is the same split the caller's two layers require. The caller's
// expectation is a plaintext, so it is compared after unsealing here; the guard
// handed to the inner backend is the ENVELOPE that was read, so the inner
// backend compares the exact bytes it holds and needs no access to the key.
//
// THE UNSEALED VALUE NEVER EXISTS IN ORDINARY MEMORY. Comparing in plaintext is
// unavoidable here, so the envelope is decrypted DIRECTLY INTO locked go-enclave
// pages, compared in constant time inside them, and destroyed before the delete
// is issued — see unsealAndCompare. It is not unsealed and then moved: that
// would put the plaintext on the heap first, and a copy that existed cannot be
// un-exposed by wiping it afterwards.
//
// This needs the sealer to implement types.UnsealerInto, and there is NO HEAP
// FALLBACK for one that does not. A fallback would make the protection depend on
// which sealer happened to be configured — the kind of invisible difference a
// security property must not have. SecretSealer implements it, so the production
// path is covered and only an exotic sealer refuses.
//
// THE PROTECTION COVERS THE STORED VALUE, NOT THE expected PARAMETER, and the
// asymmetry is deliberate rather than an oversight. What this backend decrypts
// is its own to protect, so it is decrypted into locked memory. expected arrives
// as a []byte the CALLER already holds on the Go heap; it is on the heap before
// this method is entered, and nothing done here can un-expose a copy that
// already exists. Taking an enclave-typed parameter instead would move the
// boundary one frame without removing the copy — protection theatre — since the
// caller would still have materialized the bytes to build the enclave from.
//
// The signature is not ours to change in any case. It is go-quicraft's
// seal.StorageBackend contract, which go-qrdb aliases and the barrier boundary
// in pkg/seal must satisfy; storage.CompareAndDeleter mirrors it precisely so
// that boundary is a forward and not a translation. Closing the gap for real
// means making the whole chain enclave-aware — quicraft's interface, go-qrdb's
// barrier, then xkms — which is a cross-repo API change, tracked upstream as
// go-quicraft #46 and deliberately classed there as HARDENING rather than a
// defect, for the reason the measurement below gives. It is paired with
// go-quicraft #45 so that if either lands, consumers absorb ONE interface
// break rather than two.
//
// WHAT ACTUALLY FLOWS THROUGH expected TODAY, measured rather than assumed:
//
//   - The barrier's guarded release passes the CIPHERTEXT it just read
//     (go-qrdb pkg/seal/barrier.go:919 hands `stored` to the base). It compares
//     the plaintext itself, inside go-qrdb, and the base layer never sees it.
//   - go-qrdb's custodian passes a claim marker — "claim:<unix expiry>:<random
//     token>" (pkg/custodian/service.go:437) — whose whole purpose is to be
//     compared, so that a rollback deletes only the claim this attempt took.
//     Its store is a kvstore.AtomicKVStore, not this backend.
//
// So no path routes secret key material through this parameter, and this
// backend has no production caller at all today. A caller that ever DOES hold
// real secret material must not route it here as a guard value until the chain
// above is enclave-aware; guard on a marker or a ciphertext, as both current
// consumers already do.
//
// A CONSEQUENCE WORTH STATING, because it looks like a defect and is not: an
// interleaved Put REFUSES this release even when it stores the same plaintext.
// Re-sealing produces a different envelope, so the guard no longer matches. That
// is the intended reading — go-quicraft's contract calls an interleaved write
// replacing those bytes "precisely the signal" — because the releaser is
// releasing the specific claim it observed, and a Put that landed in between is
// a new claim by someone else. Removing it because the plaintext happens to
// match is exactly the stale-releaser defect the verb exists to close.
//
// So the refusal is not weakened by adding a lock here, and a lock would be a
// lie besides: the inner backend may be shared across processes (a qrdb
// cluster), where a mutex local to this wrapper serializes nothing and would
// advertise an atomicity it cannot provide. Refusal is also the safe direction —
// the store is left unchanged and the caller can re-read and retry, whereas a
// deletion granted on a guard that no longer holds is unrecoverable.
func (b *Backend) CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error) {
	stored, err := b.inner.Get(ctx, key)
	if err != nil {
		// An absent key is an ordinary refusal, not a failure — the guarded
		// delete reports that through deleted=false. Every other read failure
		// leaves the outcome unknown and must refuse rather than decide:
		// treating it as "the value differs" would silently skip a delete the
		// caller is entitled to.
		if errors.Is(err, storage.ErrNotFound) {
			return false, nil
		}
		return false, err
	}

	var sealedData types.SealedData
	if err := json.Unmarshal(stored, &sealedData); err != nil {
		return false, &errs.Joined{Lead: ErrUnmarshalFailed, Cause: err}
	}

	unsealer, ok := b.sealer.(types.UnsealerInto)
	if !ok {
		// Refuse rather than fall back to Sealer.Unseal. The fallback would work
		// and would put the barrier's plaintext on the heap, silently, for this
		// sealer only.
		return false, ErrUnsealIntoUnsupported
	}

	matched, err := unsealAndCompare(ctx, unsealer, &sealedData, expected)
	if err != nil {
		// The comparison did not complete, so the outcome is unknown and must be
		// reported as an error rather than as a refusal: deleted=false would
		// claim the guard was evaluated and lost.
		return false, err
	}
	if !matched {
		return false, nil
	}

	cad, ok := b.inner.(storage.CompareAndDeleter)
	if !ok {
		return false, storage.ErrCompareAndDeleteUnsupported
	}
	return cad.CompareAndDelete(ctx, key, stored)
}
