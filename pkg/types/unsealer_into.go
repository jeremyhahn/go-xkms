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

package types

import "context"

// UnsealerInto is an OPTIONAL capability a Sealer may implement: decrypting
// into memory the CALLER chose, rather than into a buffer the sealer allocates.
//
// Sealer.Unseal returns a []byte, which means the plaintext is materialized on
// the ordinary Go heap before the caller ever sees it. For most callers that is
// fine. For one holding the plaintext under a memory-protection guarantee it is
// not: by the time the value could be moved into locked memory it has already
// existed outside it, where it can be paged to swap, captured in a core dump,
// or left in a heap buffer until the collector happens to reuse the pages.
// Wiping afterwards does not undo any of that, because the exposure is the
// existence of the copy, not its lifetime.
//
// A caller that needs the guarantee type-asserts for this capability and gives
// the sealer a destination it already controls -- locked pages, typically. A
// sealer that cannot honour it simply does not implement it, and the caller
// refuses rather than silently falling back to the heap: a fallback would make
// the protection depend on which sealer happened to be configured, which is
// exactly the kind of invisible difference a security property must not have.
type UnsealerInto interface {
	// PlaintextLen reports EXACTLY how many bytes UnsealInto will produce for
	// sealed, so a caller can size its destination before decrypting.
	//
	// It must be exact rather than an upper bound: a caller sizing locked memory
	// from it has no way to grow that memory afterwards, and a destination even
	// one byte short forces the decryption to allocate -- on the heap, which is
	// the outcome the capability exists to prevent.
	//
	// It reports an error when sealed is malformed, without decrypting: the
	// length is a property of the envelope, and computing it must not require
	// authenticating the ciphertext first.
	PlaintextLen(sealed *SealedData) (int, error)

	// UnsealInto decrypts sealed into dst and returns the plaintext.
	//
	// dst is an EMPTY slice with capacity for the plaintext -- conventionally
	// buf[:0] over a caller-owned array of at least PlaintextLen bytes. The
	// returned slice is dst extended to the plaintext length.
	//
	// THE CALLER MUST VERIFY THE RESULT ALIASES dst. Decryption appends, so a
	// destination too small to hold the plaintext does not fail: it silently
	// allocates a new slice on the heap and returns that instead, which looks
	// like success and defeats the entire purpose. Comparing the returned
	// slice's first element address against dst's is what distinguishes them,
	// and an implementation cannot do that check on the caller's behalf because
	// only the caller knows what dst was supposed to be.
	//
	// The plaintext is authenticated exactly as Unseal authenticates it; a
	// tampered or corrupt envelope is an error, never a short read.
	UnsealInto(ctx context.Context, dst []byte, sealed *SealedData, opts *UnsealOptions) ([]byte, error)
}
