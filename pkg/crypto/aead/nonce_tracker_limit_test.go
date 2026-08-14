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

package aead

import (
	"errors"
	"testing"
)

// TestNonceTrackerWithLimitAcceptsUpToTheLimit proves a bounded tracker still
// does its job for every nonce it has room for.
func TestNonceTrackerWithLimitAcceptsUpToTheLimit(t *testing.T) {
	tracker := NewNonceTrackerWithLimit(true, 3)

	for i := byte(0); i < 3; i++ {
		if err := tracker.CheckAndRecordNonce([]byte{i}); err != nil {
			t.Fatalf("nonce %d is within the limit and must be accepted: %v", i, err)
		}
	}
	if tracker.Count() != 3 {
		t.Fatalf("expected 3 tracked nonces, got %d", tracker.Count())
	}
}

// TestNonceTrackerWithLimitFailsClosed is the bad-input half: past the limit
// the tracker refuses rather than evicting. Evicting would turn a reuse it had
// already recorded into one it would accept.
func TestNonceTrackerWithLimitFailsClosed(t *testing.T) {
	tracker := NewNonceTrackerWithLimit(true, 1)

	if err := tracker.CheckAndRecordNonce([]byte{1}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := tracker.CheckAndRecordNonce([]byte{2}); !errors.Is(err, ErrNonceTrackerFull) {
		t.Fatalf("expected ErrNonceTrackerFull, got %v", err)
	}
	if tracker.Count() != 1 {
		t.Fatalf("a refused nonce must not be recorded, count is %d", tracker.Count())
	}
	if !tracker.Contains([]byte{1}) {
		t.Fatal("the nonce recorded before the limit was reached must still be held")
	}
	if err := tracker.CheckAndRecordNonce([]byte{1}); !errors.Is(err, ErrNonceReuse) {
		t.Fatalf("a full tracker must still report a known nonce as reuse, got %v", err)
	}
}

// TestNonceTrackerUnlimitedByDefault proves NewNonceTracker keeps its original
// unbounded behaviour, so adding the limit did not silently cap every existing
// caller.
func TestNonceTrackerUnlimitedByDefault(t *testing.T) {
	tracker := NewNonceTracker(true)

	for i := 0; i < 1000; i++ {
		if err := tracker.CheckAndRecordNonce([]byte{byte(i / 256), byte(i % 256)}); err != nil {
			t.Fatalf("an unbounded tracker must accept every distinct nonce: %v", err)
		}
	}
	if tracker.Count() != 1000 {
		t.Fatalf("expected 1000 tracked nonces, got %d", tracker.Count())
	}
}

// TestNonceTrackerDisabledIgnoresTheLimit proves a disabled tracker stays a
// no-op regardless of the bound, which is what makes the limit safe to add to
// a tracker a caller has deliberately turned off.
func TestNonceTrackerDisabledIgnoresTheLimit(t *testing.T) {
	tracker := NewNonceTrackerWithLimit(false, 1)

	for i := byte(0); i < 5; i++ {
		if err := tracker.CheckAndRecordNonce([]byte{i}); err != nil {
			t.Fatalf("a disabled tracker must accept everything: %v", err)
		}
	}
	if err := tracker.CheckAndRecordNonce([]byte{0}); err != nil {
		t.Fatalf("a disabled tracker must not report reuse: %v", err)
	}
	if tracker.Count() != 0 {
		t.Fatalf("a disabled tracker reports no count, got %d", tracker.Count())
	}
}
