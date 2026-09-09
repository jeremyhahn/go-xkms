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

// Package shamirtest provides the one test fixture that stands in for a
// Shamir ceremony distributor: it splits a barrier secret with the real
// library and keeps the shares so a test can unseal or recover with them.
//
// The shares are held as shamir.ProtectedShare, in mlock'd, guard-paged
// memory that Destroy wipes, never as Go strings (#46). A string is
// immortal: it cannot be zeroed, so a fixture that kept every share in a
// []string held the point of widest exposure in the whole scheme readable
// until the GC got round to it, and rekeying only dropped the slice. Here
// a rekey destroys the previous round, and the test's cleanup destroys the
// last one. The transports take a share as a string, so the base64 text is
// materialised only where a request is built, by Share and Shares, and
// nothing here retains it.
package shamirtest

import (
	"context"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-quicraft/pkg/crypto/shamir"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// CaptureDistributor implements seal.CeremonyDistributor for unit tests.
type CaptureDistributor struct {
	mu     sync.Mutex
	shares []*shamir.ProtectedShare
}

// New returns an empty distributor whose shares are destroyed when the
// test ends.
func New(t testing.TB) *CaptureDistributor {
	t.Helper()
	c := &CaptureDistributor{}
	t.Cleanup(c.Destroy)
	return c
}

// SealAndDistribute splits secret into total shares with the given
// threshold, destroys any previous round, keeps the new shares in protected
// memory, and returns their count.
func (c *CaptureDistributor) SealAndDistribute(_ context.Context, secret []byte, threshold, total int) (int, error) {
	shares, err := shamir.SplitProtected(secret, threshold, total)
	if err != nil {
		return 0, &errs.Wrapped{Msg: "shamir split failed", Err: err}
	}
	c.mu.Lock()
	previous := c.shares
	c.shares = shares
	c.mu.Unlock()
	destroyAll(previous)
	return len(shares), nil
}

// RekeyAndDistribute destroys the prior round and produces fresh shares.
func (c *CaptureDistributor) RekeyAndDistribute(ctx context.Context, newSecret []byte, newThreshold, newTotal int) (int, error) {
	return c.SealAndDistribute(ctx, newSecret, newThreshold, newTotal)
}

// Count returns the number of shares in the current round.
func (c *CaptureDistributor) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.shares)
}

// Share returns share i's base64 text for one request. The string is the
// transport's own representation and cannot be wiped; build the request
// with it and let it go.
func (c *CaptureDistributor) Share(i int) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if i < 0 || i >= len(c.shares) {
		return ""
	}
	return shareText(c.shares[i])
}

// Shares returns every share's base64 text for a request that carries the
// whole set (UnsealWithShares, RecoverWithKeys). Nothing is retained: each
// call materialises the strings afresh from protected memory.
func (c *CaptureDistributor) Shares() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.shares))
	for i, s := range c.shares {
		out[i] = shareText(s)
	}
	return out
}

// Destroy wipes every share of the current round. Safe to call more than
// once; New registers it as the test's cleanup.
func (c *CaptureDistributor) Destroy() {
	c.mu.Lock()
	shares := c.shares
	c.shares = nil
	c.mu.Unlock()
	destroyAll(shares)
}

func destroyAll(shares []*shamir.ProtectedShare) {
	for _, s := range shares {
		s.Destroy()
	}
}

// shareText copies the share's base64 value out of protected memory into a
// string, holding the enclave's read lock for the copy only.
func shareText(s *shamir.ProtectedShare) string {
	var text string
	if err := s.WithValue(func(b []byte) error {
		text = string(b)
		return nil
	}); err != nil {
		return ""
	}
	return text
}
