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

package shamirtest

import (
	"bytes"
	"context"
	"testing"

	"github.com/jeremyhahn/go-quicraft/pkg/crypto/shamir"
)

func TestCaptureDistributor_SplitsAndReconstructs(t *testing.T) {
	c := New(t)
	secret := []byte("barrier root key material 0123456789")

	n, err := c.SealAndDistribute(context.Background(), secret, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 || c.Count() != 3 {
		t.Fatalf("expected 3 shares, got %d / %d", n, c.Count())
	}

	// The materialised text is the shares' own base64 value, so the
	// protected shares reconstruct the secret and the text is what a
	// request would carry.
	c.mu.Lock()
	shares := append([]*shamir.ProtectedShare(nil), c.shares[:2]...)
	c.mu.Unlock()
	enc, err := shamir.CombineProtected(shares)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Destroy()
	if err := enc.WithBytes(func(b []byte) error {
		if !bytes.Equal(b, secret) {
			t.Fatalf("reconstructed %q, want %q", b, secret)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if c.Share(0) == "" || c.Share(0) != c.Shares()[0] {
		t.Fatal("Share and Shares must materialise the same text")
	}
	if c.Share(3) != "" || c.Share(-1) != "" {
		t.Fatal("an out-of-range index yields no text")
	}
}

func TestCaptureDistributor_RekeyDestroysThePreviousRound(t *testing.T) {
	c := New(t)
	if _, err := c.SealAndDistribute(context.Background(), []byte("first round secret"), 2, 3); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	old := c.shares[0]
	c.mu.Unlock()

	if _, err := c.RekeyAndDistribute(context.Background(), []byte("second round secret"), 2, 2); err != nil {
		t.Fatal(err)
	}
	if c.Count() != 2 {
		t.Fatalf("rekey must replace the round, got %d shares", c.Count())
	}
	if old.Value() != nil {
		t.Fatal("a rekey must destroy the previous round's shares, not merely drop them")
	}
}

func TestCaptureDistributor_DestroyWipesAndIsIdempotent(t *testing.T) {
	c := New(t)
	if _, err := c.SealAndDistribute(context.Background(), []byte("secret to wipe"), 2, 3); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	first := c.shares[0]
	c.mu.Unlock()

	c.Destroy()
	c.Destroy()
	if c.Count() != 0 || first.Value() != nil || len(c.Shares()) != 0 || c.Share(0) != "" {
		t.Fatal("Destroy must wipe every share and leave nothing to materialise")
	}
}

func TestCaptureDistributor_RefusesAnInvalidSplit(t *testing.T) {
	c := New(t)
	if _, err := c.SealAndDistribute(context.Background(), []byte("s"), 4, 3); err == nil {
		t.Fatal("a threshold above the total must be refused")
	}
	if c.Count() != 0 {
		t.Fatal("a refused split must leave no shares behind")
	}
}
