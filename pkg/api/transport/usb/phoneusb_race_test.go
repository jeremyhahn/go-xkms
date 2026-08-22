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

package usb

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// phoneUSB was published under mu by Connect but cleared under busMu by Close
// and discardPhoneUSB. Two mutexes guarding one field guard nothing: a Healthy
// or Conn call concurrent with Close performed an unsynchronised read against
// an unsynchronised write, and could reach IsConnected on a bus that was being
// torn down underneath it.
//
// Run under -race. Before the fix these report WARNING: DATA RACE on
// Transport.phoneUSB.
//
// The loops matter. A single Close/Healthy pair rarely interleaves on the
// window that matters, so a one-shot test would pass against the broken code
// and prove nothing.
func TestCloseDoesNotRaceHealthy(t *testing.T) {
	for range 20 {
		tr, g := newGatedTransport(t)
		close(g.gate)

		require.NoError(t, tr.Connect(context.Background()))

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			_ = tr.Close()
		}()
		go func() {
			defer wg.Done()
			for range 50 {
				_ = tr.Healthy(context.Background())
			}
		}()

		waitOrFail(t, &wg, "Close and Healthy did not both finish")
	}
}

func TestCloseDoesNotRaceConn(t *testing.T) {
	for range 20 {
		tr, g := newGatedTransport(t)
		close(g.gate)

		require.NoError(t, tr.Connect(context.Background()))

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			_ = tr.Close()
		}()
		go func() {
			defer wg.Done()
			for range 50 {
				_ = tr.Conn()
			}
		}()

		waitOrFail(t, &wg, "Close and Conn did not both finish")
	}
}

// A failed Connect discards the bus through discardPhoneUSB, which is the other
// writer of the field, so it races the same readers.
func TestDiscardDoesNotRaceHealthy(t *testing.T) {
	for range 20 {
		tr, g := newGatedTransport(t)
		close(g.gate)

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			tr.discardPhoneUSB()
		}()
		go func() {
			defer wg.Done()
			for range 50 {
				_ = tr.Healthy(context.Background())
				_ = tr.Conn()
			}
		}()

		waitOrFail(t, &wg, "discardPhoneUSB and the readers did not both finish")
	}
}

// waitOrFail bounds every wait in this file, so a regression fails the test
// rather than hanging the package until the go test timeout reports it as
// infrastructure trouble.
func waitOrFail(t *testing.T, wg *sync.WaitGroup, msg string) {
	t.Helper()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	select {
	case <-done:
	case <-time.After(testWait):
		t.Fatal(msg)
	}
}
