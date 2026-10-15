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

package phone

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
)

// TestDirectRequestPathSerializesTheCipherState covers the nonce race on the
// path that has no router.
//
// A Noise CipherState advances a monotonic nonce per message and is not
// concurrent-safe. MessageRouter says exactly that at its own sendMu and takes
// it around encrypt-and-send. The DIRECT path — the one taken when no router
// is active — admits concurrent leaseholders and had no equivalent, so two
// operations could interleave their nonce advancement and pair a response with
// the wrong request.
//
// The observable is overlap at the transport: with the sequence serialized,
// SendAndReceive is never inside two calls at once. Without it, concurrent
// requests overlap there almost immediately.
func TestDirectRequestPathSerializesTheCipherState(t *testing.T) {
	backend, responder := setupNoiseSessionPair(t)
	defer backend.Close()

	const requests = 8

	// One responder turn per request; the pipe is synchronous, so each
	// handleOne answers exactly one round trip.
	for i := 0; i < requests; i++ {
		go responder.handleOne()
	}

	var mu sync.Mutex
	inFlight, maxInFlight := 0, 0

	backend.mu.RLock()
	transport := backend.transport
	backend.mu.RUnlock()

	backend.mu.Lock()
	backend.transport = &countingTransport{
		Transport: transport,
		enter: func() {
			mu.Lock()
			inFlight++
			if inFlight > maxInFlight {
				maxInFlight = inFlight
			}
			mu.Unlock()
		},
		exit: func() {
			mu.Lock()
			inFlight--
			mu.Unlock()
		},
	}
	backend.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = backend.SendRequest(ctx, pairingproto.NewRequest(pairingproto.MethodPing, nil))
		}()
	}
	wg.Wait()

	mu.Lock()
	peak := maxInFlight
	mu.Unlock()

	if peak > 1 {
		t.Fatalf("%d requests were inside the transport at once: the direct "+
			"path advanced the Noise nonce concurrently, so frames go out of "+
			"nonce order and responses pair with the wrong request", peak)
	}
}

// countingTransport reports when a call is inside the underlying transport.
type countingTransport struct {
	pairingproto.Transport
	enter func()
	exit  func()
}

func (c *countingTransport) SendAndReceive(ctx context.Context, message []byte) ([]byte, error) {
	c.enter()
	defer c.exit()
	return c.Transport.SendAndReceive(ctx, message)
}
