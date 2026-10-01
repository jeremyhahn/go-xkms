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

package credential

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	qrdbembedded "github.com/jeremyhahn/go-qrdb/sdk/go/transport/embedded"
)

const (
	// lockPrefix is the qrdb key prefix of per-credential refresh leases.
	// The key carries a hash of the record key, never a tenant, owner or
	// credential name, because lease keys live outside the barrier.
	lockPrefix = "xkms/oidc/lock/"

	// lockTTL bounds how long a crashed holder blocks a credential's
	// refresh. A refresh is one token request, far shorter.
	lockTTL = 30 * time.Second

	// lockRetry is how often a contender retries a held lease.
	lockRetry = 200 * time.Millisecond
)

// Leases is the slice of qrdb coordination the service takes: an exclusive
// TTL lease (qrdbsdk.Coordinator.AcquireLease). A lease is the cluster-wide
// lock around a credential's refresh and the scheduler's leadership.
type Leases interface {
	AcquireLease(ctx context.Context, key string, ttl time.Duration) (qrdbsdk.Lease, error)
}

// locker serializes refreshes of one credential: an in-process mutex per
// record key, and, on a raft cluster, a qrdb lease per record key so two
// nodes never redeem the same rotating refresh token.
//
// A standalone qrdb node refuses the lease family with a typed
// capability error (qrdb's run-mode split: leases are raft-only, and a
// standalone node is one process). The locker records that once and from
// then on relies on the in-process mutex, which on a single-process node is
// the whole of the exclusion there is to have.
type locker struct {
	leases     Leases
	logger     *slog.Logger
	standalone atomic.Bool
	mu         sync.Mutex
	held       map[string]*sync.Mutex
}

func newLocker(leases Leases, logger *slog.Logger) *locker {
	l := &locker{leases: leases, logger: logger, held: make(map[string]*sync.Mutex)}
	if leases == nil {
		l.standalone.Store(true)
	}
	return l
}

// keyMutex returns the in-process mutex of key.
func (l *locker) keyMutex(key string) *sync.Mutex {
	l.mu.Lock()
	defer l.mu.Unlock()
	m, ok := l.held[key]
	if !ok {
		m = &sync.Mutex{}
		l.held[key] = m
	}
	return m
}

// lock acquires key's lock, blocking until it is free or ctx ends. The
// returned function releases it.
func (l *locker) lock(ctx context.Context, key string) (func(), error) {
	m := l.keyMutex(key)
	m.Lock()
	lease, err := l.acquire(ctx, lockPrefix+hashKey(key), lockTTL)
	if err != nil {
		m.Unlock()
		return nil, err
	}
	return func() {
		defer m.Unlock()
		if lease == nil {
			return
		}
		releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), lockTTL)
		defer cancel()
		// A release that fails leaves the lease to expire on its TTL; the
		// refresh it guarded has already been written.
		if releaseErr := lease.Release(releaseCtx); releaseErr != nil {
			l.logger.Warn("oidc credential: refresh lease release failed", "error", releaseErr)
		}
	}, nil
}

// acquire takes the cluster lease at key, retrying while another node holds
// it. It returns a nil lease on a standalone node.
func (l *locker) acquire(ctx context.Context, key string, ttl time.Duration) (qrdbsdk.Lease, error) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		lease, held, err := l.tryAcquire(ctx, key, ttl)
		if err != nil || !held {
			return lease, err
		}
		timer.Reset(lockRetry)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

// tryAcquire makes one attempt at the lease at key. held is true when
// another holder owns it.
func (l *locker) tryAcquire(ctx context.Context, key string, ttl time.Duration) (lease qrdbsdk.Lease, held bool, err error) {
	if l.standalone.Load() {
		return nil, false, nil
	}
	lease, err = l.leases.AcquireLease(ctx, key, ttl)
	if err == nil {
		return lease, false, nil
	}
	var heldErr *qrdbsdk.LeaseHeldError
	if errors.As(err, &heldErr) {
		return nil, true, nil
	}
	if leaseFamilyRefused(err) {
		l.standalone.Store(true)
		return nil, false, nil
	}
	return nil, false, err
}

// leaseFamilyRefused reports whether err is a standalone qrdb node refusing
// the raft-only lease family. Over a network transport the node answers
// with the typed capability error; an in-process node.Client() built for a
// standalone node has no lease servicer at all and says so with its own
// typed error.
func leaseFamilyRefused(err error) bool {
	var unsupported *qrdbtransport.CapabilityUnsupportedError
	if errors.As(err, &unsupported) {
		return true
	}
	var missing *qrdbembedded.NilServiceError
	return errors.As(err, &missing) && missing.Service == "LeaseServicer"
}

// hashKey returns the hex SHA-256 of a record key.
func hashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:16])
}
