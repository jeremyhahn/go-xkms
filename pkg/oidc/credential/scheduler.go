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
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

const (
	// DefaultSchedulerInterval is how often the leader looks for
	// credentials due for refresh. It is well inside DefaultRefreshMargin,
	// so a credential is refreshed several ticks before it expires.
	DefaultSchedulerInterval = 30 * time.Second

	// schedulerLeaseKey is the qrdb lease the scheduler's leader holds.
	schedulerLeaseKey = "xkms/oidc/scheduler"
)

// Start runs the refresh scheduler until Close: every interval, the elected
// leader -- the node holding the scheduler's qrdb lease -- refreshes every
// credential that is due (RefreshDue). The other nodes campaign for the
// lease each interval and take over when the leader's lease lapses. On a
// standalone node the one process is the leader. A non-positive interval
// means DefaultSchedulerInterval. Start is a no-op after the first call.
func (s *Service) Start(interval time.Duration) {
	if interval <= 0 {
		interval = DefaultSchedulerInterval
	}
	s.runMu.Lock()
	defer s.runMu.Unlock()
	if s.started || s.closed {
		return
	}
	s.started = true
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.done = make(chan struct{})
	go s.schedule(ctx, interval)
}

// schedule campaigns for leadership and, while leader, refreshes every
// interval.
func (s *Service) schedule(ctx context.Context, interval time.Duration) {
	defer close(s.done)
	leaseCtx, err := s.locks.leaseContext(ctx)
	if err != nil {
		s.logger.Error("oidc credential: scheduler cannot take its lease", "error", err)
		return
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		lease, held, err := s.locks.tryAcquire(leaseCtx, schedulerLeaseKey, 3*interval)
		switch {
		case err != nil:
			s.logger.Warn("oidc credential: scheduler campaign failed", "error", err)
		case !held:
			s.lead(ctx, leaseCtx, lease, interval)
		}
		timer.Reset(interval)
	}
}

// lead refreshes due credentials every interval until ctx ends or the
// leadership lease is lost. A nil lease is a standalone node's permanent
// leadership. leaseCtx is the context the lease's own calls run on.
func (s *Service) lead(ctx, leaseCtx context.Context, lease qrdbsdk.Lease, interval time.Duration) {
	var lost <-chan struct{}
	if lease != nil {
		lost = lease.Done()
		defer func() {
			releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(leaseCtx), interval)
			defer cancel()
			if err := lease.Release(releaseCtx); err != nil {
				s.logger.Debug("oidc credential: scheduler lease release failed", "error", err)
			}
		}()
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if n, err := s.RefreshDue(ctx); err != nil {
			s.logger.Warn("oidc credential: scheduled refresh had failures", "refreshed", n, "error", err)
		} else if n > 0 {
			s.logger.Info("oidc credential: scheduled refresh", "refreshed", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-lost:
			s.logger.Info("oidc credential: scheduler leadership lost")
			return
		case <-ticker.C:
		}
		if lease != nil {
			if err := lease.Renew(leaseCtx); err != nil {
				s.logger.Info("oidc credential: scheduler leadership not renewed", "error", err)
				return
			}
		}
	}
}
