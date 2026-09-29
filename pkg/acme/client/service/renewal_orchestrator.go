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

package service

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

const defaultCheckInterval = 24 * time.Hour

// RenewalResult holds the outcome of a single certificate renewal attempt.
type RenewalResult struct {
	Name    string
	Renewed bool
	Error   error
}

// RenewalOrchestrator monitors managed certificates and automatically renews
// those approaching expiration based on their renewal configuration.
type RenewalOrchestrator struct {
	config       *Config
	certificates CertificateManager
	logger       *slog.Logger
	running      atomic.Bool
	stopChan     chan struct{}
	wg           sync.WaitGroup
}

// NewRenewalOrchestrator creates a new RenewalOrchestrator.
func NewRenewalOrchestrator(config *Config, certificates CertificateManager, logger *slog.Logger) *RenewalOrchestrator {
	return &RenewalOrchestrator{
		config:       config,
		certificates: certificates,
		logger:       logger,
		stopChan:     make(chan struct{}),
	}
}

// Start begins the renewal monitoring loop. It checks certificates at the
// configured interval and renews those approaching expiration.
// The default check interval is 24 hours.
func (ro *RenewalOrchestrator) Start(ctx context.Context) error {
	if !ro.running.CompareAndSwap(false, true) {
		return &ErrValidation{Field: "orchestrator", Reason: "already running"}
	}

	ro.wg.Add(1)
	go func() {
		defer ro.wg.Done()

		ticker := time.NewTicker(defaultCheckInterval)
		defer ticker.Stop()

		ro.logger.InfoContext(ctx, "renewal orchestrator started",
			slog.Duration("check_interval", defaultCheckInterval),
		)

		for {
			select {
			case <-ticker.C:
				results := ro.CheckAndRenew(ctx)
				for _, r := range results {
					if r.Error != nil {
						ro.logger.WarnContext(ctx, "certificate renewal failed",
							slog.String("name", r.Name),
							slog.String("error", r.Error.Error()),
						)
						continue
					}
					if r.Renewed {
						ro.logger.InfoContext(ctx, "certificate renewed successfully",
							slog.String("name", r.Name),
						)
					}
				}
			case <-ro.stopChan:
				ro.logger.InfoContext(ctx, "renewal orchestrator stopping")
				return
			case <-ctx.Done():
				ro.logger.InfoContext(ctx, "renewal orchestrator context cancelled")
				return
			}
		}
	}()

	return nil
}

// Stop gracefully shuts down the renewal orchestrator and waits for the
// monitoring goroutine to complete. Stop is safe to call concurrently or
// more than once: only the caller that wins the running-flag CAS closes
// stopChan, so a second Stop (concurrent or subsequent) is a no-op rather
// than a double-close of the channel.
func (ro *RenewalOrchestrator) Stop() error {
	if !ro.running.CompareAndSwap(true, false) {
		return nil
	}
	close(ro.stopChan)
	ro.wg.Wait()
	return nil
}

// Running returns whether the orchestrator is currently active.
func (ro *RenewalOrchestrator) Running() bool {
	return ro.running.Load()
}

// CheckAndRenew performs a single renewal check across all auto-renewable
// certificates. This is useful for testing or manual triggering.
func (ro *RenewalOrchestrator) CheckAndRenew(ctx context.Context) []RenewalResult {
	var results []RenewalResult

	for name, spec := range ro.config.Certificates {
		if spec.Renewal == nil || !spec.Renewal.Auto {
			continue
		}

		info, err := ro.certificates.Show(name)
		if err != nil {
			// Certificate not yet managed; attempt initial request via renewal.
			ro.logger.InfoContext(ctx, "certificate not yet managed, renewing",
				slog.String("name", name),
			)
			_, renewErr := ro.certificates.Renew(ctx, name)
			results = append(results, RenewalResult{
				Name:    name,
				Renewed: renewErr == nil,
				Error:   renewErr,
			})
			continue
		}

		threshold := time.Duration(spec.Renewal.DaysBefore) * 24 * time.Hour
		if info.ExpiresAt.Before(time.Now().Add(threshold)) {
			ro.logger.InfoContext(ctx, "certificate approaching expiration, renewing",
				slog.String("name", name),
				slog.Time("expires_at", info.ExpiresAt),
				slog.Int("days_before", spec.Renewal.DaysBefore),
			)
			_, renewErr := ro.certificates.Renew(ctx, name)
			results = append(results, RenewalResult{
				Name:    name,
				Renewed: renewErr == nil,
				Error:   renewErr,
			})
			continue
		}

		ro.logger.DebugContext(ctx, "certificate does not need renewal",
			slog.String("name", name),
			slog.Time("expires_at", info.ExpiresAt),
		)
	}

	return results
}
