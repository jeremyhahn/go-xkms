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

package server

import (
	"context"
	"errors"
	"log/slog"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// leaderWait bounds how long boot-time operations wait for the cluster to
// elect a leader before giving up. Standalone nodes are their own leader
// immediately and never wait.
const leaderWait = 90 * time.Second

// retryNotLeader runs op, retrying with capped exponential backoff while it
// fails with the qrdb service layer's not-leader condition. On a cluster,
// boot-time writes against the replicated store race the initial leader
// election; the not-leader error is transient by construction, so bounded
// waiting is correct where failing would abort the boot. Any other error —
// and not-leader past the deadline — is returned to the caller.
func retryNotLeader(ctx context.Context, logger *slog.Logger, what string, op func() error) error {
	deadline := time.Now().Add(leaderWait)
	backoff := 250 * time.Millisecond

	for {
		err := op()
		if err == nil {
			return nil
		}
		if !isNotLeaderErr(err) || time.Now().After(deadline) {
			return err
		}
		logger.Info("waiting for cluster leader",
			slog.String("op", what),
			slog.Duration("backoff", backoff),
			slog.Any("cause", err))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > 2*time.Second {
			backoff = 2 * time.Second
		}
	}
}

// isNotLeaderErr reports whether err is the qrdb service layer's not-leader
// condition, through any wrapping.
func isNotLeaderErr(err error) bool {
	var notLeader *qrdbsdk.NotLeaderError
	return errors.As(err, &notLeader)
}
