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

package authenticator

import (
	"context"
	"sync/atomic"
)

// blockingPresenceHandler is a UserPresenceHandler that never answers: a
// presence request blocks until its context is cancelled, the way a daemon
// waiting on an out-of-band approval does. It lets tests prove that context
// cancellation (CTAPHID_CANCEL, a cancelled ProcessCBORWithContext) aborts a
// pending presence request.
type blockingPresenceHandler struct {
	pending atomic.Int32
}

func (h *blockingPresenceHandler) RequestUserPresence(ctx context.Context, _ *UserPresenceRequest) (*UserPresenceResult, error) {
	h.pending.Add(1)
	defer h.pending.Add(-1)
	<-ctx.Done()
	return nil, ctx.Err()
}

func (h *blockingPresenceHandler) RequestUserVerification(context.Context, *UserVerificationRequest) (*UserVerificationResult, error) {
	return nil, ErrTerminalUnavailable
}

// HasPending reports whether a presence request is currently blocked.
func (h *blockingPresenceHandler) HasPending() bool {
	return h.pending.Load() > 0
}

var _ UserPresenceHandler = (*blockingPresenceHandler)(nil)
