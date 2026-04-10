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

package notify

import (
	"log/slog"
	"sync/atomic"
)

// LogNotifier sends touch-required notifications via structured logging.
// It is always available and serves as a reliable fallback when desktop
// notification systems are unavailable.
type LogNotifier struct {
	logger *slog.Logger
	closed atomic.Bool
}

// NewLogNotifier creates a LogNotifier that writes notifications to the
// provided slog.Logger.
func NewLogNotifier(logger *slog.Logger) *LogNotifier {
	return &LogNotifier{
		logger: logger,
	}
}

// NotifyTouchRequired logs a touch-required notification at Warn level with
// structured fields describing the operation, relying party, and user.
func (n *LogNotifier) NotifyTouchRequired(req *TouchRequest) error {
	if n.closed.Load() {
		return ErrNotifierClosed
	}

	display := req.RPName
	if display == "" {
		display = req.RPID
	}

	n.logger.Warn("Touch required",
		slog.String("operation", req.Operation),
		slog.String("rp_id", req.RPID),
		slog.String("rp_name", req.RPName),
		slog.String("user", req.UserName),
		slog.String("display", display),
	)
	return nil
}

// Close is a no-op for LogNotifier since slog loggers do not require cleanup.
// Subsequent calls to NotifyTouchRequired will return ErrNotifierClosed.
func (n *LogNotifier) Close() error {
	n.closed.Store(true)
	return nil
}
