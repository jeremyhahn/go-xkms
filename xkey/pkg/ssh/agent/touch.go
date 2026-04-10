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

package agent

import "context"

// TouchHandler handles touch confirmation requests for SSH signing operations.
type TouchHandler interface {
	// RequestTouch requests user confirmation for a signing operation.
	// operation describes what is being signed (e.g., "ssh-sign").
	// keyID identifies the key being used.
	// Returns nil if touch was confirmed, error otherwise.
	RequestTouch(ctx context.Context, operation, keyID string) error
}

// NoOpTouchHandler is a TouchHandler that always approves without user interaction.
type NoOpTouchHandler struct{}

// RequestTouch always returns nil (auto-approve).
func (h *NoOpTouchHandler) RequestTouch(ctx context.Context, operation, keyID string) error {
	return nil
}
