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

package client

// ErrServerStart indicates the embedded API server failed to start.
type ErrServerStart struct {
	Detail string
}

// Error returns the error message.
func (e *ErrServerStart) Error() string {
	return "gui/client: server start failed: " + e.Detail
}

// ErrServerShutdown indicates the embedded API server failed to shut down.
type ErrServerShutdown struct {
	Detail string
}

// Error returns the error message.
func (e *ErrServerShutdown) Error() string {
	return "gui/client: server shutdown failed: " + e.Detail
}

// ErrInvalidConfig indicates the GUI configuration is invalid.
type ErrInvalidConfig struct {
	Detail string
}

// Error returns the error message.
func (e *ErrInvalidConfig) Error() string {
	return "gui/client: invalid config: " + e.Detail
}
