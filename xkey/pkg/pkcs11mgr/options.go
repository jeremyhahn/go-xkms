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

package pkcs11mgr

import (
	"log/slog"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/backendregistry"
)

// Option is a functional option for configuring the Manager.
type Option func(*options)

// options holds the resolved configuration for the Manager.
type options struct {
	registry backendregistry.Registry
	logger   *slog.Logger
}

// WithRegistry configures the Manager to auto-register each discovered slot
// as a RegisteredBackend in the given registry.
func WithRegistry(r backendregistry.Registry) Option {
	return func(o *options) {
		o.registry = r
	}
}

// WithLogger configures the Manager to use the given structured logger.
func WithLogger(l *slog.Logger) Option {
	return func(o *options) {
		o.logger = l
	}
}
