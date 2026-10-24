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

package usb

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// The repository signing-key API (go-xkms#1697) administers a tenant's
// bindings on a server; a USB device holds none, so it is not available
// over USB.

// SetSigningKeyBinding is not available over USB.
func (t *Transport) SetSigningKeyBinding(_ context.Context, _ *transport.SetSigningKeyBindingRequest) (*transport.SigningKeyBinding, error) {
	return nil, ErrNotSupported
}

// GetSigningKeyBinding is not available over USB.
func (t *Transport) GetSigningKeyBinding(_ context.Context, _ *transport.GetSigningKeyBindingRequest) (*transport.SigningKeyBinding, error) {
	return nil, ErrNotSupported
}

// ListSigningKeyBindings is not available over USB.
func (t *Transport) ListSigningKeyBindings(_ context.Context) (*transport.ListSigningKeyBindingsResponse, error) {
	return nil, ErrNotSupported
}

// DeleteSigningKeyBinding is not available over USB.
func (t *Transport) DeleteSigningKeyBinding(_ context.Context, _ *transport.DeleteSigningKeyBindingRequest) error {
	return ErrNotSupported
}

// ResolveSigningKey is not available over USB.
func (t *Transport) ResolveSigningKey(_ context.Context, _ *transport.ResolveSigningKeyRequest) (*transport.SigningKeyResolution, error) {
	return nil, ErrNotSupported
}

// SignCoRIM is not available over USB.
func (t *Transport) SignCoRIM(_ context.Context, _ *transport.SignCoRIMRequest) (*transport.SignedCoRIM, error) {
	return nil, ErrNotSupported
}
