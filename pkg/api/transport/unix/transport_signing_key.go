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

package unix

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/api/grpc/pbconv"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// The repository signing-key API is served by pbconv.SigningKeyClient,
// shared by the gRPC and Unix-socket transports, once this transport holds
// a connection.

// signingKeys returns the shared signing-key client over this transport's
// connection, or ErrNotConnected before it holds one.
func (t *Transport) signingKeys() (pbconv.SigningKeyClient, error) {
	if t.client == nil {
		return pbconv.SigningKeyClient{}, ErrNotConnected
	}
	return pbconv.SigningKeyClient{Client: t.client}, nil
}

// SetSigningKeyBinding names the key that signs a repository.
func (t *Transport) SetSigningKeyBinding(ctx context.Context, req *transport.SetSigningKeyBindingRequest) (*transport.SigningKeyBinding, error) {
	c, err := t.signingKeys()
	if err != nil {
		return nil, err
	}
	return c.SetSigningKeyBinding(ctx, req)
}

// GetSigningKeyBinding returns a repository's binding.
func (t *Transport) GetSigningKeyBinding(ctx context.Context, req *transport.GetSigningKeyBindingRequest) (*transport.SigningKeyBinding, error) {
	c, err := t.signingKeys()
	if err != nil {
		return nil, err
	}
	return c.GetSigningKeyBinding(ctx, req)
}

// ListSigningKeyBindings returns the caller's tenant's bindings.
func (t *Transport) ListSigningKeyBindings(ctx context.Context) (*transport.ListSigningKeyBindingsResponse, error) {
	c, err := t.signingKeys()
	if err != nil {
		return nil, err
	}
	return c.ListSigningKeyBindings(ctx)
}

// DeleteSigningKeyBinding removes a repository's binding.
func (t *Transport) DeleteSigningKeyBinding(ctx context.Context, req *transport.DeleteSigningKeyBindingRequest) error {
	c, err := t.signingKeys()
	if err != nil {
		return err
	}
	return c.DeleteSigningKeyBinding(ctx, req)
}

// ResolveSigningKey returns the key that signs a repository.
func (t *Transport) ResolveSigningKey(ctx context.Context, req *transport.ResolveSigningKeyRequest) (*transport.SigningKeyResolution, error) {
	c, err := t.signingKeys()
	if err != nil {
		return nil, err
	}
	return c.ResolveSigningKey(ctx, req)
}
