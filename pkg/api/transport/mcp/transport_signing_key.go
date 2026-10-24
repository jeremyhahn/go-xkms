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

package mcp

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// The repository signing-key API (go-xkms#1697) over the MCP JSON-RPC
// methods attestation.signing_key.*.

// SetSigningKeyBinding names the key that signs a repository.
func (t *Transport) SetSigningKeyBinding(ctx context.Context, req *transport.SetSigningKeyBindingRequest) (*transport.SigningKeyBinding, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var resp transport.SigningKeyBinding
	if err := t.rpcCall(ctx, "attestation.signing_key.set", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetSigningKeyBinding returns a repository's binding.
func (t *Transport) GetSigningKeyBinding(ctx context.Context, req *transport.GetSigningKeyBindingRequest) (*transport.SigningKeyBinding, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var resp transport.SigningKeyBinding
	if err := t.rpcCall(ctx, "attestation.signing_key.get", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ListSigningKeyBindings returns the caller's tenant's bindings.
func (t *Transport) ListSigningKeyBindings(ctx context.Context) (*transport.ListSigningKeyBindingsResponse, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var resp transport.ListSigningKeyBindingsResponse
	if err := t.rpcCall(ctx, "attestation.signing_key.list", struct{}{}, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DeleteSigningKeyBinding removes a repository's binding.
func (t *Transport) DeleteSigningKeyBinding(ctx context.Context, req *transport.DeleteSigningKeyBindingRequest) error {
	if !t.IsConnected() {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "attestation.signing_key.delete", req, nil)
}

// ResolveSigningKey returns the key that signs a repository.
func (t *Transport) ResolveSigningKey(ctx context.Context, req *transport.ResolveSigningKeyRequest) (*transport.SigningKeyResolution, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var resp transport.SigningKeyResolution
	if err := t.rpcCall(ctx, "attestation.signing_key.resolve", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
