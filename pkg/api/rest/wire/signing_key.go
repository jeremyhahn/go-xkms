// Copyright (c) 2026 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-or-later

package wire

import (
	"context"
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// SigningKeysPath is the collection of the caller's tenant's repository
// signing-key bindings. A repository path holds slashes ("org/app"), so the
// routes that name one carry it in the repository query parameter.
const SigningKeysPath = "/api/v1/attestation/signing-keys"

// SigningKeyBindingPath is a repository's binding; SigningKeyResolvePath is
// the key that signs a repository; SigningKeySignCoRIMPath signs a
// repository's CoRIM with that key and SigningKeySignImagePath an image of
// the repository.
const (
	SigningKeyBindingPath   = SigningKeysPath + "/binding"
	SigningKeyResolvePath   = SigningKeysPath + "/resolve"
	SigningKeySignCoRIMPath = SigningKeysPath + "/sign-corim"
	SigningKeySignImagePath = SigningKeysPath + "/sign-image"
)

// SigningKeyRepositoryParam names the repository on the routes that take
// one.
const SigningKeyRepositoryParam = "repository"

// signingKeyPath returns path naming repository.
func signingKeyPath(path, repository string) string {
	return withQuery(path, map[string]string{SigningKeyRepositoryParam: repository})
}

// Compile-time check that the client serves the whole signing-key API.
var _ transport.SigningKeyService = SigningKeyClient{}

// SigningKeyClient serves transport.SigningKeyService over the REST routes.
// The REST and QUIC transports (QUIC serves the same router over HTTP/3)
// delegate to it with their own Requester.
type SigningKeyClient struct {
	// Do performs the requests.
	Do Requester
}

// SetSigningKeyBinding names the key that signs a repository.
func (c SigningKeyClient) SetSigningKeyBinding(ctx context.Context, req *transport.SetSigningKeyBindingRequest) (*transport.SigningKeyBinding, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.SigningKeyBinding
	if err := callJSON(ctx, c.Do, http.MethodPut, SigningKeysPath, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetSigningKeyBinding returns a repository's binding.
func (c SigningKeyClient) GetSigningKeyBinding(ctx context.Context, req *transport.GetSigningKeyBindingRequest) (*transport.SigningKeyBinding, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.SigningKeyBinding
	if err := callJSON(ctx, c.Do, http.MethodGet, signingKeyPath(SigningKeyBindingPath, req.Repository), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ListSigningKeyBindings returns the caller's tenant's bindings.
func (c SigningKeyClient) ListSigningKeyBindings(ctx context.Context) (*transport.ListSigningKeyBindingsResponse, error) {
	var resp transport.ListSigningKeyBindingsResponse
	if err := callJSON(ctx, c.Do, http.MethodGet, SigningKeysPath, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DeleteSigningKeyBinding removes a repository's binding.
func (c SigningKeyClient) DeleteSigningKeyBinding(ctx context.Context, req *transport.DeleteSigningKeyBindingRequest) error {
	if req == nil {
		return ErrNilRequest
	}
	return callJSON(ctx, c.Do, http.MethodDelete, signingKeyPath(SigningKeyBindingPath, req.Repository), nil, nil)
}

// ResolveSigningKey returns the key that signs a repository.
func (c SigningKeyClient) ResolveSigningKey(ctx context.Context, req *transport.ResolveSigningKeyRequest) (*transport.SigningKeyResolution, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.SigningKeyResolution
	if err := callJSON(ctx, c.Do, http.MethodGet, signingKeyPath(SigningKeyResolvePath, req.Repository), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// SignCoRIM signs a repository's CoRIM with the key that signs the
// repository.
func (c SigningKeyClient) SignCoRIM(ctx context.Context, req *transport.SignCoRIMRequest) (*transport.SignedCoRIM, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.SignedCoRIM
	if err := callJSON(ctx, c.Do, http.MethodPost, SigningKeySignCoRIMPath, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// SignImage signs an image with the key that signs its repository.
func (c SigningKeyClient) SignImage(ctx context.Context, req *transport.SignImageRequest) (*transport.SignedImage, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.SignedImage
	if err := callJSON(ctx, c.Do, http.MethodPost, SigningKeySignImagePath, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
