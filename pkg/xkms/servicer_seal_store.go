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

package xkms

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// SealStoreServicer defines operations for the platform-sealed secret store.
//
// The platform store holds platform-global secrets -- backend credentials
// live under credentials/<name> -- sealed by the system barrier, so every
// method is platform-scoped (requirePlatformScope, go-xkms#1226): a
// tenant-scoped caller is refused with a *TenantBindingError that reads as
// not-found, before the store is touched.
type SealStoreServicer interface {
	SealStorePut(ctx context.Context, req *transport.SealStorePutRequest) error
	SealStoreGet(ctx context.Context, req *transport.SealStoreGetRequest) (*transport.SealStoreGetResponse, error)
	SealStoreDelete(ctx context.Context, req *transport.SealStoreDeleteRequest) error
	SealStoreList(ctx context.Context) (*transport.SealStoreListResponse, error)
	SealStoreReseal(ctx context.Context, req *transport.SealStoreResealRequest) error
	SealStoreStatus(ctx context.Context) (*transport.SealStoreStatusResponse, error)
}

// SealStorePut stores a secret in the platform-sealed store.
func (s *XKMSService) SealStorePut(ctx context.Context, req *transport.SealStorePutRequest) error {
	if err := requirePlatformScope(ctx, "seal store put", ""); err != nil {
		return err
	}
	if s.platformStore == nil {
		return ErrNotConfigured
	}
	if req == nil {
		return ErrNilRequest
	}
	return s.platformStore.Put(ctx, req.Name, req.Secret)
}

// SealStoreGet retrieves a secret from the platform-sealed store.
func (s *XKMSService) SealStoreGet(ctx context.Context, req *transport.SealStoreGetRequest) (*transport.SealStoreGetResponse, error) {
	if err := requirePlatformScope(ctx, "seal store get", ""); err != nil {
		return nil, err
	}
	if s.platformStore == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	secret, err := s.platformStore.Get(ctx, req.Name)
	if err != nil {
		return nil, err
	}
	return &transport.SealStoreGetResponse{
		Name:   req.Name,
		Secret: secret,
	}, nil
}

// SealStoreDelete deletes a secret from the platform-sealed store.
func (s *XKMSService) SealStoreDelete(ctx context.Context, req *transport.SealStoreDeleteRequest) error {
	if err := requirePlatformScope(ctx, "seal store delete", ""); err != nil {
		return err
	}
	if s.platformStore == nil {
		return ErrNotConfigured
	}
	if req == nil {
		return ErrNilRequest
	}
	return s.platformStore.Delete(ctx, req.Name)
}

// SealStoreList returns a list of all secrets in the platform-sealed store.
func (s *XKMSService) SealStoreList(ctx context.Context) (*transport.SealStoreListResponse, error) {
	if err := requirePlatformScope(ctx, "seal store list", ""); err != nil {
		return nil, err
	}
	if s.platformStore == nil {
		return nil, ErrNotConfigured
	}
	names, err := s.platformStore.List(ctx)
	if err != nil {
		return nil, err
	}
	return &transport.SealStoreListResponse{
		Names: names,
	}, nil
}

// SealStoreReseal re-seals a secret with updated platform state.
func (s *XKMSService) SealStoreReseal(ctx context.Context, req *transport.SealStoreResealRequest) error {
	if err := requirePlatformScope(ctx, "seal store reseal", ""); err != nil {
		return err
	}
	if s.platformStore == nil {
		return ErrNotConfigured
	}
	if req == nil {
		return ErrNilRequest
	}
	return s.platformStore.Reseal(ctx, req.Name)
}

// SealStoreStatus returns the status of the platform-sealed store.
func (s *XKMSService) SealStoreStatus(ctx context.Context) (*transport.SealStoreStatusResponse, error) {
	if err := requirePlatformScope(ctx, "seal store status", ""); err != nil {
		return nil, err
	}
	if s.platformStore == nil {
		return nil, ErrNotConfigured
	}
	names, err := s.platformStore.List(ctx)
	if err != nil {
		return nil, err
	}
	return &transport.SealStoreStatusResponse{
		Available:   true,
		SecretCount: len(names),
		SecretNames: names,
	}, nil
}
