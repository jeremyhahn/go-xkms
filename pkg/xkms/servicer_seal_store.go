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
	credentialspkg "github.com/jeremyhahn/go-xkms/pkg/server/credentials"
)

// SealStoreServicer defines operations for the platform-sealed secret store.
//
// The platform store holds platform-global secrets sealed by the system
// barrier, so every method is platform-scoped (requireSystemTenant,
// go-xkms#1226): a tenant-scoped caller is refused with a *TenantBindingError
// that reads as not-found, before the store is touched.
//
// The same store also holds the backend credentials of the hardware and
// cloud credential strategies, under credentials/<name>. That namespace is
// not part of platform secrets (go-xkms#1465): a name inside it is refused
// with ErrReservedSecretName, and List and Status leave it out, so a
// credential's value stays write-only and is read only by the credentials
// service.
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
	platformStore := s.platformStore.load()
	if err := requireSystemTenant(ctx, "seal store put", ""); err != nil {
		return err
	}
	if platformStore == nil {
		return ErrNotConfigured
	}
	if req == nil {
		return ErrNilRequest
	}
	if err := requirePlatformSecretName(req.Name); err != nil {
		return err
	}
	return platformStore.Put(ctx, req.Name, req.Secret)
}

// SealStoreGet retrieves a secret from the platform-sealed store.
func (s *XKMSService) SealStoreGet(ctx context.Context, req *transport.SealStoreGetRequest) (*transport.SealStoreGetResponse, error) {
	platformStore := s.platformStore.load()
	if err := requireSystemTenant(ctx, "seal store get", ""); err != nil {
		return nil, err
	}
	if platformStore == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	if err := requirePlatformSecretName(req.Name); err != nil {
		return nil, err
	}
	secret, err := platformStore.Get(ctx, req.Name)
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
	platformStore := s.platformStore.load()
	if err := requireSystemTenant(ctx, "seal store delete", ""); err != nil {
		return err
	}
	if platformStore == nil {
		return ErrNotConfigured
	}
	if req == nil {
		return ErrNilRequest
	}
	if err := requirePlatformSecretName(req.Name); err != nil {
		return err
	}
	return platformStore.Delete(ctx, req.Name)
}

// SealStoreList returns the names of the platform secrets in the
// platform-sealed store, without the backend-credential namespace.
func (s *XKMSService) SealStoreList(ctx context.Context) (*transport.SealStoreListResponse, error) {
	platformStore := s.platformStore.load()
	if err := requireSystemTenant(ctx, "seal store list", ""); err != nil {
		return nil, err
	}
	if platformStore == nil {
		return nil, ErrNotConfigured
	}
	names, err := platformStore.List(ctx)
	if err != nil {
		return nil, err
	}
	return &transport.SealStoreListResponse{
		Names: platformSecretNames(names),
	}, nil
}

// SealStoreReseal re-seals a secret with updated platform state.
func (s *XKMSService) SealStoreReseal(ctx context.Context, req *transport.SealStoreResealRequest) error {
	platformStore := s.platformStore.load()
	if err := requireSystemTenant(ctx, "seal store reseal", ""); err != nil {
		return err
	}
	if platformStore == nil {
		return ErrNotConfigured
	}
	if req == nil {
		return ErrNilRequest
	}
	if err := requirePlatformSecretName(req.Name); err != nil {
		return err
	}
	return platformStore.Reseal(ctx, req.Name)
}

// SealStoreStatus returns the status of the platform-sealed store, counting
// the platform secrets only.
func (s *XKMSService) SealStoreStatus(ctx context.Context) (*transport.SealStoreStatusResponse, error) {
	platformStore := s.platformStore.load()
	if err := requireSystemTenant(ctx, "seal store status", ""); err != nil {
		return nil, err
	}
	if platformStore == nil {
		return nil, ErrNotConfigured
	}
	names, err := platformStore.List(ctx)
	if err != nil {
		return nil, err
	}
	names = platformSecretNames(names)
	return &transport.SealStoreStatusResponse{
		Available:   true,
		SecretCount: len(names),
		SecretNames: names,
	}, nil
}

// requirePlatformSecretName refuses a name inside the backend-credential
// namespace with ErrReservedSecretName.
func requirePlatformSecretName(name string) error {
	if credentialspkg.InNamespace(name) {
		return ErrReservedSecretName
	}
	return nil
}

// platformSecretNames returns names without the backend-credential namespace.
func platformSecretNames(names []string) []string {
	visible := make([]string, 0, len(names))
	for _, name := range names {
		if !credentialspkg.InNamespace(name) {
			visible = append(visible, name)
		}
	}
	return visible
}
