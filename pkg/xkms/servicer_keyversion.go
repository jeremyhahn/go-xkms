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

package xkms

import (
	"context"
	"sort"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/keyversion"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Compile-time check that XKMSService serves the key-version API.
var _ transport.KeyVersionServicer = (*XKMSService)(nil)

// ListKeyVersions lists a key's versions, oldest first, with each version's
// state and, for a version that still has key material, its public key. A
// key that was never rotated lists version 1 alone.
func (s *XKMSService) ListKeyVersions(ctx context.Context, req *transport.ListKeyVersionsRequest) (*transport.ListKeyVersionsResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	k, err := s.resolveKeyIn(ctx, req.Backend, req.TenantID, req.KeyID)
	if err != nil {
		return nil, err
	}

	resp := &transport.ListKeyVersionsResponse{
		KeyID:          k.keyID,
		Backend:        k.backendName,
		CurrentVersion: k.record.Current,
		Versions:       make([]transport.KeyVersionInfo, 0, len(k.record.Versions)),
	}
	for _, v := range k.record.Versions {
		info := transport.KeyVersionInfo{
			Version:   v.Number,
			State:     string(v.State),
			Current:   v.Number == k.record.Current,
			CreatedAt: formatTPMTime(v.CreatedAt),
			CreatedBy: v.CreatedBy,
		}
		if attrs, ok := k.present[v.Number]; ok && v.State != keyversion.StateRetired {
			info.PublicKeyPEM = publicKeyPEMOf(ctx, k.backend, attrs)
		}
		resp.Versions = append(resp.Versions, info)
	}
	return resp, nil
}

// EnableKeyVersion enables a disabled version of a key, so operations may
// use it again. A retired version is refused with
// *keyversion.RetiredVersionError.
func (s *XKMSService) EnableKeyVersion(ctx context.Context, req *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	return s.setKeyVersionState(ctx, req, keyversion.StateEnabled)
}

// DisableKeyVersion disables a version of a key: no operation may use it
// until it is enabled again, and its key material is kept. The current
// version is refused with *keyversion.CurrentVersionError; rotate first.
func (s *XKMSService) DisableKeyVersion(ctx context.Context, req *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	return s.setKeyVersionState(ctx, req, keyversion.StateDisabled)
}

// setKeyVersionState sets the state of the version req names, recording the
// change when there is one.
func (s *XKMSService) setKeyVersionState(ctx context.Context, req *transport.KeyVersionRequest, state keyversion.State) (*transport.KeyVersionStateResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var changed bool
	k, err := s.updateVersions(ctx, req.Backend, req.TenantID, req.KeyID, func(k *versionedKey) (bool, error) {
		var err error
		changed, err = k.record.SetState(req.Version, state)
		return changed, err
	})
	if err != nil {
		return nil, err
	}
	return &transport.KeyVersionStateResponse{KeyID: k.keyID, Version: req.Version, State: string(state), Changed: changed}, nil
}

// RetireKeyVersion retires a version of a key: its backend key is deleted
// and the version can never be used or enabled again. The current version is
// refused with *keyversion.CurrentVersionError; rotate first.
func (s *XKMSService) RetireKeyVersion(ctx context.Context, req *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	k, err := s.updateVersions(ctx, req.Backend, req.TenantID, req.KeyID, func(k *versionedKey) (bool, error) {
		if err := k.record.Retire(req.Version); err != nil {
			return false, err
		}
		// The key material goes before the record says so. Should the
		// record then fail to store, the version's key is gone while its
		// record still lists it; a retry finds no key to delete and records
		// the retirement.
		if attrs, ok := k.present[req.Version]; ok {
			if err := k.backend.DeleteKey(ctx, attrs); err != nil {
				return false, &ErrKeyOperation{Operation: "retire key version", KeyID: keyversion.Name(k.keyID, req.Version), Err: err}
			}
		}
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	return &transport.KeyVersionStateResponse{KeyID: k.keyID, Version: req.Version, State: string(keyversion.StateRetired), Changed: true}, nil
}

// EnableAllKeyVersions enables every disabled version of a key. Retired
// versions are not touched.
func (s *XKMSService) EnableAllKeyVersions(ctx context.Context, req *transport.AllKeyVersionsRequest) (*transport.AllKeyVersionsResponse, error) {
	return s.setAllKeyVersions(ctx, req, keyversion.StateEnabled)
}

// DisableAllKeyVersions disables every enabled version of a key except the
// current one, which sign and encrypt keep using.
func (s *XKMSService) DisableAllKeyVersions(ctx context.Context, req *transport.AllKeyVersionsRequest) (*transport.AllKeyVersionsResponse, error) {
	return s.setAllKeyVersions(ctx, req, keyversion.StateDisabled)
}

// setAllKeyVersions sets every version of the key req names that can take
// state to it.
func (s *XKMSService) setAllKeyVersions(ctx context.Context, req *transport.AllKeyVersionsRequest, state keyversion.State) (*transport.AllKeyVersionsResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var changed []uint32
	k, err := s.updateVersions(ctx, req.Backend, req.TenantID, req.KeyID, func(k *versionedKey) (bool, error) {
		changed = k.record.SetAll(state)
		return len(changed) > 0, nil
	})
	if err != nil {
		return nil, err
	}
	if changed == nil {
		changed = []uint32{}
	}
	return &transport.AllKeyVersionsResponse{KeyID: k.keyID, State: string(state), Versions: changed, Count: len(changed)}, nil
}

// updateVersions runs change on the record of the key keyID names, under
// the key's lock, and stores the record when change reports a change. The
// store is required, so a change the caller cannot persist is never
// reported as made.
func (s *XKMSService) updateVersions(ctx context.Context, backendName, tenantID, keyID string, change func(*versionedKey) (bool, error)) (*versionedKey, error) {
	b, resolvedName, err := s.resolveTenantBackendWithName(backendName, tenantID)
	if err != nil {
		return nil, err
	}
	k, err := s.resolveKey(ctx, b, resolvedName, keyID)
	if err != nil {
		return nil, err
	}
	store, err := s.requireVersionStore()
	if err != nil {
		return nil, err
	}

	unlock := store.Lock(k.tenant, resolvedName, keyID)
	defer unlock()
	if k, err = s.resolveKey(ctx, b, resolvedName, keyID); err != nil {
		return nil, err
	}

	changed, err := change(k)
	if err != nil {
		return nil, err
	}
	if changed {
		if err := store.Put(ctx, k.tenant, k.record); err != nil {
			return nil, err
		}
	}
	return k, nil
}

// RotateScopeKeys rotates every key of a tenant -- in every backend, each
// key once however many versions it has -- and reports each key's result. A
// key that cannot be rotated is reported and the rest are still rotated.
//
// A tenant-scoped caller rotates its own tenant; only a system caller may
// name another, and a system caller naming none rotates the system tenant's
// own keys. Naming another tenant without system scope is refused with
// *TenantBindingError.
func (s *XKMSService) RotateScopeKeys(ctx context.Context, req *transport.RotateScopeKeysRequest) (*transport.RotateScopeKeysResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	tenant, err := targetTenant(ctx, "rotate scope keys", req.TenantID)
	if err != nil {
		return nil, err
	}
	if _, err := s.requireVersionStore(); err != nil {
		return nil, err
	}
	tenant = recordTenant(tenant)

	resp := &transport.RotateScopeKeysResponse{TenantID: keyversion.TenantSegment(tenant), Results: []transport.KeyRotationResult{}}
	for _, name := range s.sortedBackendNames() {
		base, err := s.LookupBackend(name)
		if err != nil {
			return nil, err
		}
		b, err := ScopeBackendToTenant(base, tenant)
		if err != nil {
			return nil, err
		}
		keys, err := b.ListKeys(ctx)
		if err != nil {
			resp.Results = append(resp.Results, transport.KeyRotationResult{Backend: name, Error: err.Error()})
			resp.Failed++
			continue
		}
		for _, keyID := range tenantKeyIDs(keys, tenant) {
			result := transport.KeyRotationResult{Backend: name, KeyID: keyID}
			rotated, err := s.rotateKey(ctx, b, name, keyID)
			if err != nil {
				result.Error = err.Error()
				resp.Failed++
			} else {
				result.KeyVersion = rotated.version
				resp.Rotated++
			}
			resp.Results = append(resp.Results, result)
		}
	}
	return resp, nil
}

// tenantKeyIDs returns the IDs of tenant's keys among keys, each once and
// sorted, folding every version's backend key into its key.
func tenantKeyIDs(keys []*types.KeyAttributes, tenant string) []string {
	seen := make(map[string]struct{})
	for _, attrs := range keys {
		if attrs == nil || recordTenant(attrs.TenantID) != tenant {
			continue
		}
		seen[keyversion.BaseKeyID(attrs.CN)] = struct{}{}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// sortedBackendNames returns the names of the full-service backends, sorted.
func (s *XKMSService) sortedBackendNames() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	names := make([]string, 0, len(s.backends))
	for name := range s.backends {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
