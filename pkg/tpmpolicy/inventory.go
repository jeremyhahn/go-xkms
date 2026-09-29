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

package tpmpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
)

// reservedPrefixes are the CN prefixes of the objects the service itself
// keeps in a scope's key store: storage keys, policy authorities, sealed
// scope secrets and vTPM state keys. They are infrastructure, never a
// caller's key.
var reservedPrefixes = []string{storageKeyCN, authorityCNPrefix, secretsCNPrefix, stateKeyCNPrefix}

// IsReservedObject reports whether cn names an object the service keeps for
// itself in a scope's key store. A key listing must not offer such an object
// to a caller, who could otherwise delete a scope's authority or secrets.
func IsReservedObject(cn string) bool {
	for _, prefix := range reservedPrefixes {
		if strings.HasPrefix(cn, prefix) {
			return true
		}
	}
	return false
}

// Scopes returns the names of every scope with a scope record, sorted.
func (r *Registry) Scopes(ctx context.Context) ([]string, error) {
	keys, err := r.store.List(ctx, "")
	if err != nil {
		return nil, &StoreError{Op: "list", Key: "", Err: err}
	}
	suffix := registryPrefix + scopeKey
	var out []string
	for _, k := range keys {
		if scope, ok := strings.CutSuffix(k, suffix); ok && scope != "" && !strings.Contains(scope, "/") {
			out = append(out, scope)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Assignments returns every assignment recorded in tenant's scope, sorted by
// object ID.
func (r *Registry) Assignments(ctx context.Context, tenant string) ([]*Assignment, error) {
	prefix, err := key(tenant, objectsPrefix)
	if err != nil {
		return nil, err
	}
	var out []*Assignment
	err = r.store.Scan(ctx, prefix, func(k string, v []byte) error {
		var a Assignment
		if err := json.Unmarshal(v, &a); err != nil {
			return &StoreError{Op: "decode", Key: k, Err: err}
		}
		out = append(out, &a)
		return nil
	})
	if err != nil {
		var storeErr *StoreError
		if errors.As(err, &storeErr) {
			return nil, err
		}
		return nil, &StoreError{Op: "scan", Key: prefix, Err: err}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ObjectID < out[j].ObjectID })
	return out, nil
}

// Scopes returns the names of every scope the service has created, sorted:
// "system" and each tenant with a TPM scope.
func (s *Service) Scopes(ctx context.Context) ([]string, error) {
	return s.registry.Scopes(ctx)
}

// Assignments returns every object assignment of tenant's scope, sorted by
// object ID. It reads the registry only, so it answers for a tenant whose
// mode is none (with no assignments) rather than refusing.
func (s *Service) Assignments(ctx context.Context, tenant string) ([]*Assignment, error) {
	name, err := scopeName(tenant)
	if err != nil {
		return nil, err
	}
	return s.registry.Assignments(ctx, name)
}

// KeyStore returns the key store holding tenant's object blobs without
// opening the scope: the physical key store for the system scope, and the
// tenant's "<tenant>/tpm/keys/" prefix of Config.KeyStorage otherwise. It
// reads blobs only; loading an object still needs ScopeTPM.
func (s *Service) KeyStore(tenant string) (store.KeyBackend, error) {
	name, err := scopeName(tenant)
	if err != nil {
		return nil, err
	}
	if name == systemScopeName {
		return s.keys, nil
	}
	return s.tenantKeys(name)
}
