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

package policy

import (
	"context"
	"strings"

	xscope "github.com/jeremyhahn/go-xkms/pkg/scope"
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
// opening the scope: the physical key store for the system scope, and
// Config.TenantKeys scoped to the tenant otherwise. It
// reads blobs only; loading an object still needs ScopeTPM.
func (s *Service) KeyStore(tenant string) (store.KeyBackend, error) {
	name, err := scopeName(tenant)
	if err != nil {
		return nil, err
	}
	if name == xscope.SystemTenant {
		return s.keys, nil
	}
	return s.tenantKeys(name)
}
