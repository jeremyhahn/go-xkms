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

package server

import (
	qrdbsecret "github.com/jeremyhahn/go-qrdb/sdk/go/secret"
)

// buildSecretRegistry constructs the server's secret resolver registry for
// resolving URI-addressed secrets at startup. When the credential service
// is available, a credential:// resolver backed by that service is registered.
// Literal passthrough is automatic via the registry's fallback behaviour.
//
// The CA is system-scoped, so only the system credential service is wired here;
// per-tenant credential routing is not required for CA key passwords.
func (s *Server) buildSecretRegistry() *qrdbsecret.ResolverRegistry {
	reg := qrdbsecret.NewResolverRegistry()
	if svc := s.CredentialService(); svc != nil {
		reg.Register(qrdbsecret.NewCredentialResolver(svc.RetrieveCredential))
	}
	return reg
}
