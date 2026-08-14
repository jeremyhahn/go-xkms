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

package rest

import (
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/api/initgate"
)

// publicCeremonyPaths is the exact-match allowlist of init ceremony routes an
// officer may reach without an established credential. It is derived from the
// canonical transport-neutral table in pkg/api/initgate — never hand-edited —
// so the REST, QUIC and MCP exemptions cannot drift apart. See the initgate
// package documentation for the full rationale: why each claim route may skip
// *account* authentication (challenge-response against the officer's
// pre-submitted CSR key, mTLS peer-thumbprint matching on the share-claim
// routes, SPKI-pinned transport) and why sign-csr is deliberately excluded.
//
// The map is keyed on the FULL request path and matched exactly. Prefix
// matching is deliberately avoided: "/api/v1/init" as a prefix would also
// exempt hypothetical routes such as "/api/v1/initialize".
var publicCeremonyPaths = initgate.HTTPPublicPaths()

// isPublicCeremonyRequest reports whether r may skip authentication because it
// targets an init ceremony route that a credential-less officer must be able
// to reach while the ceremony is still in progress.
//
// The check fails closed on every axis: no ceremony service wired, a path that
// is not an exact allowlist match, a percent-encoded path whose escaped form
// differs from the decoded form (so the path this function inspects can never
// diverge from the path chi routes on), or a ceremony that has already reached
// the operational state.
func (s *Server) isPublicCeremonyRequest(r *http.Request) bool {
	if s.initHandlers == nil || s.initHandlers.ceremony == nil {
		return false
	}

	path, ok := unescapedRequestPath(r)
	if !ok {
		return false
	}
	if !publicCeremonyPaths[path] {
		return false
	}

	// The exemption applies only while the ceremony is pre-operational;
	// initgate.PreOperational fails closed on any state it does not name.
	return initgate.PreOperational(s.initHandlers.ceremony.State())
}

// unescapedRequestPath returns the request path when, and only when, its
// escaped form is identical to its decoded form. chi routes on URL.RawPath
// whenever that field is populated, so a request carrying percent-encoding
// could otherwise be compared against one string and routed with another. Such
// requests are reported as not-comparable and are handled as non-public.
func unescapedRequestPath(r *http.Request) (string, bool) {
	if r.URL.RawPath != "" {
		return "", false
	}
	return r.URL.Path, true
}
