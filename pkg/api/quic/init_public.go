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

package quic

import (
	"net/http"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/initgate"
	"github.com/jeremyhahn/go-xkms/pkg/audit"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// publicCeremonyPaths is the exact-match allowlist of init ceremony routes an
// officer may reach without an established *account*. It is derived from the
// canonical transport-neutral table in pkg/api/initgate — never hand-edited —
// so the REST, QUIC and MCP exemptions cannot drift apart. The QUIC transport
// mounts the same /api/v1/init HTTP surface as REST, so both consume the same
// derivation.
//
// The two claim-share routes additionally require a client certificate: the
// handlers derive the caller's thumbprint from the verified mTLS peer chain
// and match it against the officer's enrolment record before issuing a nonce
// or releasing a share. Naming an enrolled officer buys nothing.
//
// sign-csr is deliberately absent (initgate.Exclusions): it requires the SO
// PIN and is invoked by an already-enrolled operator, so it stays
// authenticated and authorized.
var publicCeremonyPaths = initgate.HTTPPublicPaths()

// isPublicCeremonyRequest reports whether r targets an init ceremony route
// that a credential-less officer must be able to reach while the ceremony is
// still in progress.
//
// The check fails closed on every axis: no XKMS service wired, no ceremony
// service behind it, a percent-encoded path (whose escaped form the mux may
// route on instead of the decoded form this function inspects), a path that is
// not an exact allowlist match, or a ceremony that has already reached the
// operational state.
func (s *Server) isPublicCeremonyRequest(r *http.Request) bool {
	if s.xkmsService == nil {
		return false
	}
	if r.URL.RawPath != "" {
		return false
	}
	if !publicCeremonyPaths[r.URL.Path] {
		return false
	}

	status, err := s.xkmsService.GetInitStatus(r.Context())
	if err != nil || status == nil {
		return false
	}
	// The exemption applies only while the ceremony is pre-operational;
	// initgate.PreOperationalName fails closed on any state it does not name.
	return initgate.PreOperationalName(status.State)
}

// authorizeCeremony gates an init ceremony route. Requests that qualify as
// public ceremony requests bypass the authorizer but are still audited, so the
// unauthenticated enrollment traffic leaves the same trail as every other
// privileged operation. All other requests take the ordinary authorize path.
func (s *Server) authorizeCeremony(w http.ResponseWriter, r *http.Request, action string) bool {
	if !s.isPublicCeremonyRequest(r) {
		return s.authorize(w, r, auth.ResourceCeremony, action)
	}

	// Best effort: an audit sink failure must not break the ceremony, and the
	// authorize() path discards the same error for the same reason.
	_ = s.auditLogger.Log(r.Context(), &audit.Event{
		Timestamp:  time.Now(),
		Action:     action,
		Resource:   auth.ResourceCeremony,
		ResourceID: r.URL.Path,
		Outcome:    audit.OutcomeAllow,
		Details: map[string]string{
			"method":      r.Method,
			"remote_addr": r.RemoteAddr,
			"reason":      "init ceremony public claim endpoint",
		},
	})
	return true
}
