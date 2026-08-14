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

package rest

import "net/http"

// capabilitiesResponse is the unauthenticated capability discovery document
// served at GET /api/v1/capabilities. It carries ONLY the coarse flags a
// login page needs to render its authentication options; anything beyond
// that would let an anonymous scanner fingerprint the deployment. The full
// capability map is served to authenticated callers at /api/v1/auth/me
// (see capabilityFlags in handlers_auth.go).
type capabilitiesResponse struct {
	Version         string `json:"version"`
	WebAuthnEnabled bool   `json:"webauthn_enabled"`
	PIVLoginEnabled bool   `json:"piv_login_enabled"`
	UIEnabled       bool   `json:"ui_enabled"`
}

// handleCapabilities serves the unauthenticated login-page capability flags.
func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, capabilitiesResponse{
		Version:         s.handlers.Version,
		WebAuthnEnabled: s.webauthnHandler != nil,
		PIVLoginEnabled: s.pivLogin != nil && s.pivLogin.Enabled,
		UIEnabled:       s.ui != nil && s.ui.Enabled && s.ui.Assets != nil,
	}, http.StatusOK)
}
