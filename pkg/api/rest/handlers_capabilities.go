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
	// One flag per subsystem whose routes answer 501 when it is absent, so
	// the console disables the control instead (ruling 972 (1)). Each is the
	// same predicate routes.go gates the subsystem's routes with.
	CAEnabled        bool `json:"ca_enabled"`
	SSHEnabled       bool `json:"ssh_enabled"`
	TenantsEnabled   bool `json:"tenants_enabled"`
	PasswordsEnabled bool `json:"passwords_enabled"`
}

// Route guards shared by Routes() and the capabilities response: one
// predicate per subsystem, so the flag the console reads can never disagree
// with whether the route is served.

func (s *Server) hasWebAuthn() bool  { return s.webauthnHandler != nil }
func (s *Server) hasCA() bool        { return s.caHandlers != nil }
func (s *Server) hasSSH() bool       { return s.sshHandlers != nil }
func (s *Server) hasTenants() bool   { return s.tenantHandlers != nil }
func (s *Server) hasPasswords() bool { return s.passwordHandlers != nil }

// handleCapabilities serves the unauthenticated login-page capability flags.
func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, capabilitiesResponse{
		Version:          s.handlers.Version,
		WebAuthnEnabled:  s.hasWebAuthn(),
		PIVLoginEnabled:  s.pivLogin != nil && s.pivLogin.Enabled,
		UIEnabled:        s.ui != nil && s.ui.Enabled && s.ui.Assets != nil,
		CAEnabled:        s.hasCA(),
		SSHEnabled:       s.hasSSH(),
		TenantsEnabled:   s.hasTenants(),
		PasswordsEnabled: s.hasPasswords(),
	}, http.StatusOK)
}
