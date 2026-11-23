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

import "github.com/jeremyhahn/go-xkms/pkg/api/rest"

// corsOptions is the configured cross-origin policy, shared by the REST
// router and the apimodule routes on the unified server. Cross-origin access
// is opt-in: without cors.enabled it returns nil, no CORS headers are emitted
// and browsers enforce same-origin (the embedded web UI is served same-origin
// and needs none).
func (s *Server) corsOptions() *rest.CORSOptions {
	if s.config == nil || !s.config.CORS.Enabled {
		return nil
	}
	return &rest.CORSOptions{
		AllowedOrigins:   s.config.CORS.AllowedOrigins,
		AllowCredentials: s.config.CORS.AllowCredentials,
		MaxAgeSeconds:    s.config.CORS.MaxAgeSeconds,
	}
}
