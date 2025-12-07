// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// Package http provides composable HTTP handlers for WebAuthn operations.
//
// This package allows applications to easily add WebAuthn authentication
// to their existing HTTP servers without coupling to go-keychain's internal
// REST implementation.
//
// # Usage
//
// Create a handler from a WebAuthn service and mount it on your router:
//
//	svc, _ := webauthn.NewService(...)
//	handler := webauthnhttp.NewHandler(svc)
//
//	// For chi router:
//	r.Route("/api/v1/webauthn", func(r chi.Router) {
//	    webauthnhttp.MountChi(r, handler)
//	})
//
//	// For gorilla/mux:
//	webauthnhttp.MountMux(r.PathPrefix("/api/v1/webauthn").Subrouter(), handler)
//
//	// For stdlib http.ServeMux (Go 1.22+):
//	webauthnhttp.MountStdlib(mux, "/api/v1/webauthn", handler)
//
// # Endpoints
//
// The handler provides the following endpoints:
//
//	POST /registration/begin   - Start registration ceremony
//	POST /registration/finish  - Complete registration
//	GET  /registration/status  - Check if user is registered
//	POST /login/begin          - Start authentication ceremony
//	POST /login/finish         - Complete authentication
//
// # Headers
//
// The handlers use the following custom headers:
//
//	X-Session-Id: Session identifier returned by begin operations
//	              Must be included in finish operations
//
// # Response Format
//
// All responses are JSON. Successful responses include the data directly.
// Error responses have the format:
//
//	{
//	    "error": "error_code",
//	    "message": "Human-readable message"
//	}
package http
