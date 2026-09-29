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

// Package http provides composable HTTP handlers for WebAuthn operations.
//
// This package allows applications to easily add WebAuthn authentication
// to their existing HTTP servers without coupling to go-xkms's internal
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
//	POST /registration/begin   - Start registration of an account's FIRST passkey
//	POST /registration/finish  - Complete registration
//	POST /login/begin          - Start authentication ceremony
//	POST /login/finish         - Complete authentication
//
// The mount helpers register only these public ceremonies. Handler also
// provides BeginAddCredential, which adds a passkey to the account of the
// caller's authenticated session; mount it yourself, behind authentication
// middleware that stores the identity with auth.WithIdentity:
//
//	POST /credentials/begin    - Start adding a passkey to the session's account
//
// Neither begin route reveals whether an account exists: registration is
// refused the same way for an account that already has a passkey and (with
// public registration off) for an unknown email, and login answers an
// unknown account with decoy options.
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
