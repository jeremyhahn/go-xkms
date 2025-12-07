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

// Package webauthn provides a WebAuthn (FIDO2) server-side implementation
// that can be used as a library in any Go application.
//
// This package wraps the go-webauthn/webauthn library and provides:
//   - Pluggable storage interfaces for users, credentials, and sessions
//   - In-memory storage implementations for development/testing
//   - Composable HTTP handlers that can be mounted on any router
//   - Optional JWT generation after successful authentication
//
// # Architecture
//
// The package is designed with a layered architecture:
//
//  1. Service layer (Service) - Core WebAuthn operations
//  2. Storage layer (UserStore, CredentialStore, SessionStore) - Pluggable persistence
//  3. HTTP layer (pkg/webauthn/http) - Composable HTTP handlers
//
// # Usage
//
// Basic usage with in-memory storage (for development):
//
//	svc, err := webauthn.NewService(webauthn.ServiceParams{
//	    Config: &webauthn.Config{
//	        RPID:          "localhost",
//	        RPDisplayName: "My App",
//	        RPOrigins:     []string{"https://localhost:3000"},
//	    },
//	    UserStore:       webauthn.NewMemoryUserStore(),
//	    SessionStore:    webauthn.NewMemorySessionStore(),
//	    CredentialStore: webauthn.NewMemoryCredentialStore(),
//	})
//
// For production, implement the storage interfaces with your database.
//
// # HTTP Handlers
//
// The http subpackage provides handlers that can be mounted on any router:
//
//	handler := webauthnhttp.NewHandler(svc)
//	webauthnhttp.MountChi(r, handler)  // For chi router
//	webauthnhttp.MountMux(r, handler)  // For gorilla/mux
//
// # WebAuthn Specification Compliance
//
// This implementation follows the W3C Web Authentication specification:
//   - https://www.w3.org/TR/webauthn-2/
//   - https://www.w3.org/TR/webauthn-3/
//
// Note: WebAuthn requires HTTPS for all operations. Browsers will only
// expose the WebAuthn API in secure contexts.
package webauthn
