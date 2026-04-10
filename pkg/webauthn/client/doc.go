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

// Package client provides a headless WebAuthn client that acts as the "browser"
// in the WebAuthn flow. It communicates with a WebAuthn relying party (server)
// over HTTP and delegates CTAP2 operations to a local authenticator via the
// AuthenticatorAdapter interface.
//
// # Architecture
//
// The client bridges two sides of the WebAuthn protocol:
//
//   - Server side: HTTP communication with the RP endpoints
//     (registration/begin, registration/finish, login/begin, login/finish)
//   - Authenticator side: CTAP2 operations via the AuthenticatorAdapter
//     interface, which can be backed by xkey IPC, hardware tokens, or
//     a software adapter for testing
//
// # Usage
//
// With a real authenticator (via IPC to xkey):
//
//	c, err := client.NewClient(&client.Config{
//	    ServerURL:            "https://xkms.example.com:8443",
//	    AuthenticatorAdapter: ipcAdapter,
//	})
//	result, err := c.Register(ctx, &client.RegistrationRequest{
//	    Username: "user@example.com",
//	})
//
// With the software adapter (for testing):
//
//	c, err := client.NewClient(&client.Config{
//	    ServerURL:            server.URL,
//	    AuthenticatorAdapter: client.NewSoftwareAdapter(),
//	})
package client
