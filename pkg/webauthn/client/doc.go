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

// Package client provides the single headless WebAuthn ceremony driver in
// go-xkms. It acts as the "browser" in the WebAuthn flow, bridging a
// RelyingParty (the server side) and an AuthenticatorAdapter (the
// authenticator side).
//
// # Architecture
//
// Client is deliberately thin: it drives the three-step ceremony
// (begin -> authenticator -> finish) and leaves the two sides pluggable.
//
//   - Server side (RelyingParty): HTTPRelyingParty speaks the browser-shaped
//     pkg/webauthn/http routes (registration/begin, .../finish, login/begin,
//     .../finish); TransportRelyingParty speaks the SDK transport routes
//     (/api/v1/webauthn/sdk/...) through a pkg/api/transport.Client, in
//     whichever protocol that client was built with.
//   - Authenticator side (AuthenticatorAdapter): HardwareAdapter drives a
//     real CTAP2 authenticator over HID via pkg/fido2, including xkey's
//     virtual "xkey fido2" uhid authenticator; SoftwareAdapter is a
//     software-only CTAP2 authenticator for headless testing and CI.
//
// Every consumer in the stack — xkey, xkmsctl, and any composer reached
// through sdk/go — drives ceremonies through this one Client with one of
// these RelyingParty/AuthenticatorAdapter pairs; none reimplements the
// ceremony.
//
// # Usage
//
// Browser-shaped RP with a real authenticator:
//
//	adapter, err := client.NewHardwareAdapter(nil, nil)
//	// ... defer adapter.Close()
//	c, err := client.NewClient(&client.Config{
//	    ServerURL:            "https://xkms.example.com:8443",
//	    AuthenticatorAdapter: adapter,
//	})
//	result, err := c.Register(ctx, &client.RegistrationRequest{
//	    Username: "user@example.com",
//	})
//
// SDK transport RP (xkey/xkmsctl shape) with a real authenticator:
//
//	rp, err := client.NewTransportRelyingParty(transportClient) // e.g. an sdk/go Client
//	adapter, err := client.NewHardwareAdapter(nil, nil)
//	c, err := client.NewClient(&client.Config{
//	    RelyingParty:         rp,
//	    AuthenticatorAdapter: adapter,
//	})
//
// With the software adapter (for testing):
//
//	c, err := client.NewClient(&client.Config{
//	    ServerURL:            server.URL,
//	    AuthenticatorAdapter: client.NewSoftwareAdapter(),
//	})
package client
