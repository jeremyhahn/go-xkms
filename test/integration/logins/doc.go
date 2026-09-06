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

//go:build integration && logins

// Package logins is the login-plane verification matrix: it drives every
// path xkey ships as the stack's login key (docs/17-xkey.md) against a real,
// running server and asserts each one actually authenticates.
//
// Coverage per server target (see targets in testutil.go):
//
//   - mtls:  an admin mTLS client certificate authenticates a session-gated
//     REST route; an anonymous caller is denied.
//   - piv:   POST /api/v1/auth/login/piv over mTLS, using a certificate
//     already SPKI-bound to an enrolled user (the first-boot admin
//     credential), mints a token pair; validate/refresh/logout exercise it.
//   - fido2: the real xkey CLI (auth register / auth login) drives a
//     headless CTAP2 ceremony (xkey fido2 --require-touch=false --pin=false,
//     see VirtualAuthenticatorArgv in argv.go, with presence supplied by
//     "xkey touch") against the server's WebAuthn relying party and stores
//     the issued token.
//
// The suite is table-driven over server base URLs so a second target
// (quicbaasd) slots in once its login-plane parity work lands; only xkmsd is
// wired today.
//
// Run via `make integration-test-logins` in the devcontainer, which starts
// the compose xkms-server and publishes its CA and first-boot admin
// credential to /tmp/xkms (see .devcontainer/scripts/ensure-server-ca.sh).
package logins
