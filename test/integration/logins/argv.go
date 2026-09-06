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

// This file carries no build tag on purpose. The rest of the package is
// behind `integration && logins`, so nothing in it is compiled by the unit
// test jobs, and a flag the harness execs can be removed from the xkey CLI
// without any test noticing until the daemon refuses to start inside the
// devcontainer (#409: --auto-uv, removed by #365, was still exec'd here).
// Keeping the argv in an untagged file lets the xkey command package's
// unit tests (xkey/cmd/xkey/cmd) resolve it against the real Cobra command
// tree, so a removed or renamed flag is a red unit test rather than a dark
// integration suite.

package logins

// VirtualAuthenticatorArgv is the argument vector the fido2 leg passes to
// the xkey binary to start the headless CTAP2 virtual authenticator that
// stands in for an attached security key. The binary path is not part of
// it.
//
// --require-touch=false drops the post-PIN touch, and --pin=false runs the
// authenticator without a CTAP2 PIN. A no-PIN ceremony still blocks on user
// presence, which startTouchPump supplies through "xkey touch", and carries
// no user verification.
var VirtualAuthenticatorArgv = []string{"fido2", "--require-touch=false", "--pin=false"}
