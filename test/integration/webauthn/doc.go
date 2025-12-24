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

// Package webauthn provides end-to-end integration tests for WebAuthn functionality.
//
// These tests use chromedp with Chrome's Virtual WebAuthn Authenticator to perform
// real browser-based WebAuthn registration and authentication ceremonies.
//
// # Test Types
//
//  1. Virtual Authenticator Tests - Use Chrome's CDP WebAuthn domain to create
//     virtual authenticators that simulate real hardware security keys.
//
//  2. E2E Flow Tests - Test the complete registration and authentication flows
//     through a browser, validating the full user experience.
//
//  3. CanoKey Integration Tests - Optional tests that use a real CanoKey hardware
//     token when available (build with -tags canokey).
//
// # Requirements
//
// - Chrome/Chromium browser installed
// - chromedp package for browser automation
// - go-keychain server running (for full E2E tests)
//
// # Running Tests
//
//	# Run all WebAuthn integration tests
//	go test -v -tags integration ./test/integration/webauthn/...
//
//	# Run only virtual authenticator tests (no server required)
//	go test -v -tags integration -run TestVirtual ./test/integration/webauthn/...
//
//	# Run E2E tests against running server
//	go test -v -tags integration -run TestE2E ./test/integration/webauthn/...
//
// # Environment Variables
//
//   - WEBAUTHN_TEST_SERVER: Base URL of the test server (default: http://localhost:8443)
//   - WEBAUTHN_TEST_ORIGIN: Origin for WebAuthn (default: https://localhost)
//   - CHROME_BIN: Path to Chrome binary (optional, chromedp will auto-detect)
//   - HEADLESS: Set to "false" to show browser during tests (default: true)
package webauthn
