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

// Package keyversiontest holds key-version fixtures for tests of the
// transports above the key-version API. It imports only pkg/api/transport,
// so every transport package's tests can use it.
package keyversiontest

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// Backend is the backend name Calls' requests name.
const Backend = "software"

// Calls returns one call of every transport.KeyVersionService method on
// svc, keyed by method name, each with a minimal well-formed request naming
// key "signer" in the Backend backend. A test runs them to prove a property
// of the whole method set, such as refusing before a transport is
// connected.
func Calls(ctx context.Context, svc transport.KeyVersionService) map[string]func() error {
	version := &transport.KeyVersionRequest{Backend: Backend, KeyID: "signer", Version: 1}
	all := &transport.AllKeyVersionsRequest{Backend: Backend, KeyID: "signer"}
	return map[string]func() error{
		"ListKeyVersions": func() error {
			_, err := svc.ListKeyVersions(ctx, &transport.ListKeyVersionsRequest{Backend: Backend, KeyID: "signer"})
			return err
		},
		"EnableKeyVersion":      func() error { _, err := svc.EnableKeyVersion(ctx, version); return err },
		"DisableKeyVersion":     func() error { _, err := svc.DisableKeyVersion(ctx, version); return err },
		"RetireKeyVersion":      func() error { _, err := svc.RetireKeyVersion(ctx, version); return err },
		"EnableAllKeyVersions":  func() error { _, err := svc.EnableAllKeyVersions(ctx, all); return err },
		"DisableAllKeyVersions": func() error { _, err := svc.DisableAllKeyVersions(ctx, all); return err },
		"RotateScopeKeys": func() error {
			_, err := svc.RotateScopeKeys(ctx, &transport.RotateScopeKeysRequest{})
			return err
		},
	}
}
