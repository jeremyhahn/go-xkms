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

// Package signingkeytest holds the fixtures of tests that exercise the
// repository signing-key API (transport.SigningKeyService). It imports only
// pkg/api/transport, so every transport's tests can use it.
package signingkeytest

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// Repository is the repository every call of Calls names.
const Repository = "acme/app"

// Calls returns one call of every signing-key method of svc, by method name,
// each returning only its error.
func Calls(ctx context.Context, svc transport.SigningKeyService) map[string]func() error {
	return map[string]func() error{
		"SetSigningKeyBinding": func() error {
			_, err := svc.SetSigningKeyBinding(ctx, &transport.SetSigningKeyBindingRequest{Repository: Repository, KeyID: "app-release"})
			return err
		},
		"GetSigningKeyBinding": func() error {
			_, err := svc.GetSigningKeyBinding(ctx, &transport.GetSigningKeyBindingRequest{Repository: Repository})
			return err
		},
		"ListSigningKeyBindings": func() error {
			_, err := svc.ListSigningKeyBindings(ctx)
			return err
		},
		"DeleteSigningKeyBinding": func() error {
			return svc.DeleteSigningKeyBinding(ctx, &transport.DeleteSigningKeyBindingRequest{Repository: Repository})
		},
		"ResolveSigningKey": func() error {
			_, err := svc.ResolveSigningKey(ctx, &transport.ResolveSigningKeyRequest{Repository: Repository})
			return err
		},
		"SignCoRIM": func() error {
			_, err := svc.SignCoRIM(ctx, &transport.SignCoRIMRequest{Repository: Repository, CoRIM: []byte{0xd9, 0x01, 0xf5, 0xa0}, SignerName: "Acme"})
			return err
		},
		"SignImage": func() error {
			_, err := svc.SignImage(ctx, &transport.SignImageRequest{Reference: "registry.example/" + Repository + ":1.0.0"})
			return err
		},
	}
}
