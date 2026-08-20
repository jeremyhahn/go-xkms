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

package types

import (
	"context"

	qrdbsecret "github.com/jeremyhahn/go-qrdb/sdk/go/secret"
)

// KeyAttributesFromConfigResolved is identical to KeyAttributesFromConfig but
// resolves any secret URI references in KeyConfig.Password (and in the
// Password of any nested Parent config) before parsing. When registry is nil,
// the call is equivalent to KeyAttributesFromConfig(config).
//
// Typical usage: config.Password = "credential://my-ca-pw" and registry
// holds a CredentialResolver backed by the qrdb credential store.
// The resolved plaintext is placed into a memguard enclave by
// NewPasswordFromString and the SecretValue is cleared immediately after to
// minimise the window during which plaintext material resides on the heap.
//
// A resolved empty value (credential returns zero bytes) results in
// attrs.Password being nil, preserving the fail-closed behaviour of
// pkcs8 backends that have AllowPlaintextKeys: false.
func KeyAttributesFromConfigResolved(
	ctx context.Context,
	config *KeyConfig,
	registry *qrdbsecret.ResolverRegistry,
) (*KeyAttributes, error) {
	if registry == nil {
		return KeyAttributesFromConfig(config)
	}
	resolved, err := resolveKeyConfigPasswords(ctx, config, registry)
	if err != nil {
		return nil, err
	}
	return KeyAttributesFromConfig(resolved)
}

// resolveKeyConfigPasswords returns a shallow copy of config with all Password
// fields resolved through registry. The original config is unmodified.
// Recurses into Parent to resolve nested password references.
// Returns nil when config is nil.
func resolveKeyConfigPasswords(
	ctx context.Context,
	config *KeyConfig,
	registry *qrdbsecret.ResolverRegistry,
) (*KeyConfig, error) {
	if config == nil {
		return nil, nil
	}
	local := *config
	if local.Password != "" {
		sv, err := registry.Resolve(ctx, local.Password)
		if err != nil {
			return nil, err
		}
		// nolint:staticcheck // go-xkms#41: SecretValue.String copies the
		// plaintext into an unwipeable heap string. local.Password is a plain
		// string field that outlives this call, so the borrow-scoped
		// replacement is a custody change, not a call swap. Delete this
		// directive when #41 lands.
		local.Password = sv.String()
		sv.Clear()
	}
	if config.Parent != nil {
		parent, err := resolveKeyConfigPasswords(ctx, config.Parent, registry)
		if err != nil {
			return nil, err
		}
		local.Parent = parent
	}
	return &local, nil
}
