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

// SecretValue holds a resolved secret sealed in a memguard enclave, together
// with resolution metadata (Raw, Strategy, ExpiresAt). It is the protected
// replacement for a plain string config field: declaring a field as
// SecretValue instead of string keeps the resolved plaintext inside its own
// enclave rather than writing it back as an unwipeable Go string. It decodes
// from, and re-encodes to, the plain reference string in YAML and JSON, so
// config documents are unchanged. See qrdbsecret.SecretValue for the full
// contract (WithBytes, Open, Clear).
type SecretValue = qrdbsecret.SecretValue

// NewLiteralSecretValue seals value into its own memguard enclave and
// returns a SecretValue carrying it, with no Raw reference (the caller
// already holds resolved plaintext — it did not come from resolving a
// reference string). Every call seals a fresh enclave, even for the same
// value bytes: SecretValue is single-owner for its working life, so a
// caller assigning the same resolved password into several config fields
// must give each field its own SecretValue rather than share one.
func NewLiteralSecretValue(value []byte) SecretValue {
	return *qrdbsecret.NewSecretValue("", value, qrdbsecret.StrategyLiteral)
}

// NewPasswordFromSecretValue converts a resolved secret into a Password,
// returning (nil, nil) when sv carries no password material.
//
// WithBytes takes priority: a SecretValue resolved through a
// ResolverRegistry (see KeyAttributesFromConfigResolved and
// resolveKeyConfigPasswords) holds its plaintext only inside its enclave,
// never re-exposed through Raw, so the enclave is read first. A resolved
// SecretValue always carries a non-empty Strategy (Resolve sets one even for
// an empty result), so an empty enclave with a Strategy set is a genuine
// empty password and must NOT fall back to Raw — Raw there is the reference
// that was resolved FROM (e.g. "credential://empty-pw"), not a password.
//
// Only a SecretValue that was never resolved — Strategy is the zero value,
// straight off a YAML/JSON decode or a literal composite built with no
// registry — falls back to treating Raw itself as the plaintext password, so
// a plain operator-supplied password still wires a working Password without
// requiring a registry round trip.
func NewPasswordFromSecretValue(sv *SecretValue) (Password, error) {
	if sv == nil {
		return nil, nil
	}
	var pw Password
	if err := sv.WithBytes(func(b []byte) error {
		if len(b) == 0 {
			return nil
		}
		p, err := NewPassword(b)
		if err != nil {
			return err
		}
		pw = p
		return nil
	}); err != nil {
		return nil, err
	}
	if pw != nil {
		return pw, nil
	}
	if sv.Strategy != "" || sv.Raw == "" {
		return nil, nil
	}
	return NewPasswordFromString(sv.Raw)
}

// KeyAttributesFromConfigResolved is identical to KeyAttributesFromConfig but
// resolves any secret URI references in KeyConfig.Password (and in the
// Password of any nested Parent config) before parsing. When registry is nil,
// the call is equivalent to KeyAttributesFromConfig(config).
//
// Typical usage: config.Password.Raw = "credential://my-ca-pw" and registry
// holds a CredentialResolver backed by the qrdb credential store. The
// resolved plaintext stays sealed in the SecretValue's own memguard enclave
// for the life of the config; NewPasswordFromSecretValue borrows it via
// WithBytes at the point KeyAttributesFromConfig builds the Password.
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
	if local.Password.Raw != "" {
		sv, err := registry.Resolve(ctx, local.Password.Raw)
		if err != nil {
			return nil, err
		}
		// Custody transfer, not a copy: sv is a freshly resolved SecretValue
		// owned by nobody else, so moving it into local.Password (a value
		// field) hands the enclave to the shallow config copy directly. There
		// is nothing to Clear — local.Password now owns the same enclave sv
		// pointed at, and clearing sv would destroy it out from under local.
		local.Password = *sv
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
