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
	"fmt"
	"strings"

	qrdbsecret "github.com/jeremyhahn/go-qrdb/sdk/go/secret"
)

// SecretValue holds a resolved secret sealed in a go-enclave sealed enclave, together
// with resolution metadata (Raw, Strategy, ExpiresAt). It is the protected
// replacement for a plain string config field: declaring a field as
// SecretValue instead of string keeps the resolved plaintext inside its own
// enclave rather than writing it back as an unwipeable Go string. It decodes
// from, and re-encodes to, the plain reference string in YAML and JSON, so
// config documents are unchanged. See qrdbsecret.SecretValue for the full
// contract (WithBytes, Open, Clear).
type SecretValue = qrdbsecret.SecretValue

// NewLiteralSecretValue seals value into its own go-enclave sealed enclave and
// returns a SecretValue carrying it, with no Raw reference (the caller
// already holds resolved plaintext — it did not come from resolving a
// reference string). Every call seals a fresh enclave, even for the same
// value bytes: SecretValue is single-owner for its working life, so a
// caller assigning the same resolved password into several config fields
// must give each field its own SecretValue rather than share one.
//
// It is qrdb's own sanctioned constructor for a SecretValue built from a
// runtime value rather than a config-file reference (go-qrdb#654's
// secret.NewSecretValue), re-exported unchanged. Every secret-bearing config
// field is now a *SecretValue (nil means "not configured" to
// secret.ConfigProcessor — the only way to spell an optional secret in its
// contract), so this returns a pointer to match; it must never be handed to
// a protected target secret.ConfigProcessor walks, since a literal there is
// refused with *secret.UnresolvableTargetError by design — it is for a
// runtime-only value (a CLI flag, a Go-code default) that the walker never
// reaches. A value that cannot be sealed is an error (qrdb's
// *secret.SealFailedError), never a SecretValue that reports empty. ctx bounds
// the wait for the process sealer.
func NewLiteralSecretValue(ctx context.Context, value []byte) (*SecretValue, error) {
	return qrdbsecret.NewSecretValue(ctx, "", value, qrdbsecret.StrategyLiteral)
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
func NewPasswordFromSecretValue(ctx context.Context, sv *SecretValue) (Password, error) {
	if sv == nil {
		return nil, nil
	}
	var pw Password
	if err := sv.WithBytes(ctx, func(b []byte) error {
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

// SecretReferenceUnresolvedError is returned by SecretValueBytes when a
// SecretValue is configured (a non-empty Raw) but carries no resolved
// plaintext in its enclave: either it was never run through a
// secret.ConfigProcessor / ResolverRegistry pass at all, or a reference
// resolver claimed it and the enclave still came back empty. Falling through
// to treat Raw itself as the plaintext — what a bare string field would
// effectively do, and what this package's Raw-literal fallback used to do —
// would silently authenticate with the reference text (or an inline literal)
// instead of a secret held elsewhere, which go-qrdb's own protected-target
// contract (pkg/secret.ConfigProcessor) refuses outright rather than accept:
// a protected SecretValue target must reference a secret held elsewhere, and
// an inline value, however it arrived, is never honoured (go-xkms#654).
// Raw is never included in the message — see secretReferenceScheme.
type SecretReferenceUnresolvedError struct {
	// Scheme is the reference's URI scheme (e.g. "credential"), or "" when
	// Raw carries no scheme (a bare, unresolved literal). Never the full
	// reference: a literal value that happens to contain "://" could be the
	// secret itself.
	Scheme string
}

// Error implements the error interface.
func (e *SecretReferenceUnresolvedError) Error() string {
	if e.Scheme == "" {
		return "types: secret value was never resolved (no config-sourced literal is honoured)"
	}
	return fmt.Sprintf("types: %s:// secret reference was never resolved", e.Scheme)
}

// secretReferenceScheme extracts the scheme of a "scheme://name"-shaped raw
// string (e.g. "credential" from "credential://db-password"), or "" when raw
// has no such shape (a bare literal). Only the scheme is ever surfaced in an
// error — never the full raw string.
func secretReferenceScheme(raw string) string {
	if i := strings.Index(raw, "://"); i > 0 {
		return raw[:i]
	}
	return ""
}

// SecretValueBytes borrows sv's plaintext into a fresh, garbage-collected
// byte slice. It is a thin borrow helper over an ALREADY-RESOLVED value —
// go-xkms#654 deleted the Raw-literal fallback this used to fall back to,
// which is exactly the divergence from go-qrdb's protected-target contract
// (pkg/secret.ConfigProcessor: a protected target must reference a secret
// held elsewhere, and an unresolved one — including a config-sourced literal
// — is refused, never used verbatim) that #654 introduced by suppressing the
// walk's own *secret.UnresolvableTargetError. It exists for call sites that
// must hand a resolved secret to a third-party API boundary requiring a
// plain []byte or string (miekg/pkcs11's Login, a cloud SDK's credential
// constructor, and similar) — the accepted plaintext-copy boundary for those
// callers; prefer WithBytes directly when the caller can consume the
// plaintext inside a callback instead.
//
// Returns (nil, nil) when sv is nil or genuinely unconfigured (empty Raw,
// never resolved): that is how an optional secret is spelled, both as a nil
// *SecretValue the walker skips entirely and as an empty one nothing ever
// pointed at. Returns *SecretReferenceUnresolvedError when sv is configured
// (non-empty Raw) but its enclave holds nothing — it was never run through a
// secret.ConfigProcessor pass, or a resolver claimed it and still produced
// nothing — rather than trusting Raw as the plaintext.
func SecretValueBytes(ctx context.Context, sv *SecretValue) ([]byte, error) {
	if sv == nil {
		return nil, nil
	}
	var out []byte
	if err := sv.WithBytes(ctx, func(b []byte) error {
		if len(b) == 0 {
			return nil
		}
		out = append([]byte(nil), b...)
		return nil
	}); err != nil {
		return nil, err
	}
	if out != nil {
		return out, nil
	}
	if sv.Raw == "" {
		return nil, nil
	}
	return nil, &SecretReferenceUnresolvedError{Scheme: secretReferenceScheme(sv.Raw)}
}

// SecretValueSet is deleted (go-xkms#654): every caller that used it was
// asking "did the operator configure this field", a presence check —
// answerable, in the pointer-based field model go-xkms#653/#654 moved every
// secret-bearing config field to, by the field itself: `field != nil`. A
// wrapper function over that comparison would have to choose between the
// resolved-only semantics SecretValueBytes now has (which would make it
// unusable for the config-validation call sites it existed for — they run
// before any secret.ConfigProcessor pass, when nothing is resolved yet) and
// the discarded Raw-literal-aware semantics (exactly the go-qrdb contract
// divergence go-xkms#654 is being corrected for). Neither is right, and
// go-qrdb's own SecretValue has no presence accessor either, because it
// does not need one: a nil *SecretValue already answers the question. Every
// call site now compares its field to nil directly.

// KeyAttributesFromConfigResolved is identical to KeyAttributesFromConfig but
// resolves any secret URI references in KeyConfig.Password (and in the
// Password of any nested Parent config) before parsing. When registry is nil,
// the call is equivalent to KeyAttributesFromConfig(config).
//
// Typical usage: config.Password.Raw = "credential://my-ca-pw" and registry
// holds a CredentialResolver backed by the qrdb credential store. The
// resolved plaintext stays sealed in the SecretValue's own go-enclave sealed enclave
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
		return KeyAttributesFromConfig(ctx, config)
	}
	resolved, err := resolveKeyConfigPasswords(ctx, config, registry)
	if err != nil {
		return nil, err
	}
	return KeyAttributesFromConfig(ctx, resolved)
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
	if local.Password != nil && local.Password.Raw != "" {
		sv, err := registry.Resolve(ctx, local.Password.Raw)
		if err != nil {
			return nil, err
		}
		// Custody transfer, not a copy: sv is a freshly resolved SecretValue
		// owned by nobody else, so moving it into local.Password hands the
		// enclave to the shallow config copy directly. There is nothing to
		// Clear — local.Password now owns the same enclave sv pointed at,
		// and clearing sv would destroy it out from under local.
		local.Password = sv
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
