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

// referenceSchemeSeparator is the same "scheme://name" shape
// qrdbsecret.SecretValue.Redacted() uses to decide whether Raw points AT a
// secret rather than carrying one. SecretValueBytes reuses it to recognize a
// value nothing has resolved yet.
const referenceSchemeSeparator = "://"

// secretReferenceScheme extracts the scheme of a "scheme://name"-shaped raw
// string (e.g. "credential" from "credential://db-password"), or "" when raw
// has no such shape. Only the scheme is ever surfaced in an error — never
// the full raw string — because in the false-positive case (a literal value
// that happens to contain "://") the full string could be the secret itself.
func secretReferenceScheme(raw string) string {
	if i := strings.Index(raw, referenceSchemeSeparator); i > 0 {
		return raw[:i]
	}
	return ""
}

// isReferenceStrategy reports whether strategy names an actual resolution
// (a ResolverRegistry matched some resolver to the reference and ran it)
// rather than the zero value (never resolved) or StrategyLiteral (the
// registry's own "no resolver claimed this, use it verbatim" fallback,
// which behaves exactly like an operator-supplied plaintext value).
func isReferenceStrategy(strategy qrdbsecret.ResolvedStrategy) bool {
	return strategy != "" && strategy != qrdbsecret.StrategyLiteral
}

// SecretReferenceUnresolvedError is returned by SecretValueBytes when a
// SecretValue's Raw is shaped like a secret reference (e.g.
// "credential://db-password") that nothing has resolved: either a
// ResolverRegistry ran and a reference-strategy resolver claimed it but the
// enclave came back empty, or the field was never run through a registry at
// all. Falling through to treat the reference text itself as the plaintext —
// what a bare string field would effectively do — would silently
// authenticate with the URI instead of the secret it names, which is worse
// than refusing outright: a wrong-but-plausible-looking credential fails
// confusingly deep inside a third-party client instead of at the boundary
// that could name the problem.
type SecretReferenceUnresolvedError struct {
	// Scheme is the reference's URI scheme (e.g. "credential"), not the full
	// reference: see secretReferenceScheme for why the rest is never
	// surfaced.
	Scheme string
}

// Error implements the error interface.
func (e *SecretReferenceUnresolvedError) Error() string {
	return fmt.Sprintf("types: %s:// secret reference was never resolved", e.Scheme)
}

// SecretValueBytes borrows sv's plaintext into a fresh, garbage-collected
// byte slice, returning (nil, nil) when sv carries no material at all (an
// unconfigured field) and *SecretReferenceUnresolvedError when it carries an
// unresolved reference instead of material — see that type's doc. It exists
// for call sites that must hand a config-sourced secret to a third-party API
// boundary requiring a plain []byte or string (miekg/pkcs11's Login, a cloud
// SDK's credential constructor, and similar) — the accepted plaintext-copy
// boundary for those callers; prefer WithBytes directly when the caller can
// consume the plaintext inside a callback instead.
//
// Resolution priority mirrors NewPasswordFromSecretValue: WithBytes is tried
// first (a SecretValue resolved through a ResolverRegistry holds its
// plaintext only in the enclave), and only a SecretValue that was never
// resolved (Strategy is the zero value) falls back to treating Raw as the
// plaintext — unless Raw is itself reference-shaped, in which case nothing
// has resolved it yet and *SecretReferenceUnresolvedError is returned
// instead of the reference text.
func SecretValueBytes(sv *SecretValue) ([]byte, error) {
	if sv == nil {
		return nil, nil
	}
	var out []byte
	if err := sv.WithBytes(func(b []byte) error {
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
	if isReferenceStrategy(sv.Strategy) {
		// A reference-strategy resolver ran (Resolve sets one even for an
		// empty result) yet the enclave holds nothing. Unlike an empty
		// StrategyLiteral value — a plain operator-supplied "", genuinely no
		// secret — this is ambiguous between "the reference legitimately
		// names an empty value" and "resolution silently failed", so it is
		// refused rather than guessed at.
		return nil, &SecretReferenceUnresolvedError{Scheme: secretReferenceScheme(sv.Raw)}
	}
	if sv.Strategy != "" || sv.Raw == "" {
		return nil, nil
	}
	if scheme := secretReferenceScheme(sv.Raw); scheme != "" {
		return nil, &SecretReferenceUnresolvedError{Scheme: scheme}
	}
	return []byte(sv.Raw), nil
}

// SecretValueSet reports whether sv carries any material, for call sites that
// need a plain boolean (an "is this configured" gate, a masked String/Debug
// representation, a length-only validation) rather than the plaintext
// itself. A bare `sv.Raw != ""` check is WRONG here: it misses a SecretValue
// populated through NewLiteralSecretValue or a resolved ResolverRegistry
// lookup, both of which hold their material in the enclave with Raw empty or
// pointing at the reference rather than the value. SecretValueSet checks the
// enclave first via WithBytes, matching SecretValueBytes and
// NewPasswordFromSecretValue, and falls back to Raw only for a SecretValue
// that was never resolved. A nil sv, or a WithBytes failure (the enclave
// could not be opened), reports false rather than erroring, since every
// caller of this function already has a bool-only signature.
//
// SecretValueSet answers "did the operator configure something here", not
// "is it ready to use": an unresolved reference (Raw shaped like
// "scheme://name", or a reference-strategy resolution that came back empty)
// reports true — the operator did point at a secret — even though
// SecretValueBytes will refuse the same value with
// *SecretReferenceUnresolvedError. A caller that branches on SecretValueSet
// to choose a code path (e.g. "service-principal configured, use it" vs.
// "fall back to ambient credentials") is expected to reach SecretValueBytes
// (directly or through a third-party constructor built on it) on the chosen
// path, which is where an unresolved reference is actually caught.
func SecretValueSet(sv *SecretValue) bool {
	if sv == nil {
		return false
	}
	has := false
	_ = sv.WithBytes(func(b []byte) error {
		has = len(b) > 0
		return nil
	})
	if has {
		return true
	}
	return sv.Raw != ""
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
