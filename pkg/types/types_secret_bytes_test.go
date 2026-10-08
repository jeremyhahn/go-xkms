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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSecretValueBytes_UnresolvedLiteralErrors proves go-xkms#654's core
// fix: a plain operator-supplied value — unresolved, straight off a
// YAML/JSON decode (Raw set, Strategy the zero value), never run through a
// secret.ConfigProcessor / ResolverRegistry pass — is refused rather than
// trusted as the plaintext. Falling back to Raw here is exactly the
// divergence from go-qrdb's protected-target contract (a protected target
// must reference a secret held elsewhere; an inline value is refused, never
// honoured) that #654 introduced.
func TestSecretValueBytes_UnresolvedLiteralErrors(t *testing.T) {
	t.Parallel()

	sv := SecretValue{Raw: "hunter2"}
	got, err := SecretValueBytes(t.Context(), &sv)
	require.Error(t, err)
	assert.Nil(t, got)

	var refErr *SecretReferenceUnresolvedError
	require.True(t, errors.As(err, &refErr), "error must be *SecretReferenceUnresolvedError, got %T", err)
	assert.Equal(t, "", refErr.Scheme, "a bare literal carries no scheme")
	assert.NotContains(t, err.Error(), "hunter2",
		"the error must never quote a literal's own plaintext")
}

// TestSecretValueBytes_EmptyFieldMeansNotConfigured proves the zero value —
// no Raw, never resolved — reports "not configured" as (nil, nil), not an
// error: an absent config key must stay indistinguishable from an absent
// secret.
func TestSecretValueBytes_EmptyFieldMeansNotConfigured(t *testing.T) {
	t.Parallel()

	var sv SecretValue
	got, err := SecretValueBytes(t.Context(), &sv)
	require.NoError(t, err)
	assert.Nil(t, got)
}

// TestSecretValueBytes_NilReceiver proves a nil *SecretValue is handled the
// same as an empty field rather than panicking.
func TestSecretValueBytes_NilReceiver(t *testing.T) {
	t.Parallel()

	got, err := SecretValueBytes(t.Context(), nil)
	require.NoError(t, err)
	assert.Nil(t, got)
}

// TestSecretValueBytes_ResolvedReference proves a "credential://" reference
// that a ResolverRegistry actually resolved — the same custody-transfer
// shape pkg/server's CA identity password resolution and
// RegisterPhoneBackend use (field = *sv) — yields the resolved plaintext,
// read from the enclave rather than Raw (which still names the reference,
// per SecretValue's own contract).
func TestSecretValueBytes_ResolvedReference(t *testing.T) {
	t.Parallel()

	reg := fakeCredentialRegistry(map[string]string{"boot-secret": "s3cr3t-value"})
	resolved, err := reg.Resolve(context.Background(), "credential://boot-secret")
	require.NoError(t, err)
	sv := *resolved

	got, err := SecretValueBytes(t.Context(), &sv)
	require.NoError(t, err)
	assert.Equal(t, []byte("s3cr3t-value"), got)
	assert.Equal(t, "credential://boot-secret", sv.Raw,
		"Raw must still name the reference, not the resolved plaintext")
}

// TestSecretValueBytes_UnresolvedReferenceErrors proves the core fix: a
// value shaped like a secret reference that NOTHING has resolved (Strategy
// is the zero value, straight off decode, with no ResolverRegistry in the
// loop) is refused with *SecretReferenceUnresolvedError rather than being
// treated as literal plaintext — using the reference URI itself as the
// secret would silently authenticate with the wrong material.
func TestSecretValueBytes_UnresolvedReferenceErrors(t *testing.T) {
	t.Parallel()

	sv := SecretValue{Raw: "credential://boot-secret"}
	got, err := SecretValueBytes(t.Context(), &sv)
	require.Error(t, err)
	assert.Nil(t, got)

	var refErr *SecretReferenceUnresolvedError
	require.True(t, errors.As(err, &refErr), "error must be *SecretReferenceUnresolvedError, got %T", err)
	assert.Equal(t, "credential", refErr.Scheme)
	assert.NotContains(t, err.Error(), "boot-secret",
		"the error must never quote the reference name/value, only the scheme")
}

// TestSecretValueBytes_UnresolvableReferenceErrors proves that a reference
// a ResolverRegistry genuinely could not resolve (the named credential does
// not exist) fails loudly through the registry's own error rather than
// silently producing an empty or wrong secret -- the "unresolvable
// reference fails start-up or load" requirement, exercised at the
// ResolverRegistry.Resolve boundary every real call site (pkg/server's CA
// resolution, RegisterPhoneBackend) uses.
func TestSecretValueBytes_UnresolvableReferenceErrors(t *testing.T) {
	t.Parallel()

	reg := fakeCredentialRegistry(map[string]string{}) // no credentials stored
	_, err := reg.Resolve(context.Background(), "credential://does-not-exist")
	require.Error(t, err, "resolving an unknown credential must fail, not synthesize an empty secret")
}

// TestSecretValueBytes_ReferenceStrategyResolvedEmpty proves that a value a
// reference-strategy resolver DID run against (Strategy is set to something
// other than the zero value or StrategyLiteral) but which came back with no
// enclave material is refused rather than silently treated as "no secret
// configured": that ambiguity (a credential that legitimately resolves to
// zero bytes vs. a resolution that silently failed to populate the enclave)
// is not the caller's to guess at.
func TestSecretValueBytes_ReferenceStrategyResolvedEmpty(t *testing.T) {
	t.Parallel()

	reg := fakeCredentialRegistry(map[string]string{"empty-secret": ""})
	resolved, err := reg.Resolve(context.Background(), "credential://empty-secret")
	require.NoError(t, err)
	sv := *resolved

	got, err := SecretValueBytes(t.Context(), &sv)
	require.Error(t, err)
	assert.Nil(t, got)
	var refErr *SecretReferenceUnresolvedError
	require.True(t, errors.As(err, &refErr))
	assert.Equal(t, "credential", refErr.Scheme)
}

// TestSecretValueBytes_LiteralViaRegistryFallback proves a plain value
// resolved through the registry's own literal-passthrough fallback (no
// resolver claims it, so it comes back as StrategyLiteral) still works: the
// fallback is not a "reference strategy" for SecretValueBytes's purposes,
// so an empty result from it stays "not configured" rather than an error.
func TestSecretValueBytes_LiteralViaRegistryFallback(t *testing.T) {
	t.Parallel()

	reg := fakeCredentialRegistry(map[string]string{})
	resolved, err := reg.Resolve(context.Background(), "a-plain-literal-value")
	require.NoError(t, err)
	sv := *resolved

	got, err := SecretValueBytes(t.Context(), &sv)
	require.NoError(t, err)
	assert.Equal(t, []byte("a-plain-literal-value"), got)
}

// TestSecretValue_PointerFieldIsThePresenceSignal proves the replacement for
// the deleted SecretValueSet: go-xkms#653/#654 made every secret-bearing
// config field a *SecretValue, so "did the operator configure this field" is
// answered by the field itself (`field != nil`) rather than a wrapper
// function — including for a field that names a reference nothing has
// resolved yet, exactly the case SecretValueSet used to special-case.
func TestSecretValue_PointerFieldIsThePresenceSignal(t *testing.T) {
	t.Parallel()

	var unconfigured *SecretValue
	assert.Nil(t, unconfigured, "unconfigured is nil: the field was never set")

	configured := &SecretValue{Raw: "credential://client-secret"}
	assert.NotNil(t, configured, "configured is non-nil even before resolution")
}
