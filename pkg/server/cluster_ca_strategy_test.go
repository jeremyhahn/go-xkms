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

package server

import (
	"context"
	"testing"
	"time"

	credentialspkg "github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResolveClusterCAKeyPassphrase_Empty verifies that an unset
// CAKeyPassphrase (Raw == "") resolves to (nil, nil) — no passphrase
// configured — rather than an error or an empty-but-allocated Secret.
func TestResolveClusterCAKeyPassphrase_Empty(t *testing.T) {
	t.Parallel()

	s := &Server{ctx: context.Background()}
	sec, err := s.resolveClusterCAKeyPassphrase(&types.SecretValue{})
	require.NoError(t, err)
	assert.Nil(t, sec)
}

// TestResolveClusterCAKeyPassphrase_Literal verifies that a plain-string
// passphrase (no credential:// scheme) resolves via the registry's literal
// fallback into a *secure.Secret carrying that exact plaintext.
func TestResolveClusterCAKeyPassphrase_Literal(t *testing.T) {
	t.Parallel()

	s := &Server{ctx: context.Background()}
	sv := &types.SecretValue{Raw: "operator-secret"}

	sec, err := s.resolveClusterCAKeyPassphrase(sv)
	require.NoError(t, err)
	require.NotNil(t, sec)

	buf, err := sec.Open()
	require.NoError(t, err)
	defer buf.Destroy()
	assert.Equal(t, "operator-secret", string(buf.Bytes()))
}

// TestResolveClusterCAKeyPassphrase_CredentialReference verifies that a
// credential:// reference is dereferenced through the server's credential
// service into a *secure.Secret carrying the stored plaintext, not the URI.
func TestResolveClusterCAKeyPassphrase_CredentialReference(t *testing.T) {
	t.Parallel()

	svc, err := credentialspkg.New(
		&credentialspkg.Config{Strategy: credentialspkg.StrategyManual},
		nil, // platformStore — not required for StrategyManual
		nil, // barrier      — not required for StrategyManual
		nil, // logger       — defaults to slog.Default()
	)
	require.NoError(t, err)

	const credName = "cluster-ca-key-pw"
	const credValue = "hunter2"
	require.NoError(t, svc.StoreCredential(context.Background(), credName, []byte(credValue)))

	s := &Server{ctx: context.Background(), credentialService: svc}
	sv := &types.SecretValue{Raw: "credential://" + credName}

	sec, err := s.resolveClusterCAKeyPassphrase(sv)
	require.NoError(t, err)
	require.NotNil(t, sec)

	buf, err := sec.Open()
	require.NoError(t, err)
	defer buf.Destroy()
	assert.Equal(t, credValue, string(buf.Bytes()))
}

// TestResolveClusterCAKeyPassphrase_CredentialReferenceMissing verifies that
// a credential:// reference the credential service cannot satisfy surfaces
// as an error rather than silently falling back to an empty passphrase.
//
// The "manual" strategy's RetrieveCredential blocks until SubmitCredential
// is called or ctx is cancelled — it has no "not found" answer of its own —
// so a never-submitted name is proven "cannot be satisfied" the same way any
// caller would see it: the resolve call is bounded by a short-lived context,
// and its cancellation is what resolveClusterCAKeyPassphrase must surface as
// an error, never as a silent empty passphrase.
func TestResolveClusterCAKeyPassphrase_CredentialReferenceMissing(t *testing.T) {
	t.Parallel()

	svc, err := credentialspkg.New(
		&credentialspkg.Config{Strategy: credentialspkg.StrategyManual},
		nil,
		nil,
		nil,
	)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	s := &Server{ctx: ctx, credentialService: svc}
	sv := &types.SecretValue{Raw: "credential://does-not-exist"}

	sec, err := s.resolveClusterCAKeyPassphrase(sv)
	require.Error(t, err)
	assert.Nil(t, sec)
}
