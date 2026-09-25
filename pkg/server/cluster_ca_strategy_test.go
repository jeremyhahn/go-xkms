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
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/config"
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

// TestResolveClusterCAKeyPassphrase_UnresolvedLiteralFailsClosed verifies
// go-xkms#654's core fix: a plain-string passphrase (no credential:// scheme)
// that was never run through a secret.ConfigProcessor pass is refused rather
// than trusted as the plaintext — go-qrdb's protected-target contract admits
// no inline literal, however it arrived.
func TestResolveClusterCAKeyPassphrase_UnresolvedLiteralFailsClosed(t *testing.T) {
	t.Parallel()

	s := &Server{ctx: context.Background()}
	sv := &types.SecretValue{Raw: "operator-secret"}

	sec, err := s.resolveClusterCAKeyPassphrase(sv)
	require.Error(t, err)
	assert.Nil(t, sec)

	var refErr *types.SecretReferenceUnresolvedError
	require.True(t, errors.As(err, &refErr))
}

// TestResolveClusterCAKeyPassphrase_CredentialReference verifies that a
// credential:// reference, already resolved by Server.resolveConfigSecrets
// (the post-node initializeCA path — see resolveClusterCAKeyPassphrase's
// doc), reaches resolveClusterCAKeyPassphrase as a *secure.Secret carrying
// the stored plaintext, not the URI.
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

	s := &Server{
		ctx:               context.Background(),
		credentialService: svc,
		config: &config.Config{
			Cluster: config.ClusterConfig{
				RaftEnrollment: config.RaftEnrollmentConfig{
					CAKeyPassphrase: &types.SecretValue{Raw: "credential://" + credName},
				},
			},
		},
	}
	require.NoError(t, s.resolveConfigSecrets())

	sec, err := s.resolveClusterCAKeyPassphrase(s.config.Cluster.RaftEnrollment.CAKeyPassphrase)
	require.NoError(t, err)
	require.NotNil(t, sec)

	buf, err := sec.Open()
	require.NoError(t, err)
	defer buf.Destroy()
	assert.Equal(t, credValue, string(buf.Bytes()))
}

// TestResolveClusterCAKeyPassphrase_CredentialReferenceMissing verifies that
// a credential:// reference the credential service cannot satisfy surfaces as
// an error from resolveConfigSecrets — the boot-time pass now performs this
// resolution — rather than silently falling back to an empty passphrase.
//
// The "manual" strategy's RetrieveCredential blocks until SubmitCredential is
// called or ctx is cancelled — it has no "not found" answer of its own — so a
// never-submitted name is proven "cannot be satisfied" the same way any
// caller would see it: resolveConfigSecrets is bounded by a short-lived
// context, and its cancellation is what surfaces as the typed error.
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

	s := &Server{
		ctx:               ctx,
		credentialService: svc,
		config: &config.Config{
			Cluster: config.ClusterConfig{
				RaftEnrollment: config.RaftEnrollmentConfig{
					CAKeyPassphrase: &types.SecretValue{Raw: "credential://does-not-exist"},
				},
			},
		},
	}

	resolveErr := s.resolveConfigSecrets()
	require.Error(t, resolveErr)
	var typedErr *ErrConfigSecretResolution
	require.ErrorAs(t, resolveErr, &typedErr)

	// The field is left unresolved: resolveClusterCAKeyPassphrase must refuse
	// it rather than treat the reference text as the passphrase.
	sec, err := s.resolveClusterCAKeyPassphrase(s.config.Cluster.RaftEnrollment.CAKeyPassphrase)
	require.Error(t, err)
	assert.Nil(t, sec)
}
