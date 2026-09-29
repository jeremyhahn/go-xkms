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

//go:build tpm_simulator

package tpm2

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestGenerateKey_DefaultsToThePlatformPolicy proves a TPM key whose caller
// names no policy is bound to the built-in "platform" policy, and that the
// key is usable under it: with no password the platform PCR branch
// authorizes the signature.
func TestGenerateKey_DefaultsToThePlatformPolicy(t *testing.T) {
	backend, err := NewBackend(&Config{UseSimulator: true, KeyDir: t.TempDir()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	attrs := &types.KeyAttributes{
		CN:            "default-policy-key",
		KeyAlgorithm:  x509.ECDSA,
		KeyType:       types.KeyTypeSigning,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	}
	_, err = backend.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)
	assert.Equal(t, types.TPMPolicyPlatform, attrs.TPMPolicy)

	signer, err := backend.Signer(context.Background(), attrs)
	require.NoError(t, err)
	digest := sha256.Sum256([]byte("platform policy default"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.True(t, ecdsa.VerifyASN1(pub, digest[:], sig))
}

// TestGenerateKey_KeepsAnExplicitPolicyReference proves a caller-named
// policy is not overwritten by the default.
func TestGenerateKey_KeepsAnExplicitPolicyReference(t *testing.T) {
	attrs := &types.KeyAttributes{TPMPolicy: "boot-state"}
	applyDefaultTPMPolicy(attrs)
	assert.Equal(t, "boot-state", attrs.TPMPolicy)

	empty := &types.KeyAttributes{}
	applyDefaultTPMPolicy(empty)
	assert.Equal(t, types.TPMPolicyPlatform, empty.TPMPolicy)
}
