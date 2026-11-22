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

package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"io"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/require"
)

// TestCA_RepeatedSigningKeepsPasswordAllocationsBounded proves each signer
// lookup releases the temporary key password it opened: N signatures with a
// password-protected CA key leave the process allocator's locked bytes where
// they started. Not parallel: it measures the process-wide allocator.
func TestCA_RepeatedSigningKeepsPasswordAllocationsBounded(t *testing.T) {
	ctx := context.Background()
	backend, _ := newPKCS8CABackend(t)

	root := passwordProtectedIdentity(t, rootIdentity("PW Signing CA"), "signing-key-password")
	parent, err := NewParentCA(&Params{
		Identity:           []Identity{root},
		KeyStore:           backend,
		BackendForStore:    singleBackendFactory(backend),
		RevocationStore:    storage.NewMemory(),
		CertStore:          newInMemoryCertStore(t),
		RequireKeyPassword: true,
	})
	require.NoError(t, err)
	require.NoError(t, parent.Init(ctx))
	ca, ok := parent.(*CA)
	require.True(t, ok, "NewParentCA must return a *CA")

	alloc, err := enclave.ProcessAllocator()
	require.NoError(t, err)

	// Warm up once so lazily created state is not counted as a leak.
	_, err = ca.getSigner(ctx)
	require.NoError(t, err)

	before := alloc.InUse()
	const n = 50
	for i := 0; i < n; i++ {
		_, err := ca.getSigner(ctx)
		require.NoError(t, err)
	}
	after := alloc.InUse()
	require.LessOrEqual(t, after, before,
		"%d signer lookups grew locked bytes from %d to %d", n, before, after)
}

// signerFailingKeyStore fails Signer when fail is set and delegates every
// other call, so a test can drive CASigner down its backend-error path.
type signerFailingKeyStore struct {
	xkms.Backend
	fail bool
}

func (s *signerFailingKeyStore) Signer(ctx context.Context, attrs *types.KeyAttributes) (crypto.Signer, error) {
	if s.fail {
		return nil, errors.New("injected Signer failure")
	}
	return s.Backend.Signer(ctx, attrs)
}

// TestCA_RepeatedCASignerKeepsPasswordAllocationsBounded is the CASigner
// counterpart of the getSigner regression: each CASigner lookup allocates a
// fresh locked key password, and none of them, on success, on an algorithm
// mismatch or on a backend error, may stay live after the call returns.
func TestCA_RepeatedCASignerKeepsPasswordAllocationsBounded(t *testing.T) {
	ctx := context.Background()
	backend, _ := newPKCS8CABackend(t)

	root := passwordProtectedIdentity(t, rootIdentity("PW CASigner CA"), "casigner-key-password")
	parent, err := NewParentCA(&Params{
		Identity:           []Identity{root},
		KeyStore:           backend,
		BackendForStore:    singleBackendFactory(backend),
		RevocationStore:    storage.NewMemory(),
		CertStore:          newInMemoryCertStore(t),
		RequireKeyPassword: true,
	})
	require.NoError(t, err)
	require.NoError(t, parent.Init(ctx))
	ca, ok := parent.(*CA)
	require.True(t, ok, "NewParentCA must return a *CA")
	failing := &signerFailingKeyStore{Backend: ca.keyStore}
	ca.keyStore = failing

	alloc, err := enclave.ProcessAllocator()
	require.NoError(t, err)

	digest := sha256.Sum256([]byte("casigner"))
	sign := func() {
		t.Helper()
		signer, err := ca.CASigner(ctx, "", x509.UnknownPublicKeyAlgorithm)
		require.NoError(t, err)
		_, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		require.NoError(t, err)
	}

	// Warm up once so lazily created state is not counted as a leak.
	sign()

	before := alloc.InUse()
	const n = 50
	for i := 0; i < n; i++ {
		sign()

		_, err := ca.CASigner(ctx, "", x509.DSA)
		require.ErrorIs(t, err, ErrInvalidKeyAlgorithm)

		failing.fail = true
		_, err = ca.CASigner(ctx, "", x509.UnknownPublicKeyAlgorithm)
		failing.fail = false
		require.Error(t, err)
	}
	after := alloc.InUse()
	require.LessOrEqual(t, after, before,
		"%d CASigner rounds grew locked bytes from %d to %d", n, before, after)
}

// lazyPasswordBackend wraps a CA backend so its signers read the key
// password at Sign time from the attrs they were created with, as the TPM 2.0
// backend's signer does.
type lazyPasswordBackend struct {
	xkms.Backend
}

func (b lazyPasswordBackend) Signer(ctx context.Context, attrs *types.KeyAttributes) (crypto.Signer, error) {
	inner, err := b.Backend.Signer(ctx, attrs)
	if err != nil {
		return nil, err
	}
	return lazyPasswordSigner{Signer: inner, attrs: attrs}, nil
}

type lazyPasswordSigner struct {
	crypto.Signer
	attrs *types.KeyAttributes
}

func (s lazyPasswordSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s.attrs.Password == nil {
		return nil, errors.New("lazy signer: no key password")
	}
	pw := s.attrs.Password.Bytes()
	if len(pw) == 0 {
		return nil, errors.New("lazy signer: key password cleared before Sign")
	}
	enclave.Wipe(pw)
	return s.Signer.Sign(r, digest, opts)
}

// TestCA_SignerReadsPasswordAtSignTime proves the signers getSigner and
// IssuerForIdentity return still sign when the backend signer reads the key
// password only inside Sign, after the getter has returned.
func TestCA_SignerReadsPasswordAtSignTime(t *testing.T) {
	ctx := context.Background()
	backend, _ := newPKCS8CABackend(t)

	root := passwordProtectedIdentity(t, rootIdentity("PW Lazy CA"), "lazy-key-password")
	parent, err := NewParentCA(&Params{
		Identity:           []Identity{root},
		KeyStore:           backend,
		BackendForStore:    singleBackendFactory(backend),
		RevocationStore:    storage.NewMemory(),
		CertStore:          newInMemoryCertStore(t),
		RequireKeyPassword: true,
	})
	require.NoError(t, err)
	require.NoError(t, parent.Init(ctx))
	ca, ok := parent.(*CA)
	require.True(t, ok, "NewParentCA must return a *CA")
	for st, b := range ca.keystoreMap {
		ca.keystoreMap[st] = lazyPasswordBackend{Backend: b}
	}

	digest := sha256.Sum256([]byte("lazy signer"))

	signer, err := ca.getSigner(ctx)
	require.NoError(t, err)
	_, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err, "getSigner's signer must still hold the key password at Sign time")

	signer, _, err = ca.IssuerForIdentity(ctx, "PW Lazy CA")
	require.NoError(t, err)
	_, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err, "IssuerForIdentity's signer must still hold the key password at Sign time")
}

// TestPasswordScopedSigner_RefusesAKeyOtherThanItsOwn proves the scoped
// signer pins the key it was created for: when the per-Sign lookup resolves
// a different key (a rotated or replaced CA key), Sign refuses instead of
// producing a signature that Public() does not verify.
func TestPasswordScopedSigner_RefusesAKeyOtherThanItsOwn(t *testing.T) {
	t.Parallel()

	pinned, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	digest := sha256.Sum256([]byte("pinned key"))

	open := func(k crypto.Signer) func() (crypto.Signer, caKeyPasswords, error) {
		return func() (crypto.Signer, caKeyPasswords, error) { return k, nil, nil }
	}

	same := &passwordScopedSigner{pub: pinned.Public(), open: open(pinned)}
	sig, err := same.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	require.True(t, ecdsa.VerifyASN1(&pinned.PublicKey, digest[:], sig))

	swapped := &passwordScopedSigner{pub: pinned.Public(), open: open(other)}
	_, err = swapped.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.Error(t, err, "Sign must refuse a key other than the one Public reports")
}

// TestCA_RepeatedSignKeepsParentPasswordsBounded proves the per-lookup and
// per-Sign cleanup clears every password the key conversion allocated, the
// parent key's included: N lookups and signatures with a CA key whose
// KeyConfig carries a password-protected parent leave the process
// allocator's locked bytes where they started. Not parallel: it measures the
// process-wide allocator.
func TestCA_RepeatedSignKeepsParentPasswordsBounded(t *testing.T) {
	ctx := context.Background()
	backend, _ := newPKCS8CABackend(t)

	root := passwordProtectedIdentity(t, rootIdentity("PW Parent Chain CA"), "chain-key-password")
	trusted, err := NewParentCA(&Params{
		Identity:           []Identity{root},
		KeyStore:           backend,
		BackendForStore:    singleBackendFactory(backend),
		RevocationStore:    storage.NewMemory(),
		CertStore:          newInMemoryCertStore(t),
		RequireKeyPassword: true,
	})
	require.NoError(t, err)
	require.NoError(t, trusted.Init(ctx))
	ca, ok := trusted.(*CA)
	require.True(t, ok, "NewParentCA must return a *CA")

	// The constructors rebuild the identity from the flat CAConfig, so the
	// parent key is attached to the live issuing identity after Init.
	issuing := ca.config.IssuingIdentity()
	require.NotNil(t, issuing)
	parentPassword, err := types.NewLiteralSecretValue(ctx, []byte("parent-key-password"))
	require.NoError(t, err)
	parentKey := *issuing.Keys[0]
	parentKey.Password = parentPassword
	parentKey.Parent = nil
	key := *issuing.Keys[0]
	key.Parent = &parentKey
	issuing.Keys = []*types.KeyConfig{&key}

	alloc, err := enclave.ProcessAllocator()
	require.NoError(t, err)
	digest := sha256.Sum256([]byte("parent chain"))
	signOnce := func() {
		signer, err := ca.getSigner(ctx)
		require.NoError(t, err)
		_, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		require.NoError(t, err)
	}

	signOnce() // warm up lazily created state
	before := alloc.InUse()
	const n = 50
	for i := 0; i < n; i++ {
		signOnce()
	}
	after := alloc.InUse()
	require.LessOrEqual(t, after, before,
		"%d lookups and signatures grew locked bytes from %d to %d", n, before, after)
}
