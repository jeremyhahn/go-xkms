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

package image

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// TestVerifier_VerifyImage_PersistedTrustRootStore: the image verifier fed
// the persisted trust-root store (PurposeImageSigner) trusts the signer
// root installed there.
func TestVerifier_VerifyImage_PersistedTrustRootStore(t *testing.T) {
	f := newSignerFixture(t, registryConfig{referrers: true})
	f.pushAttestation(t, f.validAttestation(t))

	store, err := truststore.NewDAOStore(testutil.NewMemoryDAOFactory())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	require.NoError(t, store.Add(t.Context(), f.pki.certificate,
		&truststore.AddCertificateOptions{Purpose: truststore.PurposeImageSigner}))

	verifier, err := NewVerifier(&VerifierConfig[truststore.CertPurpose]{
		Registry: f.client,
		Roots:    store,
		Purpose:  truststore.PurposeImageSigner,
	})
	require.NoError(t, err)

	result, err := verifier.VerifyImage(t.Context(), f.ref)
	require.NoError(t, err, "a signer root in the persisted store is trusted")
	assert.Equal(t, f.digest, result.Digest)
}

// TestVerifier_VerifyImage_PersistedTrustRootStoreOtherPurpose: a root the
// store files under another purpose does not sign images.
func TestVerifier_VerifyImage_PersistedTrustRootStoreOtherPurpose(t *testing.T) {
	f := newSignerFixture(t, registryConfig{referrers: true})
	f.pushAttestation(t, f.validAttestation(t))

	store, err := truststore.NewDAOStore(testutil.NewMemoryDAOFactory())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	require.NoError(t, store.Add(t.Context(), f.pki.certificate,
		&truststore.AddCertificateOptions{Purpose: truststore.PurposeUserCA}))

	verifier, err := NewVerifier(&VerifierConfig[truststore.CertPurpose]{
		Registry: f.client,
		Roots:    store,
		Purpose:  truststore.PurposeImageSigner,
	})
	require.NoError(t, err)

	_, err = verifier.VerifyImage(t.Context(), f.ref)
	require.Error(t, err)
}
