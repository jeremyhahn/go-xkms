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

package ca

import (
	"context"
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/image"
)

// The image signer names the certificate after a caller-chosen repository,
// and the certificate store is keyed by common name alone, so a code-signing
// certificate issued for image signing must never be stored there.
func TestImageCodeSigning_TenantsSigningOneRepositoryReplaceNothing(t *testing.T) {
	c := setupTestCA(t)
	ctx := context.Background()

	certA, err := image.RequestCodeSigningCertificate(ctx, c, newECKey(t, elliptic.P256()), "tenant-a", "acme/app")
	require.NoError(t, err)
	certB, err := image.RequestCodeSigningCertificate(ctx, c, newECKey(t, elliptic.P256()), "tenant-b", "acme/app")
	require.NoError(t, err)
	assert.NotEqual(t, certA.SerialNumber, certB.SerialNumber)

	_, err = c.certStore.GetCertificate("acme/app")
	require.ErrorIs(t, err, certstore.ErrCertNotFound, "neither tenant's certificate is stored for the other to replace")
}

func TestImageCodeSigning_RepositoryNamedAfterACertificateLeavesItUnchanged(t *testing.T) {
	c := setupTestCA(t)
	ctx := context.Background()
	root, err := c.certStore.GetCertificate("Test Root CA")
	require.NoError(t, err)

	_, err = image.RequestCodeSigningCertificate(ctx, c, newECKey(t, elliptic.P256()), "tenant-a", "Test Root CA")
	require.NoError(t, err)

	stored, err := c.certStore.GetCertificate("Test Root CA")
	require.NoError(t, err)
	assert.True(t, root.Equal(stored), "the CA certificate is not replaced by a code-signing certificate")
}
