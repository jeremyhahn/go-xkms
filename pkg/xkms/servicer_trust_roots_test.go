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

package xkms

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// newTrustRootService returns a service over an in-memory trust-root store.
func newTrustRootService(t *testing.T) *XKMSService {
	t.Helper()
	store, err := truststore.NewDAOStore(testutil.NewMemoryDAOFactory())
	require.NoError(t, err)
	svc := &XKMSService{}
	svc.SetTrustRootStore(store)
	return svc
}

// trustRootPEM returns a fresh self-signed CA certificate, PEM-encoded.
func trustRootPEM(t *testing.T) string {
	t.Helper()
	ca, err := testutil.GenerateTestCA()
	require.NoError(t, err)
	return string(ca.CertPEM)
}

// importTrustRoot imports one user-CA root into svc's empty store and
// returns its fingerprint.
func importTrustRoot(t *testing.T, svc *XKMSService) string {
	t.Helper()
	ctx := systemCtx()
	resp, err := svc.TrustRootImport(ctx, &transport.TrustRootImportRequest{
		PEM: trustRootPEM(t), Purpose: string(truststore.PurposeUserCA), Source: "test",
	})
	require.NoError(t, err)
	require.Equal(t, 1, resp.Added)
	list, err := svc.TrustRootList(ctx, &transport.TrustRootListRequest{})
	require.NoError(t, err)
	require.Len(t, list.Roots, 1, "the store holds only the imported root")
	return list.Roots[0].Fingerprint
}

// TestTrustRoot_RoundTripsThroughTheDAO proves an imported root is listed,
// filtered by purpose, read back with its PEM, and gone once removed.
func TestTrustRoot_RoundTripsThroughTheDAO(t *testing.T) {
	svc := newTrustRootService(t)
	ctx := systemCtx()
	fp := importTrustRoot(t, svc)

	root, err := svc.TrustRootGet(ctx, &transport.TrustRootRequest{Fingerprint: fp})
	require.NoError(t, err)
	assert.Equal(t, string(truststore.PurposeUserCA), root.Purpose)
	assert.Equal(t, "test", root.Source)
	block, _ := pem.Decode([]byte(root.PEM))
	require.NotNil(t, block, "get returns the certificate PEM")
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, fp, truststore.Fingerprint(cert), "get returns the certificate it was asked for")

	list, err := svc.TrustRootList(ctx, &transport.TrustRootListRequest{Purpose: string(truststore.PurposeUserCA)})
	require.NoError(t, err)
	require.Len(t, list.Roots, 1)
	assert.Empty(t, list.Roots[0].PEM, "list leaves the PEM out")
	list, err = svc.TrustRootList(ctx, &transport.TrustRootListRequest{Purpose: string(truststore.PurposeImageSigner)})
	require.NoError(t, err)
	assert.Empty(t, list.Roots)

	require.NoError(t, svc.TrustRootRemove(ctx, &transport.TrustRootRequest{Fingerprint: fp}))
	_, err = svc.TrustRootGet(ctx, &transport.TrustRootRequest{Fingerprint: fp})
	assert.ErrorIs(t, err, truststore.ErrCertificateNotFound)
}

// TestTrustRoot_DuplicateImportKeepsItsPurpose proves re-importing a held
// certificate is skipped rather than reclassified.
func TestTrustRoot_DuplicateImportKeepsItsPurpose(t *testing.T) {
	svc := newTrustRootService(t)
	ctx := systemCtx()
	bundle := trustRootPEM(t)
	_, err := svc.TrustRootImport(ctx, &transport.TrustRootImportRequest{PEM: bundle, Purpose: string(truststore.PurposeUserCA)})
	require.NoError(t, err)

	resp, err := svc.TrustRootImport(ctx, &transport.TrustRootImportRequest{PEM: bundle, Purpose: string(truststore.PurposeImageSigner)})
	require.NoError(t, err)
	assert.Equal(t, 0, resp.Added)
	assert.Equal(t, 1, resp.Skipped)
	list, err := svc.TrustRootList(ctx, &transport.TrustRootListRequest{})
	require.NoError(t, err)
	require.Len(t, list.Roots, 1)
	assert.Equal(t, string(truststore.PurposeUserCA), list.Roots[0].Purpose)
}

// TestTrustRoot_QuarantinedRootAnchorsNothing proves a quarantined root is
// still listed, as synced, but no longer anchors its former purpose.
func TestTrustRoot_QuarantinedRootAnchorsNothing(t *testing.T) {
	svc := newTrustRootService(t)
	ctx := systemCtx()
	fp := importTrustRoot(t, svc)
	anchors, err := svc.TrustRootStore().Anchors(ctx, truststore.PurposeUserCA)
	require.NoError(t, err)
	require.Len(t, anchors, 1)

	root, err := svc.TrustRootQuarantine(ctx, &transport.TrustRootRequest{Fingerprint: fp})
	require.NoError(t, err)
	assert.Equal(t, string(truststore.PurposeSynced), root.Purpose)

	anchors, err = svc.TrustRootStore().Anchors(ctx, truststore.PurposeUserCA)
	require.NoError(t, err)
	assert.Empty(t, anchors, "a quarantined root anchors no verification")
	_, err = svc.TrustRootStore().Anchors(ctx, truststore.PurposeSynced)
	assert.ErrorIs(t, err, truststore.ErrNotAnchorPurpose)

	list, err := svc.TrustRootList(ctx, &transport.TrustRootListRequest{Purpose: string(truststore.PurposeSynced)})
	require.NoError(t, err)
	assert.Len(t, list.Roots, 1, "a quarantined root stays listed")
}

// TestTrustRoot_RejectsBadInput proves malformed requests are refused with
// the store's typed errors.
func TestTrustRoot_RejectsBadInput(t *testing.T) {
	svc := newTrustRootService(t)
	ctx := systemCtx()

	_, err := svc.TrustRootList(ctx, &transport.TrustRootListRequest{Purpose: "no-such-purpose"})
	assert.ErrorIs(t, err, truststore.ErrInvalidPurpose)
	_, err = svc.TrustRootImport(ctx, &transport.TrustRootImportRequest{PEM: trustRootPEM(t), Purpose: "no-such-purpose"})
	assert.ErrorIs(t, err, truststore.ErrInvalidPurpose)
	_, err = svc.TrustRootGet(ctx, &transport.TrustRootRequest{Fingerprint: "00"})
	assert.Error(t, err)
	_, err = svc.TrustRootQuarantine(ctx, &transport.TrustRootRequest{Fingerprint: "00"})
	assert.Error(t, err)

	for name, call := range trustRootServiceCalls(ctx, svc, nil) {
		assert.ErrorIs(t, call(), ErrNilRequest, name)
	}
}

// TestTrustRoot_RefusesATenantCaller proves every trust-root operation is
// platform-scoped: a tenant-scoped caller is refused as a miss, before the
// store is touched.
func TestTrustRoot_RefusesATenantCaller(t *testing.T) {
	svc := newTrustRootService(t)
	fp := importTrustRoot(t, svc)
	ref := &transport.TrustRootRequest{Fingerprint: fp}
	for name, call := range trustRootServiceCalls(tenantCtx("tenant-a"), svc, ref) {
		requireBindingRefusal(t, call(), name)
	}
	_, err := svc.TrustRootGet(systemCtx(), ref)
	assert.NoError(t, err, "the refused remove left the root in place")
}

// TestTrustRoot_NotConfigured proves every operation answers
// ErrNotConfigured when no store is wired.
func TestTrustRoot_NotConfigured(t *testing.T) {
	svc := &XKMSService{}
	assert.Nil(t, svc.TrustRootStore())
	ref := &transport.TrustRootRequest{Fingerprint: "00"}
	for name, call := range trustRootServiceCalls(systemCtx(), svc, ref) {
		assert.ErrorIs(t, call(), ErrNotConfigured, name)
	}
}

// trustRootServiceCalls returns one call per trust-root method of svc. A nil
// ref sends a nil request to every method.
func trustRootServiceCalls(ctx context.Context, svc *XKMSService, ref *transport.TrustRootRequest) map[string]func() error {
	var (
		list *transport.TrustRootListRequest
		imp  *transport.TrustRootImportRequest
	)
	if ref != nil {
		list = &transport.TrustRootListRequest{}
		imp = &transport.TrustRootImportRequest{PEM: "-"}
	}
	return map[string]func() error{
		"list": func() error {
			_, err := svc.TrustRootList(ctx, list)
			return err
		},
		"get": func() error {
			_, err := svc.TrustRootGet(ctx, ref)
			return err
		},
		"import": func() error {
			_, err := svc.TrustRootImport(ctx, imp)
			return err
		},
		"quarantine": func() error {
			_, err := svc.TrustRootQuarantine(ctx, ref)
			return err
		},
		"remove": func() error { return svc.TrustRootRemove(ctx, ref) },
	}
}
