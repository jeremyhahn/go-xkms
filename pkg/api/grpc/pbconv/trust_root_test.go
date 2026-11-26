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

package pbconv

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

func sampleTrustRoot() transport.TrustRoot {
	return transport.TrustRoot{
		Fingerprint: "ab12",
		Purpose:     "tpm-manufacturer",
		Subject:     "CN=EK Root",
		Issuer:      "CN=EK Root",
		Algorithm:   "ECDSA-P384",
		NotBefore:   "2026-01-01T00:00:00Z",
		NotAfter:    "2036-01-01T00:00:00Z",
		AddedAt:     "2026-11-08T00:00:00Z",
		Source:      "vendor bundle",
		PEM:         "-----BEGIN CERTIFICATE-----",
	}
}

func TestTrustRootConversions(t *testing.T) {
	root := sampleTrustRoot()
	assert.Equal(t, &root, TrustRootFromProto(TrustRootToProto(&root)))

	list := &transport.TrustRootListResponse{Roots: []transport.TrustRoot{root, {Fingerprint: "cd34", Purpose: "synced"}}}
	assert.Equal(t, list, TrustRootListResponseFromProto(TrustRootListResponseToProto(list)))

	empty := TrustRootListResponseFromProto(&pb.TrustRootListResponse{})
	assert.NotNil(t, empty.Roots, "an empty list is [], not null")
	assert.Empty(t, empty.Roots)

	assert.Equal(t,
		&transport.TrustRootImportRequest{PEM: "pem", Purpose: "general", Source: "ops"},
		TrustRootImportRequestFromProto(&pb.TrustRootImportRequest{Pem: "pem", Purpose: "general", Source: "ops"}))
}

func TestTrustRootClient(t *testing.T) {
	root := sampleTrustRoot()
	stub := &stubKeystoreClient{resp: map[string]any{
		"TrustRootList":       &pb.TrustRootListResponse{Roots: []*pb.TrustRoot{TrustRootToProto(&root)}},
		"TrustRootGet":        TrustRootToProto(&root),
		"TrustRootImport":     &pb.TrustRootImportResponse{Added: 2, Skipped: 1},
		"TrustRootQuarantine": &pb.TrustRoot{Fingerprint: "ab12", Purpose: "synced"},
	}}
	c := TrustRootClient{Client: stub}
	ctx := context.Background()

	list, err := c.TrustRootList(ctx, &transport.TrustRootListRequest{Purpose: "tpm-manufacturer"})
	require.NoError(t, err)
	assert.Equal(t, []transport.TrustRoot{root}, list.Roots)
	assert.Equal(t, "tpm-manufacturer", stub.got[0].(*pb.TrustRootListRequest).GetPurpose())

	got, err := c.TrustRootGet(ctx, &transport.TrustRootRequest{Fingerprint: "ab12"})
	require.NoError(t, err)
	assert.Equal(t, &root, got)

	imported, err := c.TrustRootImport(ctx, &transport.TrustRootImportRequest{PEM: "pem", Purpose: "general", Source: "ops"})
	require.NoError(t, err)
	assert.Equal(t, &transport.TrustRootImportResponse{Added: 2, Skipped: 1}, imported)
	assert.Equal(t, "ops", stub.got[2].(*pb.TrustRootImportRequest).GetSource())

	quarantined, err := c.TrustRootQuarantine(ctx, &transport.TrustRootRequest{Fingerprint: "ab12"})
	require.NoError(t, err)
	assert.Equal(t, "synced", quarantined.Purpose)

	require.NoError(t, c.TrustRootRemove(ctx, &transport.TrustRootRequest{Fingerprint: "ab12"}))
	assert.Equal(t, "ab12", stub.got[4].(*pb.TrustRootRequest).GetFingerprint())

	rootReq := &transport.TrustRootRequest{Fingerprint: "ab12"}
	assertClientCalls(t, stub, []clientCall{
		{"TrustRootList",
			func(ctx context.Context) error {
				_, err := c.TrustRootList(ctx, &transport.TrustRootListRequest{})
				return err
			},
			func(ctx context.Context) error { _, err := c.TrustRootList(ctx, nil); return err }},
		{"TrustRootGet",
			func(ctx context.Context) error { _, err := c.TrustRootGet(ctx, rootReq); return err },
			func(ctx context.Context) error { _, err := c.TrustRootGet(ctx, nil); return err }},
		{"TrustRootImport",
			func(ctx context.Context) error {
				_, err := c.TrustRootImport(ctx, &transport.TrustRootImportRequest{})
				return err
			},
			func(ctx context.Context) error { _, err := c.TrustRootImport(ctx, nil); return err }},
		{"TrustRootQuarantine",
			func(ctx context.Context) error { _, err := c.TrustRootQuarantine(ctx, rootReq); return err },
			func(ctx context.Context) error { _, err := c.TrustRootQuarantine(ctx, nil); return err }},
		{"TrustRootRemove",
			func(ctx context.Context) error { return c.TrustRootRemove(ctx, rootReq) },
			func(ctx context.Context) error { return c.TrustRootRemove(ctx, nil) }},
	})
}
