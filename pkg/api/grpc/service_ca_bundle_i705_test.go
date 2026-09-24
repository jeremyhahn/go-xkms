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

package grpc

import (
	"context"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// This file covers servicerBundleSource.CABundle in service_ca_bundle.go
// (go-xkms #705, batch A): GetCABundle's fallback path when no CABundler is
// set via SetCABundler but a CA implementing the transport-shaped
// GetCABundle method is set via SetCA. That adapter path had no test.

// mockGRPCCABundleServicer implements ONLY grpcCABundleServicer (not
// caBundleSource) so GetCABundle's type switch is forced into the
// servicerBundleSource branch rather than the direct caBundleSource one.
type mockGRPCCABundleServicer struct {
	bundlePEM []byte
	err       error
}

func (m *mockGRPCCABundleServicer) GetCABundle(_ context.Context, _ *transport.GetCABundleRequest) (*transport.GetCABundleResponse, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &transport.GetCABundleResponse{BundlePEM: m.bundlePEM, ContentType: ContentTypePEMCertificateChain}, nil
}

func TestServiceGetCABundle_ServicerAdapterPath(t *testing.T) {
	old := getCAInstance()
	defer SetCA(old)

	cert, _ := createTestRootCACert(t)
	bundlePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	SetCA(&mockGRPCCABundleServicer{bundlePEM: bundlePEM})
	svc := newTestService()

	resp, err := svc.GetCABundle(context.Background(), &pb.GetCABundleRequest{})
	require.NoError(t, err)
	assert.Equal(t, bundlePEM, resp.BundlePem)
	require.Len(t, resp.Certificates, 1)
	assert.Equal(t, cert.Raw, resp.Certificates[0])
}

func TestServiceGetCABundle_ServicerAdapterPropagatesError(t *testing.T) {
	old := getCAInstance()
	defer SetCA(old)

	SetCA(&mockGRPCCABundleServicer{err: errors.New("ca unavailable")})
	svc := newTestService()

	_, err := svc.GetCABundle(context.Background(), &pb.GetCABundleRequest{})
	require.Error(t, err)
}
