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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
)

// This file covers the success paths of GetPIVCertificate, StorePIVCertificate
// and ImportPIVCertificate in service_piv.go (go-xkms #705, batch A); only
// their validation branches had a test (service_piv_test.go), never the
// actual store round trip. It reuses that file's setupPIVTest helper.

func TestServiceStorePIVCertificate_Success(t *testing.T) {
	cleanup := setupPIVTest(t)
	defer cleanup()
	svc := newPIVTestService()
	ctx := context.Background()

	genResp, err := svc.GeneratePIVKey(ctx, &pb.GeneratePIVKeyRequest{Backend: "software", Slot: "9c", Subject: "Test Key"})
	require.NoError(t, err)

	_, err = svc.StorePIVCertificate(ctx, &pb.StorePIVCertificateRequest{
		Backend: "software", Slot: "9c", Format: "pem", Certificate: genResp.Certificate,
	})
	require.NoError(t, err)

	getResp, err := svc.GetPIVCertificate(ctx, &pb.GetPIVCertificateRequest{Backend: "software", Slot: "9c", Format: "pem"})
	require.NoError(t, err)
	assert.Equal(t, genResp.Certificate, getResp.Certificate)
}

func TestServiceImportPIVCertificate_Success(t *testing.T) {
	cleanup := setupPIVTest(t)
	defer cleanup()
	svc := newPIVTestService()
	ctx := context.Background()

	genResp, err := svc.GeneratePIVKey(ctx, &pb.GeneratePIVKeyRequest{Backend: "software", Slot: "9d", Subject: "Test Key"})
	require.NoError(t, err)

	_, err = svc.ImportPIVCertificate(ctx, &pb.StorePIVCertificateRequest{
		Backend: "software", Slot: "9d", Format: "pem", Certificate: genResp.Certificate,
	})
	require.NoError(t, err)

	getResp, err := svc.GetPIVCertificate(ctx, &pb.GetPIVCertificateRequest{Backend: "software", Slot: "9d", Format: "pem"})
	require.NoError(t, err)
	assert.Equal(t, genResp.Certificate, getResp.Certificate)
}
