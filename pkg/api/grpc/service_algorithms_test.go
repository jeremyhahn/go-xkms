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

//go:build codec_json && codec_cbor && codec_msgpack

// service_algorithms_test.go covers the gRPC algorithm discovery RPC.
package grpc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestAlgorithms_Success proves the RPC reports a real inventory and that the
// proto conversion carries every field a caller needs to act on.
func TestAlgorithms_Success(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	resp, err := svc.Algorithms(context.Background(), &pb.AlgorithmsRequest{})
	require.NoError(t, err)
	require.NotEmpty(t, resp.GetSigning(), "a build with a software backend must report signing algorithms")

	for _, a := range resp.GetSigning() {
		assert.NotEmpty(t, a.GetAlgorithm(), "every entry must name its algorithm")
		assert.NotEmpty(t, a.GetBackends(), "every entry must name the backends providing it")
	}

	// At least one entry must carry a curve or a key size, otherwise the
	// conversion silently dropped the parameters that make the inventory
	// actionable.
	var parameterized bool
	for _, a := range resp.GetSigning() {
		if len(a.GetCurves()) > 0 || len(a.GetKeySizes()) > 0 {
			parameterized = true
			break
		}
	}
	assert.True(t, parameterized, "curves and key sizes must survive proto conversion")
}

// TestAlgorithms_NotConfigured proves the RPC degrades to Unavailable rather
// than panicking when no service is wired.
func TestAlgorithms_NotConfigured(t *testing.T) {
	xkms.Reset()
	svc := NewService(nil, nil, nil)

	_, err := svc.Algorithms(context.Background(), &pb.AlgorithmsRequest{})
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
}
