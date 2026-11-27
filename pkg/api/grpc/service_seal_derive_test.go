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

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestAttestKey_SoftwareBackendDoesNotSupportAttestation(t *testing.T) {
	svc := setupServiceTest(t)
	defer xkms.Reset()

	// Generate a key first
	_, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:     "attest-test-key",
		Backend:   "software",
		Algorithm: "ECDSA",
		KeyType:   "signing",
	})
	require.NoError(t, err)

	// Try to attest - software backend doesn't support attestation
	_, err = svc.AttestKey(context.Background(), &pb.AttestKeyRequest{
		Backend: "software",
		KeyId:   "attest-test-key",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unimplemented, st.Code())
}

func TestUnwrapKeyByID_BackendDoesNotSupportImportExport(t *testing.T) {
	// Use pkcs8 backend
	setupXKMSForTest(t)
	defer xkms.Reset()
	xkmsSvc, err := xkms.Get()
	if err != nil {
		t.Fatalf("Failed to get xkms service: %v", err)
	}
	svc := NewService(nil, nil, xkmsSvc)

	_, err = svc.UnwrapKeyByID(context.Background(), &pb.UnwrapKeyByIDRequest{
		WrappedKey:           []byte("wrapped"),
		UnwrappingKeyId:      "k",
		UnwrappingKeyBackend: "test",
		Algorithm:            "AES-WRAP",
		TargetKeyId:          "k2",
		TargetKeyBackend:     "test",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unimplemented, st.Code())
}
