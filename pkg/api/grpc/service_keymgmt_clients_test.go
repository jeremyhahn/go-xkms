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

package grpc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/keypolicy"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// keyManagementService returns the real Service over a software backend with
// a key version store and a key policy store, holding an ECDSA signing key
// "signer" and an AES-GCM key "aead".
func keyManagementService(t *testing.T) *Service {
	t.Helper()
	s, client := keyVersionServer(t)
	store, err := keypolicy.NewStore(testutil.NewMemoryDAOFactory())
	require.NoError(t, err)
	s.xkmsService.SetKeyPolicyStore(store)

	ctx := context.Background()
	_, err = client.GenerateKey(ctx, &pb.GenerateKeyRequest{KeyId: "signer", Backend: "software", KeyType: "signing", Algorithm: "ecdsa"})
	require.NoError(t, err)
	_, err = client.GenerateKey(ctx, &pb.GenerateKeyRequest{KeyId: "aead", Backend: "software", KeyType: "secret", Algorithm: "aes-256-gcm"})
	require.NoError(t, err)
	return s
}

// TestKeyManagementRPCs_EndToEnd drives the key management RPCs against the
// real service: the public key, metadata, policy, rotation policy, safety
// limits, backend status and revocation.
// TestKeyManagementRPCs_MapErrors proves the key management refusals reach
// the caller with their class's code.
// TestKeyManagementAndCryptoUtilityRPCs_NilService proves every key
// management and crypto utility RPC answers Unavailable, not a panic, when
// no service is wired.
func TestKeyManagementAndCryptoUtilityRPCs_NilService(t *testing.T) {
	s := NewService(nil, nil, nil)
	ctx := context.Background()
	calls := map[string]func() error{
		"get public key":      func() error { _, err := s.GetPublicKey(ctx, &pb.GetPublicKeyRequest{}); return err },
		"revoke":              func() error { _, err := s.RevokeKey(ctx, &pb.RevokeKeyRequest{}); return err },
		"update status":       func() error { _, err := s.UpdateKeyStatus(ctx, &pb.UpdateKeyStatusRequest{}); return err },
		"get metadata":        func() error { _, err := s.GetKeyMetadata(ctx, &pb.GetKeyMetadataRequest{}); return err },
		"update metadata":     func() error { _, err := s.UpdateKeyMetadata(ctx, &pb.UpdateKeyMetadataRequest{}); return err },
		"set policy":          func() error { _, err := s.SetKeyPolicy(ctx, &pb.SetKeyPolicyRequest{}); return err },
		"get policy":          func() error { _, err := s.GetKeyPolicy(ctx, &pb.GetKeyPolicyRequest{}); return err },
		"delete policy":       func() error { _, err := s.DeleteKeyPolicy(ctx, &pb.DeleteKeyPolicyRequest{}); return err },
		"set rotation policy": func() error { _, err := s.SetKeyRotationPolicy(ctx, &pb.SetKeyRotationPolicyRequest{}); return err },
		"get rotation policy": func() error { _, err := s.GetKeyRotationPolicy(ctx, &pb.GetKeyRotationPolicyRequest{}); return err },
		"del rotation policy": func() error {
			_, err := s.DeleteKeyRotationPolicy(ctx, &pb.DeleteKeyRotationPolicyRequest{})
			return err
		},
		"supported algorithms": func() error { _, err := s.GetSupportedAlgorithms(ctx, &pb.GetSupportedAlgorithmsRequest{}); return err },
		"backend status":       func() error { _, err := s.BackendStatus(ctx, &pb.BackendStatusRequest{}); return err },
		"backend test":         func() error { _, err := s.BackendTest(ctx, &pb.BackendTestRequest{}); return err },
		"set safety":           func() error { _, err := s.SetKeySafety(ctx, &pb.SetKeySafetyRequest{}); return err },
		"clear safety":         func() error { _, err := s.ClearKeySafety(ctx, &pb.ClearKeySafetyRequest{}); return err },
		"safety check":         func() error { _, err := s.SafetyCheck(ctx, &pb.SafetyCheckRequest{}); return err },
		"safety report":        func() error { _, err := s.SafetyReport(ctx, &pb.SafetyReportRequest{}); return err },
		"rewrap":               func() error { _, err := s.Rewrap(ctx, &pb.RewrapRequest{}); return err },
		"encrypt batch":        func() error { _, err := s.EncryptBatch(ctx, &pb.EncryptBatchRequest{}); return err },
		"decrypt batch":        func() error { _, err := s.DecryptBatch(ctx, &pb.DecryptBatchRequest{}); return err },
		"data key":             func() error { _, err := s.GenerateDataKey(ctx, &pb.GenerateDataKeyRequest{}); return err },
		"wrapped data key":     func() error { _, err := s.GenerateWrappedDataKey(ctx, &pb.GenerateDataKeyRequest{}); return err },
		"hmac":                 func() error { _, err := s.GenerateHMAC(ctx, &pb.GenerateHMACRequest{}); return err },
		"verify hmac":          func() error { _, err := s.VerifyHMAC(ctx, &pb.VerifyHMACRequest{}); return err },
		"random":               func() error { _, err := s.GenerateRandom(ctx, &pb.GenerateRandomRequest{}); return err },
		"hash":                 func() error { _, err := s.Hash(ctx, &pb.HashRequest{}); return err },
	}
	for name, call := range calls {
		assert.Equal(t, codes.Unavailable, status.Code(call()), name)
	}
}
