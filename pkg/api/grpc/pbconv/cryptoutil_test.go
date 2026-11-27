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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// errStubWire stands in for a gRPC status error from the server.
var errStubWire = errors.New("stub wire failure")

// stubKeystoreClient answers the crypto utility, key management and trust
// root RPCs with canned responses, or with err when it is set, and records
// every request it receives.
type stubKeystoreClient struct {
	pb.KeystoreServiceClient
	err  error
	got  []any
	resp map[string]any
}

// stubReply records in and returns the canned response for the method, or
// the stub's error.
func stubReply[T any](s *stubKeystoreClient, method string, in any) (*T, error) {
	s.got = append(s.got, in)
	if s.err != nil {
		return nil, s.err
	}
	if r, ok := s.resp[method].(*T); ok {
		return r, nil
	}
	return new(T), nil
}

func (s *stubKeystoreClient) Rewrap(_ context.Context, in *pb.RewrapRequest, _ ...grpc.CallOption) (*pb.RewrapResponse, error) {
	return stubReply[pb.RewrapResponse](s, "Rewrap", in)
}

func (s *stubKeystoreClient) EncryptBatch(_ context.Context, in *pb.EncryptBatchRequest, _ ...grpc.CallOption) (*pb.EncryptBatchResponse, error) {
	return stubReply[pb.EncryptBatchResponse](s, "EncryptBatch", in)
}

func (s *stubKeystoreClient) DecryptBatch(_ context.Context, in *pb.DecryptBatchRequest, _ ...grpc.CallOption) (*pb.DecryptBatchResponse, error) {
	return stubReply[pb.DecryptBatchResponse](s, "DecryptBatch", in)
}

func (s *stubKeystoreClient) GenerateDataKey(_ context.Context, in *pb.GenerateDataKeyRequest, _ ...grpc.CallOption) (*pb.GenerateDataKeyResponse, error) {
	return stubReply[pb.GenerateDataKeyResponse](s, "GenerateDataKey", in)
}

func (s *stubKeystoreClient) GenerateWrappedDataKey(_ context.Context, in *pb.GenerateDataKeyRequest, _ ...grpc.CallOption) (*pb.GenerateWrappedDataKeyResponse, error) {
	return stubReply[pb.GenerateWrappedDataKeyResponse](s, "GenerateWrappedDataKey", in)
}

func (s *stubKeystoreClient) GenerateHMAC(_ context.Context, in *pb.GenerateHMACRequest, _ ...grpc.CallOption) (*pb.GenerateHMACResponse, error) {
	return stubReply[pb.GenerateHMACResponse](s, "GenerateHMAC", in)
}

func (s *stubKeystoreClient) VerifyHMAC(_ context.Context, in *pb.VerifyHMACRequest, _ ...grpc.CallOption) (*pb.VerifyHMACResponse, error) {
	return stubReply[pb.VerifyHMACResponse](s, "VerifyHMAC", in)
}

func (s *stubKeystoreClient) GenerateRandom(_ context.Context, in *pb.GenerateRandomRequest, _ ...grpc.CallOption) (*pb.GenerateRandomResponse, error) {
	return stubReply[pb.GenerateRandomResponse](s, "GenerateRandom", in)
}

func (s *stubKeystoreClient) Hash(_ context.Context, in *pb.HashRequest, _ ...grpc.CallOption) (*pb.HashResponse, error) {
	return stubReply[pb.HashResponse](s, "Hash", in)
}

func (s *stubKeystoreClient) GetPublicKey(_ context.Context, in *pb.GetPublicKeyRequest, _ ...grpc.CallOption) (*pb.GetPublicKeyResponse, error) {
	return stubReply[pb.GetPublicKeyResponse](s, "GetPublicKey", in)
}

func (s *stubKeystoreClient) RevokeKey(_ context.Context, in *pb.RevokeKeyRequest, _ ...grpc.CallOption) (*pb.RevokeKeyResponse, error) {
	return stubReply[pb.RevokeKeyResponse](s, "RevokeKey", in)
}

func (s *stubKeystoreClient) UpdateKeyStatus(_ context.Context, in *pb.UpdateKeyStatusRequest, _ ...grpc.CallOption) (*pb.UpdateKeyStatusResponse, error) {
	return stubReply[pb.UpdateKeyStatusResponse](s, "UpdateKeyStatus", in)
}

func (s *stubKeystoreClient) GetKeyMetadata(_ context.Context, in *pb.GetKeyMetadataRequest, _ ...grpc.CallOption) (*pb.GetKeyMetadataResponse, error) {
	return stubReply[pb.GetKeyMetadataResponse](s, "GetKeyMetadata", in)
}

func (s *stubKeystoreClient) UpdateKeyMetadata(_ context.Context, in *pb.UpdateKeyMetadataRequest, _ ...grpc.CallOption) (*pb.UpdateKeyMetadataResponse, error) {
	return stubReply[pb.UpdateKeyMetadataResponse](s, "UpdateKeyMetadata", in)
}

func (s *stubKeystoreClient) SetKeyPolicy(_ context.Context, in *pb.SetKeyPolicyRequest, _ ...grpc.CallOption) (*pb.SetKeyPolicyResponse, error) {
	return stubReply[pb.SetKeyPolicyResponse](s, "SetKeyPolicy", in)
}

func (s *stubKeystoreClient) GetKeyPolicy(_ context.Context, in *pb.GetKeyPolicyRequest, _ ...grpc.CallOption) (*pb.GetKeyPolicyResponse, error) {
	return stubReply[pb.GetKeyPolicyResponse](s, "GetKeyPolicy", in)
}

func (s *stubKeystoreClient) DeleteKeyPolicy(_ context.Context, in *pb.DeleteKeyPolicyRequest, _ ...grpc.CallOption) (*pb.DeleteKeyPolicyResponse, error) {
	return stubReply[pb.DeleteKeyPolicyResponse](s, "DeleteKeyPolicy", in)
}

func (s *stubKeystoreClient) SetKeyRotationPolicy(_ context.Context, in *pb.SetKeyRotationPolicyRequest, _ ...grpc.CallOption) (*pb.SetKeyRotationPolicyResponse, error) {
	return stubReply[pb.SetKeyRotationPolicyResponse](s, "SetKeyRotationPolicy", in)
}

func (s *stubKeystoreClient) GetKeyRotationPolicy(_ context.Context, in *pb.GetKeyRotationPolicyRequest, _ ...grpc.CallOption) (*pb.GetKeyRotationPolicyResponse, error) {
	return stubReply[pb.GetKeyRotationPolicyResponse](s, "GetKeyRotationPolicy", in)
}

func (s *stubKeystoreClient) DeleteKeyRotationPolicy(_ context.Context, in *pb.DeleteKeyRotationPolicyRequest, _ ...grpc.CallOption) (*pb.DeleteKeyRotationPolicyResponse, error) {
	return stubReply[pb.DeleteKeyRotationPolicyResponse](s, "DeleteKeyRotationPolicy", in)
}

func (s *stubKeystoreClient) GetSupportedAlgorithms(_ context.Context, in *pb.GetSupportedAlgorithmsRequest, _ ...grpc.CallOption) (*pb.GetSupportedAlgorithmsResponse, error) {
	return stubReply[pb.GetSupportedAlgorithmsResponse](s, "GetSupportedAlgorithms", in)
}

func (s *stubKeystoreClient) BackendStatus(_ context.Context, in *pb.BackendStatusRequest, _ ...grpc.CallOption) (*pb.BackendStatusResponse, error) {
	return stubReply[pb.BackendStatusResponse](s, "BackendStatus", in)
}

func (s *stubKeystoreClient) BackendTest(_ context.Context, in *pb.BackendTestRequest, _ ...grpc.CallOption) (*pb.BackendTestResponse, error) {
	return stubReply[pb.BackendTestResponse](s, "BackendTest", in)
}

func (s *stubKeystoreClient) SetKeySafety(_ context.Context, in *pb.SetKeySafetyRequest, _ ...grpc.CallOption) (*pb.SetKeySafetyResponse, error) {
	return stubReply[pb.SetKeySafetyResponse](s, "SetKeySafety", in)
}

func (s *stubKeystoreClient) ClearKeySafety(_ context.Context, in *pb.ClearKeySafetyRequest, _ ...grpc.CallOption) (*pb.ClearKeySafetyResponse, error) {
	return stubReply[pb.ClearKeySafetyResponse](s, "ClearKeySafety", in)
}

func (s *stubKeystoreClient) SafetyCheck(_ context.Context, in *pb.SafetyCheckRequest, _ ...grpc.CallOption) (*pb.SafetyCheckResponse, error) {
	return stubReply[pb.SafetyCheckResponse](s, "SafetyCheck", in)
}

func (s *stubKeystoreClient) SafetyReport(_ context.Context, in *pb.SafetyReportRequest, _ ...grpc.CallOption) (*pb.SafetyReportResponse, error) {
	return stubReply[pb.SafetyReportResponse](s, "SafetyReport", in)
}

func (s *stubKeystoreClient) TrustRootList(_ context.Context, in *pb.TrustRootListRequest, _ ...grpc.CallOption) (*pb.TrustRootListResponse, error) {
	return stubReply[pb.TrustRootListResponse](s, "TrustRootList", in)
}

func (s *stubKeystoreClient) TrustRootGet(_ context.Context, in *pb.TrustRootRequest, _ ...grpc.CallOption) (*pb.TrustRoot, error) {
	return stubReply[pb.TrustRoot](s, "TrustRootGet", in)
}

func (s *stubKeystoreClient) TrustRootImport(_ context.Context, in *pb.TrustRootImportRequest, _ ...grpc.CallOption) (*pb.TrustRootImportResponse, error) {
	return stubReply[pb.TrustRootImportResponse](s, "TrustRootImport", in)
}

func (s *stubKeystoreClient) TrustRootQuarantine(_ context.Context, in *pb.TrustRootRequest, _ ...grpc.CallOption) (*pb.TrustRoot, error) {
	return stubReply[pb.TrustRoot](s, "TrustRootQuarantine", in)
}

func (s *stubKeystoreClient) TrustRootRemove(_ context.Context, in *pb.TrustRootRequest, _ ...grpc.CallOption) (*pb.TrustRootRemoveResponse, error) {
	return stubReply[pb.TrustRootRemoveResponse](s, "TrustRootRemove", in)
}

// clientCall is one client method driven with a valid request and with a
// nil one.
type clientCall struct {
	name    string
	call    func(ctx context.Context) error
	nilCall func(ctx context.Context) error
}

// assertClientCalls checks that every call succeeds against stub, returns
// the wire error unchanged when the stub fails, and refuses a nil request
// without reaching the wire.
func assertClientCalls(t *testing.T, stub *stubKeystoreClient, calls []clientCall) {
	t.Helper()
	ctx := context.Background()
	for _, tc := range calls {
		t.Run(tc.name, func(t *testing.T) {
			stub.err, stub.got = nil, nil
			require.NoError(t, tc.call(ctx))
			assert.Len(t, stub.got, 1, "one RPC per call")

			stub.err = errStubWire
			assert.ErrorIs(t, tc.call(ctx), errStubWire)

			stub.err, stub.got = nil, nil
			assert.ErrorIs(t, tc.nilCall(ctx), ErrNilRequest)
			assert.Empty(t, stub.got, "a nil request never reaches the wire")
		})
	}
}

func sampleEncryptResponse() *transport.EncryptResponse {
	return &transport.EncryptResponse{
		Ciphertext:   []byte("ct"),
		Nonce:        []byte("nonce"),
		Tag:          []byte("tag"),
		IV:           []byte("iv"),
		GCMNonceMode: "random",
		KeyVersion:   3,
	}
}

func sampleDecryptRequest() *transport.DecryptRequest {
	return &transport.DecryptRequest{
		Backend:        "pkcs8",
		KeyID:          "k1",
		Ciphertext:     []byte("ct"),
		Nonce:          []byte("nonce"),
		Tag:            []byte("tag"),
		AdditionalData: []byte("aad"),
		GCMNonceMode:   "random",
		Mode:           "cbc",
		IV:             []byte("iv"),
		Padding:        "oaep",
		Hash:           "SHA-256",
		Label:          []byte("label"),
		TagSize:        12,
		KeyVersion:     2,
	}
}

func TestCryptoUtilityConversions_RoundTrip(t *testing.T) {
	enc := sampleEncryptResponse()
	assert.Equal(t, enc, EncryptResponseFromProto(EncryptResponseToProto(enc)))

	dec := sampleDecryptRequest()
	assert.Equal(t, dec, DecryptRequestFromProto(DecryptRequestToProto(dec)))

	rewrap := &transport.RewrapRequest{Source: dec, TargetKeyID: "k2", TargetBackend: "tpm2"}
	assert.Equal(t, rewrap, RewrapRequestFromProto(RewrapRequestToProto(rewrap)))

	rewrapped := &transport.RewrapResponse{SourceKeyVersion: 2, Wrapped: enc}
	assert.Equal(t, rewrapped, RewrapResponseFromProto(RewrapResponseToProto(rewrapped)))

	encBatch := &transport.EncryptBatchRequest{
		KeyID:   "k1",
		Backend: "pkcs8",
		Items:   []transport.EncryptBatchItem{{Plaintext: []byte("a"), AdditionalData: []byte("x")}, {Plaintext: []byte("b")}},
	}
	assert.Equal(t, encBatch, EncryptBatchRequestFromProto(EncryptBatchRequestToProto(encBatch)))

	encResults := &transport.EncryptBatchResponse{Results: []transport.EncryptBatchResult{{Result: enc}, {Error: "key disabled"}}}
	assert.Equal(t, encResults, EncryptBatchResponseFromProto(EncryptBatchResponseToProto(encResults)))

	decBatch := &transport.DecryptBatchRequest{
		KeyID:   "k1",
		Backend: "pkcs8",
		Items: []transport.DecryptBatchItem{{
			Ciphertext: []byte("ct"), AdditionalData: []byte("aad"), Nonce: []byte("n"),
			Tag: []byte("t"), GCMNonceMode: "random", KeyVersion: 4,
		}},
	}
	assert.Equal(t, decBatch, DecryptBatchRequestFromProto(DecryptBatchRequestToProto(decBatch)))

	decResults := &transport.DecryptBatchResponse{Results: []transport.DecryptBatchResult{{Plaintext: []byte("p"), KeyVersion: 4}, {Error: "bad tag"}}}
	assert.Equal(t, decResults, DecryptBatchResponseFromProto(DecryptBatchResponseToProto(decResults)))

	dataKey := &transport.GenerateDataKeyRequest{KeyID: "k1", Backend: "pkcs8", KeySize: 32, AdditionalData: []byte("aad")}
	assert.Equal(t, dataKey, GenerateDataKeyRequestFromProto(GenerateDataKeyRequestToProto(dataKey)))

	hmac := &transport.GenerateHMACRequest{KeyID: "h1", Backend: "pkcs8", Data: []byte("d"), Hash: "SHA-384"}
	assert.Equal(t, hmac, GenerateHMACRequestFromProto(GenerateHMACRequestToProto(hmac)))

	verify := &transport.VerifyHMACRequest{KeyID: "h1", Backend: "pkcs8", Data: []byte("d"), MAC: []byte("m"), Hash: "SHA-384", KeyVersion: 5}
	assert.Equal(t, verify, VerifyHMACRequestFromProto(VerifyHMACRequestToProto(verify)))
}

func TestCryptoUtilityConversions_NilAndTenant(t *testing.T) {
	assert.Nil(t, EncryptResponseToProto(nil))
	assert.Nil(t, EncryptResponseFromProto(nil))
	assert.Nil(t, DecryptRequestToProto(nil))
	assert.Nil(t, DecryptRequestFromProto(nil))

	// A rewrap without a source keeps the missing source for the server to
	// refuse, rather than inventing an empty one.
	assert.Nil(t, RewrapRequestToProto(&transport.RewrapRequest{TargetKeyID: "k2"}).GetSource())
	assert.Nil(t, RewrapRequestFromProto(&pb.RewrapRequest{}).Source)
	assert.Nil(t, RewrapResponseFromProto(&pb.RewrapResponse{}).Wrapped)

	// The tenant never crosses the wire: the server scopes to the caller.
	dec := sampleDecryptRequest()
	dec.TenantID = "acme"
	assert.Empty(t, DecryptRequestFromProto(DecryptRequestToProto(dec)).TenantID)
	batch := &transport.EncryptBatchRequest{KeyID: "k1", TenantID: "acme"}
	assert.Empty(t, EncryptBatchRequestFromProto(EncryptBatchRequestToProto(batch)).TenantID)
	assert.Empty(t, EncryptBatchRequestFromProto(&pb.EncryptBatchRequest{}).Items)
}

func TestCryptoUtilityClient(t *testing.T) {
	stub := &stubKeystoreClient{resp: map[string]any{
		"Rewrap":                 &pb.RewrapResponse{SourceKeyVersion: 2, Wrapped: EncryptResponseToProto(sampleEncryptResponse())},
		"GenerateDataKey":        &pb.GenerateDataKeyResponse{Plaintext: []byte("dek"), Wrapped: EncryptResponseToProto(sampleEncryptResponse())},
		"GenerateWrappedDataKey": &pb.GenerateWrappedDataKeyResponse{Wrapped: EncryptResponseToProto(sampleEncryptResponse())},
		"GenerateHMAC":           &pb.GenerateHMACResponse{Mac: []byte("mac"), KeyVersion: 7, Hash: "SHA-256"},
		"VerifyHMAC":             &pb.VerifyHMACResponse{Valid: true, KeyVersion: 7},
		"GenerateRandom":         &pb.GenerateRandomResponse{Random: []byte("rnd")},
		"Hash":                   &pb.HashResponse{Digest: []byte("dig"), Hash: "SHA-256"},
	}}
	c := CryptoUtilityClient{Client: stub}
	ctx := context.Background()

	rewrapped, err := c.Rewrap(ctx, &transport.RewrapRequest{Source: sampleDecryptRequest(), TargetKeyID: "k2"})
	require.NoError(t, err)
	assert.Equal(t, &transport.RewrapResponse{SourceKeyVersion: 2, Wrapped: sampleEncryptResponse()}, rewrapped)
	assert.Equal(t, "k2", stub.got[0].(*pb.RewrapRequest).GetTargetKeyId())

	dataKey, err := c.GenerateDataKey(ctx, &transport.GenerateDataKeyRequest{KeyID: "k1", KeySize: 32})
	require.NoError(t, err)
	assert.Equal(t, []byte("dek"), dataKey.Plaintext)
	assert.Equal(t, sampleEncryptResponse(), dataKey.Wrapped)

	wrapped, err := c.GenerateWrappedDataKey(ctx, &transport.GenerateDataKeyRequest{KeyID: "k1"})
	require.NoError(t, err)
	assert.Equal(t, sampleEncryptResponse(), wrapped.Wrapped)

	mac, err := c.GenerateHMAC(ctx, &transport.GenerateHMACRequest{KeyID: "h1"})
	require.NoError(t, err)
	assert.Equal(t, &transport.GenerateHMACResponse{MAC: []byte("mac"), KeyVersion: 7, Hash: "SHA-256"}, mac)

	verified, err := c.VerifyHMAC(ctx, &transport.VerifyHMACRequest{KeyID: "h1"})
	require.NoError(t, err)
	assert.Equal(t, &transport.VerifyHMACResponse{Valid: true, KeyVersion: 7}, verified)

	random, err := c.GenerateRandom(ctx, &transport.GenerateRandomRequest{Length: 16})
	require.NoError(t, err)
	assert.Equal(t, []byte("rnd"), random.Random)
	assert.Equal(t, int32(16), stub.got[len(stub.got)-1].(*pb.GenerateRandomRequest).GetLength())

	digest, err := c.Hash(ctx, &transport.HashRequest{Data: []byte("d"), Hash: "SHA-256"})
	require.NoError(t, err)
	assert.Equal(t, &transport.HashResponse{Digest: []byte("dig"), Hash: "SHA-256"}, digest)

	assertClientCalls(t, stub, []clientCall{
		{"Rewrap",
			func(ctx context.Context) error { _, err := c.Rewrap(ctx, &transport.RewrapRequest{}); return err },
			func(ctx context.Context) error { _, err := c.Rewrap(ctx, nil); return err }},
		{"EncryptBatch",
			func(ctx context.Context) error {
				_, err := c.EncryptBatch(ctx, &transport.EncryptBatchRequest{})
				return err
			},
			func(ctx context.Context) error { _, err := c.EncryptBatch(ctx, nil); return err }},
		{"DecryptBatch",
			func(ctx context.Context) error {
				_, err := c.DecryptBatch(ctx, &transport.DecryptBatchRequest{})
				return err
			},
			func(ctx context.Context) error { _, err := c.DecryptBatch(ctx, nil); return err }},
		{"GenerateDataKey",
			func(ctx context.Context) error {
				_, err := c.GenerateDataKey(ctx, &transport.GenerateDataKeyRequest{})
				return err
			},
			func(ctx context.Context) error { _, err := c.GenerateDataKey(ctx, nil); return err }},
		{"GenerateWrappedDataKey",
			func(ctx context.Context) error {
				_, err := c.GenerateWrappedDataKey(ctx, &transport.GenerateDataKeyRequest{})
				return err
			},
			func(ctx context.Context) error { _, err := c.GenerateWrappedDataKey(ctx, nil); return err }},
		{"GenerateHMAC",
			func(ctx context.Context) error {
				_, err := c.GenerateHMAC(ctx, &transport.GenerateHMACRequest{})
				return err
			},
			func(ctx context.Context) error { _, err := c.GenerateHMAC(ctx, nil); return err }},
		{"VerifyHMAC",
			func(ctx context.Context) error {
				_, err := c.VerifyHMAC(ctx, &transport.VerifyHMACRequest{})
				return err
			},
			func(ctx context.Context) error { _, err := c.VerifyHMAC(ctx, nil); return err }},
		{"GenerateRandom",
			func(ctx context.Context) error {
				_, err := c.GenerateRandom(ctx, &transport.GenerateRandomRequest{})
				return err
			},
			func(ctx context.Context) error { _, err := c.GenerateRandom(ctx, nil); return err }},
		{"Hash",
			func(ctx context.Context) error { _, err := c.Hash(ctx, &transport.HashRequest{}); return err },
			func(ctx context.Context) error { _, err := c.Hash(ctx, nil); return err }},
	})
}
