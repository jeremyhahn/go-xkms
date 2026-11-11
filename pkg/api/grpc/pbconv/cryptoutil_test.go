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

func (s *cannedServer) Rewrap(_ context.Context, in *pb.RewrapRequest) (*pb.RewrapResponse, error) {
	return answer[*pb.RewrapResponse](s, in)
}

func (s *cannedServer) EncryptBatch(_ context.Context, in *pb.EncryptBatchRequest) (*pb.EncryptBatchResponse, error) {
	return answer[*pb.EncryptBatchResponse](s, in)
}

func (s *cannedServer) DecryptBatch(_ context.Context, in *pb.DecryptBatchRequest) (*pb.DecryptBatchResponse, error) {
	return answer[*pb.DecryptBatchResponse](s, in)
}

func (s *cannedServer) GenerateDataKey(_ context.Context, in *pb.GenerateDataKeyRequest) (*pb.GenerateDataKeyResponse, error) {
	return answer[*pb.GenerateDataKeyResponse](s, in)
}

func (s *cannedServer) GenerateWrappedDataKey(_ context.Context, in *pb.GenerateDataKeyRequest) (*pb.GenerateWrappedDataKeyResponse, error) {
	return answer[*pb.GenerateWrappedDataKeyResponse](s, in)
}

func (s *cannedServer) GenerateHMAC(_ context.Context, in *pb.GenerateHMACRequest) (*pb.GenerateHMACResponse, error) {
	return answer[*pb.GenerateHMACResponse](s, in)
}

func (s *cannedServer) VerifyHMAC(_ context.Context, in *pb.VerifyHMACRequest) (*pb.VerifyHMACResponse, error) {
	return answer[*pb.VerifyHMACResponse](s, in)
}

func (s *cannedServer) GenerateRandom(_ context.Context, in *pb.GenerateRandomRequest) (*pb.GenerateRandomResponse, error) {
	return answer[*pb.GenerateRandomResponse](s, in)
}

func (s *cannedServer) Hash(_ context.Context, in *pb.HashRequest) (*pb.HashResponse, error) {
	return answer[*pb.HashResponse](s, in)
}

// sampleDecryptRequest sets every field, the tenant included.
func sampleDecryptRequest() *transport.DecryptRequest {
	return &transport.DecryptRequest{
		Backend:        "pkcs11",
		KeyID:          "k1",
		Ciphertext:     []byte("ciphertext"),
		Nonce:          []byte("nonce"),
		Tag:            []byte("tag"),
		AdditionalData: []byte("aad"),
		GCMNonceMode:   "random",
		Mode:           "gcm",
		IV:             []byte("iv"),
		Padding:        "oaep",
		Hash:           "SHA-256",
		Label:          []byte("label"),
		TagSize:        12,
		TenantID:       "tenant-a",
		KeyVersion:     3,
	}
}

// sampleDecryptRequestPB is sampleDecryptRequest on the wire.
func sampleDecryptRequestPB() *pb.DecryptRequest {
	return &pb.DecryptRequest{
		KeyId:          "k1",
		Backend:        "pkcs11",
		Ciphertext:     []byte("ciphertext"),
		AdditionalData: []byte("aad"),
		Nonce:          []byte("nonce"),
		Tag:            []byte("tag"),
		Padding:        "oaep",
		Hash:           "SHA-256",
		Label:          []byte("label"),
		Mode:           "gcm",
		Iv:             []byte("iv"),
		TagSize:        12,
		GcmNonceMode:   "random",
		KeyVersion:     3,
	}
}

func sampleEncryptResponse() *transport.EncryptResponse {
	return &transport.EncryptResponse{
		Ciphertext:   []byte("ciphertext"),
		Nonce:        []byte("nonce"),
		Tag:          []byte("tag"),
		IV:           []byte("iv"),
		GCMNonceMode: "random",
		KeyVersion:   3,
	}
}

func testEncryptResponse() *transport.EncryptResponse {
	return &transport.EncryptResponse{
		Ciphertext:   []byte("ct"),
		Nonce:        []byte("nonce"),
		Tag:          []byte("tag"),
		IV:           []byte("iv"),
		GCMNonceMode: "random",
		KeyVersion:   3,
	}
}

func TestCryptoUtilityConversions_RoundTrip(t *testing.T) {
	// The wire carries no tenant: the server scopes every request to the
	// caller's tenant.
	untenanted := sampleDecryptRequest()
	untenanted.TenantID = ""
	assert.Equal(t, untenanted, DecryptRequestFromProto(DecryptRequestToProto(sampleDecryptRequest())))
	assert.Equal(t, sampleEncryptResponse(), EncryptResponseFromProto(EncryptResponseToProto(sampleEncryptResponse())))

	rewrap := &transport.RewrapRequest{Source: untenanted, TargetKeyID: "k2", TargetBackend: "awskms"}
	assert.Equal(t, rewrap, RewrapRequestFromProto(RewrapRequestToProto(rewrap)))
	rewrapped := &transport.RewrapResponse{SourceKeyVersion: 3, Wrapped: sampleEncryptResponse()}
	assert.Equal(t, rewrapped, RewrapResponseFromProto(RewrapResponseToProto(rewrapped)))

	encBatch := &transport.EncryptBatchRequest{KeyID: "k1", Backend: "software", Items: []transport.EncryptBatchItem{
		{Plaintext: []byte("a"), AdditionalData: []byte("aad")},
		{Plaintext: []byte("b")},
	}}
	assert.Equal(t, encBatch, EncryptBatchRequestFromProto(EncryptBatchRequestToProto(encBatch)))
	encResults := &transport.EncryptBatchResponse{Results: []transport.EncryptBatchResult{
		{Result: sampleEncryptResponse()},
		{Error: "key disabled"},
	}}
	assert.Equal(t, encResults, EncryptBatchResponseFromProto(EncryptBatchResponseToProto(encResults)))

	decBatch := &transport.DecryptBatchRequest{KeyID: "k1", Backend: "software", Items: []transport.DecryptBatchItem{{
		Ciphertext: []byte("c"), AdditionalData: []byte("aad"), Nonce: []byte("n"), Tag: []byte("t"),
		GCMNonceMode: "random", KeyVersion: 2,
	}}}
	assert.Equal(t, decBatch, DecryptBatchRequestFromProto(DecryptBatchRequestToProto(decBatch)))
	decResults := &transport.DecryptBatchResponse{Results: []transport.DecryptBatchResult{
		{Plaintext: []byte("p"), KeyVersion: 2},
		{Error: "authentication failed"},
	}}
	assert.Equal(t, decResults, DecryptBatchResponseFromProto(DecryptBatchResponseToProto(decResults)))

	dataKey := &transport.GenerateDataKeyRequest{KeyID: "k1", Backend: "software", KeySize: 32, AdditionalData: []byte("aad")}
	assert.Equal(t, dataKey, GenerateDataKeyRequestFromProto(GenerateDataKeyRequestToProto(dataKey)))
	hmac := &transport.GenerateHMACRequest{KeyID: "k1", Backend: "software", Data: []byte("d"), Hash: "SHA-384"}
	assert.Equal(t, hmac, GenerateHMACRequestFromProto(GenerateHMACRequestToProto(hmac)))
	verify := &transport.VerifyHMACRequest{KeyID: "k1", Backend: "software", Data: []byte("d"), MAC: []byte("m"), Hash: "SHA-384", KeyVersion: 2}
	assert.Equal(t, verify, VerifyHMACRequestFromProto(VerifyHMACRequestToProto(verify)))
}

func testDecryptRequest() *transport.DecryptRequest {
	return &transport.DecryptRequest{
		Backend:        "software",
		KeyID:          "k",
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

// TestCryptoUtil_RoundTrip asserts every field of every crypto-utility
// conversion survives the trip to the wire and back.
func TestCryptoUtil_RoundTrip(t *testing.T) {
	tests := map[string]struct {
		in   any
		trip func(any) any
	}{
		"encrypt-response": {testEncryptResponse(), func(v any) any {
			return EncryptResponseFromProto(EncryptResponseToProto(v.(*transport.EncryptResponse)))
		}},
		"decrypt-request": {testDecryptRequest(), func(v any) any {
			return DecryptRequestFromProto(DecryptRequestToProto(v.(*transport.DecryptRequest)))
		}},
		"rewrap-request": {&transport.RewrapRequest{Source: testDecryptRequest(), TargetKeyID: "k2", TargetBackend: "pkcs11"}, func(v any) any {
			return RewrapRequestFromProto(RewrapRequestToProto(v.(*transport.RewrapRequest)))
		}},
		"rewrap-request-no-source": {&transport.RewrapRequest{TargetKeyID: "k2"}, func(v any) any {
			return RewrapRequestFromProto(RewrapRequestToProto(v.(*transport.RewrapRequest)))
		}},
		"rewrap-response": {&transport.RewrapResponse{SourceKeyVersion: 4, Wrapped: testEncryptResponse()}, func(v any) any {
			return RewrapResponseFromProto(RewrapResponseToProto(v.(*transport.RewrapResponse)))
		}},
		"encrypt-batch-request": {&transport.EncryptBatchRequest{Backend: "software", KeyID: "k", Items: []transport.EncryptBatchItem{
			{Plaintext: []byte("a"), AdditionalData: []byte("aad")}, {Plaintext: []byte("b")},
		}}, func(v any) any {
			return EncryptBatchRequestFromProto(EncryptBatchRequestToProto(v.(*transport.EncryptBatchRequest)))
		}},
		"encrypt-batch-response": {&transport.EncryptBatchResponse{Results: []transport.EncryptBatchResult{
			{Result: testEncryptResponse()}, {Error: "key disabled"},
		}}, func(v any) any {
			return EncryptBatchResponseFromProto(EncryptBatchResponseToProto(v.(*transport.EncryptBatchResponse)))
		}},
		"decrypt-batch-request": {&transport.DecryptBatchRequest{Backend: "software", KeyID: "k", Items: []transport.DecryptBatchItem{
			{Ciphertext: []byte("ct"), AdditionalData: []byte("aad"), Nonce: []byte("n"), Tag: []byte("t"), GCMNonceMode: "random", KeyVersion: 2},
		}}, func(v any) any {
			return DecryptBatchRequestFromProto(DecryptBatchRequestToProto(v.(*transport.DecryptBatchRequest)))
		}},
		"decrypt-batch-response": {&transport.DecryptBatchResponse{Results: []transport.DecryptBatchResult{
			{Plaintext: []byte("pt"), KeyVersion: 2}, {Error: "authentication failed"},
		}}, func(v any) any {
			return DecryptBatchResponseFromProto(DecryptBatchResponseToProto(v.(*transport.DecryptBatchResponse)))
		}},
		"data-key-request": {&transport.GenerateDataKeyRequest{Backend: "software", KeyID: "k", KeySize: 32, AdditionalData: []byte("aad")}, func(v any) any {
			return GenerateDataKeyRequestFromProto(GenerateDataKeyRequestToProto(v.(*transport.GenerateDataKeyRequest)))
		}},
		"hmac-request": {&transport.GenerateHMACRequest{Backend: "software", KeyID: "k", Data: []byte("d"), Hash: "SHA-384"}, func(v any) any {
			return GenerateHMACRequestFromProto(GenerateHMACRequestToProto(v.(*transport.GenerateHMACRequest)))
		}},
		"verify-hmac-request": {&transport.VerifyHMACRequest{Backend: "software", KeyID: "k", Data: []byte("d"), MAC: []byte("m"), Hash: "SHA-384", KeyVersion: 5}, func(v any) any {
			return VerifyHMACRequestFromProto(VerifyHMACRequestToProto(v.(*transport.VerifyHMACRequest)))
		}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.in, tt.trip(tt.in))
		})
	}
}

// TestCryptoUtil_NilConversions pins that the nil-guarded conversions map
// nil to nil in both directions, so an absent wrapped result stays absent.
func TestCryptoUtil_NilConversions(t *testing.T) {
	assert.Nil(t, EncryptResponseToProto(nil))
	assert.Nil(t, EncryptResponseFromProto(nil))
	assert.Nil(t, DecryptRequestToProto(nil))
	assert.Nil(t, DecryptRequestFromProto(nil))

	// A rewrap without a source reaches the server without one, for the
	// service to refuse; the converter never invents an empty source.
	assert.Nil(t, RewrapRequestToProto(&transport.RewrapRequest{TargetKeyID: "k2"}).GetSource())
	assert.Nil(t, RewrapRequestFromProto(&pb.RewrapRequest{TargetKeyId: "k2"}).Source)
	// A failed batch item carries no result.
	results := EncryptBatchResponseFromProto(&pb.EncryptBatchResponse{Results: []*pb.EncryptBatchResult{{Error: "refused"}}})
	assert.Nil(t, results.Results[0].Result)
	assert.Nil(t, RewrapResponseFromProto(&pb.RewrapResponse{}).Wrapped)
}

func TestCryptoUtilityClient_CarriesEveryRequest(t *testing.T) {
	dataKeyReq := &transport.GenerateDataKeyRequest{KeyID: "k1", Backend: "software", KeySize: 32, AdditionalData: []byte("aad"), TenantID: "tenant-a"}
	dataKeyPB := &pb.GenerateDataKeyRequest{KeyId: "k1", Backend: "software", KeySize: 32, AdditionalData: []byte("aad")}
	wrapped := &pb.EncryptResponse{Ciphertext: []byte("wrapped"), KeyVersion: 1}
	wrappedT := &transport.EncryptResponse{Ciphertext: []byte("wrapped"), KeyVersion: 1}

	runClientCases(t, func(c pb.KeystoreServiceClient) CryptoUtilityClient { return CryptoUtilityClient{Client: c} }, []clientCase[CryptoUtilityClient]{
		{
			name: "Rewrap",
			call: func(ctx context.Context, c CryptoUtilityClient) (any, error) {
				return c.Rewrap(ctx, &transport.RewrapRequest{Source: sampleDecryptRequest(), TargetKeyID: "k2", TargetBackend: "awskms"})
			},
			wantReq: &pb.RewrapRequest{Source: sampleDecryptRequestPB(), TargetKeyId: "k2", TargetBackend: "awskms"},
			reply:   &pb.RewrapResponse{SourceKeyVersion: 3, Wrapped: wrapped},
			want:    &transport.RewrapResponse{SourceKeyVersion: 3, Wrapped: wrappedT},
		},
		{
			name: "EncryptBatch",
			call: func(ctx context.Context, c CryptoUtilityClient) (any, error) {
				return c.EncryptBatch(ctx, &transport.EncryptBatchRequest{KeyID: "k1", Backend: "software",
					Items: []transport.EncryptBatchItem{{Plaintext: []byte("p"), AdditionalData: []byte("aad")}}})
			},
			wantReq: &pb.EncryptBatchRequest{KeyId: "k1", Backend: "software",
				Items: []*pb.EncryptBatchItem{{Plaintext: []byte("p"), AdditionalData: []byte("aad")}}},
			reply: &pb.EncryptBatchResponse{Results: []*pb.EncryptBatchResult{{Result: wrapped}, {Error: "refused"}}},
			want:  &transport.EncryptBatchResponse{Results: []transport.EncryptBatchResult{{Result: wrappedT}, {Error: "refused"}}},
		},
		{
			name: "DecryptBatch",
			call: func(ctx context.Context, c CryptoUtilityClient) (any, error) {
				return c.DecryptBatch(ctx, &transport.DecryptBatchRequest{KeyID: "k1", Backend: "software",
					Items: []transport.DecryptBatchItem{{Ciphertext: []byte("c"), Nonce: []byte("n"), Tag: []byte("t"), GCMNonceMode: "random", KeyVersion: 2}}})
			},
			wantReq: &pb.DecryptBatchRequest{KeyId: "k1", Backend: "software",
				Items: []*pb.DecryptBatchItem{{Ciphertext: []byte("c"), Nonce: []byte("n"), Tag: []byte("t"), GcmNonceMode: "random", KeyVersion: 2}}},
			reply: &pb.DecryptBatchResponse{Results: []*pb.DecryptBatchResult{{Plaintext: []byte("p"), KeyVersion: 2}, {Error: "refused"}}},
			want:  &transport.DecryptBatchResponse{Results: []transport.DecryptBatchResult{{Plaintext: []byte("p"), KeyVersion: 2}, {Error: "refused"}}},
		},
		{
			name: "GenerateDataKey",
			call: func(ctx context.Context, c CryptoUtilityClient) (any, error) {
				return c.GenerateDataKey(ctx, dataKeyReq)
			},
			wantReq: dataKeyPB,
			reply:   &pb.GenerateDataKeyResponse{Plaintext: []byte("dek"), Wrapped: wrapped},
			want:    &transport.GenerateDataKeyResponse{Plaintext: []byte("dek"), Wrapped: wrappedT},
		},
		{
			name: "GenerateWrappedDataKey",
			call: func(ctx context.Context, c CryptoUtilityClient) (any, error) {
				return c.GenerateWrappedDataKey(ctx, dataKeyReq)
			},
			wantReq: dataKeyPB,
			reply:   &pb.GenerateWrappedDataKeyResponse{Wrapped: wrapped},
			want:    &transport.GenerateWrappedDataKeyResponse{Wrapped: wrappedT},
		},
		{
			name: "GenerateHMAC",
			call: func(ctx context.Context, c CryptoUtilityClient) (any, error) {
				return c.GenerateHMAC(ctx, &transport.GenerateHMACRequest{KeyID: "k1", Backend: "software", Data: []byte("d"), Hash: "SHA-384"})
			},
			wantReq: &pb.GenerateHMACRequest{KeyId: "k1", Backend: "software", Data: []byte("d"), Hash: "SHA-384"},
			reply:   &pb.GenerateHMACResponse{Mac: []byte("mac"), KeyVersion: 2, Hash: "SHA-384"},
			want:    &transport.GenerateHMACResponse{MAC: []byte("mac"), KeyVersion: 2, Hash: "SHA-384"},
		},
		{
			name: "VerifyHMAC",
			call: func(ctx context.Context, c CryptoUtilityClient) (any, error) {
				return c.VerifyHMAC(ctx, &transport.VerifyHMACRequest{KeyID: "k1", Backend: "software", Data: []byte("d"), MAC: []byte("mac"), Hash: "SHA-384", KeyVersion: 2})
			},
			wantReq: &pb.VerifyHMACRequest{KeyId: "k1", Backend: "software", Data: []byte("d"), Mac: []byte("mac"), Hash: "SHA-384", KeyVersion: 2},
			reply:   &pb.VerifyHMACResponse{Valid: true, KeyVersion: 2},
			want:    &transport.VerifyHMACResponse{Valid: true, KeyVersion: 2},
		},
		{
			name: "GenerateRandom",
			call: func(ctx context.Context, c CryptoUtilityClient) (any, error) {
				return c.GenerateRandom(ctx, &transport.GenerateRandomRequest{Length: 32})
			},
			wantReq: &pb.GenerateRandomRequest{Length: 32},
			reply:   &pb.GenerateRandomResponse{Random: []byte("random")},
			want:    &transport.GenerateRandomResponse{Random: []byte("random")},
		},
		{
			name: "Hash",
			call: func(ctx context.Context, c CryptoUtilityClient) (any, error) {
				return c.Hash(ctx, &transport.HashRequest{Data: []byte("d"), Hash: "SHA-512"})
			},
			wantReq: &pb.HashRequest{Data: []byte("d"), Hash: "SHA-512"},
			reply:   &pb.HashResponse{Digest: []byte("digest"), Hash: "SHA-512"},
			want:    &transport.HashResponse{Digest: []byte("digest"), Hash: "SHA-512"},
		},
	})
}

// TestCryptoUtil_TenantIDStaysOffTheWire pins that the tenant scope is not
// carried by the wire conversions: the server takes it from the caller's
// identity, never from the request body.
func TestCryptoUtil_TenantIDStaysOffTheWire(t *testing.T) {
	req := testDecryptRequest()
	req.TenantID = "tenant-a"
	assert.Empty(t, DecryptRequestFromProto(DecryptRequestToProto(req)).TenantID)
}

// cryptoUtilRecorder answers every crypto-utility call with a canned
// response and records the request it was sent.
type cryptoUtilRecorder struct {
	pb.KeystoreServiceClient
	sent any
}

func (r *cryptoUtilRecorder) Rewrap(_ context.Context, in *pb.RewrapRequest, _ ...grpc.CallOption) (*pb.RewrapResponse, error) {
	r.sent = in
	return &pb.RewrapResponse{SourceKeyVersion: 4, Wrapped: EncryptResponseToProto(testEncryptResponse())}, nil
}

func (r *cryptoUtilRecorder) EncryptBatch(_ context.Context, in *pb.EncryptBatchRequest, _ ...grpc.CallOption) (*pb.EncryptBatchResponse, error) {
	r.sent = in
	return &pb.EncryptBatchResponse{Results: []*pb.EncryptBatchResult{{Error: "key disabled"}}}, nil
}

func (r *cryptoUtilRecorder) DecryptBatch(_ context.Context, in *pb.DecryptBatchRequest, _ ...grpc.CallOption) (*pb.DecryptBatchResponse, error) {
	r.sent = in
	return &pb.DecryptBatchResponse{Results: []*pb.DecryptBatchResult{{Plaintext: []byte("pt"), KeyVersion: 2}}}, nil
}

func (r *cryptoUtilRecorder) GenerateDataKey(_ context.Context, in *pb.GenerateDataKeyRequest, _ ...grpc.CallOption) (*pb.GenerateDataKeyResponse, error) {
	r.sent = in
	return &pb.GenerateDataKeyResponse{Plaintext: []byte("dek"), Wrapped: EncryptResponseToProto(testEncryptResponse())}, nil
}

func (r *cryptoUtilRecorder) GenerateWrappedDataKey(_ context.Context, in *pb.GenerateDataKeyRequest, _ ...grpc.CallOption) (*pb.GenerateWrappedDataKeyResponse, error) {
	r.sent = in
	return &pb.GenerateWrappedDataKeyResponse{Wrapped: EncryptResponseToProto(testEncryptResponse())}, nil
}

func (r *cryptoUtilRecorder) GenerateHMAC(_ context.Context, in *pb.GenerateHMACRequest, _ ...grpc.CallOption) (*pb.GenerateHMACResponse, error) {
	r.sent = in
	return &pb.GenerateHMACResponse{Mac: []byte("mac"), KeyVersion: 5, Hash: "SHA-384"}, nil
}

func (r *cryptoUtilRecorder) VerifyHMAC(_ context.Context, in *pb.VerifyHMACRequest, _ ...grpc.CallOption) (*pb.VerifyHMACResponse, error) {
	r.sent = in
	return &pb.VerifyHMACResponse{Valid: true, KeyVersion: 5}, nil
}

func (r *cryptoUtilRecorder) GenerateRandom(_ context.Context, in *pb.GenerateRandomRequest, _ ...grpc.CallOption) (*pb.GenerateRandomResponse, error) {
	r.sent = in
	return &pb.GenerateRandomResponse{Random: []byte("rnd")}, nil
}

func (r *cryptoUtilRecorder) Hash(_ context.Context, in *pb.HashRequest, _ ...grpc.CallOption) (*pb.HashResponse, error) {
	r.sent = in
	return &pb.HashResponse{Digest: []byte("digest"), Hash: "SHA-256"}, nil
}

func TestCryptoUtilityClient_Calls(t *testing.T) {
	ctx := context.Background()
	rec := &cryptoUtilRecorder{}
	c := CryptoUtilityClient{Client: rec}

	rewrap := &transport.RewrapRequest{Source: testDecryptRequest(), TargetKeyID: "k2"}
	rewrapped, err := c.Rewrap(ctx, rewrap)
	require.NoError(t, err)
	assert.Equal(t, rewrap, RewrapRequestFromProto(rec.sent.(*pb.RewrapRequest)))
	assert.Equal(t, &transport.RewrapResponse{SourceKeyVersion: 4, Wrapped: testEncryptResponse()}, rewrapped)

	encBatch := &transport.EncryptBatchRequest{KeyID: "k", Items: []transport.EncryptBatchItem{{Plaintext: []byte("a")}}}
	encResults, err := c.EncryptBatch(ctx, encBatch)
	require.NoError(t, err)
	assert.Equal(t, encBatch, EncryptBatchRequestFromProto(rec.sent.(*pb.EncryptBatchRequest)))
	assert.Equal(t, []transport.EncryptBatchResult{{Error: "key disabled"}}, encResults.Results)

	decBatch := &transport.DecryptBatchRequest{KeyID: "k", Items: []transport.DecryptBatchItem{{Ciphertext: []byte("ct")}}}
	decResults, err := c.DecryptBatch(ctx, decBatch)
	require.NoError(t, err)
	assert.Equal(t, decBatch, DecryptBatchRequestFromProto(rec.sent.(*pb.DecryptBatchRequest)))
	assert.Equal(t, []transport.DecryptBatchResult{{Plaintext: []byte("pt"), KeyVersion: 2}}, decResults.Results)

	dataKey := &transport.GenerateDataKeyRequest{KeyID: "k", KeySize: 32}
	dek, err := c.GenerateDataKey(ctx, dataKey)
	require.NoError(t, err)
	assert.Equal(t, dataKey, GenerateDataKeyRequestFromProto(rec.sent.(*pb.GenerateDataKeyRequest)))
	assert.Equal(t, &transport.GenerateDataKeyResponse{Plaintext: []byte("dek"), Wrapped: testEncryptResponse()}, dek)

	wrapped, err := c.GenerateWrappedDataKey(ctx, &transport.GenerateDataKeyRequest{KeyID: "k2", KeySize: 16})
	require.NoError(t, err)
	assert.Equal(t, int32(16), rec.sent.(*pb.GenerateDataKeyRequest).GetKeySize())
	assert.Equal(t, &transport.GenerateWrappedDataKeyResponse{Wrapped: testEncryptResponse()}, wrapped)

	hmacReq := &transport.GenerateHMACRequest{KeyID: "k", Data: []byte("d"), Hash: "SHA-384"}
	mac, err := c.GenerateHMAC(ctx, hmacReq)
	require.NoError(t, err)
	assert.Equal(t, hmacReq, GenerateHMACRequestFromProto(rec.sent.(*pb.GenerateHMACRequest)))
	assert.Equal(t, &transport.GenerateHMACResponse{MAC: []byte("mac"), KeyVersion: 5, Hash: "SHA-384"}, mac)

	verifyReq := &transport.VerifyHMACRequest{KeyID: "k", Data: []byte("d"), MAC: []byte("mac"), KeyVersion: 5}
	verified, err := c.VerifyHMAC(ctx, verifyReq)
	require.NoError(t, err)
	assert.Equal(t, verifyReq, VerifyHMACRequestFromProto(rec.sent.(*pb.VerifyHMACRequest)))
	assert.Equal(t, &transport.VerifyHMACResponse{Valid: true, KeyVersion: 5}, verified)

	random, err := c.GenerateRandom(ctx, &transport.GenerateRandomRequest{Length: 32})
	require.NoError(t, err)
	assert.Equal(t, int32(32), rec.sent.(*pb.GenerateRandomRequest).GetLength())
	assert.Equal(t, &transport.GenerateRandomResponse{Random: []byte("rnd")}, random)

	digest, err := c.Hash(ctx, &transport.HashRequest{Data: []byte("d"), Hash: "SHA-256"})
	require.NoError(t, err)
	sent := rec.sent.(*pb.HashRequest)
	assert.Equal(t, []byte("d"), sent.GetData())
	assert.Equal(t, "SHA-256", sent.GetHash())
	assert.Equal(t, &transport.HashResponse{Digest: []byte("digest"), Hash: "SHA-256"}, digest)
}

func (c failingKeystoreClient) Rewrap(context.Context, *pb.RewrapRequest, ...grpc.CallOption) (*pb.RewrapResponse, error) {
	return nil, c.err
}

func (c failingKeystoreClient) EncryptBatch(context.Context, *pb.EncryptBatchRequest, ...grpc.CallOption) (*pb.EncryptBatchResponse, error) {
	return nil, c.err
}

func (c failingKeystoreClient) DecryptBatch(context.Context, *pb.DecryptBatchRequest, ...grpc.CallOption) (*pb.DecryptBatchResponse, error) {
	return nil, c.err
}

func (c failingKeystoreClient) GenerateDataKey(context.Context, *pb.GenerateDataKeyRequest, ...grpc.CallOption) (*pb.GenerateDataKeyResponse, error) {
	return nil, c.err
}

func (c failingKeystoreClient) GenerateWrappedDataKey(context.Context, *pb.GenerateDataKeyRequest, ...grpc.CallOption) (*pb.GenerateWrappedDataKeyResponse, error) {
	return nil, c.err
}

func (c failingKeystoreClient) GenerateHMAC(context.Context, *pb.GenerateHMACRequest, ...grpc.CallOption) (*pb.GenerateHMACResponse, error) {
	return nil, c.err
}

func (c failingKeystoreClient) VerifyHMAC(context.Context, *pb.VerifyHMACRequest, ...grpc.CallOption) (*pb.VerifyHMACResponse, error) {
	return nil, c.err
}

func (c failingKeystoreClient) GenerateRandom(context.Context, *pb.GenerateRandomRequest, ...grpc.CallOption) (*pb.GenerateRandomResponse, error) {
	return nil, c.err
}

func (c failingKeystoreClient) Hash(context.Context, *pb.HashRequest, ...grpc.CallOption) (*pb.HashResponse, error) {
	return nil, c.err
}

func TestCryptoUtilityClient_Errors(t *testing.T) {
	ctx := context.Background()
	rpcErr := errors.New("rpc failed")
	c := CryptoUtilityClient{Client: failingKeystoreClient{err: rpcErr}}
	dataKey := &transport.GenerateDataKeyRequest{KeyID: "k"}

	// Each call runs once with a nil request and once with a valid one.
	calls := map[string]func(valid bool) (any, error){
		"rewrap": func(valid bool) (any, error) {
			if !valid {
				return c.Rewrap(ctx, nil)
			}
			return c.Rewrap(ctx, &transport.RewrapRequest{Source: testDecryptRequest()})
		},
		"encrypt-batch": func(valid bool) (any, error) {
			if !valid {
				return c.EncryptBatch(ctx, nil)
			}
			return c.EncryptBatch(ctx, &transport.EncryptBatchRequest{KeyID: "k"})
		},
		"decrypt-batch": func(valid bool) (any, error) {
			if !valid {
				return c.DecryptBatch(ctx, nil)
			}
			return c.DecryptBatch(ctx, &transport.DecryptBatchRequest{KeyID: "k"})
		},
		"data-key": func(valid bool) (any, error) {
			if !valid {
				return c.GenerateDataKey(ctx, nil)
			}
			return c.GenerateDataKey(ctx, dataKey)
		},
		"wrapped-data-key": func(valid bool) (any, error) {
			if !valid {
				return c.GenerateWrappedDataKey(ctx, nil)
			}
			return c.GenerateWrappedDataKey(ctx, dataKey)
		},
		"hmac": func(valid bool) (any, error) {
			if !valid {
				return c.GenerateHMAC(ctx, nil)
			}
			return c.GenerateHMAC(ctx, &transport.GenerateHMACRequest{KeyID: "k"})
		},
		"verify-hmac": func(valid bool) (any, error) {
			if !valid {
				return c.VerifyHMAC(ctx, nil)
			}
			return c.VerifyHMAC(ctx, &transport.VerifyHMACRequest{KeyID: "k"})
		},
		"random": func(valid bool) (any, error) {
			if !valid {
				return c.GenerateRandom(ctx, nil)
			}
			return c.GenerateRandom(ctx, &transport.GenerateRandomRequest{Length: 8})
		},
		"hash": func(valid bool) (any, error) {
			if !valid {
				return c.Hash(ctx, nil)
			}
			return c.Hash(ctx, &transport.HashRequest{Data: []byte("d")})
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			out, err := call(false)
			require.ErrorIs(t, err, ErrNilRequest)
			assert.Nil(t, out)
			out, err = call(true)
			require.ErrorIs(t, err, rpcErr)
			assert.Nil(t, out, "no partial result on a transport error")
		})
	}
}
