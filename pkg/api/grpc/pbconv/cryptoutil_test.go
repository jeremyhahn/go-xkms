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

func TestCryptoUtilityConversions_AbsentValuesStayAbsent(t *testing.T) {
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

func TestCryptoUtilityClient_RefusesNilRequests(t *testing.T) {
	c := CryptoUtilityClient{}
	ctx := context.Background()
	calls := []error{
		func() error { _, err := c.Rewrap(ctx, nil); return err }(),
		func() error { _, err := c.EncryptBatch(ctx, nil); return err }(),
		func() error { _, err := c.DecryptBatch(ctx, nil); return err }(),
		func() error { _, err := c.GenerateDataKey(ctx, nil); return err }(),
		func() error { _, err := c.GenerateWrappedDataKey(ctx, nil); return err }(),
		func() error { _, err := c.GenerateHMAC(ctx, nil); return err }(),
		func() error { _, err := c.VerifyHMAC(ctx, nil); return err }(),
		func() error { _, err := c.GenerateRandom(ctx, nil); return err }(),
		func() error { _, err := c.Hash(ctx, nil); return err }(),
	}
	for i, err := range calls {
		assert.ErrorIs(t, err, ErrNilRequest, "call %d", i)
	}
}
