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

package unix

import (
	"testing"

	"google.golang.org/grpc/codes"

	"github.com/jeremyhahn/go-xkms/pkg/api/grpc/pbconv"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
)

// cryptoUtilityVerbs returns a case for every crypto utility verb.
func cryptoUtilityVerbs() map[string]verbCase {
	const backend, keyID = "pkcs11", "orders-key"
	data := []byte("ledger entry")
	mac := []byte{0x9f, 0x01, 0x7c}

	rewrap := &transport.RewrapRequest{
		Source:        &transport.DecryptRequest{Backend: backend, KeyID: keyID, Ciphertext: []byte{0x01}},
		TargetKeyID:   "archive-key",
		TargetBackend: "awskms",
	}
	rewrapped := &pb.RewrapResponse{SourceKeyVersion: 2}
	encryptBatch := &transport.EncryptBatchRequest{Backend: backend, KeyID: keyID, Items: []transport.EncryptBatchItem{{Plaintext: data}}}
	encrypted := &pb.EncryptBatchResponse{}
	decryptBatch := &transport.DecryptBatchRequest{Backend: backend, KeyID: keyID, Items: []transport.DecryptBatchItem{{Ciphertext: []byte{0x02}, KeyVersion: 1}}}
	decrypted := &pb.DecryptBatchResponse{}
	dataKey := &transport.GenerateDataKeyRequest{Backend: backend, KeyID: keyID, KeySize: 32}
	wrapped := &pb.EncryptResponse{Ciphertext: []byte{0x03, 0x04}}
	generateHMAC := &transport.GenerateHMACRequest{Backend: backend, KeyID: keyID, Data: data, Hash: "SHA-384"}
	verifyHMAC := &transport.VerifyHMACRequest{Backend: backend, KeyID: keyID, Data: data, MAC: mac, Hash: "SHA-384", KeyVersion: 2}

	return map[string]verbCase{
		"Rewrap": {
			call:    verb((*Transport).Rewrap, rewrap),
			sent:    pbconv.RewrapRequestToProto(rewrap),
			reply:   rewrapped,
			want:    pbconv.RewrapResponseFromProto(rewrapped),
			refusal: codes.PermissionDenied,
		},
		"EncryptBatch": {
			call:    verb((*Transport).EncryptBatch, encryptBatch),
			sent:    pbconv.EncryptBatchRequestToProto(encryptBatch),
			reply:   encrypted,
			want:    pbconv.EncryptBatchResponseFromProto(encrypted),
			refusal: codes.InvalidArgument,
		},
		"DecryptBatch": {
			call:    verb((*Transport).DecryptBatch, decryptBatch),
			sent:    pbconv.DecryptBatchRequestToProto(decryptBatch),
			reply:   decrypted,
			want:    pbconv.DecryptBatchResponseFromProto(decrypted),
			refusal: codes.InvalidArgument,
		},
		"GenerateDataKey": {
			call:    verb((*Transport).GenerateDataKey, dataKey),
			sent:    pbconv.GenerateDataKeyRequestToProto(dataKey),
			reply:   &pb.GenerateDataKeyResponse{Plaintext: []byte{0x05}, Wrapped: wrapped},
			want:    &transport.GenerateDataKeyResponse{Plaintext: []byte{0x05}, Wrapped: pbconv.EncryptResponseFromProto(wrapped)},
			refusal: codes.NotFound,
		},
		"GenerateWrappedDataKey": {
			call:    verb((*Transport).GenerateWrappedDataKey, dataKey),
			sent:    pbconv.GenerateDataKeyRequestToProto(dataKey),
			reply:   &pb.GenerateWrappedDataKeyResponse{Wrapped: wrapped},
			want:    &transport.GenerateWrappedDataKeyResponse{Wrapped: pbconv.EncryptResponseFromProto(wrapped)},
			refusal: codes.FailedPrecondition,
		},
		"GenerateHMAC": {
			call:    verb((*Transport).GenerateHMAC, generateHMAC),
			sent:    pbconv.GenerateHMACRequestToProto(generateHMAC),
			reply:   &pb.GenerateHMACResponse{Mac: mac, KeyVersion: 2, Hash: "SHA-384"},
			want:    &transport.GenerateHMACResponse{MAC: mac, KeyVersion: 2, Hash: "SHA-384"},
			refusal: codes.NotFound,
		},
		"VerifyHMAC": {
			call:    verb((*Transport).VerifyHMAC, verifyHMAC),
			sent:    pbconv.VerifyHMACRequestToProto(verifyHMAC),
			reply:   &pb.VerifyHMACResponse{Valid: true, KeyVersion: 2},
			want:    &transport.VerifyHMACResponse{Valid: true, KeyVersion: 2},
			refusal: codes.InvalidArgument,
		},
		"GenerateRandom": {
			call:    verb((*Transport).GenerateRandom, &transport.GenerateRandomRequest{Length: 16}),
			sent:    &pb.GenerateRandomRequest{Length: 16},
			reply:   &pb.GenerateRandomResponse{Random: []byte{0x06, 0x07}},
			want:    &transport.GenerateRandomResponse{Random: []byte{0x06, 0x07}},
			refusal: codes.OutOfRange,
		},
		"Hash": {
			call:    verb((*Transport).Hash, &transport.HashRequest{Data: data, Hash: "SHA-256"}),
			sent:    &pb.HashRequest{Data: data, Hash: "SHA-256"},
			reply:   &pb.HashResponse{Digest: []byte{0x08}, Hash: "SHA-256"},
			want:    &transport.HashResponse{Digest: []byte{0x08}, Hash: "SHA-256"},
			refusal: codes.Unimplemented,
		},
	}
}

// TestCryptoUtilityVerbs_ReachTheServer proves every crypto utility verb
// sends its request to the RPC of its name and decodes the server's answer.
func TestCryptoUtilityVerbs_ReachTheServer(t *testing.T) {
	assertVerbsReachTheServer(t, cryptoUtilityVerbs())
}

// TestCryptoUtilityVerbs_SurfaceServerRefusals proves every crypto utility
// verb returns the server's status code and no partial result.
func TestCryptoUtilityVerbs_SurfaceServerRefusals(t *testing.T) {
	assertVerbsSurfaceRefusals(t, cryptoUtilityVerbs())
}

// TestCryptoUtilityVerbs_NotConnected proves every crypto utility verb
// refuses with ErrNotConnected before the transport connects.
func TestCryptoUtilityVerbs_NotConnected(t *testing.T) {
	assertVerbsNeedAConnection(t, cryptoUtilityVerbs())
}
