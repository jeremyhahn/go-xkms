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
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// The crypto utility converters carry no tenant: the server scopes every
// request to the caller's tenant.

// EncryptResponseToProto converts an encrypt result to its wire form.
func EncryptResponseToProto(r *transport.EncryptResponse) *pb.EncryptResponse {
	if r == nil {
		return nil
	}
	return &pb.EncryptResponse{
		Ciphertext:   r.Ciphertext,
		Nonce:        r.Nonce,
		Tag:          r.Tag,
		Iv:           r.IV,
		GcmNonceMode: r.GCMNonceMode,
		KeyVersion:   r.KeyVersion,
	}
}

// EncryptResponseFromProto converts a wire encrypt result.
func EncryptResponseFromProto(r *pb.EncryptResponse) *transport.EncryptResponse {
	if r == nil {
		return nil
	}
	return &transport.EncryptResponse{
		Ciphertext:   r.Ciphertext,
		Nonce:        r.Nonce,
		Tag:          r.Tag,
		IV:           r.Iv,
		GCMNonceMode: r.GcmNonceMode,
		KeyVersion:   r.KeyVersion,
	}
}

// DecryptRequestToProto converts a decrypt request to its wire form.
func DecryptRequestToProto(r *transport.DecryptRequest) *pb.DecryptRequest {
	if r == nil {
		return nil
	}
	return &pb.DecryptRequest{
		KeyId:          r.KeyID,
		Backend:        r.Backend,
		Ciphertext:     r.Ciphertext,
		AdditionalData: r.AdditionalData,
		Nonce:          r.Nonce,
		Tag:            r.Tag,
		Padding:        r.Padding,
		Hash:           r.Hash,
		Label:          r.Label,
		Mode:           r.Mode,
		Iv:             r.IV,
		TagSize:        int32(r.TagSize),
		GcmNonceMode:   r.GCMNonceMode,
		KeyVersion:     r.KeyVersion,
	}
}

// DecryptRequestFromProto converts a wire decrypt request.
func DecryptRequestFromProto(r *pb.DecryptRequest) *transport.DecryptRequest {
	if r == nil {
		return nil
	}
	return &transport.DecryptRequest{
		KeyID:          r.KeyId,
		Backend:        r.Backend,
		Ciphertext:     r.Ciphertext,
		AdditionalData: r.AdditionalData,
		Nonce:          r.Nonce,
		Tag:            r.Tag,
		Padding:        r.Padding,
		Hash:           r.Hash,
		Label:          r.Label,
		Mode:           r.Mode,
		IV:             r.Iv,
		TagSize:        int(r.TagSize),
		GCMNonceMode:   r.GcmNonceMode,
		KeyVersion:     r.KeyVersion,
	}
}

// RewrapRequestToProto converts a rewrap request to its wire form.
func RewrapRequestToProto(r *transport.RewrapRequest) *pb.RewrapRequest {
	return &pb.RewrapRequest{
		Source:        DecryptRequestToProto(r.Source),
		TargetKeyId:   r.TargetKeyID,
		TargetBackend: r.TargetBackend,
	}
}

// RewrapRequestFromProto converts a wire rewrap request.
func RewrapRequestFromProto(r *pb.RewrapRequest) *transport.RewrapRequest {
	return &transport.RewrapRequest{
		Source:        DecryptRequestFromProto(r.GetSource()),
		TargetKeyID:   r.GetTargetKeyId(),
		TargetBackend: r.GetTargetBackend(),
	}
}

// RewrapResponseToProto converts a rewrap result to its wire form.
func RewrapResponseToProto(r *transport.RewrapResponse) *pb.RewrapResponse {
	return &pb.RewrapResponse{SourceKeyVersion: r.SourceKeyVersion, Wrapped: EncryptResponseToProto(r.Wrapped)}
}

// RewrapResponseFromProto converts a wire rewrap result.
func RewrapResponseFromProto(r *pb.RewrapResponse) *transport.RewrapResponse {
	return &transport.RewrapResponse{SourceKeyVersion: r.GetSourceKeyVersion(), Wrapped: EncryptResponseFromProto(r.GetWrapped())}
}

// EncryptBatchRequestToProto converts a batch encrypt request to its wire
// form.
func EncryptBatchRequestToProto(r *transport.EncryptBatchRequest) *pb.EncryptBatchRequest {
	items := make([]*pb.EncryptBatchItem, len(r.Items))
	for i, item := range r.Items {
		items[i] = &pb.EncryptBatchItem{Plaintext: item.Plaintext, AdditionalData: item.AdditionalData}
	}
	return &pb.EncryptBatchRequest{KeyId: r.KeyID, Backend: r.Backend, Items: items}
}

// EncryptBatchRequestFromProto converts a wire batch encrypt request.
func EncryptBatchRequestFromProto(r *pb.EncryptBatchRequest) *transport.EncryptBatchRequest {
	items := make([]transport.EncryptBatchItem, len(r.GetItems()))
	for i, item := range r.GetItems() {
		items[i] = transport.EncryptBatchItem{Plaintext: item.GetPlaintext(), AdditionalData: item.GetAdditionalData()}
	}
	return &transport.EncryptBatchRequest{KeyID: r.GetKeyId(), Backend: r.GetBackend(), Items: items}
}

// EncryptBatchResponseToProto converts batch encrypt results to their wire
// form.
func EncryptBatchResponseToProto(r *transport.EncryptBatchResponse) *pb.EncryptBatchResponse {
	results := make([]*pb.EncryptBatchResult, len(r.Results))
	for i, res := range r.Results {
		results[i] = &pb.EncryptBatchResult{Result: EncryptResponseToProto(res.Result), Error: res.Error}
	}
	return &pb.EncryptBatchResponse{Results: results}
}

// EncryptBatchResponseFromProto converts wire batch encrypt results.
func EncryptBatchResponseFromProto(r *pb.EncryptBatchResponse) *transport.EncryptBatchResponse {
	results := make([]transport.EncryptBatchResult, len(r.GetResults()))
	for i, res := range r.GetResults() {
		results[i] = transport.EncryptBatchResult{Result: EncryptResponseFromProto(res.GetResult()), Error: res.GetError()}
	}
	return &transport.EncryptBatchResponse{Results: results}
}

// DecryptBatchRequestToProto converts a batch decrypt request to its wire
// form.
func DecryptBatchRequestToProto(r *transport.DecryptBatchRequest) *pb.DecryptBatchRequest {
	items := make([]*pb.DecryptBatchItem, len(r.Items))
	for i, item := range r.Items {
		items[i] = &pb.DecryptBatchItem{
			Ciphertext:     item.Ciphertext,
			AdditionalData: item.AdditionalData,
			Nonce:          item.Nonce,
			Tag:            item.Tag,
			GcmNonceMode:   item.GCMNonceMode,
			KeyVersion:     item.KeyVersion,
		}
	}
	return &pb.DecryptBatchRequest{KeyId: r.KeyID, Backend: r.Backend, Items: items}
}

// DecryptBatchRequestFromProto converts a wire batch decrypt request.
func DecryptBatchRequestFromProto(r *pb.DecryptBatchRequest) *transport.DecryptBatchRequest {
	items := make([]transport.DecryptBatchItem, len(r.GetItems()))
	for i, item := range r.GetItems() {
		items[i] = transport.DecryptBatchItem{
			Ciphertext:     item.GetCiphertext(),
			AdditionalData: item.GetAdditionalData(),
			Nonce:          item.GetNonce(),
			Tag:            item.GetTag(),
			GCMNonceMode:   item.GetGcmNonceMode(),
			KeyVersion:     item.GetKeyVersion(),
		}
	}
	return &transport.DecryptBatchRequest{KeyID: r.GetKeyId(), Backend: r.GetBackend(), Items: items}
}

// DecryptBatchResponseToProto converts batch decrypt results to their wire
// form.
func DecryptBatchResponseToProto(r *transport.DecryptBatchResponse) *pb.DecryptBatchResponse {
	results := make([]*pb.DecryptBatchResult, len(r.Results))
	for i, res := range r.Results {
		results[i] = &pb.DecryptBatchResult{Plaintext: res.Plaintext, KeyVersion: res.KeyVersion, Error: res.Error}
	}
	return &pb.DecryptBatchResponse{Results: results}
}

// DecryptBatchResponseFromProto converts wire batch decrypt results.
func DecryptBatchResponseFromProto(r *pb.DecryptBatchResponse) *transport.DecryptBatchResponse {
	results := make([]transport.DecryptBatchResult, len(r.GetResults()))
	for i, res := range r.GetResults() {
		results[i] = transport.DecryptBatchResult{Plaintext: res.GetPlaintext(), KeyVersion: res.GetKeyVersion(), Error: res.GetError()}
	}
	return &transport.DecryptBatchResponse{Results: results}
}

// GenerateDataKeyRequestToProto converts a data key request to its wire
// form.
func GenerateDataKeyRequestToProto(r *transport.GenerateDataKeyRequest) *pb.GenerateDataKeyRequest {
	return &pb.GenerateDataKeyRequest{
		KeyId:          r.KeyID,
		Backend:        r.Backend,
		KeySize:        int32(r.KeySize),
		AdditionalData: r.AdditionalData,
	}
}

// GenerateDataKeyRequestFromProto converts a wire data key request.
func GenerateDataKeyRequestFromProto(r *pb.GenerateDataKeyRequest) *transport.GenerateDataKeyRequest {
	return &transport.GenerateDataKeyRequest{
		KeyID:          r.GetKeyId(),
		Backend:        r.GetBackend(),
		KeySize:        int(r.GetKeySize()),
		AdditionalData: r.GetAdditionalData(),
	}
}

// GenerateHMACRequestToProto converts an HMAC request to its wire form.
func GenerateHMACRequestToProto(r *transport.GenerateHMACRequest) *pb.GenerateHMACRequest {
	return &pb.GenerateHMACRequest{KeyId: r.KeyID, Backend: r.Backend, Data: r.Data, Hash: r.Hash}
}

// GenerateHMACRequestFromProto converts a wire HMAC request.
func GenerateHMACRequestFromProto(r *pb.GenerateHMACRequest) *transport.GenerateHMACRequest {
	return &transport.GenerateHMACRequest{KeyID: r.GetKeyId(), Backend: r.GetBackend(), Data: r.GetData(), Hash: r.GetHash()}
}

// VerifyHMACRequestToProto converts an HMAC verification request to its
// wire form.
func VerifyHMACRequestToProto(r *transport.VerifyHMACRequest) *pb.VerifyHMACRequest {
	return &pb.VerifyHMACRequest{
		KeyId:      r.KeyID,
		Backend:    r.Backend,
		Data:       r.Data,
		Mac:        r.MAC,
		Hash:       r.Hash,
		KeyVersion: r.KeyVersion,
	}
}

// VerifyHMACRequestFromProto converts a wire HMAC verification request.
func VerifyHMACRequestFromProto(r *pb.VerifyHMACRequest) *transport.VerifyHMACRequest {
	return &transport.VerifyHMACRequest{
		KeyID:      r.GetKeyId(),
		Backend:    r.GetBackend(),
		Data:       r.GetData(),
		MAC:        r.GetMac(),
		Hash:       r.GetHash(),
		KeyVersion: r.GetKeyVersion(),
	}
}
