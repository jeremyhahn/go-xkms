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
	"encoding/base64"
	"fmt"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// MetadataError reports a sealed-data metadata value that is not base64.
type MetadataError struct {
	Key string
	Err error
}

// Error implements the error interface.
func (e *MetadataError) Error() string {
	return fmt.Sprintf("pbconv: sealed metadata %q is not base64: %v", e.Key, e.Err)
}

// Unwrap returns the decoding error.
func (e *MetadataError) Unwrap() error { return e.Err }

// metadataToProto base64-encodes sealed-data metadata values, which proto
// carries as strings.
func metadataToProto(in map[string][]byte) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = base64.StdEncoding.EncodeToString(v)
	}
	return out
}

// metadataFromProto decodes base64 sealed-data metadata values.
func metadataFromProto(in map[string]string) (map[string][]byte, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[string][]byte, len(in))
	for k, v := range in {
		raw, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, &MetadataError{Key: k, Err: err}
		}
		out[k] = raw
	}
	return out, nil
}

// SealRequestToProto converts a seal request to its proto form. TenantID is
// not carried: the server takes it from the caller's identity.
func SealRequestToProto(r *transport.SealRequest) *pb.SealRequest {
	return &pb.SealRequest{
		Backend:   r.Backend,
		KeyId:     r.KeyID,
		Data:      r.Data,
		Aad:       r.AAD,
		Password:  r.Password,
		TpmPolicy: r.TPMPolicy,
	}
}

// SealRequestFromProto converts a proto seal request to its transport form,
// in tenant.
func SealRequestFromProto(r *pb.SealRequest, tenant string) *transport.SealRequest {
	return &transport.SealRequest{
		Backend:   r.GetBackend(),
		KeyID:     r.GetKeyId(),
		Data:      r.GetData(),
		AAD:       r.GetAad(),
		Password:  types.SecretBytes(r.GetPassword()),
		TPMPolicy: r.GetTpmPolicy(),
		TenantID:  tenant,
	}
}

// SealResponseToProto converts sealed data to its proto form.
func SealResponseToProto(r *transport.SealResponse) *pb.SealResponse {
	return &pb.SealResponse{
		Backend:    r.Backend,
		Ciphertext: r.Ciphertext,
		Nonce:      r.Nonce,
		Tag:        r.Tag,
		Metadata:   metadataToProto(r.Metadata),
		TpmPublic:  r.TPMPublic,
		TpmPrivate: r.TPMPrivate,
		WrappedDek: r.WrappedDEK,
		KeyId:      r.KeyID,
		KeyVersion: r.KeyVersion,
	}
}

// SealResponseFromProto converts proto sealed data to its transport form.
func SealResponseFromProto(r *pb.SealResponse) (*transport.SealResponse, error) {
	metadata, err := metadataFromProto(r.GetMetadata())
	if err != nil {
		return nil, err
	}
	return &transport.SealResponse{
		Backend:    r.GetBackend(),
		Ciphertext: r.GetCiphertext(),
		Nonce:      r.GetNonce(),
		Tag:        r.GetTag(),
		TPMPublic:  r.GetTpmPublic(),
		TPMPrivate: r.GetTpmPrivate(),
		WrappedDEK: r.GetWrappedDek(),
		KeyID:      r.GetKeyId(),
		Metadata:   metadata,
		KeyVersion: r.GetKeyVersion(),
	}, nil
}

// UnsealRequestToProto converts an unseal request to its proto form.
// TenantID is not carried: the server takes it from the caller's identity.
func UnsealRequestToProto(r *transport.UnsealRequest) *pb.UnsealRequest {
	return &pb.UnsealRequest{
		Backend:    r.Backend,
		KeyId:      r.KeyID,
		Ciphertext: r.Ciphertext,
		Nonce:      r.Nonce,
		Tag:        r.Tag,
		Aad:        r.AAD,
		TpmPublic:  r.TPMPublic,
		TpmPrivate: r.TPMPrivate,
		WrappedDek: r.WrappedDEK,
		Metadata:   metadataToProto(r.Metadata),
		Password:   r.Password,
		KeyVersion: r.KeyVersion,
	}
}

// UnsealRequestFromProto converts a proto unseal request to its transport
// form, in tenant.
func UnsealRequestFromProto(r *pb.UnsealRequest, tenant string) (*transport.UnsealRequest, error) {
	metadata, err := metadataFromProto(r.GetMetadata())
	if err != nil {
		return nil, err
	}
	return &transport.UnsealRequest{
		Backend:    r.GetBackend(),
		KeyID:      r.GetKeyId(),
		Ciphertext: r.GetCiphertext(),
		Nonce:      r.GetNonce(),
		Tag:        r.GetTag(),
		AAD:        r.GetAad(),
		TPMPublic:  r.GetTpmPublic(),
		TPMPrivate: r.GetTpmPrivate(),
		WrappedDEK: r.GetWrappedDek(),
		Metadata:   metadata,
		Password:   types.SecretBytes(r.GetPassword()),
		TenantID:   tenant,
		KeyVersion: r.GetKeyVersion(),
	}, nil
}
