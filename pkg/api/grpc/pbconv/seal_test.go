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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestSealConversions_CarryTheTPMFields proves a seal and an unseal carry
// the TPM policy, the password and a TPM2 sealed object's areas both ways,
// and the tenant comes from the server's caller, never the wire.
func TestSealConversions_CarryTheTPMFields(t *testing.T) {
	seal := &transport.SealRequest{Backend: "tpm2", KeyID: "vault", Data: []byte("d"), AAD: []byte("a"), Password: []byte("pw"), TPMPolicy: "boot", TenantID: "spoofed"}
	got := SealRequestFromProto(SealRequestToProto(seal), "acme")
	assert.Equal(t, "boot", got.TPMPolicy)
	assert.Equal(t, "pw", string(got.Password))
	assert.Equal(t, "acme", got.TenantID, "the tenant is the caller's, not the request's")

	sealed := &transport.SealResponse{
		Backend: "tpm2", TPMPublic: []byte("pub"), TPMPrivate: []byte("priv"),
		WrappedDEK: []byte("dek"), KeyID: "vault", KeyVersion: 4, Metadata: map[string][]byte{"tpm:handle": {0x80}},
	}
	back, err := SealResponseFromProto(SealResponseToProto(sealed))
	require.NoError(t, err)
	assert.Equal(t, sealed, back)

	unseal := &transport.UnsealRequest{
		Backend: "tpm2", KeyID: "vault", TPMPublic: []byte("pub"), TPMPrivate: []byte("priv"),
		WrappedDEK: []byte("dek"), KeyVersion: 4, Metadata: map[string][]byte{"k": []byte("v")}, Password: []byte("pw"),
	}
	u, err := UnsealRequestFromProto(UnsealRequestToProto(unseal), "acme")
	require.NoError(t, err)
	unseal.TenantID = "acme"
	assert.Equal(t, unseal, u)
}

// TestSealConversions_RefuseMalformedMetadata proves metadata that is not
// base64 is refused with a typed error naming the key.
func TestSealConversions_RefuseMalformedMetadata(t *testing.T) {
	_, err := SealResponseFromProto(&pb.SealResponse{Metadata: map[string]string{"bad": "%%%"}})
	var metaErr *MetadataError
	require.ErrorAs(t, err, &metaErr)
	assert.Equal(t, "bad", metaErr.Key)
	assert.Contains(t, metaErr.Error(), `"bad"`)
	assert.NotNil(t, metaErr.Unwrap())

	_, err = UnsealRequestFromProto(&pb.UnsealRequest{Metadata: map[string]string{"bad": "%%%"}}, "")
	require.ErrorAs(t, err, &metaErr)

	none, err := metadataFromProto(nil)
	require.NoError(t, err)
	assert.Nil(t, none)
	assert.Nil(t, metadataToProto(nil))
}

// TestSealPassword_WireIdenticalToTheStringField proves the password's field
// type change from string to bytes did not change a byte on the wire: a peer
// built against the string field still reads, and writes, the same message.
func TestSealPassword_WireIdenticalToTheStringField(t *testing.T) {
	// SealRequest.password is field 5, UnsealRequest.password is field 11; a
	// length-delimited string and bytes are encoded identically.
	for name, tc := range map[string]struct {
		field  protowire.Number
		encode func(password []byte) ([]byte, error)
		decode func(wire []byte) ([]byte, error)
	}{
		"seal": {
			field: 5,
			encode: func(password []byte) ([]byte, error) {
				return proto.Marshal(SealRequestToProto(&transport.SealRequest{Password: password}))
			},
			decode: func(wire []byte) ([]byte, error) {
				var msg pb.SealRequest
				if err := proto.Unmarshal(wire, &msg); err != nil {
					return nil, err
				}
				return msg.GetPassword(), nil
			},
		},
		"unseal": {
			field: 11,
			encode: func(password []byte) ([]byte, error) {
				return proto.Marshal(UnsealRequestToProto(&transport.UnsealRequest{Password: password}))
			},
			decode: func(wire []byte) ([]byte, error) {
				var msg pb.UnsealRequest
				if err := proto.Unmarshal(wire, &msg); err != nil {
					return nil, err
				}
				return msg.GetPassword(), nil
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			legacy := protowire.AppendTag(nil, tc.field, protowire.BytesType)
			legacy = protowire.AppendString(legacy, "pässwörd")

			got, err := tc.decode(legacy)
			require.NoError(t, err)
			assert.Equal(t, "pässwörd", string(got))

			wire, err := tc.encode([]byte("pässwörd"))
			require.NoError(t, err)
			assert.Equal(t, legacy, wire)
		})
	}
}

func TestSealPassword_ConversionKeepsTheSecretWipeable(t *testing.T) {
	password := types.SecretBytes("hunter2")
	msg := SealRequestToProto(&transport.SealRequest{Password: password})

	password.Wipe()

	assert.Equal(t, make([]byte, len("hunter2")), msg.GetPassword(),
		"the proto message shares the request's slice, so wiping the request wipes it")
}
