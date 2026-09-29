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

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// TestSealConversions_CarryTheTPMFields proves a seal and an unseal carry
// the TPM policy, the password and a TPM2 sealed object's areas both ways,
// and the tenant comes from the server's caller, never the wire.
func TestSealConversions_CarryTheTPMFields(t *testing.T) {
	seal := &transport.SealRequest{Backend: "tpm2", KeyID: "vault", Data: []byte("d"), AAD: []byte("a"), Password: "pw", TPMPolicy: "boot", TenantID: "spoofed"}
	got := SealRequestFromProto(SealRequestToProto(seal), "acme")
	assert.Equal(t, "boot", got.TPMPolicy)
	assert.Equal(t, "pw", got.Password)
	assert.Equal(t, "acme", got.TenantID, "the tenant is the caller's, not the request's")

	sealed := &transport.SealResponse{
		Backend: "tpm2", TPMPublic: []byte("pub"), TPMPrivate: []byte("priv"),
		WrappedDEK: []byte("dek"), KeyID: "vault", Metadata: map[string][]byte{"tpm:handle": {0x80}},
	}
	back, err := SealResponseFromProto(SealResponseToProto(sealed))
	require.NoError(t, err)
	assert.Equal(t, sealed, back)

	unseal := &transport.UnsealRequest{
		Backend: "tpm2", KeyID: "vault", TPMPublic: []byte("pub"), TPMPrivate: []byte("priv"),
		WrappedDEK: []byte("dek"), Metadata: map[string][]byte{"k": []byte("v")}, Password: "pw",
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
