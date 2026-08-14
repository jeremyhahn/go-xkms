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
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// This file is the evidence behind the DeriveKey collapse. The gRPC service used
// to carry its own KDF adapter table, its own parameter assembly and its own
// salt-as-IV convention, calling pkg/crypto/kdf directly instead of going
// through XKMSService.DeriveKey. Collapsing it onto the service layer is only
// safe if the derived bytes did not move, and a KDF refactor that changes
// derived keys is a silent break: every caller keeps getting a plausible key.
//
// deriveKeyGolden are hex constants captured from the gRPC service *before* the
// collapse, one per interesting point in the parameter space. They are the
// before-and-after proof.

var deriveKeyIKM = []byte("test-input-key-material-32bytes!")

var (
	deriveKeySalt  = []byte("kdf-salt-0123456")
	deriveKeyInfo  = []byte("kdf-info-abcdefg")
	deriveKeyLabel = []byte("domain-label")
	deriveKeyCtx   = []byte("app-context")
)

var deriveKeyGolden = []struct {
	name   string
	req    *pb.DeriveKeyRequest
	golden string
}{
	{
		name:   "hkdf/sha256/salt+info/32",
		req:    &pb.DeriveKeyRequest{Algorithm: "HKDF", InputKeyMaterial: deriveKeyIKM, Salt: deriveKeySalt, Info: deriveKeyInfo, KeyLength: 32, Hash: "SHA-256"},
		golden: "f05950324561db430d38fe8738dba539a024d5ab6eb4de33f1010f4354454db2",
	},
	{
		name:   "hkdf/sha384/info/48",
		req:    &pb.DeriveKeyRequest{Algorithm: "HKDF", InputKeyMaterial: deriveKeyIKM, Info: deriveKeyInfo, KeyLength: 48, Hash: "SHA-384"},
		golden: "06f255ec7127c0ca93f402ef0f693ef490030ab95908e83da48d9715507377387fa68ccf93555b99b383a3c10db4ee78",
	},
	{
		name:   "hkdf/sha512/salt/64",
		req:    &pb.DeriveKeyRequest{Algorithm: "HKDF", InputKeyMaterial: deriveKeyIKM, Salt: deriveKeySalt, KeyLength: 64, Hash: "SHA-512"},
		golden: "d9dde94e9915bcd2aa5a282bdfa874dd643104ad100f6bf766069d20fb24ad2a8a94b0842e0a9c8bd166ffdaf006fbe6211afcd5498ae268222b0d1c3144dd21",
	},
	{
		name:   "hkdf/sha3-256/salt+info/32",
		req:    &pb.DeriveKeyRequest{Algorithm: "hkdf", InputKeyMaterial: deriveKeyIKM, Salt: deriveKeySalt, Info: deriveKeyInfo, KeyLength: 32, Hash: "SHA3-256"},
		golden: "e744e9ffd28d0b9255b4ba68c637dd9f9238613e1537f9942a86b00515eefc9b",
	},
	{
		// An absent hash still selects the SHA-256 default.
		name:   "hkdf/defaulthash/salt+info/32",
		req:    &pb.DeriveKeyRequest{Algorithm: "HKDF", InputKeyMaterial: deriveKeyIKM, Salt: deriveKeySalt, Info: deriveKeyInfo, KeyLength: 32},
		golden: "f05950324561db430d38fe8738dba539a024d5ab6eb4de33f1010f4354454db2",
	},
	{
		// An absent key length still selects the 32-byte default.
		name:   "hkdf/defaultlen/sha256",
		req:    &pb.DeriveKeyRequest{Algorithm: "HKDF", InputKeyMaterial: deriveKeyIKM, Salt: deriveKeySalt, Info: deriveKeyInfo, Hash: "SHA-256"},
		golden: "f05950324561db430d38fe8738dba539a024d5ab6eb4de33f1010f4354454db2",
	},
	{
		name:   "counter/sha256/label+ctx/32",
		req:    &pb.DeriveKeyRequest{Algorithm: "SP800-108-Counter", InputKeyMaterial: deriveKeyIKM, Label: deriveKeyLabel, Context: deriveKeyCtx, KeyLength: 32, Hash: "SHA-256"},
		golden: "275f7613d47ac9490461fd3a87cc2afd05da3e746db13affe4d057f2bc174f92",
	},
	{
		// Multi-block output, so the counter actually iterates.
		name:   "counter/sha384/label+ctx/64",
		req:    &pb.DeriveKeyRequest{Algorithm: "SP800-108-Counter", InputKeyMaterial: deriveKeyIKM, Label: deriveKeyLabel, Context: deriveKeyCtx, KeyLength: 64, Hash: "SHA-384"},
		golden: "9192e7f8070ffdccdd9f0b07e75f558d9e8b282ff321927dfe756ddd3565dbe393110f0fe60f9f0f7eaf6202fe8cd71694c97caebed9d402d3568a9fc54c75b7",
	},
	{
		name:   "counter/sha256/nolabel/16",
		req:    &pb.DeriveKeyRequest{Algorithm: "sp800-108-counter", InputKeyMaterial: deriveKeyIKM, KeyLength: 16, Hash: "SHA-256"},
		golden: "feacdac7697c7e0ab1f093bfbc2d13af",
	},
	{
		name:   "feedback/sha256/label+ctx/32",
		req:    &pb.DeriveKeyRequest{Algorithm: "SP800-108-Feedback", InputKeyMaterial: deriveKeyIKM, Label: deriveKeyLabel, Context: deriveKeyCtx, KeyLength: 32, Hash: "SHA-256"},
		golden: "275f7613d47ac9490461fd3a87cc2afd05da3e746db13affe4d057f2bc174f92",
	},
	{
		// The salt-as-IV convention. This is the case where the two
		// implementations had already drifted: the gRPC copy fed the salt in as
		// K(0), and the service layer dropped it, so the same request derived
		// two different keys depending on the transport. The golden is the gRPC
		// answer, which is the one with an actual K(0) in it.
		name:   "feedback/sha256/label+ctx+iv/32",
		req:    &pb.DeriveKeyRequest{Algorithm: "SP800-108-Feedback", InputKeyMaterial: deriveKeyIKM, Label: deriveKeyLabel, Context: deriveKeyCtx, Salt: deriveKeySalt, KeyLength: 32, Hash: "SHA-256"},
		golden: "a9059c6177d4f03d0a1713c8b24dcae72e38aab925ffe6139718da6bfef100b5",
	},
	{
		name:   "feedback/sha512/iv/64",
		req:    &pb.DeriveKeyRequest{Algorithm: "sp800-108-feedback", InputKeyMaterial: deriveKeyIKM, Salt: deriveKeySalt, KeyLength: 64, Hash: "SHA-512"},
		golden: "8a5ab6553946428c348712e68547799dff73527849c4daee897c6c50baf4868f459ab6a3850d8fc4769cb47b15a3fa63e78b7166de3d63969406299eb19f7e6d",
	},
	{
		name:   "doublepipeline/sha256/label+ctx/32",
		req:    &pb.DeriveKeyRequest{Algorithm: "SP800-108-Double-Pipeline", InputKeyMaterial: deriveKeyIKM, Label: deriveKeyLabel, Context: deriveKeyCtx, KeyLength: 32, Hash: "SHA-256"},
		golden: "f86434c97c2f59e3c2b78c8b77be69e94a8198af6b0b207d7e4dd806d124b339",
	},
	{
		name:   "doublepipeline/sha3-512/label+ctx/64",
		req:    &pb.DeriveKeyRequest{Algorithm: "SP800-108-Double-Pipeline", InputKeyMaterial: deriveKeyIKM, Label: deriveKeyLabel, Context: deriveKeyCtx, KeyLength: 64, Hash: "SHA3-512"},
		golden: "a50a86efb342f3e537e5b86088e4e21a0c4e5bcaca5a808d2528e81970345759cbf1b1e772ccefd94fbf1b8645f9a8164fbd7d517afc69690684a2600f06817e",
	},
}

// TestDeriveKey_GoldenVectorsSurviveTheCollapse asserts the gRPC DeriveKey
// output is byte-identical to what it produced before the operation was
// collapsed onto XKMSService.DeriveKey.
func TestDeriveKey_GoldenVectorsSurviveTheCollapse(t *testing.T) {
	service := setupServiceTest(t)
	defer xkms.Reset()

	for _, tc := range deriveKeyGolden {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := service.DeriveKey(context.Background(), tc.req)
			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.Equal(t, tc.golden, hex.EncodeToString(resp.DerivedKey))
			assert.Equal(t, tc.req.Algorithm, resp.Algorithm)
			assert.Equal(t, int32(len(resp.DerivedKey)), resp.KeyLength)
		})
	}
}

// TestDeriveKey_TransportAndServiceLayerAgree is what proves the collapse
// actually happened. The same parameters, issued once through the gRPC service
// and once directly against the service layer, must produce the same bytes. A
// second parameter assembly reappearing on either side fails here.
func TestDeriveKey_TransportAndServiceLayerAgree(t *testing.T) {
	service := setupServiceTest(t)
	defer xkms.Reset()

	svc, err := xkms.Get()
	require.NoError(t, err)

	for _, tc := range deriveKeyGolden {
		t.Run(tc.name, func(t *testing.T) {
			overGRPC, grpcErr := service.DeriveKey(context.Background(), tc.req)
			require.NoError(t, grpcErr)

			direct, svcErr := svc.DeriveKey(context.Background(), &transport.DeriveKeyRequest{
				Algorithm:        tc.req.Algorithm,
				InputKeyMaterial: tc.req.InputKeyMaterial,
				Salt:             tc.req.Salt,
				Info:             tc.req.Info,
				Label:            tc.req.Label,
				Context:          tc.req.Context,
				KeyLength:        int(tc.req.KeyLength),
				Hash:             tc.req.Hash,
			})
			require.NoError(t, svcErr)

			assert.Equal(t, direct.DerivedKey, overGRPC.DerivedKey,
				"the transport and the service layer must derive the same key")
			assert.Equal(t, direct.Algorithm, overGRPC.Algorithm)
			assert.Equal(t, int32(direct.KeyLength), overGRPC.KeyLength)
		})
	}
}

// TestDeriveKey_SaltIsKZeroInFeedbackModeOnly pins the one convention the two
// implementations disagreed on. Feedback Mode has an initial value K(0) and the
// wire has no IV field, so the salt carries it; every other mode has no input
// for a salt at all and must refuse it rather than derive a key from parameters
// the caller did not choose.
func TestDeriveKey_SaltIsKZeroInFeedbackModeOnly(t *testing.T) {
	service := setupServiceTest(t)
	defer xkms.Reset()

	withIV, err := service.DeriveKey(context.Background(), &pb.DeriveKeyRequest{
		Algorithm:        "SP800-108-Feedback",
		InputKeyMaterial: deriveKeyIKM,
		Label:            deriveKeyLabel,
		Context:          deriveKeyCtx,
		Salt:             deriveKeySalt,
		KeyLength:        32,
		Hash:             "SHA-256",
	})
	require.NoError(t, err)

	withoutIV, err := service.DeriveKey(context.Background(), &pb.DeriveKeyRequest{
		Algorithm:        "SP800-108-Feedback",
		InputKeyMaterial: deriveKeyIKM,
		Label:            deriveKeyLabel,
		Context:          deriveKeyCtx,
		KeyLength:        32,
		Hash:             "SHA-256",
	})
	require.NoError(t, err)

	assert.NotEqual(t, withoutIV.DerivedKey, withIV.DerivedKey,
		"the salt must be consumed as K(0), not dropped")

	for _, algorithm := range []string{"SP800-108-Counter", "SP800-108-Double-Pipeline"} {
		t.Run("salt refused by "+algorithm, func(t *testing.T) {
			resp, saltErr := service.DeriveKey(context.Background(), &pb.DeriveKeyRequest{
				Algorithm:        algorithm,
				InputKeyMaterial: deriveKeyIKM,
				Label:            deriveKeyLabel,
				Context:          deriveKeyCtx,
				Salt:             deriveKeySalt,
				KeyLength:        32,
				Hash:             "SHA-256",
			})
			require.Error(t, saltErr)
			assert.Equal(t, codes.InvalidArgument, status.Code(saltErr))
			assert.Nil(t, resp)
		})
	}

	t.Run("label refused by HKDF", func(t *testing.T) {
		resp, labelErr := service.DeriveKey(context.Background(), &pb.DeriveKeyRequest{
			Algorithm:        "HKDF",
			InputKeyMaterial: deriveKeyIKM,
			Label:            deriveKeyLabel,
			KeyLength:        32,
			Hash:             "SHA-256",
		})
		require.Error(t, labelErr)
		assert.Equal(t, codes.InvalidArgument, status.Code(labelErr))
		assert.Nil(t, resp)
	})
}

// TestDeriveKey_UnresolvableHashIsRefused is the DeriveKey arm of the
// silent-hash-downgrade guard. The KDF hash used to be resolved by a parser that
// answered any unrecognized name with SHA-256, so a caller that asked to derive
// under SHA-512 and misspelled it received SHA-256 keying material and success.
func TestDeriveKey_UnresolvableHashIsRefused(t *testing.T) {
	service := setupServiceTest(t)
	defer xkms.Reset()

	for _, hash := range []string{"SHA-999", "not-a-hash", "MD5", "SHA-1"} {
		t.Run(hash, func(t *testing.T) {
			resp, err := service.DeriveKey(context.Background(), &pb.DeriveKeyRequest{
				Algorithm:        "HKDF",
				InputKeyMaterial: deriveKeyIKM,
				Salt:             deriveKeySalt,
				KeyLength:        32,
				Hash:             hash,
			})
			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
			assert.Nil(t, resp, "a refused hash must not produce derived key material")
		})
	}
}
