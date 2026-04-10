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

package transport

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tenantIDSpec defines the expected TenantID field properties.
type tenantIDSpec struct {
	typeName string
	instance interface{}
}

// allTenantAwareRequestTypes returns all request types that should have TenantID.
func allTenantAwareRequestTypes() []tenantIDSpec {
	return []tenantIDSpec{
		// Key operations
		{"GenerateKeyRequest", GenerateKeyRequest{}},
		{"ImportKeyRequest", ImportKeyRequest{}},
		{"ExportKeyRequest", ExportKeyRequest{}},
		{"RotateKeyRequest", RotateKeyRequest{}},
		{"GetImportParametersRequest", GetImportParametersRequest{}},
		{"CopyKeyRequest", CopyKeyRequest{}},
		{"WrapKeyRequest", WrapKeyRequest{}},
		{"UnwrapKeyRequest", UnwrapKeyRequest{}},
		{"WrapKeyByIDRequest", WrapKeyByIDRequest{}},
		{"UnwrapKeyByIDRequest", UnwrapKeyByIDRequest{}},
		{"ExportKeyMaterialRequest", ExportKeyMaterialRequest{}},

		// Crypto operations
		{"SignRequest", SignRequest{}},
		{"VerifyRequest", VerifyRequest{}},
		{"EncryptRequest", EncryptRequest{}},
		{"DecryptRequest", DecryptRequest{}},
		{"EncryptAsymRequest", EncryptAsymRequest{}},
		{"DeriveKeyRequest", DeriveKeyRequest{}},
		{"DeriveKeyECDHRequest", DeriveKeyECDHRequest{}},
		{"AttestKeyRequest", AttestKeyRequest{}},

		// Certificate operations
		{"SaveCertificateRequest", SaveCertificateRequest{}},
		{"SaveCertificateChainRequest", SaveCertificateChainRequest{}},

		// Seal/Unseal operations
		{"SealRequest", SealRequest{}},
		{"UnsealRequest", UnsealRequest{}},

		// PIV operations
		{"ListPIVSlotsRequest", ListPIVSlotsRequest{}},
		{"GetPIVCertificateRequest", GetPIVCertificateRequest{}},
		{"StorePIVCertificateRequest", StorePIVCertificateRequest{}},
		{"DeletePIVCertificateRequest", DeletePIVCertificateRequest{}},
		{"GeneratePIVKeyRequest", GeneratePIVKeyRequest{}},
		{"GeneratePIVCSRRequest", GeneratePIVCSRRequest{}},

		// CA operations
		{"GetCABundleRequest", GetCABundleRequest{}},
		{"GetCACertificateRequest", GetCACertificateRequest{}},
		{"SignCSRRequest", SignCSRRequest{}},
		{"IssueCertificateRequest", IssueCertificateRequest{}},
		{"RevokeCertificateRequest", RevokeCertificateRequest{}},
		{"GenerateCRLRequest", GenerateCRLRequest{}},
		{"IsRevokedRequest", IsRevokedRequest{}},
	}
}

func TestTenantID_FieldExists(t *testing.T) {
	for _, spec := range allTenantAwareRequestTypes() {
		t.Run(spec.typeName, func(t *testing.T) {
			rt := reflect.TypeOf(spec.instance)
			field, ok := rt.FieldByName("TenantID")
			require.True(t, ok, "%s must have a TenantID field", spec.typeName)
			assert.Equal(t, "string", field.Type.Name(),
				"%s.TenantID must be of type string", spec.typeName)
		})
	}
}

func TestTenantID_JSONTag(t *testing.T) {
	for _, spec := range allTenantAwareRequestTypes() {
		t.Run(spec.typeName, func(t *testing.T) {
			rt := reflect.TypeOf(spec.instance)
			field, ok := rt.FieldByName("TenantID")
			require.True(t, ok, "%s must have a TenantID field", spec.typeName)

			jsonTag := field.Tag.Get("json")
			assert.Equal(t, "tenant_id,omitempty", jsonTag,
				"%s.TenantID must have json tag \"tenant_id,omitempty\", got %q",
				spec.typeName, jsonTag)
		})
	}
}

func TestTenantID_JSONMarshal_IncludedWhenSet(t *testing.T) {
	req := GenerateKeyRequest{
		KeyID:    "test-key",
		Backend:  "pkcs8",
		KeyType:  "ecdsa",
		TenantID: "acme-corp",
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded map[string]interface{}
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	val, ok := decoded["tenant_id"]
	assert.True(t, ok, "tenant_id should be present in JSON when TenantID is set")
	assert.Equal(t, "acme-corp", val)
}

func TestTenantID_JSONMarshal_OmittedWhenEmpty(t *testing.T) {
	req := GenerateKeyRequest{
		KeyID:   "test-key",
		Backend: "pkcs8",
		KeyType: "ecdsa",
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded map[string]interface{}
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	_, ok := decoded["tenant_id"]
	assert.False(t, ok, "tenant_id should be omitted from JSON when TenantID is empty")
}

func TestTenantID_JSONUnmarshal(t *testing.T) {
	jsonData := `{"key_id":"test","backend":"pkcs8","key_type":"ecdsa","tenant_id":"tenant-42"}`

	var req GenerateKeyRequest
	err := json.Unmarshal([]byte(jsonData), &req)
	require.NoError(t, err)

	assert.Equal(t, "tenant-42", req.TenantID)
	assert.Equal(t, "test", req.KeyID)
}

func TestTenantID_JSONUnmarshal_MissingField(t *testing.T) {
	jsonData := `{"key_id":"test","backend":"pkcs8","key_type":"ecdsa"}`

	var req GenerateKeyRequest
	err := json.Unmarshal([]byte(jsonData), &req)
	require.NoError(t, err)

	assert.Equal(t, "", req.TenantID, "TenantID should be empty when not in JSON")
}

// Verify system-level request types do NOT have TenantID.
func TestTenantID_SystemTypesExcluded(t *testing.T) {
	systemTypes := []struct {
		name     string
		instance interface{}
	}{
		{"BarrierInitializeRequest", BarrierInitializeRequest{}},
		{"BarrierUnsealRequest", BarrierUnsealRequest{}},
		{"BarrierInitializeShamirRequest", BarrierInitializeShamirRequest{}},
		{"BarrierUnsealShareRequest", BarrierUnsealShareRequest{}},
		{"BarrierUnsealSharesRequest", BarrierUnsealSharesRequest{}},
		{"SetSOPINRequest", SetSOPINRequest{}},
		{"SetUserPINRequest", SetUserPINRequest{}},
		{"ChangeSOPINRequest", ChangeSOPINRequest{}},
		{"ChangeUserPINRequest", ChangeUserPINRequest{}},
		{"VerifySOPINRequest", VerifySOPINRequest{}},
		{"VerifyUserPINRequest", VerifyUserPINRequest{}},
		{"ResetLockoutRequest", ResetLockoutRequest{}},
		{"BeginRegistrationRequest", BeginRegistrationRequest{}},
		{"FinishRegistrationRequest", FinishRegistrationRequest{}},
		{"BeginAuthenticationRequest", BeginAuthenticationRequest{}},
		{"FinishAuthenticationRequest", FinishAuthenticationRequest{}},
	}

	for _, st := range systemTypes {
		t.Run(st.name, func(t *testing.T) {
			rt := reflect.TypeOf(st.instance)
			_, ok := rt.FieldByName("TenantID")
			assert.False(t, ok, "%s should NOT have a TenantID field (system-level type)", st.name)
		})
	}
}

func TestTenantID_MultipleRequestTypes_RoundTrip(t *testing.T) {
	// Test a representative selection of request types for JSON round-trip
	testCases := []struct {
		name    string
		marshal func(tenantID string) ([]byte, error)
		checkFn func(t *testing.T, data []byte)
	}{
		{
			name: "SignRequest",
			marshal: func(tenantID string) ([]byte, error) {
				return json.Marshal(SignRequest{
					Backend:  "pkcs8",
					KeyID:    "sign-key",
					Data:     []byte("hello"),
					TenantID: tenantID,
				})
			},
			checkFn: func(t *testing.T, data []byte) {
				var req SignRequest
				require.NoError(t, json.Unmarshal(data, &req))
				assert.Equal(t, "tenant-x", req.TenantID)
			},
		},
		{
			name: "EncryptRequest",
			marshal: func(tenantID string) ([]byte, error) {
				return json.Marshal(EncryptRequest{
					Backend:   "pkcs8",
					KeyID:     "enc-key",
					Plaintext: []byte("secret"),
					TenantID:  tenantID,
				})
			},
			checkFn: func(t *testing.T, data []byte) {
				var req EncryptRequest
				require.NoError(t, json.Unmarshal(data, &req))
				assert.Equal(t, "tenant-x", req.TenantID)
			},
		},
		{
			name: "SaveCertificateRequest",
			marshal: func(tenantID string) ([]byte, error) {
				return json.Marshal(SaveCertificateRequest{
					Backend:        "pkcs8",
					KeyID:          "cert-key",
					CertificatePEM: "-----BEGIN CERTIFICATE-----",
					TenantID:       tenantID,
				})
			},
			checkFn: func(t *testing.T, data []byte) {
				var req SaveCertificateRequest
				require.NoError(t, json.Unmarshal(data, &req))
				assert.Equal(t, "tenant-x", req.TenantID)
			},
		},
		{
			name: "IssueCertificateRequest",
			marshal: func(tenantID string) ([]byte, error) {
				return json.Marshal(IssueCertificateRequest{
					Profile:    "server",
					CommonName: "example.com",
					TenantID:   tenantID,
				})
			},
			checkFn: func(t *testing.T, data []byte) {
				var req IssueCertificateRequest
				require.NoError(t, json.Unmarshal(data, &req))
				assert.Equal(t, "tenant-x", req.TenantID)
			},
		},
		{
			name: "GeneratePIVKeyRequest",
			marshal: func(tenantID string) ([]byte, error) {
				return json.Marshal(GeneratePIVKeyRequest{
					Backend:   "pkcs11",
					Slot:      "9a",
					Algorithm: "ecdsap256",
					Subject:   "CN=test",
					TenantID:  tenantID,
				})
			},
			checkFn: func(t *testing.T, data []byte) {
				var req GeneratePIVKeyRequest
				require.NoError(t, json.Unmarshal(data, &req))
				assert.Equal(t, "tenant-x", req.TenantID)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name+"_with_tenant", func(t *testing.T) {
			data, err := tc.marshal("tenant-x")
			require.NoError(t, err)
			tc.checkFn(t, data)
		})

		t.Run(tc.name+"_without_tenant", func(t *testing.T) {
			data, err := tc.marshal("")
			require.NoError(t, err)

			var decoded map[string]interface{}
			require.NoError(t, json.Unmarshal(data, &decoded))
			_, ok := decoded["tenant_id"]
			assert.False(t, ok, "tenant_id should be omitted when empty")
		})
	}
}
