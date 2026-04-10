// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newCatchAllMCPServer starts a JSON-RPC mock that returns a valid empty
// result for every method. The health method returns {"status":"ok"}.
func newCatchAllMCPServer(t *testing.T) (string, func()) {
	t.Helper()
	return startMockServer(t, func(req jsonrpcRequest) jsonrpcResponse {
		switch req.Method {
		case "health":
			d, _ := json.Marshal(map[string]string{"status": "ok", "version": "1.0.0"})
			return jsonrpcResponse{Result: d}
		case "xkms.listBackends":
			d, _ := json.Marshal(map[string]interface{}{
				"backends": []map[string]interface{}{{"id": "software", "type": "software"}},
			})
			return jsonrpcResponse{Result: d}
		case "xkms.getBackend":
			d, _ := json.Marshal(map[string]string{"id": "software", "type": "software"})
			return jsonrpcResponse{Result: d}
		case "xkms.generateKey":
			d, _ := json.Marshal(map[string]string{"key_id": "gen-key", "key_type": "ECDSA"})
			return jsonrpcResponse{Result: d}
		case "xkms.getKey":
			d, _ := json.Marshal(map[string]string{"key_id": "k1", "key_type": "ECDSA"})
			return jsonrpcResponse{Result: d}
		case "xkms.sign":
			d, _ := json.Marshal(map[string]string{"signature": "c2ln"})
			return jsonrpcResponse{Result: d}
		case "xkms.verify":
			d, _ := json.Marshal(map[string]bool{"valid": true})
			return jsonrpcResponse{Result: d}
		case "xkms.encrypt":
			d, _ := json.Marshal(map[string]string{"ciphertext": "ZW5j"})
			return jsonrpcResponse{Result: d}
		case "xkms.decrypt":
			d, _ := json.Marshal(map[string]string{"plaintext": "cGxhaW4="})
			return jsonrpcResponse{Result: d}
		case "xkms.asymmetricEncrypt":
			d, _ := json.Marshal(map[string]string{"ciphertext": "YXN5bQ=="})
			return jsonrpcResponse{Result: d}
		case "xkms.seal":
			d, _ := json.Marshal(map[string]string{"ciphertext": "c2VhbGVk"})
			return jsonrpcResponse{Result: d}
		case "xkms.unseal":
			d, _ := json.Marshal(map[string]string{"plaintext": "dW5zZWFsZWQ="})
			return jsonrpcResponse{Result: d}
		case "xkms.canSeal":
			d, _ := json.Marshal(map[string]bool{"can_seal": true})
			return jsonrpcResponse{Result: d}
		case "xkms.listUsers":
			d, _ := json.Marshal(map[string]interface{}{
				"users": []map[string]interface{}{
					{"username": "admin", "display_name": "Admin", "role": "admin", "enabled": true},
				},
				"total": 1,
			})
			return jsonrpcResponse{Result: d}
		case "xkms.getUser":
			d, _ := json.Marshal(map[string]interface{}{
				"username": "admin", "display_name": "Admin", "role": "admin", "enabled": true,
			})
			return jsonrpcResponse{Result: d}
		default:
			// Return empty valid result for all other methods
			return jsonrpcResponse{Result: json.RawMessage(`{}`)}
		}
	})
}

// --- Key Service ---

func TestListBackends_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.ListBackends(context.Background())
	require.NoError(t, err)
	assert.Len(t, resp.Backends, 1)
}

func TestGetBackend_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.GetBackend(context.Background(), "software")
	require.NoError(t, err)
	assert.Equal(t, "software", resp.ID)
}

func TestGenerateKey_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		Backend: "software", KeyID: "k1", KeyType: "ECDSA",
	})
	require.NoError(t, err)
	assert.Equal(t, "gen-key", resp.KeyID)
}

func TestListKeys_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.ListKeys(context.Background(), "software")
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestGetKey_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.GetKey(context.Background(), "software", "k1")
	require.NoError(t, err)
	assert.Equal(t, "k1", resp.KeyID)
}

func TestDeleteKey_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.DeleteKey(context.Background(), "software", "k1")
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestSign_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.Sign(context.Background(), &transport.SignRequest{
		Backend: "software", KeyID: "k1", Data: []byte("data"),
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestVerify_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.Verify(context.Background(), &transport.VerifyRequest{
		Backend: "software", KeyID: "k1", Data: []byte("data"), Signature: []byte("sig"),
	})
	require.NoError(t, err)
	assert.True(t, resp.Valid)
}

func TestEncrypt_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.Encrypt(context.Background(), &transport.EncryptRequest{
		Backend: "software", KeyID: "k1", Plaintext: []byte("secret"),
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestDecrypt_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.Decrypt(context.Background(), &transport.DecryptRequest{
		Backend: "software", KeyID: "k1", Ciphertext: []byte("enc"),
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestEncryptAsym_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.EncryptAsym(context.Background(), &transport.EncryptAsymRequest{
		Backend: "software", KeyID: "k1", Plaintext: []byte("data"),
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestDeriveKey_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.DeriveKey(context.Background(), &transport.DeriveKeyRequest{
		Backend: "software", Algorithm: "HKDF",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestDeriveKeyECDH_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.DeriveKeyECDH(context.Background(), &transport.DeriveKeyECDHRequest{
		Backend: "software", KeyID: "k1",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestAttestKey_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.AttestKey(context.Background(), &transport.AttestKeyRequest{
		Backend: "software", KeyID: "k1",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// --- Certificate Service ---

func TestGetCertificate_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.GetCertificate(context.Background(), "software", "k1")
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestSaveCertificate_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.SaveCertificate(context.Background(), &transport.SaveCertificateRequest{
		Backend: "software", KeyID: "k1",
	})
	assert.NoError(t, err)
}

func TestDeleteCertificate_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.DeleteCertificate(context.Background(), "software", "k1")
	assert.NoError(t, err)
}

func TestCertificateExists_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	exists, err := tr.CertificateExists(context.Background(), "software", "k1")
	require.NoError(t, err)
	// Empty response from catch-all means false/no error
	assert.False(t, exists)
}

func TestImportKey_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.ImportKey(context.Background(), &transport.ImportKeyRequest{Backend: "software"})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestExportKey_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.ExportKey(context.Background(), &transport.ExportKeyRequest{
		Backend: "software", KeyID: "k1",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestRotateKey_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.RotateKey(context.Background(), &transport.RotateKeyRequest{
		Backend: "software", KeyID: "k1",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestGetImportParameters_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.GetImportParameters(context.Background(), &transport.GetImportParametersRequest{Backend: "software"})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestWrapKey_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.WrapKey(context.Background(), &transport.WrapKeyRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestUnwrapKey_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.UnwrapKey(context.Background(), &transport.UnwrapKeyRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestWrapKeyByID_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.WrapKeyByID(context.Background(), &transport.WrapKeyByIDRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestUnwrapKeyByID_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.UnwrapKeyByID(context.Background(), &transport.UnwrapKeyByIDRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestExportKeyMaterial_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.ExportKeyMaterial(context.Background(), &transport.ExportKeyMaterialRequest{
		Backend: "software", KeyID: "k1",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestCopyKey_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.CopyKey(context.Background(), &transport.CopyKeyRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestListCertificates_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.ListCertificates(context.Background(), "software")
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestSaveCertificateChain_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.SaveCertificateChain(context.Background(), &transport.SaveCertificateChainRequest{
		Backend: "software", KeyID: "k1",
	})
	assert.NoError(t, err)
}

func TestGetCertificateChain_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.GetCertificateChain(context.Background(), "software", "k1")
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestGetTLSCertificate_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.GetTLSCertificate(context.Background(), "software", "k1")
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// --- Seal Service ---

func TestSeal_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.Seal(context.Background(), &transport.SealRequest{
		Backend: "software", Data: []byte("secret"),
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestUnseal_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.Unseal(context.Background(), &transport.UnsealRequest{
		Backend: "software", Ciphertext: []byte("sealed"),
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestCanSeal_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.CanSeal(context.Background(), "software")
	require.NoError(t, err)
	assert.True(t, resp.CanSeal)
}

// --- User Service ---

func TestListUsers_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.ListUsers(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestGetUser_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.GetUser(context.Background(), "admin")
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestDeleteUser_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.DeleteUser(context.Background(), "admin")
	assert.NoError(t, err)
}

func TestEnableUser_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.EnableUser(context.Background(), "admin")
	assert.NoError(t, err)
}

func TestDisableUser_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.DisableUser(context.Background(), "admin")
	assert.NoError(t, err)
}

func TestListUserCredentials_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.ListUserCredentials(context.Background(), "admin")
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// --- WebAuthn (not supported) ---

func TestBeginRegistration_NotSupported(t *testing.T) {
	_, err := (&Transport{}).BeginRegistration(context.Background(), &transport.BeginRegistrationRequest{})
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestFinishRegistration_NotSupported(t *testing.T) {
	_, err := (&Transport{}).FinishRegistration(context.Background(), &transport.FinishRegistrationRequest{})
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestBeginAuthentication_NotSupported(t *testing.T) {
	_, err := (&Transport{}).BeginAuthentication(context.Background(), &transport.BeginAuthenticationRequest{})
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestFinishAuthentication_NotSupported(t *testing.T) {
	_, err := (&Transport{}).FinishAuthentication(context.Background(), &transport.FinishAuthenticationRequest{})
	assert.ErrorIs(t, err, ErrNotSupported)
}

// --- CA Service ---

func TestGetCABundle_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.GetCABundle(context.Background(), &transport.GetCABundleRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestGetCACertificate_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.GetCACertificate(context.Background(), &transport.GetCACertificateRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestSignCSR_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.SignCSR(context.Background(), &transport.SignCSRRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestIssueCertificate_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.IssueCertificate(context.Background(), &transport.IssueCertificateRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestRevokeCertificate_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.RevokeCertificate(context.Background(), &transport.RevokeCertificateRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestGenerateCRL_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.GenerateCRL(context.Background(), &transport.GenerateCRLRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestIsRevoked_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.IsRevoked(context.Background(), &transport.IsRevokedRequest{SerialNumber: "123"})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// --- TCG CA ---

func TestIssueEKCertificate_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.IssueEKCertificate(context.Background(), &transport.IssueEKCertificateRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestIssueAKCertificate_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.IssueAKCertificate(context.Background(), &transport.IssueAKCertificateRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestSignTCGCSR_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.SignTCGCSR(context.Background(), &transport.SignTCGCSRRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestEnrollDevice_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.EnrollDevice(context.Background(), &transport.EnrollDeviceRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// --- PIV ---

func TestListPIVSlots_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.ListPIVSlots(context.Background(), &transport.ListPIVSlotsRequest{Backend: "software"})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestGetPIVCertificate_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.GetPIVCertificate(context.Background(), &transport.GetPIVCertificateRequest{
		Backend: "software", Slot: "9a",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestStorePIVCertificate_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.StorePIVCertificate(context.Background(), &transport.StorePIVCertificateRequest{
		Backend: "software", Slot: "9a",
	})
	assert.NoError(t, err)
}

func TestDeletePIVCertificate_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.DeletePIVCertificate(context.Background(), &transport.DeletePIVCertificateRequest{
		Backend: "software", Slot: "9a",
	})
	assert.NoError(t, err)
}

func TestGeneratePIVKey_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.GeneratePIVKey(context.Background(), &transport.GeneratePIVKeyRequest{
		Backend: "software", Slot: "9a",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestImportPIVCertificate_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.ImportPIVCertificate(context.Background(), &transport.StorePIVCertificateRequest{
		Backend: "software", Slot: "9a",
	})
	assert.NoError(t, err)
}

func TestExportPIVCertificate_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.ExportPIVCertificate(context.Background(), &transport.GetPIVCertificateRequest{
		Backend: "software", Slot: "9a",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestGeneratePIVCSR_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.GeneratePIVCSR(context.Background(), &transport.GeneratePIVCSRRequest{
		Backend: "software", Slot: "9a",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// --- Barrier Service ---

func TestBarrierInitialize_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.BarrierInitialize(context.Background(), &transport.BarrierInitializeRequest{})
	assert.NoError(t, err)
}

func TestBarrierUnseal_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.BarrierUnseal(context.Background(), &transport.BarrierUnsealRequest{})
	assert.NoError(t, err)
}

func TestBarrierSeal_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.BarrierSeal(context.Background())
	assert.NoError(t, err)
}

func TestBarrierStatus_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.BarrierStatus(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestBarrierInitializeShamir_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.BarrierInitializeShamir(context.Background(), &transport.BarrierInitializeShamirRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestBarrierUnsealWithShare_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.BarrierUnsealWithShare(context.Background(), &transport.BarrierUnsealShareRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestBarrierUnsealWithShares_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.BarrierUnsealWithShares(context.Background(), &transport.BarrierUnsealSharesRequest{})
	assert.NoError(t, err)
}

func TestBarrierShamirListShares_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.BarrierShamirListShares(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestBarrierShamirDeleteShare_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.BarrierShamirDeleteShare(context.Background(), &transport.BarrierShamirDeleteShareRequest{Index: 0})
	assert.NoError(t, err)
}

func TestBarrierShamirDeleteAllShares_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.BarrierShamirDeleteAllShares(context.Background())
	assert.NoError(t, err)
}

func TestBarrierShamirVerify_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.BarrierShamirVerify(context.Background())
	assert.NoError(t, err)
}

func TestBarrierRekey_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.BarrierRekey(context.Background(), &transport.BarrierRekeyRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestBarrierGenerateRecoveryKeys_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.BarrierGenerateRecoveryKeys(context.Background(), &transport.BarrierGenerateRecoveryKeysRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestBarrierRecoverWithKeys_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.BarrierRecoverWithKeys(context.Background(), &transport.BarrierRecoverWithKeysRequest{})
	assert.NoError(t, err)
}

func TestBarrierDeleteRecoveryKeys_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.BarrierDeleteRecoveryKeys(context.Background())
	assert.NoError(t, err)
}

func TestBarrierHasRecoveryKeys_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.BarrierHasRecoveryKeys(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestBarrierGenerateRootToken_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.BarrierGenerateRootToken(context.Background(), &transport.BarrierGenerateRootTokenRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// --- PIN Service ---

func TestSetSOPIN_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.SetSOPIN(context.Background(), &transport.SetSOPINRequest{})
	assert.NoError(t, err)
}

func TestSetUserPIN_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.SetUserPIN(context.Background(), &transport.SetUserPINRequest{})
	assert.NoError(t, err)
}

func TestChangeSOPIN_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.ChangeSOPIN(context.Background(), &transport.ChangeSOPINRequest{})
	assert.NoError(t, err)
}

func TestChangeUserPIN_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.ChangeUserPIN(context.Background(), &transport.ChangeUserPINRequest{})
	assert.NoError(t, err)
}

func TestVerifySOPIN_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.VerifySOPIN(context.Background(), &transport.VerifySOPINRequest{})
	assert.NoError(t, err)
}

func TestVerifyUserPIN_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.VerifyUserPIN(context.Background(), &transport.VerifyUserPINRequest{})
	assert.NoError(t, err)
}

func TestGetLockoutStatus_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.GetLockoutStatus(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestResetLockout_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.ResetLockout(context.Background(), &transport.ResetLockoutRequest{})
	assert.NoError(t, err)
}

// --- Password Service ---

func TestPasswordAdd_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.PasswordAdd(context.Background(), &transport.PasswordAddRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestPasswordGet_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.PasswordGet(context.Background(), &transport.PasswordGetRequest{ID: "pw1"})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestPasswordList_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.PasswordList(context.Background(), &transport.PasswordListRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestPasswordUpdate_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.PasswordUpdate(context.Background(), &transport.PasswordUpdateRequest{ID: "pw1"})
	assert.NoError(t, err)
}

func TestPasswordDelete_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.PasswordDelete(context.Background(), &transport.PasswordDeleteRequest{ID: "pw1"})
	assert.NoError(t, err)
}

func TestPasswordStoreUnlock_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.PasswordStoreUnlock(context.Background(), &transport.PasswordStoreUnlockRequest{})
	assert.NoError(t, err)
}

func TestPasswordStoreLock_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.PasswordStoreLock(context.Background())
	assert.NoError(t, err)
}

func TestPasswordStoreStatus_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.PasswordStoreStatus(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestPasswordStoreSetAccessMode_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.PasswordStoreSetAccessMode(context.Background(), &transport.PasswordStoreSetAccessModeRequest{})
	assert.NoError(t, err)
}

func TestPasswordGenerate_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.PasswordGenerate(context.Background(), &transport.PasswordGenerateRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// --- SealStore (not supported) ---

func TestSealStorePut_NotSupported(t *testing.T) {
	err := (&Transport{}).SealStorePut(context.Background(), &transport.SealStorePutRequest{})
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestSealStoreGet_NotSupported(t *testing.T) {
	_, err := (&Transport{}).SealStoreGet(context.Background(), &transport.SealStoreGetRequest{})
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestSealStoreDelete_NotSupported(t *testing.T) {
	err := (&Transport{}).SealStoreDelete(context.Background(), &transport.SealStoreDeleteRequest{})
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestSealStoreList_NotSupported(t *testing.T) {
	_, err := (&Transport{}).SealStoreList(context.Background())
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestSealStoreReseal_NotSupported(t *testing.T) {
	err := (&Transport{}).SealStoreReseal(context.Background(), &transport.SealStoreResealRequest{})
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestSealStoreStatus_NotSupported(t *testing.T) {
	_, err := (&Transport{}).SealStoreStatus(context.Background())
	assert.ErrorIs(t, err, ErrNotSupported)
}

// --- Policy (not supported) ---

func TestPolicyCreate_NotSupported(t *testing.T) {
	_, err := (&Transport{}).PolicyCreate(context.Background(), &transport.PolicyCreateRequest{})
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestPolicyGet_NotSupported(t *testing.T) {
	_, err := (&Transport{}).PolicyGet(context.Background(), &transport.PolicyGetRequest{})
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestPolicyList_NotSupported(t *testing.T) {
	_, err := (&Transport{}).PolicyList(context.Background())
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestPolicyDelete_NotSupported(t *testing.T) {
	err := (&Transport{}).PolicyDelete(context.Background(), &transport.PolicyDeleteRequest{})
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestPolicyRefresh_NotSupported(t *testing.T) {
	_, err := (&Transport{}).PolicyRefresh(context.Background(), &transport.PolicyRefreshRequest{})
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestPolicyVerify_NotSupported(t *testing.T) {
	_, err := (&Transport{}).PolicyVerify(context.Background(), &transport.PolicyVerifyRequest{})
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestPolicyExport_NotSupported(t *testing.T) {
	_, err := (&Transport{}).PolicyExport(context.Background(), &transport.PolicyExportRequest{})
	assert.ErrorIs(t, err, ErrNotSupported)
}

// --- Init Ceremony ---

func TestGetInitStatus_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.GetInitStatus(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestClaimCertBegin_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.ClaimCertBegin(context.Background(), &transport.ClaimCertBeginRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestClaimCertComplete_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.ClaimCertComplete(context.Background(), &transport.ClaimCertCompleteRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestClaimShare_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.ClaimShare(context.Background(), &transport.ClaimShareRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestSignCSRInit_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.SignCSRInit(context.Background(), &transport.SignCSRInitRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// --- Credentials ---

func TestSubmitCredential_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.SubmitCredential(context.Background(), &transport.CredentialSubmitRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestGetCredentialStrategy_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.GetCredentialStrategy(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// --- Custodian & Shares & Tenants ---

func TestCreateCustodianGroup_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.CreateCustodianGroup(context.Background(), &transport.CreateCustodianGroupRequest{
		Name: "test", Threshold: 2,
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestGetCustodianGroup_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.GetCustodianGroup(context.Background(), "g1")
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestListCustodianGroups_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.ListCustodianGroups(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestDeleteCustodianGroup_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.DeleteCustodianGroup(context.Background(), "g1")
	assert.NoError(t, err)
}

func TestAddCustodianMember_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.AddCustodianMember(context.Background(), &transport.AddCustodianMemberRequest{
		GroupID: "g1", UserID: "u1",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestRemoveCustodianMember_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.RemoveCustodianMember(context.Background(), &transport.RemoveCustodianMemberRequest{
		GroupID: "g1", UserID: "u1",
	})
	assert.NoError(t, err)
}

func TestDistributeShares_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.DistributeShares(context.Background(), &transport.DistributeSharesRequest{GroupID: "g1"})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestSubmitShare_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.SubmitShare(context.Background(), &transport.SubmitShareRequest{GroupID: "g1"})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestListShares_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.ListShares(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestGetShareCollectionStatus_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.GetShareCollectionStatus(context.Background(), "g1")
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestCreateTenant_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.CreateTenant(context.Background(), &transport.CreateTenantRequest{Name: "Test"})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestGetTenant_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.GetTenant(context.Background(), "t1")
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestListTenants_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.ListTenants(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestDeleteTenant_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.DeleteTenant(context.Background(), "t1")
	assert.NoError(t, err)
}

func TestTenantBarrierInit_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.TenantBarrierInit(context.Background(), &transport.TenantBarrierInitRequest{TenantID: "t1"})
	assert.NoError(t, err)
}

func TestTenantBarrierUnseal_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.TenantBarrierUnseal(context.Background(), &transport.TenantBarrierUnsealRequest{TenantID: "t1"})
	assert.NoError(t, err)
}
