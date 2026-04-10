// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newFullMockServer returns an httptest.Server that handles every REST path
// exercised by the transport methods. Uses raw JSON maps to avoid struct
// field mismatch issues while still exercising the full round-trip.
func newFullMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		path := r.URL.Path

		switch {
		// --- Health ---
		case path == "/health":
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"})

		// --- Backends ---
		case path == "/api/v1/backends":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"backends": []map[string]interface{}{{"id": "software", "type": "software"}},
			})
		case strings.HasPrefix(path, "/api/v1/backends/"):
			json.NewEncoder(w).Encode(map[string]string{"id": "software", "type": "software"})

		// --- Keys ---
		case path == "/api/v1/keys" && r.Method == http.MethodPost:
			json.NewEncoder(w).Encode(map[string]string{"key_id": "gen-key", "key_type": "ECDSA"})
		case path == "/api/v1/keys" && r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(map[string]interface{}{
				"keys": []map[string]string{{"key_id": "k1", "key_type": "ECDSA", "backend": "software"}},
			})
		case strings.HasPrefix(path, "/api/v1/keys/") && strings.HasSuffix(path, "/sign"):
			json.NewEncoder(w).Encode(map[string]interface{}{"signature": "c2ln", "algorithm": "ECDSA"})
		case strings.HasPrefix(path, "/api/v1/keys/") && strings.HasSuffix(path, "/verify"):
			json.NewEncoder(w).Encode(map[string]bool{"valid": true})
		case strings.HasPrefix(path, "/api/v1/keys/") && strings.HasSuffix(path, "/encrypt"):
			json.NewEncoder(w).Encode(map[string]string{"ciphertext": "ZW5j"})
		case strings.HasPrefix(path, "/api/v1/keys/") && strings.HasSuffix(path, "/decrypt"):
			json.NewEncoder(w).Encode(map[string]string{"plaintext": "cGxhaW4="})
		case strings.HasPrefix(path, "/api/v1/keys/") && strings.HasSuffix(path, "/encrypt-asym"):
			json.NewEncoder(w).Encode(map[string]string{"ciphertext": "YXN5bQ=="})
		case strings.HasPrefix(path, "/api/v1/keys/") && strings.HasSuffix(path, "/rotate"):
			json.NewEncoder(w).Encode(map[string]string{"key_id": "rotated"})
		case strings.HasPrefix(path, "/api/v1/keys/") && strings.HasSuffix(path, "/export"):
			json.NewEncoder(w).Encode(map[string]string{"key_id": "k1", "algorithm": "AES"})
		case strings.HasPrefix(path, "/api/v1/keys/") && strings.HasSuffix(path, "/export-material"):
			json.NewEncoder(w).Encode(map[string]string{"key_material": "bWF0ZXJpYWw=", "key_type": "aes256"})
		case path == "/api/v1/keys/import":
			json.NewEncoder(w).Encode(map[string]string{"key_id": "imported"})
		case path == "/api/v1/keys/import-params":
			json.NewEncoder(w).Encode(map[string]string{})
		case path == "/api/v1/keys/wrap":
			json.NewEncoder(w).Encode(map[string]string{"wrapped_key_material": "d3JhcHBlZA=="})
		case path == "/api/v1/keys/unwrap":
			json.NewEncoder(w).Encode(map[string]string{"key_material": "dW53cmFwcGVk"})
		case path == "/api/v1/keys/wrap-by-id":
			json.NewEncoder(w).Encode(map[string]string{"wrapped_key": "d3JhcHBlZC1pZA=="})
		case path == "/api/v1/keys/unwrap-by-id":
			json.NewEncoder(w).Encode(map[string]string{"key_id": "unwrapped-id"})
		case path == "/api/v1/keys/copy":
			json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "key_id": "copied"})
		case path == "/api/v1/keys/derive":
			json.NewEncoder(w).Encode(map[string]string{"derived_key": "ZGVyaXZlZA=="})
		case path == "/api/v1/keys/derive-ecdh":
			json.NewEncoder(w).Encode(map[string]string{"derived_key": "ZWNkaC1kZXJpdmVk"})
		case strings.HasPrefix(path, "/api/v1/keys/") && r.Method == http.MethodDelete:
			json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
		case strings.HasPrefix(path, "/api/v1/keys/") && r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(map[string]string{"key_id": "k1", "key_type": "ECDSA"})

		// --- Certificates ---
		case path == "/api/v1/certs" && r.Method == http.MethodPost:
			json.NewEncoder(w).Encode(map[string]string{"result": "ok"})
		case path == "/api/v1/certs" && r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(map[string]interface{}{"certificates": []interface{}{}})
		case strings.HasPrefix(path, "/api/v1/certs/") && strings.HasSuffix(path, "/chain"):
			if r.Method == http.MethodGet {
				json.NewEncoder(w).Encode(map[string]interface{}{"certificates": []interface{}{}})
			} else {
				json.NewEncoder(w).Encode(map[string]string{"result": "ok"})
			}
		case strings.HasPrefix(path, "/api/v1/certs/") && r.Method == http.MethodHead:
			w.WriteHeader(http.StatusOK)
		case strings.HasPrefix(path, "/api/v1/certs/") && r.Method == http.MethodDelete:
			json.NewEncoder(w).Encode(map[string]string{"result": "ok"})
		case strings.HasPrefix(path, "/api/v1/certs/"):
			json.NewEncoder(w).Encode(map[string]string{"certificate_pem": "-----BEGIN CERTIFICATE-----\nMIIB..."})

		// --- TLS ---
		case strings.HasPrefix(path, "/api/v1/tls/"):
			json.NewEncoder(w).Encode(map[string]string{
				"certificate_pem": "cert-pem", "chain_pem": "chain1",
			})

		// --- Seal ---
		case path == "/api/v1/seal":
			json.NewEncoder(w).Encode(map[string]string{"ciphertext": "c2VhbGVk"})
		case path == "/api/v1/unseal":
			json.NewEncoder(w).Encode(map[string]string{"plaintext": "dW5zZWFsZWQ="})
		case strings.HasPrefix(path, "/api/v1/seal/capability"):
			json.NewEncoder(w).Encode(map[string]bool{"can_seal": true})

		// --- Attestation ---
		case path == "/api/v1/attest":
			json.NewEncoder(w).Encode(map[string]string{"backend": "software"})

		// --- Users ---
		case path == "/api/v1/users/" && r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(map[string]interface{}{
				"users": []map[string]interface{}{
					{"username": "admin", "display_name": "Admin", "role": "admin", "enabled": true},
				},
				"total": 1,
			})
		case strings.HasPrefix(path, "/api/v1/users/") && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case strings.HasPrefix(path, "/api/v1/users/") && strings.HasSuffix(path, "/enable"):
			json.NewEncoder(w).Encode(map[string]string{"result": "ok"})
		case strings.HasPrefix(path, "/api/v1/users/") && strings.HasSuffix(path, "/disable"):
			json.NewEncoder(w).Encode(map[string]string{"result": "ok"})
		case strings.HasPrefix(path, "/api/v1/users/") && strings.HasSuffix(path, "/credentials"):
			json.NewEncoder(w).Encode(map[string]interface{}{"credentials": []interface{}{}})
		case strings.HasPrefix(path, "/api/v1/users/"):
			json.NewEncoder(w).Encode(map[string]interface{}{
				"username": "admin", "display_name": "Admin", "role": "admin", "enabled": true,
			})

		// --- Barrier ---
		case path == "/api/v1/barrier/status":
			json.NewEncoder(w).Encode(map[string]interface{}{"sealed": false})
		case path == "/api/v1/barrier/initialize",
			path == "/api/v1/barrier/unseal",
			path == "/api/v1/barrier/shamir/unseal-shares",
			path == "/api/v1/barrier/seal",
			path == "/api/v1/barrier/shamir/verify",
			path == "/api/v1/barrier/recovery/recover":
			json.NewEncoder(w).Encode(map[string]string{"result": "ok"})
		case path == "/api/v1/barrier/shamir/initialize":
			json.NewEncoder(w).Encode(map[string]interface{}{"shares": []string{}})
		case path == "/api/v1/barrier/shamir/unseal-share":
			json.NewEncoder(w).Encode(map[string]interface{}{"complete": false, "progress": 1, "threshold": 3})
		case path == "/api/v1/barrier/shamir/shares" && r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(map[string]interface{}{"shares": []interface{}{}})
		case path == "/api/v1/barrier/shamir/shares" && r.Method == http.MethodDelete:
			json.NewEncoder(w).Encode(map[string]string{"result": "ok"})
		case strings.HasPrefix(path, "/api/v1/barrier/shamir/shares/"):
			json.NewEncoder(w).Encode(map[string]string{"result": "ok"})
		case path == "/api/v1/barrier/rekey":
			json.NewEncoder(w).Encode(map[string]interface{}{"shares": []string{}})
		case path == "/api/v1/barrier/recovery/root-token":
			json.NewEncoder(w).Encode(map[string]string{"token": "root-token"})
		case path == "/api/v1/barrier/recovery/generate":
			json.NewEncoder(w).Encode(map[string]interface{}{"keys": []string{}})
		case path == "/api/v1/barrier/recovery/keys" && r.Method == http.MethodDelete:
			json.NewEncoder(w).Encode(map[string]string{"result": "ok"})
		case path == "/api/v1/barrier/recovery/keys" && r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(map[string]bool{"has_keys": true})

		// --- CA ---
		case path == "/api/v1/ca/bundle":
			json.NewEncoder(w).Encode(map[string]string{"bundle_pem": "YnVuZGxl"})
		case path == "/api/v1/ca/certificate":
			json.NewEncoder(w).Encode(map[string]string{"certificate_pem": "Y2VydA==", "subject": "CN=Test"})
		case path == "/api/v1/ca/sign-csr":
			json.NewEncoder(w).Encode(map[string]string{"certificate_pem": "c2lnbmVk"})
		case path == "/api/v1/ca/issue":
			json.NewEncoder(w).Encode(map[string]string{"certificate_pem": "aXNzdWVk"})
		case path == "/api/v1/ca/revoke":
			json.NewEncoder(w).Encode(map[string]string{"result": "ok"})
		case path == "/api/v1/ca/crl":
			json.NewEncoder(w).Encode(map[string]string{"crl_pem": "Y3Js"})
		case strings.HasPrefix(path, "/api/v1/ca/revoked/"):
			json.NewEncoder(w).Encode(map[string]bool{"revoked": false})

		// --- TCG CA ---
		case path == "/api/v1/tcg-ca/issue-ek-cert":
			json.NewEncoder(w).Encode(map[string]string{"certificate_pem": "ZWs="})
		case path == "/api/v1/tcg-ca/issue-ak-cert":
			json.NewEncoder(w).Encode(map[string]string{"certificate_pem": "YWs="})
		case path == "/api/v1/tcg-ca/sign-tcg-csr":
			json.NewEncoder(w).Encode(map[string]string{"iak_cert_der": "aWFr"})
		case path == "/api/v1/tcg-ca/enroll-device":
			json.NewEncoder(w).Encode(map[string]string{"result": "ok"})

		// --- PIV ---
		case path == "/v1/piv/slots" && r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(map[string]interface{}{"slots": []interface{}{}})
		case strings.HasPrefix(path, "/v1/piv/slots") && strings.HasSuffix(path, "/certificate") && r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(map[string]string{"slot": "9a", "certificate": "Y2VydA=="})
		case strings.HasPrefix(path, "/v1/piv/slots") && strings.HasSuffix(path, "/certificate") && r.Method == http.MethodPost:
			json.NewEncoder(w).Encode(map[string]string{"result": "ok"})
		case strings.HasPrefix(path, "/v1/piv/slots") && strings.HasSuffix(path, "/certificate") && r.Method == http.MethodDelete:
			json.NewEncoder(w).Encode(map[string]string{"result": "ok"})
		case strings.HasPrefix(path, "/v1/piv/slots") && strings.HasSuffix(path, "/generate"):
			json.NewEncoder(w).Encode(map[string]string{"slot": "9a"})
		case strings.HasPrefix(path, "/v1/piv/slots") && strings.HasSuffix(path, "/import"):
			json.NewEncoder(w).Encode(map[string]string{"result": "ok"})
		case strings.HasPrefix(path, "/v1/piv/slots") && strings.HasSuffix(path, "/export"):
			json.NewEncoder(w).Encode(map[string]string{"slot": "9a", "certificate": "ZXhwb3J0ZWQ="})
		case strings.HasPrefix(path, "/v1/piv/slots") && strings.HasSuffix(path, "/csr"):
			json.NewEncoder(w).Encode(map[string]string{"slot": "9a", "csr": "Y3Ny"})

		// --- PIN ---
		case path == "/v1/pin/so-pin",
			path == "/v1/pin/user-pin",
			path == "/v1/pin/so-pin/change",
			path == "/v1/pin/user-pin/change",
			path == "/v1/pin/so-pin/verify",
			path == "/v1/pin/user-pin/verify",
			path == "/v1/pin/lockout/reset":
			json.NewEncoder(w).Encode(map[string]string{"result": "ok"})
		case path == "/v1/pin/lockout" && r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(map[string]interface{}{"failed_attempts": 0, "max_attempts": 10})

		// --- Passwords ---
		case path == "/api/v1/passwords" && r.Method == http.MethodPost:
			json.NewEncoder(w).Encode(map[string]string{"id": "pw-id", "name": "test"})
		case path == "/api/v1/passwords" && r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(map[string]interface{}{"passwords": []interface{}{}})
		case path == "/api/v1/passwords/unlock",
			path == "/api/v1/passwords/lock",
			path == "/api/v1/passwords/access-mode":
			json.NewEncoder(w).Encode(map[string]string{"result": "ok"})
		case path == "/api/v1/passwords/status":
			json.NewEncoder(w).Encode(map[string]interface{}{"access_mode": "readwrite", "is_locked": false})
		case path == "/api/v1/passwords/generate":
			json.NewEncoder(w).Encode(map[string]string{"password": "gen-pass"})
		case strings.HasPrefix(path, "/api/v1/passwords/") && r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(map[string]string{"id": "pw1", "name": "test"})
		case strings.HasPrefix(path, "/api/v1/passwords/") && r.Method == http.MethodPut:
			json.NewEncoder(w).Encode(map[string]string{"result": "ok"})
		case strings.HasPrefix(path, "/api/v1/passwords/") && r.Method == http.MethodDelete:
			json.NewEncoder(w).Encode(map[string]string{"result": "ok"})

		// --- Init Ceremony ---
		case path == "/api/v1/init/status":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"phase": "complete", "officers_needed": 3, "officers_claimed": 3,
			})
		case path == "/api/v1/init/claim-cert/begin",
			path == "/api/v1/init/claim-cert/complete",
			path == "/api/v1/init/claim-share":
			json.NewEncoder(w).Encode(map[string]string{"result": "ok"})
		case path == "/api/v1/init/sign-csr":
			json.NewEncoder(w).Encode(map[string]string{"certificate": "init-cert"})

		// --- Credentials ---
		case path == "/api/v1/credentials/submit":
			json.NewEncoder(w).Encode(map[string]string{"result": "ok"})
		case path == "/api/v1/credentials/strategy":
			json.NewEncoder(w).Encode(map[string]string{"strategy": "manual"})

		// --- Custodian Groups ---
		case path == "/api/v1/custodian/groups" && r.Method == http.MethodPost:
			json.NewEncoder(w).Encode(map[string]string{"group_id": "g1"})
		case path == "/api/v1/custodian/groups" && r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(map[string]interface{}{"groups": []interface{}{}})

		// --- Shares ---
		case path == "/api/v1/shares/submit":
			json.NewEncoder(w).Encode(map[string]string{"result": "ok"})
		case path == "/api/v1/shares" && r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(map[string]interface{}{"shares": []interface{}{}})

		// --- Tenants ---
		case path == "/api/v1/tenants" && r.Method == http.MethodPost:
			json.NewEncoder(w).Encode(map[string]string{"tenant_id": "t1"})
		case path == "/api/v1/tenants" && r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(map[string]interface{}{"tenants": []interface{}{}})

		default:
			// Catch-all: return valid JSON for any unhandled path
			json.NewEncoder(w).Encode(map[string]string{"result": "ok"})
		}
	}))
}

// connectFullMock creates a connected REST transport backed by newFullMockServer.
func connectFullMock(t *testing.T, srv *httptest.Server) *Transport {
	t.Helper()
	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	return tr
}

// --- Key Service ---

func TestListKeys_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.ListKeys(context.Background(), "software")
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Len(t, resp.Keys, 1)
}

func TestGetKey_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.GetKey(context.Background(), "software", "k1")
	require.NoError(t, err)
	assert.Equal(t, "k1", resp.KeyID)
}

func TestDeleteKey_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.DeleteKey(context.Background(), "software", "k1")
	require.NoError(t, err)
	assert.True(t, resp.Success)
}

func TestVerify_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.Verify(context.Background(), &transport.VerifyRequest{
		Backend: "software", KeyID: "k1", Data: []byte("data"), Signature: []byte("sig"),
	})
	require.NoError(t, err)
	assert.True(t, resp.Valid)
}

func TestEncrypt_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.Encrypt(context.Background(), &transport.EncryptRequest{
		Backend: "software", KeyID: "k1", Plaintext: []byte("secret"),
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestDecrypt_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.Decrypt(context.Background(), &transport.DecryptRequest{
		Backend: "software", KeyID: "k1", Ciphertext: []byte("enc"),
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestEncryptAsym_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.EncryptAsym(context.Background(), &transport.EncryptAsymRequest{
		Backend: "software", KeyID: "k1", Plaintext: []byte("data"), Hash: "SHA-256",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestDeriveKey_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.DeriveKey(context.Background(), &transport.DeriveKeyRequest{
		Backend:          "software",
		Algorithm:        "HKDF",
		KeyLength:        32,
		KeyID:            "k1",
		InputKeyMaterial: []byte("ikm"),
		Salt:             []byte("salt"),
		Info:             []byte("info"),
		PeerPublicKey:    []byte("peer"),
		Hash:             "SHA-256",
		Iterations:       100000,
		PRF:              "HMAC-SHA256",
		Label:            []byte("label"),
		Context:          []byte("ctx"),
		Counter:          1,
		UseCofactor:      true,
		StoreResult:      true,
		DerivedKeyID:     "dk1",
		DerivedKeyType:   "AES-256",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestDeriveKeyECDH_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.DeriveKeyECDH(context.Background(), &transport.DeriveKeyECDHRequest{
		Backend: "software", KeyID: "k1",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestImportKey_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.ImportKey(context.Background(), &transport.ImportKeyRequest{
		Backend: "software", KeyID: "imported",
	})
	require.NoError(t, err)
	assert.Equal(t, "imported", resp.KeyID)
}

func TestExportKey_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.ExportKey(context.Background(), &transport.ExportKeyRequest{
		Backend: "software", KeyID: "k1",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestRotateKey_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.RotateKey(context.Background(), &transport.RotateKeyRequest{
		Backend: "software", KeyID: "k1",
	})
	require.NoError(t, err)
	assert.Equal(t, "rotated", resp.KeyID)
}

func TestGetImportParameters_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.GetImportParameters(context.Background(), &transport.GetImportParametersRequest{
		Backend: "software",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestWrapKey_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.WrapKey(context.Background(), &transport.WrapKeyRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestUnwrapKey_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.UnwrapKey(context.Background(), &transport.UnwrapKeyRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestWrapKeyByID_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.WrapKeyByID(context.Background(), &transport.WrapKeyByIDRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestUnwrapKeyByID_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.UnwrapKeyByID(context.Background(), &transport.UnwrapKeyByIDRequest{})
	require.NoError(t, err)
	assert.Equal(t, "unwrapped-id", resp.KeyID)
}

func TestExportKeyMaterial_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.ExportKeyMaterial(context.Background(), &transport.ExportKeyMaterialRequest{
		Backend: "software", KeyID: "k1",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestCopyKey_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.CopyKey(context.Background(), &transport.CopyKeyRequest{})
	require.NoError(t, err)
	assert.Equal(t, "copied", resp.KeyID)
}

// --- Certificate Service ---

func TestGetCertificate_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.GetCertificate(context.Background(), "software", "k1")
	require.NoError(t, err)
	assert.NotEmpty(t, resp.CertificatePEM)
}

func TestSaveCertificate_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	err := tr.SaveCertificate(context.Background(), &transport.SaveCertificateRequest{
		Backend: "software", KeyID: "k1", CertificatePEM: "cert",
	})
	assert.NoError(t, err)
}

func TestDeleteCertificate_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	err := tr.DeleteCertificate(context.Background(), "software", "k1")
	assert.NoError(t, err)
}

func TestCertificateExists_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	exists, err := tr.CertificateExists(context.Background(), "software", "k1")
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestListCertificates_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.ListCertificates(context.Background(), "software")
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestSaveCertificateChain_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	err := tr.SaveCertificateChain(context.Background(), &transport.SaveCertificateChainRequest{
		Backend: "software", KeyID: "k1",
	})
	assert.NoError(t, err)
}

func TestGetCertificateChain_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.GetCertificateChain(context.Background(), "software", "k1")
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestGetTLSCertificate_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.GetTLSCertificate(context.Background(), "software", "k1")
	require.NoError(t, err)
	assert.NotEmpty(t, resp.CertificatePEM)
}

// --- Seal Service ---

func TestCanSeal_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.CanSeal(context.Background(), "software")
	require.NoError(t, err)
	assert.True(t, resp.CanSeal)
}

func TestCanSeal_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.CanSeal(context.Background(), "software")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestUnseal_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.Unseal(context.Background(), &transport.UnsealRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

// --- Attestation ---

func TestAttestKey_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.AttestKey(context.Background(), &transport.AttestKeyRequest{
		Backend: "software", KeyID: "k1",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestAttestKey_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.AttestKey(context.Background(), &transport.AttestKeyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

// --- Users ---

func TestListUsers_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.ListUsers(context.Background())
	require.NoError(t, err)
	require.Len(t, resp.Users, 1)
	assert.Equal(t, "admin", resp.Users[0].Username)
}

func TestListUsers_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.ListUsers(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGetUser_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.GetUser(context.Background(), "admin")
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestGetUser_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.GetUser(context.Background(), "admin")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestDeleteUser_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	err := tr.DeleteUser(context.Background(), "admin")
	assert.NoError(t, err)
}

func TestDeleteUser_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	err = tr.DeleteUser(context.Background(), "admin")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestEnableUser_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	err := tr.EnableUser(context.Background(), "admin")
	assert.NoError(t, err)
}

func TestEnableUser_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	err = tr.EnableUser(context.Background(), "admin")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestDisableUser_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	err := tr.DisableUser(context.Background(), "admin")
	assert.NoError(t, err)
}

func TestDisableUser_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	err = tr.DisableUser(context.Background(), "admin")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestListUserCredentials_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.ListUserCredentials(context.Background(), "admin")
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestListUserCredentials_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.ListUserCredentials(context.Background(), "admin")
	assert.ErrorIs(t, err, ErrNotConnected)
}

// --- WebAuthn ---

func TestBeginRegistration_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.BeginRegistration(context.Background(), &transport.BeginRegistrationRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestFinishRegistration_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.FinishRegistration(context.Background(), &transport.FinishRegistrationRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestBeginAuthentication_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.BeginAuthentication(context.Background(), &transport.BeginAuthenticationRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestFinishAuthentication_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.FinishAuthentication(context.Background(), &transport.FinishAuthenticationRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// --- Barrier Service ---

func TestBarrierInitialize_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	err := tr.BarrierInitialize(context.Background(), &transport.BarrierInitializeRequest{})
	assert.NoError(t, err)
}

func TestBarrierUnseal_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	err := tr.BarrierUnseal(context.Background(), &transport.BarrierUnsealRequest{})
	assert.NoError(t, err)
}

func TestBarrierSeal_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	err := tr.BarrierSeal(context.Background())
	assert.NoError(t, err)
}

func TestBarrierInitializeShamir_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.BarrierInitializeShamir(context.Background(), &transport.BarrierInitializeShamirRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestBarrierUnsealWithShare_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.BarrierUnsealWithShare(context.Background(), &transport.BarrierUnsealShareRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestBarrierUnsealWithShares_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	err := tr.BarrierUnsealWithShares(context.Background(), &transport.BarrierUnsealSharesRequest{})
	assert.NoError(t, err)
}

func TestBarrierShamirListShares_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.BarrierShamirListShares(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestBarrierShamirDeleteShare_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	err := tr.BarrierShamirDeleteShare(context.Background(), &transport.BarrierShamirDeleteShareRequest{Index: 0})
	assert.NoError(t, err)
}

func TestBarrierShamirDeleteAllShares_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	err := tr.BarrierShamirDeleteAllShares(context.Background())
	assert.NoError(t, err)
}

func TestBarrierShamirVerify_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	err := tr.BarrierShamirVerify(context.Background())
	assert.NoError(t, err)
}

func TestBarrierRekey_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.BarrierRekey(context.Background(), &transport.BarrierRekeyRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestBarrierGenerateRecoveryKeys_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.BarrierGenerateRecoveryKeys(context.Background(), &transport.BarrierGenerateRecoveryKeysRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestBarrierRecoverWithKeys_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	err := tr.BarrierRecoverWithKeys(context.Background(), &transport.BarrierRecoverWithKeysRequest{})
	assert.NoError(t, err)
}

func TestBarrierDeleteRecoveryKeys_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	err := tr.BarrierDeleteRecoveryKeys(context.Background())
	assert.NoError(t, err)
}

func TestBarrierHasRecoveryKeys_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.BarrierHasRecoveryKeys(context.Background())
	require.NoError(t, err)
	assert.True(t, resp.HasKeys)
}

func TestBarrierGenerateRootToken_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.BarrierGenerateRootToken(context.Background(), &transport.BarrierGenerateRootTokenRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// --- CA Service ---

func TestGetCABundle_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.GetCABundle(context.Background(), &transport.GetCABundleRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestGetCACertificate_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.GetCACertificate(context.Background(), &transport.GetCACertificateRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestSignCSR_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.SignCSR(context.Background(), &transport.SignCSRRequest{CSRPEM: []byte("csr-data")})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestIssueCertificate_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.IssueCertificate(context.Background(), &transport.IssueCertificateRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestRevokeCertificate_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.RevokeCertificate(context.Background(), &transport.RevokeCertificateRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestGenerateCRL_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.GenerateCRL(context.Background(), &transport.GenerateCRLRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestIsRevoked_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.IsRevoked(context.Background(), &transport.IsRevokedRequest{SerialNumber: "123"})
	require.NoError(t, err)
	assert.False(t, resp.Revoked)
}

// --- TCG CA ---

func TestIssueEKCertificate_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.IssueEKCertificate(context.Background(), &transport.IssueEKCertificateRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestIssueAKCertificate_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.IssueAKCertificate(context.Background(), &transport.IssueAKCertificateRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestSignTCGCSR_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.SignTCGCSR(context.Background(), &transport.SignTCGCSRRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestEnrollDevice_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.EnrollDevice(context.Background(), &transport.EnrollDeviceRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// --- PIV ---

func TestListPIVSlots_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.ListPIVSlots(context.Background(), &transport.ListPIVSlotsRequest{Backend: "software"})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestGetPIVCertificate_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.GetPIVCertificate(context.Background(), &transport.GetPIVCertificateRequest{
		Backend: "software", Slot: "9a",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestStorePIVCertificate_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	err := tr.StorePIVCertificate(context.Background(), &transport.StorePIVCertificateRequest{
		Backend: "software", Slot: "9a",
	})
	assert.NoError(t, err)
}

func TestDeletePIVCertificate_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	err := tr.DeletePIVCertificate(context.Background(), &transport.DeletePIVCertificateRequest{
		Backend: "software", Slot: "9a",
	})
	assert.NoError(t, err)
}

func TestGeneratePIVKey_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.GeneratePIVKey(context.Background(), &transport.GeneratePIVKeyRequest{
		Backend: "software", Slot: "9a",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestImportPIVCertificate_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	err := tr.ImportPIVCertificate(context.Background(), &transport.StorePIVCertificateRequest{
		Backend: "software", Slot: "9a",
	})
	assert.NoError(t, err)
}

func TestExportPIVCertificate_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.ExportPIVCertificate(context.Background(), &transport.GetPIVCertificateRequest{
		Backend: "software", Slot: "9a",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestGeneratePIVCSR_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.GeneratePIVCSR(context.Background(), &transport.GeneratePIVCSRRequest{
		Backend: "software", Slot: "9a",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// --- PIN Service ---

func TestSetSOPIN_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	err := tr.SetSOPIN(context.Background(), &transport.SetSOPINRequest{NewSOPIN: "123456"})
	assert.NoError(t, err)
}

func TestSetUserPIN_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	err := tr.SetUserPIN(context.Background(), &transport.SetUserPINRequest{NewUserPIN: "1234"})
	assert.NoError(t, err)
}

func TestChangeSOPIN_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	err := tr.ChangeSOPIN(context.Background(), &transport.ChangeSOPINRequest{})
	assert.NoError(t, err)
}

func TestChangeUserPIN_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	err := tr.ChangeUserPIN(context.Background(), &transport.ChangeUserPINRequest{})
	assert.NoError(t, err)
}

func TestVerifySOPIN_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	err := tr.VerifySOPIN(context.Background(), &transport.VerifySOPINRequest{SOPIN: "123456"})
	assert.NoError(t, err)
}

func TestVerifyUserPIN_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	err := tr.VerifyUserPIN(context.Background(), &transport.VerifyUserPINRequest{UserPIN: "1234"})
	assert.NoError(t, err)
}

func TestGetLockoutStatus_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.GetLockoutStatus(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestResetLockout_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	err := tr.ResetLockout(context.Background(), &transport.ResetLockoutRequest{})
	assert.NoError(t, err)
}

// --- Password Service ---

func TestPasswordAdd_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.PasswordAdd(context.Background(), &transport.PasswordAddRequest{})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.ID)
}

func TestPasswordGet_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.PasswordGet(context.Background(), &transport.PasswordGetRequest{ID: "pw1"})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestPasswordList_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.PasswordList(context.Background(), &transport.PasswordListRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestPasswordUpdate_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	err := tr.PasswordUpdate(context.Background(), &transport.PasswordUpdateRequest{ID: "pw1"})
	assert.NoError(t, err)
}

func TestPasswordDelete_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	err := tr.PasswordDelete(context.Background(), &transport.PasswordDeleteRequest{ID: "pw1"})
	assert.NoError(t, err)
}

func TestPasswordStoreUnlock_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	err := tr.PasswordStoreUnlock(context.Background(), &transport.PasswordStoreUnlockRequest{})
	assert.NoError(t, err)
}

func TestPasswordStoreLock_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	err := tr.PasswordStoreLock(context.Background())
	assert.NoError(t, err)
}

func TestPasswordStoreStatus_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.PasswordStoreStatus(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestPasswordStoreSetAccessMode_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	err := tr.PasswordStoreSetAccessMode(context.Background(), &transport.PasswordStoreSetAccessModeRequest{})
	assert.NoError(t, err)
}

func TestPasswordGenerate_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.PasswordGenerate(context.Background(), &transport.PasswordGenerateRequest{})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Password)
}

// --- SealStore (not supported, returns ErrNotSupported) ---

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

// --- Policy (not supported, returns ErrNotSupported) ---

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
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.GetInitStatus(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestClaimCertBegin_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.ClaimCertBegin(context.Background(), &transport.ClaimCertBeginRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestClaimCertComplete_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.ClaimCertComplete(context.Background(), &transport.ClaimCertCompleteRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestClaimShare_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.ClaimShare(context.Background(), &transport.ClaimShareRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestSignCSRInit_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.SignCSRInit(context.Background(), &transport.SignCSRInitRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// --- Credentials ---

func TestSubmitCredential_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.SubmitCredential(context.Background(), &transport.CredentialSubmitRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestGetCredentialStrategy_Connected(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	resp, err := tr.GetCredentialStrategy(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "manual", resp.Strategy)
}
