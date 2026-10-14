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

package quic

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/keyversiontest"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/oidccredentialtest"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tpmpolicytest"
)

// wireRequest is one request a wireRecorder saw.
type wireRequest struct {
	Method string
	Path   string
	Header http.Header
	Body   map[string]any
}

// wireRecorder answers every request with a fixed status and body and
// records what it was sent, so a test can pin what a Transport method put
// on the wire.
type wireRecorder struct {
	mu       sync.Mutex
	requests []wireRequest
}

func (s *wireRecorder) record(r *http.Request) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}
	var body map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &body); err != nil {
			panic(err)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, wireRequest{Method: r.Method, Path: r.URL.Path, Header: r.Header.Clone(), Body: body})
}

func (s *wireRecorder) take() []wireRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	got := s.requests
	s.requests = nil
	return got
}

// newWireTransport serves status and body for every request over an
// in-process TLS listener on a loopback ephemeral port.
func newWireTransport(t *testing.T, status int, body string) (*Transport, *wireRecorder) {
	t.Helper()
	rec := &wireRecorder{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.record(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if _, err := io.WriteString(w, body); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	return &Transport{
		config:     transport.DefaultConfig(),
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		connected:  true,
	}, rec
}

// serviceCalls gathers the shared per-service call tables for the services
// whose QUIC methods are thin wrappers over the REST wire clients.
func serviceCalls(ctx context.Context, tr *Transport) map[string]func() error {
	calls := map[string]func() error{}
	for _, set := range []map[string]func() error{
		keyversiontest.Calls(ctx, tr),
		tpmpolicytest.Calls(ctx, tr),
		oidccredentialtest.Calls(ctx, tr),
	} {
		for name, call := range set {
			calls[name] = call
		}
	}
	return calls
}

// TestServiceWrappers_ReachTheServer proves every key-version, TPM-policy
// and OIDC-credential method of a connected transport sends exactly one
// request and decodes the answer. Each route is pinned once, in
// pkg/api/rest/wire.
func TestServiceWrappers_ReachTheServer(t *testing.T) {
	tr, rec := newWireTransport(t, http.StatusOK, `{}`)
	for name, call := range serviceCalls(context.Background(), tr) {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, call())
			assert.Len(t, rec.take(), 1)
		})
	}
}

// TestServiceWrappers_ServerErrorReachesTheCaller proves a server failure
// is returned to the caller of every wrapper, not swallowed.
func TestServiceWrappers_ServerErrorReachesTheCaller(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	for name, call := range serviceCalls(context.Background(), tr) {
		t.Run(name, func(t *testing.T) {
			err := call()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "internal failure")
		})
	}
}

// decodingCalls lists every Transport method that decodes a JSON response
// body, for the malformed-response test.
func decodingCalls(ctx context.Context, tr *Transport) map[string]func() error {
	return map[string]func() error{
		"Health":         func() error { _, err := tr.Health(ctx); return err },
		"ListBackends":   func() error { _, err := tr.ListBackends(ctx); return err },
		"GetBackend":     func() error { _, err := tr.GetBackend(ctx, "software"); return err },
		"Algorithms":     func() error { _, err := tr.Algorithms(ctx); return err },
		"GenerateKey":    func() error { _, err := tr.GenerateKey(ctx, &transport.GenerateKeyRequest{}); return err },
		"ListKeys":       func() error { _, err := tr.ListKeys(ctx, "software"); return err },
		"GetKey":         func() error { _, err := tr.GetKey(ctx, "software", "k"); return err },
		"DeleteKey":      func() error { _, err := tr.DeleteKey(ctx, "software", "k"); return err },
		"Sign":           func() error { _, err := tr.Sign(ctx, &transport.SignRequest{}); return err },
		"Verify":         func() error { _, err := tr.Verify(ctx, &transport.VerifyRequest{}); return err },
		"Encrypt":        func() error { _, err := tr.Encrypt(ctx, &transport.EncryptRequest{}); return err },
		"Decrypt":        func() error { _, err := tr.Decrypt(ctx, &transport.DecryptRequest{}); return err },
		"EncryptAsym":    func() error { _, err := tr.EncryptAsym(ctx, &transport.EncryptAsymRequest{}); return err },
		"GetCertificate": func() error { _, err := tr.GetCertificate(ctx, "software", "k"); return err },
		"ImportKey":      func() error { _, err := tr.ImportKey(ctx, &transport.ImportKeyRequest{}); return err },
		"ExportKey":      func() error { _, err := tr.ExportKey(ctx, &transport.ExportKeyRequest{}); return err },
		"RotateKey":      func() error { _, err := tr.RotateKey(ctx, &transport.RotateKeyRequest{}); return err },
		"GetImportParameters": func() error {
			_, err := tr.GetImportParameters(ctx, &transport.GetImportParametersRequest{})
			return err
		},
		"WrapKey":             func() error { _, err := tr.WrapKey(ctx, &transport.WrapKeyRequest{}); return err },
		"UnwrapKey":           func() error { _, err := tr.UnwrapKey(ctx, &transport.UnwrapKeyRequest{}); return err },
		"WrapKeyByID":         func() error { _, err := tr.WrapKeyByID(ctx, &transport.WrapKeyByIDRequest{}); return err },
		"UnwrapKeyByID":       func() error { _, err := tr.UnwrapKeyByID(ctx, &transport.UnwrapKeyByIDRequest{}); return err },
		"ExportKeyMaterial":   func() error { _, err := tr.ExportKeyMaterial(ctx, &transport.ExportKeyMaterialRequest{}); return err },
		"DeriveKeyECDH":       func() error { _, err := tr.DeriveKeyECDH(ctx, &transport.DeriveKeyECDHRequest{}); return err },
		"CopyKey":             func() error { _, err := tr.CopyKey(ctx, &transport.CopyKeyRequest{}); return err },
		"ListCertificates":    func() error { _, err := tr.ListCertificates(ctx, "software"); return err },
		"GetCertificateChain": func() error { _, err := tr.GetCertificateChain(ctx, "software", "k"); return err },
		"GetTLSCertificate":   func() error { _, err := tr.GetTLSCertificate(ctx, "software", "k"); return err },
		"Seal":                func() error { _, err := tr.Seal(ctx, &transport.SealRequest{}); return err },
		"CanSeal":             func() error { _, err := tr.CanSeal(ctx, "software"); return err },
		"AttestKey":           func() error { _, err := tr.AttestKey(ctx, &transport.AttestKeyRequest{}); return err },
		"BeginRegistration":   func() error { _, err := tr.BeginRegistration(ctx, &transport.BeginRegistrationRequest{}); return err },
		"FinishRegistration":  func() error { _, err := tr.FinishRegistration(ctx, &transport.FinishRegistrationRequest{}); return err },
		"BeginAuthentication": func() error {
			_, err := tr.BeginAuthentication(ctx, &transport.BeginAuthenticationRequest{})
			return err
		},
		"FinishAuthentication": func() error {
			_, err := tr.FinishAuthentication(ctx, &transport.FinishAuthenticationRequest{})
			return err
		},
		"GetInvite": func() error { _, err := tr.GetInvite(ctx, &transport.GetInviteRequest{}); return err },
		"BeginInviteReg": func() error {
			_, err := tr.BeginInviteRegistration(ctx, &transport.BeginInviteRegistrationRequest{})
			return err
		},
		"FinishInviteReg": func() error {
			_, err := tr.FinishInviteRegistration(ctx, &transport.FinishInviteRegistrationRequest{})
			return err
		},
		"ActivateInvitePIV": func() error { _, err := tr.ActivateInvitePIV(ctx, &transport.ActivateInvitePIVRequest{}); return err },
		"IssueLAKCertificate": func() error {
			_, err := tr.IssueLAKCertificate(ctx, &transport.IssueLAKCertificateRequest{})
			return err
		},
		"BootstrapListenerKeys": func() error { _, err := tr.BootstrapListenerKeys(ctx); return err },
		"GetLockoutStatus":      func() error { _, err := tr.GetLockoutStatus(ctx); return err },
		"PasswordAdd":           func() error { _, err := tr.PasswordAdd(ctx, &transport.PasswordAddRequest{}); return err },
		"PasswordStoreStatus":   func() error { _, err := tr.PasswordStoreStatus(ctx); return err },
		"PasswordGenerate":      func() error { _, err := tr.PasswordGenerate(ctx, &transport.PasswordGenerateRequest{}); return err },
		"SealStoreGet":          func() error { _, err := tr.SealStoreGet(ctx, &transport.SealStoreGetRequest{}); return err },
		"SealStoreList":         func() error { _, err := tr.SealStoreList(ctx); return err },
		"SealStoreStatus":       func() error { _, err := tr.SealStoreStatus(ctx); return err },
		"CreateTenant":          func() error { _, err := tr.CreateTenant(ctx, &transport.CreateTenantRequest{}); return err },
		"GetTenant":             func() error { _, err := tr.GetTenant(ctx, "acme"); return err },
		"ListTenants":           func() error { _, err := tr.ListTenants(ctx); return err },
		"UpdateTenantEntitlements": func() error {
			_, err := tr.UpdateTenantEntitlements(ctx, &transport.UpdateTenantEntitlementsRequest{})
			return err
		},
		"UpdateTenantQuotas":    func() error { _, err := tr.UpdateTenantQuotas(ctx, &transport.UpdateTenantQuotasRequest{}); return err },
		"SubmitCredential":      func() error { _, err := tr.SubmitCredential(ctx, &transport.CredentialSubmitRequest{}); return err },
		"GetCredentialStrategy": func() error { _, err := tr.GetCredentialStrategy(ctx); return err },
		"CreateUser":            func() error { _, err := tr.CreateUser(ctx, &transport.CreateUserRequest{}); return err },
		"ListUsers":             func() error { _, err := tr.ListUsers(ctx); return err },
		"GetUser":               func() error { _, err := tr.GetUser(ctx, "alice"); return err },
		"ListUserCredentials":   func() error { _, err := tr.ListUserCredentials(ctx, "alice"); return err },
		"PKCS11StatePutIfAbsent": func() error {
			_, err := tr.PKCS11StatePutIfAbsent(ctx, &transport.PKCS11StatePutIfAbsentRequest{})
			return err
		},
		"PKCS11StateCAS":  func() error { _, err := tr.PKCS11StateCAS(ctx, &transport.PKCS11StateCASRequest{}); return err },
		"PKCS11StateGet":  func() error { _, err := tr.PKCS11StateGet(ctx, &transport.PKCS11StateGetRequest{}); return err },
		"PKCS11StateList": func() error { _, err := tr.PKCS11StateList(ctx, &transport.PKCS11StateListRequest{}); return err },
	}
}

// TestMalformedResponse_IsAnError proves a 200 whose body is not JSON
// surfaces as an error from every decoding method instead of a zero-valued
// success the caller would act on.
func TestMalformedResponse_IsAnError(t *testing.T) {
	tr, _ := newWireTransport(t, http.StatusOK, "not json")
	for name, call := range decodingCalls(context.Background(), tr) {
		t.Run(name, func(t *testing.T) {
			assert.Error(t, call())
		})
	}
}

// TestPKCS11State_ServerErrorReachesTheCaller covers the PKCS#11 state
// methods that report a failed request without decoding a body.
func TestPKCS11State_ServerErrorReachesTheCaller(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	ctx := context.Background()

	calls := map[string]func() error{
		"Put": func() error { _, err := tr.PKCS11StatePut(ctx, &transport.PKCS11StatePutRequest{}); return err },
		"PutIfAbsent": func() error {
			_, err := tr.PKCS11StatePutIfAbsent(ctx, &transport.PKCS11StatePutIfAbsentRequest{})
			return err
		},
		"CAS":    func() error { _, err := tr.PKCS11StateCAS(ctx, &transport.PKCS11StateCASRequest{}); return err },
		"Get":    func() error { _, err := tr.PKCS11StateGet(ctx, &transport.PKCS11StateGetRequest{}); return err },
		"Delete": func() error { _, err := tr.PKCS11StateDelete(ctx, &transport.PKCS11StateDeleteRequest{}); return err },
		"List":   func() error { _, err := tr.PKCS11StateList(ctx, &transport.PKCS11StateListRequest{}); return err },
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			err := call()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "internal failure")
		})
	}
}

// TestInvites_SendTheirRoutesAndDecode pins the invite-activation routes:
// the tenant and token travel in the path, the FIDO2 and PIV payloads in
// the body, and the user ID decodes from its string form.
func TestInvites_SendTheirRoutesAndDecode(t *testing.T) {
	ctx := context.Background()

	t.Run("GetInvite", func(t *testing.T) {
		tr, rec := newWireTransport(t, http.StatusOK, `{"email":"a@example.com","methods":["webauthn","piv"]}`)
		resp, err := tr.GetInvite(ctx, &transport.GetInviteRequest{TenantID: "acme", Token: "t/1"})
		require.NoError(t, err)
		assert.Equal(t, "a@example.com", resp.Email)
		assert.Equal(t, []string{"webauthn", "piv"}, resp.Methods)
		got := rec.take()
		require.Len(t, got, 1)
		assert.Equal(t, http.MethodGet, got[0].Method)
		assert.Equal(t, "/api/v1/invites/acme/t/1", got[0].Path)
	})

	t.Run("BeginInviteRegistration", func(t *testing.T) {
		tr, rec := newWireTransport(t, http.StatusOK, `{"session_id":"s1","options_json":"{}"}`)
		resp, err := tr.BeginInviteRegistration(ctx, &transport.BeginInviteRegistrationRequest{TenantID: "acme", Token: "tok"})
		require.NoError(t, err)
		assert.Equal(t, "s1", resp.SessionID)
		got := rec.take()
		require.Len(t, got, 1)
		assert.Equal(t, http.MethodPost, got[0].Method)
		assert.Equal(t, "/api/v1/invites/acme/tok/fido2/begin", got[0].Path)
	})

	t.Run("FinishInviteRegistration", func(t *testing.T) {
		tr, rec := newWireTransport(t, http.StatusOK, `{"user_id":"42"}`)
		resp, err := tr.FinishInviteRegistration(ctx, &transport.FinishInviteRegistrationRequest{
			TenantID: "acme", Token: "tok", SessionID: "s1", AttestationJSON: `{"id":"x"}`,
		})
		require.NoError(t, err)
		assert.Equal(t, uint64(42), resp.UserID)
		got := rec.take()
		require.Len(t, got, 1)
		assert.Equal(t, "/api/v1/invites/acme/tok/fido2/finish", got[0].Path)
		assert.Equal(t, map[string]any{"session_id": "s1", "attestation_json": `{"id":"x"}`}, got[0].Body)
	})

	t.Run("ActivateInvitePIV", func(t *testing.T) {
		tr, rec := newWireTransport(t, http.StatusOK, `{"user_id":"7"}`)
		resp, err := tr.ActivateInvitePIV(ctx, &transport.ActivateInvitePIVRequest{TenantID: "acme", Token: "tok", CertPEM: "pem"})
		require.NoError(t, err)
		assert.Equal(t, uint64(7), resp.UserID)
		got := rec.take()
		require.Len(t, got, 1)
		assert.Equal(t, "/api/v1/invites/acme/tok/piv/activate", got[0].Path)
		assert.Equal(t, map[string]any{"cert_pem": "pem"}, got[0].Body)
	})
}

// TestInvites_ServerErrorReachesTheCaller proves a refused invite (expired,
// consumed) is reported, not decoded into an empty response.
func TestInvites_ServerErrorReachesTheCaller(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	ctx := context.Background()

	calls := map[string]func() error{
		"GetInvite": func() error { _, err := tr.GetInvite(ctx, &transport.GetInviteRequest{}); return err },
		"Begin": func() error {
			_, err := tr.BeginInviteRegistration(ctx, &transport.BeginInviteRegistrationRequest{})
			return err
		},
		"Finish": func() error {
			_, err := tr.FinishInviteRegistration(ctx, &transport.FinishInviteRegistrationRequest{})
			return err
		},
		"ActivatePIV": func() error { _, err := tr.ActivateInvitePIV(ctx, &transport.ActivateInvitePIVRequest{}); return err },
		"IssueLAK": func() error {
			_, err := tr.IssueLAKCertificate(ctx, &transport.IssueLAKCertificateRequest{})
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			err := call()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "internal failure")
		})
	}
}

// TestIssueLAKCertificate_SendsTheEvidence pins the LAK issuance body: the
// TPM identity and TPM2_Certify evidence are always sent, the tenant only
// when set.
func TestIssueLAKCertificate_SendsTheEvidence(t *testing.T) {
	ctx := context.Background()
	req := &transport.IssueLAKCertificateRequest{
		TPMManufacturer:    "id:49465800",
		TPMModel:           "SLB9670",
		TPMFirmwareVersion: "7.85",
		IAKCertificateDER:  []byte{0x30},
		CertifyInfo:        []byte{0x01},
		Signature:          []byte{0x02},
		SignatureAlgorithm: 10,
		LAKPublicArea:      []byte{0x03},
		Nonce:              []byte{0x04},
	}

	tr, rec := newWireTransport(t, http.StatusOK, `{"serial_number":"0a"}`)
	resp, err := tr.IssueLAKCertificate(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, "0a", resp.SerialNumber)

	got := rec.take()
	require.Len(t, got, 1)
	assert.Equal(t, http.MethodPost, got[0].Method)
	assert.Equal(t, "/api/v1/ca/tcg/lak", got[0].Path)
	assert.Equal(t, "SLB9670", got[0].Body["tpm_model"])
	assert.Equal(t, float64(10), got[0].Body["signature_algorithm"])
	assert.NotContains(t, got[0].Body, "tenant_id")

	req.TenantID = "acme"
	_, err = tr.IssueLAKCertificate(ctx, req)
	require.NoError(t, err)
	got = rec.take()
	require.Len(t, got, 1)
	assert.Equal(t, "acme", got[0].Body["tenant_id"])
}

// TestCryptoOps_SendOptionalFieldsOnlyWhenSet pins the optional body fields
// of Sign, Verify, Encrypt and Decrypt: each is sent under its wire name
// when set and omitted otherwise, so the server applies its own default.
func TestCryptoOps_SendOptionalFieldsOnlyWhenSet(t *testing.T) {
	ctx := context.Background()
	tr, rec := newWireTransport(t, http.StatusOK, `{}`)

	tests := []struct {
		name     string
		call     func() error
		bare     func() error
		optional []string
	}{
		{
			name: "Sign",
			call: func() error {
				_, err := tr.Sign(ctx, &transport.SignRequest{KeyID: "k", Data: []byte("d"), Hash: "SHA-256", Padding: "pss", SaltLength: 32, DataIsDigest: true})
				return err
			},
			bare: func() error {
				_, err := tr.Sign(ctx, &transport.SignRequest{KeyID: "k", Data: []byte("d")})
				return err
			},
			optional: []string{"hash", "padding", "salt_length", "data_is_digest"},
		},
		{
			name: "Verify",
			call: func() error {
				_, err := tr.Verify(ctx, &transport.VerifyRequest{KeyID: "k", Data: []byte("d"), Signature: []byte("s"), Hash: "SHA-256", Padding: "pss", SaltLength: 32, DataIsDigest: true, KeyVersion: 2})
				return err
			},
			bare: func() error {
				_, err := tr.Verify(ctx, &transport.VerifyRequest{KeyID: "k", Data: []byte("d"), Signature: []byte("s")})
				return err
			},
			optional: []string{"hash", "padding", "salt_length", "data_is_digest", "key_version"},
		},
		{
			name: "Encrypt",
			call: func() error {
				_, err := tr.Encrypt(ctx, &transport.EncryptRequest{KeyID: "k", Plaintext: []byte("p"), AdditionalData: []byte("a"), Nonce: []byte("n"), Mode: "cbc", IV: []byte("iv"), TagSize: 12})
				return err
			},
			bare: func() error {
				_, err := tr.Encrypt(ctx, &transport.EncryptRequest{KeyID: "k", Plaintext: []byte("p")})
				return err
			},
			optional: []string{"additional_data", "nonce", "mode", "iv", "tag_size"},
		},
		{
			name: "Decrypt",
			call: func() error {
				_, err := tr.Decrypt(ctx, &transport.DecryptRequest{
					KeyID: "k", Ciphertext: []byte("c"), Nonce: []byte("n"), Tag: []byte("t"), AdditionalData: []byte("a"),
					Mode: "gcm", IV: []byte("iv"), TagSize: 12, GCMNonceMode: "random", Padding: "oaep", Hash: "SHA-256",
					Label: []byte("l"), KeyVersion: 2,
				})
				return err
			},
			bare: func() error {
				_, err := tr.Decrypt(ctx, &transport.DecryptRequest{KeyID: "k", Ciphertext: []byte("c")})
				return err
			},
			optional: []string{
				"nonce", "tag", "additional_data", "mode", "iv", "tag_size", "gcm_nonce_mode",
				"padding", "hash", "label", "key_version",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, tt.call())
			full := rec.take()
			require.Len(t, full, 1)
			require.NoError(t, tt.bare())
			bare := rec.take()
			require.Len(t, bare, 1)
			for _, field := range tt.optional {
				assert.Contains(t, full[0].Body, field)
				assert.NotContains(t, bare[0].Body, field)
			}
		})
	}
}

// TestDoHeadRequest_SendsAuthAndHeaders proves a HEAD probe carries the
// configured bearer token and custom headers and maps a non-200 to false.
func TestDoHeadRequest_SendsAuthAndHeaders(t *testing.T) {
	tr, rec := newWireTransport(t, http.StatusNotFound, "")
	tr.config.JWTToken = "jwt-1"
	tr.config.Headers = map[string]string{"X-Tenant": "acme"}

	ok, err := tr.DoHeadRequest(context.Background(), "/api/v1/certs/k/exists")
	require.NoError(t, err)
	assert.False(t, ok)

	got := rec.take()
	require.Len(t, got, 1)
	assert.Equal(t, http.MethodHead, got[0].Method)
	assert.Equal(t, "Bearer jwt-1", got[0].Header.Get("Authorization"))
	assert.Equal(t, "acme", got[0].Header.Get("X-Tenant"))
}

// TestDoHeadRequest_RequestFailures covers an unbuildable URL and an
// unreachable server: both are errors, never a silent false.
func TestDoHeadRequest_RequestFailures(t *testing.T) {
	tr, _ := newWireTransport(t, http.StatusOK, "")

	tr.baseURL = "https://bad host\x7f"
	_, err := tr.DoHeadRequest(context.Background(), "/x")
	assert.ErrorContains(t, err, "failed to create request")

	tr.baseURL = closedServerURL(t)
	_, err = tr.DoHeadRequest(context.Background(), "/x")
	assert.ErrorContains(t, err, "request failed")
}

// TestHealthy_RequestFailures proves Healthy reports false, rather than
// panicking or hanging, when the request cannot be built or sent.
func TestHealthy_RequestFailures(t *testing.T) {
	tr, _ := newWireTransport(t, http.StatusOK, "")

	tr.baseURL = "https://bad host\x7f"
	assert.False(t, tr.Healthy(context.Background()))

	tr.baseURL = closedServerURL(t)
	assert.False(t, tr.Healthy(context.Background()))
}

// closedServerURL returns the URL of a loopback TLS server that has already
// been shut down, so a request to it fails immediately.
func closedServerURL(t *testing.T) string {
	t.Helper()
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	u := srv.URL
	srv.Close()
	return u
}
