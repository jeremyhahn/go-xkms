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

package xkms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/testutil/appraisaltest"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// mockCryptoClient implements the subset of Client used by XKMSSigner and
// XKMSDecrypter. It embeds mockXKMSService (which already satisfies the full
// embedded.XKMSServicer interface) and overrides the transport.Client methods
// that are actually called.
type mockCryptoClient struct {
	getKeyFn  func(ctx context.Context, backend, keyID string) (*transport.GetKeyResponse, error)
	signFn    func(ctx context.Context, req *transport.SignRequest) (*transport.SignResponse, error)
	decryptFn func(ctx context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error)

	// Embed a nil-safe base that satisfies the rest of the interface.
	*noopClient
}

func (m *mockCryptoClient) GetKey(ctx context.Context, backend, keyID string) (*transport.GetKeyResponse, error) {
	if m.getKeyFn != nil {
		return m.getKeyFn(ctx, backend, keyID)
	}
	return nil, errors.New("GetKey not implemented")
}

func (m *mockCryptoClient) Sign(ctx context.Context, req *transport.SignRequest) (*transport.SignResponse, error) {
	if m.signFn != nil {
		return m.signFn(ctx, req)
	}
	return nil, errors.New("Sign not implemented")
}

func (m *mockCryptoClient) Decrypt(ctx context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error) {
	if m.decryptFn != nil {
		return m.decryptFn(ctx, req)
	}
	return nil, errors.New("Decrypt not implemented")
}

// generateTestPublicKeyPEM creates an ECDSA P-256 key pair and returns the
// public key in PEM-encoded PKIX format.
func generateTestPublicKeyPEM(t *testing.T) (string, *ecdsa.PrivateKey) {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	return string(pemBytes), privKey
}

// --- Error type tests ---

func TestErrSignerKeyFetch_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("network timeout")
	err := &ErrSignerKeyFetch{KeyID: "k1", Backend: "software", Err: inner}

	msg := err.Error()
	if msg != "xkms signer: failed to fetch key k1 from backend software: network timeout" {
		t.Errorf("unexpected error message: %s", msg)
	}
	if err.Unwrap() != inner {
		t.Error("Unwrap() did not return the inner error")
	}
}

func TestErrSignerParsePEM_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("bad pem")
	err := &ErrSignerParsePEM{KeyID: "k2", Err: inner}

	msg := err.Error()
	if msg != "xkms signer: failed to parse public key PEM for key k2: bad pem" {
		t.Errorf("unexpected error message: %s", msg)
	}
	if err.Unwrap() != inner {
		t.Error("Unwrap() did not return the inner error")
	}
}

func TestErrSignerSign_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("sign failed")
	err := &ErrSignerSign{KeyID: "k3", Err: inner}

	msg := err.Error()
	if msg != "xkms signer: signing failed for key k3: sign failed" {
		t.Errorf("unexpected error message: %s", msg)
	}
	if err.Unwrap() != inner {
		t.Error("Unwrap() did not return the inner error")
	}
}

func TestErrDecrypterKeyFetch_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("dns error")
	err := &ErrDecrypterKeyFetch{KeyID: "k4", Backend: "tpm2", Err: inner}

	msg := err.Error()
	if msg != "xkms decrypter: failed to fetch key k4 from backend tpm2: dns error" {
		t.Errorf("unexpected error message: %s", msg)
	}
	if err.Unwrap() != inner {
		t.Error("Unwrap() did not return the inner error")
	}
}

func TestErrDecrypterParsePEM_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("malformed")
	err := &ErrDecrypterParsePEM{KeyID: "k5", Err: inner}

	msg := err.Error()
	if msg != "xkms decrypter: failed to parse public key PEM for key k5: malformed" {
		t.Errorf("unexpected error message: %s", msg)
	}
	if err.Unwrap() != inner {
		t.Error("Unwrap() did not return the inner error")
	}
}

func TestErrDecrypterDecrypt_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("padding error")
	err := &ErrDecrypterDecrypt{KeyID: "k6", Err: inner}

	msg := err.Error()
	if msg != "xkms decrypter: decryption failed for key k6: padding error" {
		t.Errorf("unexpected error message: %s", msg)
	}
	if err.Unwrap() != inner {
		t.Error("Unwrap() did not return the inner error")
	}
}

// --- XKMSSigner tests ---

func TestNewXKMSSigner_Success(t *testing.T) {
	pubPEM, _ := generateTestPublicKeyPEM(t)

	client := &mockCryptoClient{
		getKeyFn: func(_ context.Context, backend, keyID string) (*transport.GetKeyResponse, error) {
			return &transport.GetKeyResponse{PublicKeyPEM: pubPEM}, nil
		},
	}

	signer, err := NewXKMSSigner(client, "software", "test-key")
	if err != nil {
		t.Fatalf("NewXKMSSigner() error: %v", err)
	}
	if signer == nil {
		t.Fatal("NewXKMSSigner() returned nil")
	}
	if signer.Public() == nil {
		t.Fatal("Public() returned nil")
	}
}

func TestNewXKMSSigner_GetKeyError(t *testing.T) {
	client := &mockCryptoClient{
		getKeyFn: func(_ context.Context, backend, keyID string) (*transport.GetKeyResponse, error) {
			return nil, errors.New("backend unavailable")
		},
	}

	_, err := NewXKMSSigner(client, "software", "test-key")
	if err == nil {
		t.Fatal("expected error when GetKey fails")
	}

	var fetchErr *ErrSignerKeyFetch
	if !errors.As(err, &fetchErr) {
		t.Errorf("expected ErrSignerKeyFetch, got %T: %v", err, err)
	}
}

func TestXKMSSigner_Sign_Success(t *testing.T) {
	pubPEM, _ := generateTestPublicKeyPEM(t)
	expectedSig := []byte("mock-signature-bytes")

	client := &mockCryptoClient{
		getKeyFn: func(_ context.Context, _, _ string) (*transport.GetKeyResponse, error) {
			return &transport.GetKeyResponse{PublicKeyPEM: pubPEM}, nil
		},
		signFn: func(_ context.Context, req *transport.SignRequest) (*transport.SignResponse, error) {
			if req.Hash != "SHA-256" {
				t.Errorf("expected hash SHA-256, got %q", req.Hash)
			}
			return &transport.SignResponse{Signature: expectedSig}, nil
		},
	}

	signer, err := NewXKMSSigner(client, "software", "test-key")
	if err != nil {
		t.Fatalf("NewXKMSSigner() error: %v", err)
	}

	digest := sha256.Sum256([]byte("test data"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}
	if string(sig) != string(expectedSig) {
		t.Errorf("signature = %v, want %v", sig, expectedSig)
	}
}

func TestXKMSSigner_Sign_NilOpts(t *testing.T) {
	pubPEM, _ := generateTestPublicKeyPEM(t)

	client := &mockCryptoClient{
		getKeyFn: func(_ context.Context, _, _ string) (*transport.GetKeyResponse, error) {
			return &transport.GetKeyResponse{PublicKeyPEM: pubPEM}, nil
		},
		signFn: func(_ context.Context, req *transport.SignRequest) (*transport.SignResponse, error) {
			if req.Hash != "" {
				t.Errorf("expected empty hash for nil opts, got %q", req.Hash)
			}
			return &transport.SignResponse{Signature: []byte("sig")}, nil
		},
	}

	signer, err := NewXKMSSigner(client, "sw", "k1")
	if err != nil {
		t.Fatalf("NewXKMSSigner() error: %v", err)
	}

	_, err = signer.Sign(rand.Reader, []byte("digest"), nil)
	if err != nil {
		t.Fatalf("Sign(nil opts) error: %v", err)
	}
}

func TestXKMSSigner_Sign_Error(t *testing.T) {
	pubPEM, _ := generateTestPublicKeyPEM(t)

	client := &mockCryptoClient{
		getKeyFn: func(_ context.Context, _, _ string) (*transport.GetKeyResponse, error) {
			return &transport.GetKeyResponse{PublicKeyPEM: pubPEM}, nil
		},
		signFn: func(_ context.Context, _ *transport.SignRequest) (*transport.SignResponse, error) {
			return nil, errors.New("server busy")
		},
	}

	signer, err := NewXKMSSigner(client, "sw", "k1")
	if err != nil {
		t.Fatalf("NewXKMSSigner() error: %v", err)
	}

	_, err = signer.Sign(rand.Reader, []byte("digest"), crypto.SHA256)
	if err == nil {
		t.Fatal("expected error from Sign")
	}

	var signErr *ErrSignerSign
	if !errors.As(err, &signErr) {
		t.Errorf("expected ErrSignerSign, got %T: %v", err, err)
	}
}

// --- XKMSDecrypter tests ---

func TestNewXKMSDecrypter_Success(t *testing.T) {
	pubPEM, _ := generateTestPublicKeyPEM(t)

	client := &mockCryptoClient{
		getKeyFn: func(_ context.Context, _, _ string) (*transport.GetKeyResponse, error) {
			return &transport.GetKeyResponse{PublicKeyPEM: pubPEM}, nil
		},
	}

	dec, err := NewXKMSDecrypter(client, "software", "rsa-key")
	if err != nil {
		t.Fatalf("NewXKMSDecrypter() error: %v", err)
	}
	if dec == nil {
		t.Fatal("NewXKMSDecrypter() returned nil")
	}
	if dec.Public() == nil {
		t.Fatal("Public() returned nil")
	}
}

func TestNewXKMSDecrypter_GetKeyError(t *testing.T) {
	client := &mockCryptoClient{
		getKeyFn: func(_ context.Context, _, _ string) (*transport.GetKeyResponse, error) {
			return nil, errors.New("not found")
		},
	}

	_, err := NewXKMSDecrypter(client, "sw", "k1")
	if err == nil {
		t.Fatal("expected error when GetKey fails")
	}

	var fetchErr *ErrDecrypterKeyFetch
	if !errors.As(err, &fetchErr) {
		t.Errorf("expected ErrDecrypterKeyFetch, got %T: %v", err, err)
	}
}

func TestXKMSDecrypter_Decrypt_Success(t *testing.T) {
	pubPEM, _ := generateTestPublicKeyPEM(t)
	expectedPlaintext := []byte("secret data")

	client := &mockCryptoClient{
		getKeyFn: func(_ context.Context, _, _ string) (*transport.GetKeyResponse, error) {
			return &transport.GetKeyResponse{PublicKeyPEM: pubPEM}, nil
		},
		decryptFn: func(_ context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error) {
			return &transport.DecryptResponse{Plaintext: expectedPlaintext}, nil
		},
	}

	dec, err := NewXKMSDecrypter(client, "sw", "rsa-key")
	if err != nil {
		t.Fatalf("NewXKMSDecrypter() error: %v", err)
	}

	plaintext, err := dec.Decrypt(rand.Reader, []byte("ciphertext"), nil)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}
	if string(plaintext) != string(expectedPlaintext) {
		t.Errorf("plaintext = %q, want %q", plaintext, expectedPlaintext)
	}
}

func TestXKMSDecrypter_Decrypt_Error(t *testing.T) {
	pubPEM, _ := generateTestPublicKeyPEM(t)

	client := &mockCryptoClient{
		getKeyFn: func(_ context.Context, _, _ string) (*transport.GetKeyResponse, error) {
			return &transport.GetKeyResponse{PublicKeyPEM: pubPEM}, nil
		},
		decryptFn: func(_ context.Context, _ *transport.DecryptRequest) (*transport.DecryptResponse, error) {
			return nil, errors.New("decryption failed on server")
		},
	}

	dec, err := NewXKMSDecrypter(client, "sw", "k1")
	if err != nil {
		t.Fatalf("NewXKMSDecrypter() error: %v", err)
	}

	_, err = dec.Decrypt(rand.Reader, []byte("ct"), nil)
	if err == nil {
		t.Fatal("expected error from Decrypt")
	}

	var decErr *ErrDecrypterDecrypt
	if !errors.As(err, &decErr) {
		t.Errorf("expected ErrDecrypterDecrypt, got %T: %v", err, err)
	}
}

// --- parsePublicKeyPEM tests ---

func TestParsePublicKeyPEM_Success(t *testing.T) {
	pubPEM, _ := generateTestPublicKeyPEM(t)

	key, err := parsePublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("parsePublicKeyPEM() error: %v", err)
	}
	if key == nil {
		t.Fatal("parsePublicKeyPEM() returned nil")
	}
}

func TestParsePublicKeyPEM_NoPEMBlock(t *testing.T) {
	_, err := parsePublicKeyPEM("not a pem block")
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}

	var parseErr *ErrSignerParsePEM
	if !errors.As(err, &parseErr) {
		t.Errorf("expected ErrSignerParsePEM, got %T: %v", err, err)
	}
}

func TestParsePublicKeyPEM_InvalidDER(t *testing.T) {
	badPEM := "-----BEGIN PUBLIC KEY-----\naW52YWxpZCBkZXIgZGF0YQ==\n-----END PUBLIC KEY-----\n"
	_, err := parsePublicKeyPEM(badPEM)
	if err == nil {
		t.Fatal("expected error for invalid DER data inside PEM")
	}
}

// --- hashToString coverage ---

func TestHashToString_AllMappings(t *testing.T) {
	tests := []struct {
		hash crypto.Hash
		want string
	}{
		{crypto.SHA256, "SHA-256"},
		{crypto.SHA384, "SHA-384"},
		{crypto.SHA512, "SHA-512"},
		{crypto.SHA1, "SHA-1"},
		{crypto.SHA512_256, "SHA-512/256"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got, ok := hashToString[tt.hash]
			if !ok {
				t.Fatalf("hash %v not found in hashToString", tt.hash)
			}
			if got != tt.want {
				t.Errorf("hashToString[%v] = %q, want %q", tt.hash, got, tt.want)
			}
		})
	}
}

func TestXKMSSigner_Sign_UnknownHash(t *testing.T) {
	pubPEM, _ := generateTestPublicKeyPEM(t)

	client := &mockCryptoClient{
		getKeyFn: func(_ context.Context, _, _ string) (*transport.GetKeyResponse, error) {
			return &transport.GetKeyResponse{PublicKeyPEM: pubPEM}, nil
		},
		signFn: func(_ context.Context, req *transport.SignRequest) (*transport.SignResponse, error) {
			// An unmapped hash should result in empty string
			if req.Hash != "" {
				t.Errorf("expected empty hash for unmapped hash, got %q", req.Hash)
			}
			return &transport.SignResponse{Signature: []byte("sig")}, nil
		},
	}

	signer, err := NewXKMSSigner(client, "sw", "k1")
	if err != nil {
		t.Fatalf("NewXKMSSigner() error: %v", err)
	}

	// crypto.Hash(0) is not mapped
	_, err = signer.Sign(rand.Reader, []byte("digest"), crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}
}

// noopClient provides a minimal no-op implementation of transport.Client
// to satisfy the interface for embedding in mockCryptoClient.
type noopClient struct {
	// Unserved serves the attestation Verifier API, which these tests do
	// not exercise.
	appraisaltest.Unserved
}

func (n *noopClient) Connect(context.Context) error { return nil }
func (n *noopClient) Close() error                  { return nil }
func (n *noopClient) Health(context.Context) (*transport.HealthResponse, error) {
	return nil, nil
}
func (n *noopClient) ListBackends(context.Context, ...transport.ListOption) (*transport.ListBackendsResponse, error) {
	return nil, nil
}
func (n *noopClient) Algorithms(context.Context) (*transport.AlgorithmsResponse, error) {
	return nil, nil
}
func (n *noopClient) GetBackend(context.Context, string) (*transport.BackendInfo, error) {
	return nil, nil
}
func (n *noopClient) GenerateKey(context.Context, *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
	return nil, nil
}
func (n *noopClient) ListKeys(context.Context, string, ...transport.ListOption) (*transport.ListKeysResponse, error) {
	return nil, nil
}
func (n *noopClient) GetKey(context.Context, string, string) (*transport.GetKeyResponse, error) {
	return nil, nil
}
func (n *noopClient) DeleteKey(context.Context, string, string) (*transport.DeleteKeyResponse, error) {
	return nil, nil
}
func (n *noopClient) ImportKey(context.Context, *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error) {
	return nil, nil
}
func (n *noopClient) ExportKey(context.Context, *transport.ExportKeyRequest) (*transport.ExportKeyResponse, error) {
	return nil, nil
}
func (n *noopClient) RotateKey(context.Context, *transport.RotateKeyRequest) (*transport.RotateKeyResponse, error) {
	return nil, nil
}

func (n *noopClient) CreateOTAImageKey(context.Context, *transport.OTAImageKeyRequest) (*transport.GenerateKeyResponse, error) {
	return nil, nil
}

func (n *noopClient) RotateOTAImageKey(context.Context, *transport.OTAImageKeyRequest) (*transport.RotateKeyResponse, error) {
	return nil, nil
}

func (n *noopClient) SignOTAImage(context.Context, *transport.OTAImageSignRequest) (*transport.SignResponse, error) {
	return nil, nil
}
func (n *noopClient) GetImportParameters(context.Context, *transport.GetImportParametersRequest) (*transport.GetImportParametersResponse, error) {
	return nil, nil
}
func (n *noopClient) CopyKey(context.Context, *transport.CopyKeyRequest) (*transport.CopyKeyResponse, error) {
	return nil, nil
}
func (n *noopClient) ExportKeyMaterial(context.Context, *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error) {
	return nil, nil
}
func (n *noopClient) WrapKey(context.Context, *transport.WrapKeyRequest) (*transport.WrapKeyResponse, error) {
	return nil, nil
}
func (n *noopClient) UnwrapKey(context.Context, *transport.UnwrapKeyRequest) (*transport.UnwrapKeyResponse, error) {
	return nil, nil
}
func (n *noopClient) WrapKeyByID(context.Context, *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	return nil, nil
}
func (n *noopClient) UnwrapKeyByID(context.Context, *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error) {
	return nil, nil
}
func (n *noopClient) Sign(context.Context, *transport.SignRequest) (*transport.SignResponse, error) {
	return nil, nil
}
func (n *noopClient) Verify(context.Context, *transport.VerifyRequest) (*transport.VerifyResponse, error) {
	return nil, nil
}
func (n *noopClient) Encrypt(context.Context, *transport.EncryptRequest) (*transport.EncryptResponse, error) {
	return nil, nil
}
func (n *noopClient) Decrypt(context.Context, *transport.DecryptRequest) (*transport.DecryptResponse, error) {
	return nil, nil
}
func (n *noopClient) EncryptAsym(context.Context, *transport.EncryptAsymRequest) (*transport.EncryptAsymResponse, error) {
	return nil, nil
}
func (n *noopClient) DeriveKey(context.Context, *transport.DeriveKeyRequest) (*transport.DeriveKeyResponse, error) {
	return nil, nil
}
func (n *noopClient) DeriveKeyECDH(context.Context, *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error) {
	return nil, nil
}
func (n *noopClient) AttestKey(context.Context, *transport.AttestKeyRequest) (*transport.AttestKeyResponse, error) {
	return nil, nil
}
func (n *noopClient) GetCertificate(context.Context, string, string) (*transport.GetCertificateResponse, error) {
	return nil, nil
}
func (n *noopClient) SaveCertificate(context.Context, *transport.SaveCertificateRequest) error {
	return nil
}
func (n *noopClient) DeleteCertificate(context.Context, string, string) error { return nil }
func (n *noopClient) CertificateExists(context.Context, string, string) (bool, error) {
	return false, nil
}
func (n *noopClient) ListCertificates(context.Context, string, ...transport.ListOption) (*transport.ListCertificatesResponse, error) {
	return nil, nil
}
func (n *noopClient) SaveCertificateChain(context.Context, *transport.SaveCertificateChainRequest) error {
	return nil
}
func (n *noopClient) GetCertificateChain(context.Context, string, string) (*transport.GetCertificateChainResponse, error) {
	return nil, nil
}
func (n *noopClient) GetTLSCertificate(context.Context, string, string) (*transport.GetTLSCertificateResponse, error) {
	return nil, nil
}
func (n *noopClient) Seal(context.Context, *transport.SealRequest) (*transport.SealResponse, error) {
	return nil, nil
}
func (n *noopClient) Unseal(context.Context, *transport.UnsealRequest) (*transport.UnsealResponse, error) {
	return nil, nil
}
func (n *noopClient) CanSeal(context.Context, string) (*transport.CanSealResponse, error) {
	return nil, nil
}
func (n *noopClient) BootstrapListenerKeys(context.Context) (*transport.BootstrapListenerKeysResponse, error) {
	return nil, nil
}
func (n *noopClient) ListPIVSlots(context.Context, *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	return nil, nil
}
func (n *noopClient) GetPIVCertificate(context.Context, *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return nil, nil
}
func (n *noopClient) StorePIVCertificate(context.Context, *transport.StorePIVCertificateRequest) error {
	return nil
}
func (n *noopClient) DeletePIVCertificate(context.Context, *transport.DeletePIVCertificateRequest) error {
	return nil
}
func (n *noopClient) GeneratePIVKey(context.Context, *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error) {
	return nil, nil
}
func (n *noopClient) ImportPIVCertificate(context.Context, *transport.StorePIVCertificateRequest) error {
	return nil
}
func (n *noopClient) ExportPIVCertificate(context.Context, *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return nil, nil
}
func (n *noopClient) GeneratePIVCSR(context.Context, *transport.GeneratePIVCSRRequest) (*transport.GeneratePIVCSRResponse, error) {
	return nil, nil
}
func (n *noopClient) BeginRegistration(context.Context, *transport.BeginRegistrationRequest) (*transport.BeginRegistrationResponse, error) {
	return nil, nil
}
func (n *noopClient) FinishRegistration(context.Context, *transport.FinishRegistrationRequest) (*transport.FinishRegistrationResponse, error) {
	return nil, nil
}
func (n *noopClient) BeginAuthentication(context.Context, *transport.BeginAuthenticationRequest) (*transport.BeginAuthenticationResponse, error) {
	return nil, nil
}
func (n *noopClient) FinishAuthentication(context.Context, *transport.FinishAuthenticationRequest) (*transport.FinishAuthenticationResponse, error) {
	return nil, nil
}
func (n *noopClient) GetInvite(context.Context, *transport.GetInviteRequest) (*transport.GetInviteResponse, error) {
	return nil, nil
}
func (n *noopClient) BeginInviteRegistration(context.Context, *transport.BeginInviteRegistrationRequest) (*transport.BeginInviteRegistrationResponse, error) {
	return nil, nil
}
func (n *noopClient) FinishInviteRegistration(context.Context, *transport.FinishInviteRegistrationRequest) (*transport.FinishInviteRegistrationResponse, error) {
	return nil, nil
}
func (n *noopClient) ActivateInvitePIV(context.Context, *transport.ActivateInvitePIVRequest) (*transport.ActivateInvitePIVResponse, error) {
	return nil, nil
}
func (n *noopClient) GetCABundle(context.Context, *transport.GetCABundleRequest) (*transport.GetCABundleResponse, error) {
	return nil, nil
}
func (n *noopClient) GetCACertificate(context.Context, *transport.GetCACertificateRequest) (*transport.GetCACertificateResponse, error) {
	return nil, nil
}
func (n *noopClient) SignCSR(context.Context, *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
	return nil, nil
}
func (n *noopClient) IssueCertificate(context.Context, *transport.IssueCertificateRequest) (*transport.IssueCertificateResponse, error) {
	return nil, nil
}
func (n *noopClient) RevokeCertificate(context.Context, *transport.RevokeCertificateRequest) (*transport.RevokeCertificateResponse, error) {
	return nil, nil
}
func (n *noopClient) GenerateCRL(context.Context, *transport.GenerateCRLRequest) (*transport.GenerateCRLResponse, error) {
	return nil, nil
}
func (n *noopClient) IsRevoked(context.Context, *transport.IsRevokedRequest) (*transport.IsRevokedResponse, error) {
	return nil, nil
}
func (n *noopClient) IssueEKCertificate(context.Context, *transport.IssueEKCertificateRequest) (*transport.IssueEKCertificateResponse, error) {
	return nil, nil
}
func (n *noopClient) IssueAKCertificate(context.Context, *transport.IssueAKCertificateRequest) (*transport.IssueAKCertificateResponse, error) {
	return nil, nil
}
func (n *noopClient) SignTCGCSR(context.Context, *transport.SignTCGCSRRequest) (*transport.SignTCGCSRResponse, error) {
	return nil, nil
}
func (n *noopClient) EnrollDevice(context.Context, *transport.EnrollDeviceRequest) (*transport.EnrollDeviceResponse, error) {
	return nil, nil
}
func (n *noopClient) IssueLAKCertificate(context.Context, *transport.IssueLAKCertificateRequest) (*transport.IssueLAKCertificateResponse, error) {
	return nil, nil
}
func (n *noopClient) SetSOPIN(context.Context, *transport.SetSOPINRequest) error       { return nil }
func (n *noopClient) SetUserPIN(context.Context, *transport.SetUserPINRequest) error   { return nil }
func (n *noopClient) ChangeSOPIN(context.Context, *transport.ChangeSOPINRequest) error { return nil }
func (n *noopClient) ChangeUserPIN(context.Context, *transport.ChangeUserPINRequest) error {
	return nil
}
func (n *noopClient) VerifySOPIN(context.Context, *transport.VerifySOPINRequest) error { return nil }
func (n *noopClient) VerifyUserPIN(context.Context, *transport.VerifyUserPINRequest) error {
	return nil
}
func (n *noopClient) GetLockoutStatus(context.Context) (*transport.LockoutStatusResponse, error) {
	return nil, nil
}
func (n *noopClient) ResetLockout(context.Context, *transport.ResetLockoutRequest) error { return nil }
func (n *noopClient) PasswordAdd(context.Context, *transport.PasswordAddRequest) (*transport.PasswordAddResponse, error) {
	return nil, nil
}
func (n *noopClient) PasswordGet(context.Context, *transport.PasswordGetRequest) (*transport.PasswordGetResponse, error) {
	return nil, nil
}
func (n *noopClient) PasswordList(context.Context, *transport.PasswordListRequest) (*transport.PasswordListResponse, error) {
	return nil, nil
}
func (n *noopClient) PasswordUpdate(context.Context, *transport.PasswordUpdateRequest) error {
	return nil
}
func (n *noopClient) PasswordDelete(context.Context, *transport.PasswordDeleteRequest) error {
	return nil
}
func (n *noopClient) PasswordStoreUnlock(context.Context, *transport.PasswordStoreUnlockRequest) error {
	return nil
}
func (n *noopClient) PasswordStoreLock(context.Context) error { return nil }
func (n *noopClient) PasswordStoreStatus(context.Context) (*transport.PasswordStoreStatusResponse, error) {
	return nil, nil
}
func (n *noopClient) PasswordStoreSetAccessMode(context.Context, *transport.PasswordStoreSetAccessModeRequest) error {
	return nil
}
func (n *noopClient) PasswordGenerate(context.Context, *transport.PasswordGenerateRequest) (*transport.PasswordGenerateResponse, error) {
	return nil, nil
}
func (n *noopClient) PasswordVaultStatus(context.Context) (*transport.PasswordVaultStatusResponse, error) {
	return nil, nil
}
func (n *noopClient) PasswordVaultEnroll(context.Context, *transport.PasswordVaultEnrollRequest) (*transport.PasswordVaultEnrollResponse, error) {
	return nil, nil
}
func (n *noopClient) PasswordVaultRotate(context.Context, *transport.PasswordVaultRotateRequest) (*transport.PasswordVaultEnrollResponse, error) {
	return nil, nil
}
func (n *noopClient) PasswordVaultRemoveFactor(context.Context, *transport.PasswordVaultRemoveFactorRequest) error {
	return nil
}
func (n *noopClient) PasswordVaultRecover(context.Context, *transport.PasswordVaultRecoverRequest) (*transport.PasswordVaultEnrollResponse, error) {
	return nil, nil
}
func (n *noopClient) SealStorePut(context.Context, *transport.SealStorePutRequest) error {
	return nil
}
func (n *noopClient) SealStoreGet(context.Context, *transport.SealStoreGetRequest) (*transport.SealStoreGetResponse, error) {
	return nil, nil
}
func (n *noopClient) SealStoreDelete(context.Context, *transport.SealStoreDeleteRequest) error {
	return nil
}
func (n *noopClient) SealStoreList(context.Context) (*transport.SealStoreListResponse, error) {
	return nil, nil
}
func (n *noopClient) SealStoreReseal(context.Context, *transport.SealStoreResealRequest) error {
	return nil
}
func (n *noopClient) SealStoreStatus(context.Context) (*transport.SealStoreStatusResponse, error) {
	return nil, nil
}
func (n *noopClient) EscrowKey(context.Context, *transport.EscrowRequest) ([]*transport.EscrowReceipt, error) {
	return nil, nil
}
func (n *noopClient) RecoverKey(context.Context, *transport.RecoverRequest) (*transport.RecoverResponse, error) {
	return nil, nil
}
func (n *noopClient) ListEscrowed(context.Context) ([]transport.EscrowRecord, error) {
	return nil, nil
}
func (n *noopClient) RevokeEscrow(context.Context, string) error {
	return nil
}
func (n *noopClient) ListKeyVersions(context.Context, *transport.ListKeyVersionsRequest) (*transport.ListKeyVersionsResponse, error) {
	return nil, nil
}

func (n *noopClient) EnableKeyVersion(context.Context, *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	return nil, nil
}

func (n *noopClient) DisableKeyVersion(context.Context, *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	return nil, nil
}

func (n *noopClient) RetireKeyVersion(context.Context, *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	return nil, nil
}

func (n *noopClient) EnableAllKeyVersions(context.Context, *transport.AllKeyVersionsRequest) (*transport.AllKeyVersionsResponse, error) {
	return nil, nil
}

func (n *noopClient) DisableAllKeyVersions(context.Context, *transport.AllKeyVersionsRequest) (*transport.AllKeyVersionsResponse, error) {
	return nil, nil
}

func (n *noopClient) RotateScopeKeys(context.Context, *transport.RotateScopeKeysRequest) (*transport.RotateScopeKeysResponse, error) {
	return nil, nil
}

func (n *noopClient) TPMPolicyCreate(context.Context, *transport.TPMPolicyCreateRequest) (*transport.TPMPolicy, error) {
	return nil, nil
}

func (n *noopClient) TPMPolicyGet(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	return nil, nil
}

func (n *noopClient) TPMPolicyList(context.Context, *transport.TPMPolicyListRequest) (*transport.TPMPolicyListResponse, error) {
	return nil, nil
}

func (n *noopClient) TPMPolicyUpdate(context.Context, *transport.TPMPolicyUpdateRequest) (*transport.TPMPolicy, error) {
	return nil, nil
}

func (n *noopClient) TPMPolicyRevoke(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	return nil, nil
}

func (n *noopClient) TPMPolicyVerify(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicyVerifyResponse, error) {
	return nil, nil
}

func (n *noopClient) TPMPolicyDelete(context.Context, *transport.TPMPolicyDeleteRequest) error {
	return nil
}

func (n *noopClient) TPMPolicyObjects(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicyObjectsResponse, error) {
	return nil, nil
}

func (n *noopClient) TPMPolicySetAutoUnseal(context.Context, *transport.TPMPolicyAutoUnsealRequest) (*transport.TPMPolicy, error) {
	return nil, nil
}

func (n *noopClient) TPMPolicySetDescription(context.Context, *transport.TPMPolicyDescriptionRequest) (*transport.TPMPolicy, error) {
	return nil, nil
}

// OIDC credential operations are not exercised by this double.
func (*noopClient) OIDCCredentialCreate(context.Context, *transport.OIDCCredentialCreateRequest) (*transport.OIDCCredential, error) {
	return nil, nil
}
func (*noopClient) OIDCCredentialImport(context.Context, *transport.OIDCCredentialImportRequest) (*transport.OIDCCredential, error) {
	return nil, nil
}
func (*noopClient) OIDCCredentialGet(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return nil, nil
}
func (*noopClient) OIDCCredentialList(context.Context, *transport.OIDCCredentialListRequest) (*transport.OIDCCredentialListResponse, error) {
	return nil, nil
}
func (*noopClient) TrustRootList(context.Context, *transport.TrustRootListRequest) (*transport.TrustRootListResponse, error) {
	return nil, nil
}
func (*noopClient) TrustRootGet(context.Context, *transport.TrustRootRequest) (*transport.TrustRoot, error) {
	return nil, nil
}
func (*noopClient) TrustRootImport(context.Context, *transport.TrustRootImportRequest) (*transport.TrustRootImportResponse, error) {
	return nil, nil
}
func (*noopClient) TrustRootQuarantine(context.Context, *transport.TrustRootRequest) (*transport.TrustRoot, error) {
	return nil, nil
}
func (*noopClient) TrustRootRemove(context.Context, *transport.TrustRootRequest) error {
	return nil
}
func (*noopClient) OIDCCredentialDelete(context.Context, *transport.OIDCCredentialRef) error {
	return nil
}
func (*noopClient) OIDCCredentialRefresh(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return nil, nil
}
func (*noopClient) OIDCCredentialGetAccessToken(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCAccessToken, error) {
	return nil, nil
}
func (*noopClient) OIDCCredentialDeviceStart(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return nil, nil
}
func (*noopClient) OIDCCredentialDevicePoll(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return nil, nil
}

func (n *noopClient) TPMObjectPolicy(context.Context, *transport.TPMObjectPolicyRequest) (*transport.TPMObjectPolicyResponse, error) {
	return nil, nil
}

func (n *noopClient) TPMPolicyRotateAuthority(context.Context, *transport.TPMAuthorityRotateRequest) (*transport.TPMAuthorityRotateResponse, error) {
	return nil, nil
}

func (n *noopClient) GetTenantTPMMode(context.Context, string) (*transport.TenantTPMModeResponse, error) {
	return nil, nil
}

func (n *noopClient) SetTenantTPMMode(context.Context, *transport.SetTenantTPMModeRequest) (*transport.TenantTPMModeResponse, error) {
	return nil, nil
}

func (n *noopClient) TenantVTPMStatus(context.Context, string) (*transport.TenantVTPMStatusResponse, error) {
	return nil, nil
}

func (n *noopClient) TenantVTPMStart(context.Context, string) (*transport.TenantVTPMStatusResponse, error) {
	return nil, nil
}

func (n *noopClient) TenantVTPMStop(context.Context, string) (*transport.TenantVTPMStatusResponse, error) {
	return nil, nil
}

func (n *noopClient) CreateTenant(context.Context, *transport.CreateTenantRequest) (*transport.CreateTenantResponse, error) {
	return nil, nil
}
func (n *noopClient) GetTenant(context.Context, string) (*transport.GetTenantResponse, error) {
	return nil, nil
}
func (n *noopClient) ListTenants(context.Context) (*transport.ListTenantsResponse, error) {
	return nil, nil
}
func (n *noopClient) DeleteTenant(context.Context, string) error { return nil }
func (n *noopClient) UpdateTenantEntitlements(_ context.Context, _ *transport.UpdateTenantEntitlementsRequest) (*transport.UpdateTenantEntitlementsResponse, error) {
	return nil, nil
}
func (n *noopClient) UpdateTenantQuotas(_ context.Context, _ *transport.UpdateTenantQuotasRequest) (*transport.UpdateTenantQuotasResponse, error) {
	return nil, nil
}
func (n *noopClient) SubmitCredential(context.Context, *transport.CredentialSubmitRequest) (*transport.CredentialSubmitResponse, error) {
	return nil, nil
}
func (n *noopClient) GetCredentialStrategy(context.Context) (*transport.CredentialStrategyResponse, error) {
	return nil, nil
}

func (n *noopClient) CreateUser(context.Context, *transport.CreateUserRequest) (*transport.GetUserResponse, error) {
	return nil, nil
}

func (n *noopClient) ListUsers(context.Context, ...transport.ListOption) (*transport.ListUsersResponse, error) {
	return nil, nil
}

func (n *noopClient) GetUser(context.Context, string) (*transport.GetUserResponse, error) {
	return nil, nil
}

func (n *noopClient) DeleteUser(context.Context, string) error {
	return nil
}

func (n *noopClient) EnableUser(context.Context, string) error {
	return nil
}

func (n *noopClient) DisableUser(context.Context, string) error {
	return nil
}

func (n *noopClient) BindUserCert(context.Context, string, string, int64) error {
	return nil
}

func (n *noopClient) ListUserCredentials(context.Context, string) (*transport.ListUserCredentialsResponse, error) {
	return nil, nil
}

// ----------------------------------------------------------------------------
// SecureMemZero
//
// pkg/crypto/mem was retired (go-xkms#623): SecureMemZero is now a
// re-export of enclave.Wipe rather than the deleted mem.Zero. These tests
// exercise the re-export from the SDK's own package, since a consumer only
// ever calls it as xkms.SecureMemZero.
// ----------------------------------------------------------------------------

func TestSecureMemZero_Success(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0xFF, 0xAB}
	SecureMemZero(data)
	for i, b := range data {
		if b != 0 {
			t.Fatalf("byte at index %d not cleared: %#x", i, b)
		}
	}
}

func TestSecureMemZero_NilSlice(t *testing.T) {
	// SecureMemZero must not panic on a nil slice -- callers defer it
	// unconditionally, including on error paths where the source was
	// never allocated.
	var data []byte
	SecureMemZero(data)
	if data != nil {
		t.Fatalf("expected nil slice to remain nil, got %v", data)
	}
}

func (*noopClient) SetSigningKeyBinding(context.Context, *transport.SetSigningKeyBindingRequest) (*transport.SigningKeyBinding, error) {
	return nil, nil
}
func (*noopClient) GetSigningKeyBinding(context.Context, *transport.GetSigningKeyBindingRequest) (*transport.SigningKeyBinding, error) {
	return nil, nil
}
func (*noopClient) ListSigningKeyBindings(context.Context) (*transport.ListSigningKeyBindingsResponse, error) {
	return nil, nil
}
func (*noopClient) DeleteSigningKeyBinding(context.Context, *transport.DeleteSigningKeyBindingRequest) error {
	return nil
}
func (*noopClient) ResolveSigningKey(context.Context, *transport.ResolveSigningKeyRequest) (*transport.SigningKeyResolution, error) {
	return nil, nil
}
func (*noopClient) SignCoRIM(context.Context, *transport.SignCoRIMRequest) (*transport.SignedCoRIM, error) {
	return nil, nil
}

func (*noopClient) SignImage(context.Context, *transport.SignImageRequest) (*transport.SignedImage, error) {
	return nil, nil
}
