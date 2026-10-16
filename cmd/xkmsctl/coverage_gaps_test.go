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

// coverage_gaps_test.go closes the remaining coverage gaps in cmd/xkmsctl
// that were not covered by the original test files. All tests run fully
// in-process without network or host filesystem mutations (t.TempDir only).
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	trustresolver "github.com/jeremyhahn/go-xkms/pkg/trust/resolver"
	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/spf13/cobra"
)

// =============================================================================
// auth_factor_handlers.go — typed error methods (all at 0%)
// =============================================================================

// TestAuthFactorErrorMessages exercises every Error() and Unwrap() method on
// the typed errors defined in auth_factor_handlers.go. These were all at 0%
// because they are never triggered via the mock-backed command tests.
func TestAuthFactorErrorMessages(t *testing.T) {
	inner := errors.New("inner-cause")

	cases := []struct {
		name     string
		err      error
		contains string
	}{
		{
			"MissingFactorIDError",
			&MissingFactorIDError{Op: "auth factor remove"},
			"factor id is required",
		},
		{
			"MissingLabelError",
			&MissingLabelError{Op: "auth factor relabel"},
			"--label is required",
		},
		{
			"MissingUserError",
			&MissingUserError{Op: "auth factor list"},
			"--user is required",
		},
		{
			"InvalidUserIDError",
			&InvalidUserIDError{Value: "abc", Cause: inner},
			"abc",
		},
		{
			"InvalidFactorTypeError",
			&InvalidFactorTypeError{Type: "smartcard"},
			"smartcard",
		},
		{
			"InvalidAuthMethodError",
			&InvalidAuthMethodError{Method: "bluetooth"},
			"bluetooth",
		},
		{
			"MissingCertPathError",
			&MissingCertPathError{},
			"--cert",
		},
		{
			"MissingCredentialError",
			&MissingCredentialError{Type: "fido2"},
			"fido2",
		},
		{
			"CertReadError with path",
			&CertReadError{Path: "/etc/cert.pem", Cause: inner},
			"/etc/cert.pem",
		},
		{
			"CertReadError without path",
			&CertReadError{Cause: inner},
			"cert read error",
		},
		{
			"InvalidCredentialHexError",
			&InvalidCredentialHexError{Cause: inner},
			"inner-cause",
		},
		{
			"AuthFactorMissingClientError",
			&AuthFactorMissingClientError{},
			"qrdb SDK",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := tc.err.Error()
			if !strings.Contains(msg, tc.contains) {
				t.Errorf("Error() = %q, want substring %q", msg, tc.contains)
			}
		})
	}
}

// TestAuthFactorErrorUnwrap validates the Unwrap chains on the error types
// that embed a Cause field.
func TestAuthFactorErrorUnwrap(t *testing.T) {
	inner := errors.New("wrapped")

	t.Run("InvalidUserIDError.Unwrap", func(t *testing.T) {
		e := &InvalidUserIDError{Value: "x", Cause: inner}
		if !errors.Is(e, inner) {
			t.Error("expected errors.Is to traverse Unwrap")
		}
	})
	t.Run("CertReadError.Unwrap", func(t *testing.T) {
		e := &CertReadError{Path: "/p", Cause: inner}
		if !errors.Is(e, inner) {
			t.Error("expected errors.Is to traverse Unwrap")
		}
	})
	t.Run("InvalidCredentialHexError.Unwrap", func(t *testing.T) {
		e := &InvalidCredentialHexError{Cause: inner}
		if !errors.Is(e, inner) {
			t.Error("expected errors.Is to traverse Unwrap")
		}
	})
}

// =============================================================================
// auth_factor_handlers.go — xkmsLoadCertCredentialAndMetadata (0%)
// =============================================================================

// TestXkmsLoadCertCredentialAndMetadata_Success validates the happy path:
// a DER-encoded self-signed certificate is read from a PEM file and the
// SPKI thumbprint plus metadata map are returned.
func TestXkmsLoadCertCredentialAndMetadata_Success(t *testing.T) {
	certPEM := makeSelfSignedCert(t, "test-cn")
	p := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(p, certPEM, 0600); err != nil {
		t.Fatal(err)
	}

	key, meta, err := xkmsLoadCertCredentialAndMetadata(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(key) == 0 {
		t.Error("expected non-empty lookup key")
	}
	if meta["cert_cn"] != "test-cn" {
		t.Errorf("cert_cn = %q, want test-cn", meta["cert_cn"])
	}
	for _, field := range []string{"cert_serial", "cert_not_after", "cert_not_before", "cert_spki_thumbprint"} {
		if meta[field] == "" {
			t.Errorf("metadata field %q is empty", field)
		}
	}
}

// TestXkmsLoadCertCredentialAndMetadata_Missing exercises the
// os.ReadFile error path.
func TestXkmsLoadCertCredentialAndMetadata_Missing(t *testing.T) {
	_, _, err := xkmsLoadCertCredentialAndMetadata("/nonexistent/file.pem")
	var ce *CertReadError
	if !errors.As(err, &ce) {
		t.Fatalf("want *CertReadError, got %T: %v", err, err)
	}
}

// TestXkmsLoadCertCredentialAndMetadata_NoPEMBlock exercises the
// pem.Decode failure path.
func TestXkmsLoadCertCredentialAndMetadata_NoPEMBlock(t *testing.T) {
	p := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(p, []byte("not-pem-data"), 0600); err != nil {
		t.Fatal(err)
	}

	_, _, err := xkmsLoadCertCredentialAndMetadata(p)
	var ce *CertReadError
	if !errors.As(err, &ce) {
		t.Fatalf("want *CertReadError (no PEM block), got %T: %v", err, err)
	}
}

// =============================================================================
// auth_factor_handlers.go — buildXKMSAddRequest uncovered branches (60%)
// =============================================================================

// TestBuildXKMSAddRequest_PivType tests PIV credential and metadata assembly.
func TestBuildXKMSAddRequest_PivType(t *testing.T) {
	f := &authFactorAddFlags{
		factorType:    "piv",
		label:         "piv-slot-9a",
		user:          "",
		credentialHex: "deadbeef",
		pivReader:     "Yubico YubiKey",
		pivSlot:       "9a",
	}

	req, err := buildXKMSAddRequest(0, f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Type != "piv" {
		t.Errorf("Type = %q, want piv", req.Type)
	}
	if req.Metadata["reader"] != "Yubico YubiKey" {
		t.Errorf("reader metadata = %q, want Yubico YubiKey", req.Metadata["reader"])
	}
	if req.Metadata["slot"] != "9a" {
		t.Errorf("slot metadata = %q, want 9a", req.Metadata["slot"])
	}
}

// TestBuildXKMSAddRequest_Pkcs11Type tests PKCS#11 credential and metadata assembly.
func TestBuildXKMSAddRequest_Pkcs11Type(t *testing.T) {
	f := &authFactorAddFlags{
		factorType:    "pkcs11",
		label:         "token-key",
		credentialHex: "cafebabe",
		pkcs11Slot:    "0",
		pkcs11Label:   "my-key",
	}

	req, err := buildXKMSAddRequest(5, f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Metadata["slot"] != "0" {
		t.Errorf("slot metadata = %q, want 0", req.Metadata["slot"])
	}
	if req.Metadata["label"] != "my-key" {
		t.Errorf("label metadata = %q, want my-key", req.Metadata["label"])
	}
}

// TestBuildXKMSAddRequest_MissingType tests the empty type error.
func TestBuildXKMSAddRequest_MissingType(t *testing.T) {
	f := &authFactorAddFlags{label: "lbl", credentialHex: "00"}
	_, err := buildXKMSAddRequest(0, f)
	var ift *InvalidFactorTypeError
	if !errors.As(err, &ift) {
		t.Fatalf("want *InvalidFactorTypeError, got %T: %v", err, err)
	}
}

// TestBuildXKMSAddRequest_InvalidType tests an unrecognised type string.
func TestBuildXKMSAddRequest_InvalidType(t *testing.T) {
	f := &authFactorAddFlags{factorType: "bluetooth", label: "lbl", credentialHex: "00"}
	_, err := buildXKMSAddRequest(0, f)
	var ift *InvalidFactorTypeError
	if !errors.As(err, &ift) {
		t.Fatalf("want *InvalidFactorTypeError, got %T: %v", err, err)
	}
}

// TestBuildXKMSAddRequest_MissingLabel exercises the missing-label path.
func TestBuildXKMSAddRequest_MissingLabel(t *testing.T) {
	f := &authFactorAddFlags{factorType: "fido2", credentialHex: "00"}
	_, err := buildXKMSAddRequest(0, f)
	var mle *MissingLabelError
	if !errors.As(err, &mle) {
		t.Fatalf("want *MissingLabelError, got %T: %v", err, err)
	}
}

// TestBuildXKMSAddRequest_MtlsMissingCert tests --type mtls with no --cert.
func TestBuildXKMSAddRequest_MtlsMissingCert(t *testing.T) {
	f := &authFactorAddFlags{factorType: "mtls", label: "admin-cert"}
	_, err := buildXKMSAddRequest(0, f)
	var mcp *MissingCertPathError
	if !errors.As(err, &mcp) {
		t.Fatalf("want *MissingCertPathError, got %T: %v", err, err)
	}
}

// TestBuildXKMSAddRequest_InvalidHex tests hex decode failure paths.
func TestBuildXKMSAddRequest_InvalidHex(t *testing.T) {
	for _, ft := range []string{"fido2", "piv", "pkcs11"} {
		t.Run(ft, func(t *testing.T) {
			f := &authFactorAddFlags{factorType: ft, label: "lbl", credentialHex: "not-hex!"}
			_, err := buildXKMSAddRequest(0, f)
			var ihe *InvalidCredentialHexError
			if !errors.As(err, &ihe) {
				t.Fatalf("want *InvalidCredentialHexError for %s, got %T: %v", ft, err, err)
			}
		})
	}
}

// TestBuildXKMSAddRequest_MissingCredential tests missing --credential-hex paths.
func TestBuildXKMSAddRequest_MissingCredential(t *testing.T) {
	for _, ft := range []string{"fido2", "piv", "pkcs11"} {
		t.Run(ft, func(t *testing.T) {
			f := &authFactorAddFlags{factorType: ft, label: "lbl"}
			_, err := buildXKMSAddRequest(0, f)
			var mce *MissingCredentialError
			if !errors.As(err, &mce) {
				t.Fatalf("want *MissingCredentialError for %s, got %T: %v", ft, err, err)
			}
		})
	}
}

// =============================================================================
// auth_factor_handlers.go — buildXKMSLoginLookupKey uncovered branches (41%)
// =============================================================================

// TestBuildXKMSLoginLookupKey_Fido2 exercises the fido2 credential hex path.
func TestBuildXKMSLoginLookupKey_Fido2(t *testing.T) {
	key, err := buildXKMSLoginLookupKey("fido2", "", "deadbeef")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(key) == 0 {
		t.Error("expected non-empty lookup key")
	}
}

// TestBuildXKMSLoginLookupKey_Pkcs11 exercises the pkcs11 path.
func TestBuildXKMSLoginLookupKey_Pkcs11(t *testing.T) {
	key, err := buildXKMSLoginLookupKey("pkcs11", "", "cafebabe")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(key) == 0 {
		t.Error("expected non-empty lookup key")
	}
}

// TestBuildXKMSLoginLookupKey_MissingMtlsCert exercises --type mtls with no cert path.
func TestBuildXKMSLoginLookupKey_MissingMtlsCert(t *testing.T) {
	_, err := buildXKMSLoginLookupKey("mtls", "", "")
	var mcp *MissingCertPathError
	if !errors.As(err, &mcp) {
		t.Fatalf("want *MissingCertPathError, got %T: %v", err, err)
	}
}

// TestBuildXKMSLoginLookupKey_InvalidHex exercises hex decode failure.
func TestBuildXKMSLoginLookupKey_InvalidHex(t *testing.T) {
	_, err := buildXKMSLoginLookupKey("fido2", "", "not-hex!")
	var ihe *InvalidCredentialHexError
	if !errors.As(err, &ihe) {
		t.Fatalf("want *InvalidCredentialHexError, got %T: %v", err, err)
	}
}

// TestBuildXKMSLoginLookupKey_InvalidMethod exercises the unreachable
// default branch (method already validated at call-site in production
// but the switch default is still a reachable statement).
func TestBuildXKMSLoginLookupKey_InvalidMethod(t *testing.T) {
	_, err := buildXKMSLoginLookupKey("unknown-method", "", "")
	var iam *InvalidAuthMethodError
	if !errors.As(err, &iam) {
		t.Fatalf("want *InvalidAuthMethodError, got %T: %v", err, err)
	}
}

// =============================================================================
// auth_factor_handlers.go — xkmsCredentialAndMetadata coverage with mtls cert
// =============================================================================

// TestXkmsCredentialAndMetadata_MtlsWithCert exercises the full mtls path
// by providing a temporary valid PEM certificate.
func TestXkmsCredentialAndMetadata_MtlsWithCert(t *testing.T) {
	certPEM := makeSelfSignedCert(t, "mtls-user")
	p := filepath.Join(t.TempDir(), "client.pem")
	if err := os.WriteFile(p, certPEM, 0600); err != nil {
		t.Fatal(err)
	}

	f := &authFactorAddFlags{
		factorType: "mtls",
		certPath:   p,
	}

	cred, meta, err := xkmsCredentialAndMetadata(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cred) == 0 {
		t.Error("expected non-empty credential bytes")
	}
	if meta["cert_cn"] != "mtls-user" {
		t.Errorf("cert_cn = %q, want mtls-user", meta["cert_cn"])
	}
}

// TestXkmsCredentialAndMetadata_Fido2WithDevice exercises the device metadata branch.
func TestXkmsCredentialAndMetadata_Fido2WithDevice(t *testing.T) {
	f := &authFactorAddFlags{
		factorType:    "fido2",
		credentialHex: "deadbeef",
		fido2Device:   "yubikey-5c",
	}

	cred, meta, err := xkmsCredentialAndMetadata(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cred) == 0 {
		t.Error("expected non-empty credential bytes")
	}
	if meta["device_id"] != "yubikey-5c" {
		t.Errorf("device_id = %q, want yubikey-5c", meta["device_id"])
	}
}

// =============================================================================
// auth_factor_handlers.go — runXKMSAuthFactorRelabel error path (80%)
// =============================================================================

// TestRunXKMSAuthFactorRelabel_ClientError exercises the client-open error path.
func TestRunXKMSAuthFactorRelabel_ClientError(t *testing.T) {
	restore := SetUserAuthFactorClientFactory(func(_ context.Context) (qrdbtransport.UserAuthFactorClient, func() error, error) {
		return nil, nil, errors.New("dial failed")
	})
	defer restore()

	err := runXKMSAuthFactorRelabel(context.Background(), "factor-x", "new-label")
	if err == nil {
		t.Fatal("expected error when client factory fails")
	}
}

// =============================================================================
// auth_factor_handlers.go — runXKMSAuthLogin uncovered branch (empty method)
// =============================================================================

// TestRunXKMSAuthLogin_EmptyMethod exercises the empty-method guard.
func TestRunXKMSAuthLogin_EmptyMethod(t *testing.T) {
	err := runXKMSAuthLogin(context.Background(), "", "", "")
	var iam *InvalidAuthMethodError
	if !errors.As(err, &iam) {
		t.Fatalf("want *InvalidAuthMethodError, got %T: %v", err, err)
	}
}

// =============================================================================
// auth_factor_handlers.go — printXKMSFactorRecord revoked branch (90%)
// =============================================================================

// TestPrintXKMSFactorRecord_Revoked exercises the revoked-at printing path.
func TestPrintXKMSFactorRecord_Revoked(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	printXKMSFactorRecord(&qrdbtransport.AuthFactorRecord{
		ID:           "f-1",
		Type:         "fido2",
		UserID:       42,
		Label:        "yubikey",
		RegisteredAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		RevokedAt:    &now,
		CreatedBy:    "admin",
	})

	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()

	if !strings.Contains(out, "Revoked At:") {
		t.Errorf("expected 'Revoked At:' in output, got: %q", out)
	}
	if !strings.Contains(out, "admin") {
		t.Errorf("expected created-by in output, got: %q", out)
	}
}

// =============================================================================
// auth_factor_handlers.go — runXKMSAuthFactorList empty-result branch (75%)
// =============================================================================

// TestRunXKMSAuthFactorList_EmptyResult exercises the "no enrolled factors"
// output path.
func TestRunXKMSAuthFactorList_EmptyResult(t *testing.T) {
	_, restore := installMockFactory(t)
	defer restore()

	out, err := runAuthCmd(t, "auth", "factor", "list", "--user", "99")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "no enrolled factors") {
		t.Errorf("expected 'no enrolled factors', got: %q", out)
	}
}

// =============================================================================
// auth_factor_handlers.go — runXKMSAuthFactorList with revokedAt set (75%)
// =============================================================================

// TestRunXKMSAuthFactorList_WithRevokedFactor exercises the revoked-at
// display branch in the list output loop.
func TestRunXKMSAuthFactorList_WithRevokedFactor(t *testing.T) {
	mock, restore := installMockFactory(t)
	defer restore()

	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	mock.factors["rev-1"] = &qrdbtransport.AuthFactorRecord{
		ID:           "rev-1",
		UserID:       5,
		Type:         "mtls",
		Label:        "expired-cert",
		Credential:   []byte("c"),
		RegisteredAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		RevokedAt:    &now,
	}

	out, err := runAuthCmd(t, "auth", "factor", "list", "--user", "5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "rev-1") {
		t.Errorf("expected factor id in output, got: %q", out)
	}
}

// =============================================================================
// auth_factor_handlers.go — runXKMSAuthLogin output branches (75%)
// =============================================================================

// TestRunXKMSAuthLogin_WithEmailAndTenantAndRoles exercises the optional
// Email, TenantID, and Roles output branches in runXKMSAuthLogin.
func TestRunXKMSAuthLogin_WithEmailAndTenantAndRoles(t *testing.T) {
	mock, restore := installMockFactory(t)
	defer restore()

	// Seed a factor with enough data that LoginAuthFactor succeeds.
	mock.factors["login-full"] = &qrdbtransport.AuthFactorRecord{
		ID:           "login-full",
		UserID:       55,
		Type:         "fido2",
		Label:        "yk-full",
		Credential:   []byte{0xaa, 0xbb},
		RegisteredAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	// Override the mock LoginAuthFactor to return extra fields.
	origLogin := mock.LoginAuthFactor
	_ = origLogin // keep the reference to avoid unused import warnings

	// We can't override individual methods on the struct mock, so we use
	// a factory that wraps the original mock and augments the response.
	restore2 := SetUserAuthFactorClientFactory(func(_ context.Context) (qrdbtransport.UserAuthFactorClient, func() error, error) {
		return &loginWithExtrasMock{inner: mock}, func() error { return nil }, nil
	})
	defer restore2()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runXKMSAuthLogin(context.Background(), "fido2", "", "aabb")
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "Email:") {
		t.Errorf("expected Email in output, got: %q", out)
	}
	if !strings.Contains(out, "Tenant:") {
		t.Errorf("expected Tenant in output, got: %q", out)
	}
	if !strings.Contains(out, "Roles:") {
		t.Errorf("expected Roles in output, got: %q", out)
	}
}

// loginWithExtrasMock wraps the base mock and returns an augmented login
// response that includes Email, TenantID, and Roles.
type loginWithExtrasMock struct {
	inner *mockXKMSUserAuthFactorClient
}

func (m *loginWithExtrasMock) AddAuthFactor(ctx context.Context, req *qrdbtransport.AuthFactorAddRequest) (*qrdbtransport.AuthFactorAddResponse, error) {
	return m.inner.AddAuthFactor(ctx, req)
}

func (m *loginWithExtrasMock) ListAuthFactors(ctx context.Context, req *qrdbtransport.AuthFactorListRequest) (*qrdbtransport.AuthFactorListResponse, error) {
	return m.inner.ListAuthFactors(ctx, req)
}

func (m *loginWithExtrasMock) GetAuthFactor(ctx context.Context, req *qrdbtransport.AuthFactorGetRequest) (*qrdbtransport.AuthFactorGetResponse, error) {
	return m.inner.GetAuthFactor(ctx, req)
}

func (m *loginWithExtrasMock) RemoveAuthFactor(ctx context.Context, req *qrdbtransport.AuthFactorRemoveRequest) (*qrdbtransport.AuthFactorRemoveResponse, error) {
	return m.inner.RemoveAuthFactor(ctx, req)
}

func (m *loginWithExtrasMock) RotateAuthFactor(ctx context.Context, req *qrdbtransport.AuthFactorRotateRequest) (*qrdbtransport.AuthFactorRotateResponse, error) {
	return m.inner.RotateAuthFactor(ctx, req)
}

func (m *loginWithExtrasMock) RelabelAuthFactor(ctx context.Context, req *qrdbtransport.AuthFactorRelabelRequest) (*qrdbtransport.AuthFactorRelabelResponse, error) {
	return m.inner.RelabelAuthFactor(ctx, req)
}

func (m *loginWithExtrasMock) LoginAuthFactor(_ context.Context, req *qrdbtransport.AuthFactorLoginRequest) (*qrdbtransport.AuthFactorLoginResponse, error) {
	base, err := m.inner.LoginAuthFactor(context.Background(), req)
	if err != nil {
		return nil, err
	}
	base.Email = "user@example.com"
	base.TenantID = "acme"
	base.Roles = []string{"admin", "user"}
	return base, nil
}

// =============================================================================
// auth_factor_handlers.go — invokeClose nil path (66%)
// =============================================================================

// TestInvokeClose_NilFn exercises the nil-closer guard (no panic).
func TestInvokeClose_NilFn(t *testing.T) {
	if err := invokeClose(nil); err != nil {
		t.Fatalf("unexpected error from nil closer: %v", err)
	}
}

// TestInvokeClose_NonNilFn exercises the non-nil closer path.
func TestInvokeClose_NonNilFn(t *testing.T) {
	called := false
	err := invokeClose(func() error { called = true; return nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("expected closer to be invoked")
	}
}

// TestInvokeClose_ReturnsError exercises the error propagation path.
func TestInvokeClose_ReturnsError(t *testing.T) {
	want := errors.New("close failed")
	err := invokeClose(func() error { return want })
	if !errors.Is(err, want) {
		t.Errorf("expected wrapped close error, got: %v", err)
	}
}

// =============================================================================
// auth_factor_handlers.go — userAuthFactorClient with nil factory (66%)
// =============================================================================

// TestUserAuthFactorClient_NilFactory exercises the nil-factory guard.
func TestUserAuthFactorClient_NilFactory(t *testing.T) {
	prev := userAuthFactorClientFactory
	userAuthFactorClientFactory = nil
	defer func() { userAuthFactorClientFactory = prev }()

	cl, closeFn, err := userAuthFactorClient(context.Background())
	if cl != nil {
		t.Fatalf("expected nil client, got %T", cl)
	}
	if closeFn != nil {
		t.Fatal("expected nil closeFn")
	}
	var mc *AuthFactorMissingClientError
	if !errors.As(err, &mc) {
		t.Fatalf("want *AuthFactorMissingClientError, got %T: %v", err, err)
	}
}

// =============================================================================
// canonical.go — PendingCredentialBackendError (0%)
// =============================================================================

// TestCanonicalErrorMessages exercises the 0% canonical error type.
func TestCanonicalErrorMessages(t *testing.T) {
	t.Run("PendingCredentialBackendError", func(t *testing.T) {
		e := &PendingCredentialBackendError{Op: "credential list"}
		msg := e.Error()
		if !strings.Contains(msg, "credential list") {
			t.Errorf("error %q does not contain op", msg)
		}
	})
}

// =============================================================================
// canonical.go — newCanonicalBootstrapDirectCmd (30%)
// =============================================================================

// TestNewCanonicalBootstrapDirectCmd_NoBundleErrors exercises the missing
// --bundle flag error path.
func TestNewCanonicalBootstrapDirectCmd_NoBundleErrors(t *testing.T) {
	cmd := newCanonicalBootstrapDirectCmd()
	cmd.SetOut(&bytes.Buffer{})
	err := cmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("expected error when --bundle is not supplied")
	}
	if !strings.Contains(err.Error(), "--bundle is required") {
		t.Errorf("error %q does not mention --bundle", err.Error())
	}
}

// TestNewCanonicalBootstrapDirectCmd_DirectoryPathErrors exercises the
// "bundle is a directory" error.
func TestNewCanonicalBootstrapDirectCmd_DirectoryPathErrors(t *testing.T) {
	dir := t.TempDir()
	cmd := newCanonicalBootstrapDirectCmd()
	cmd.SetOut(&bytes.Buffer{})
	if err := cmd.Flags().Set("bundle", dir); err != nil {
		t.Fatalf("set flag: %v", err)
	}
	err := cmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("expected error for directory path")
	}
	if !strings.Contains(err.Error(), "directory") {
		t.Errorf("error %q does not mention directory", err.Error())
	}
}

// TestNewCanonicalBootstrapDirectCmd_MissingFileErrors exercises the
// os.Stat error path when the bundle file does not exist.
func TestNewCanonicalBootstrapDirectCmd_MissingFileErrors(t *testing.T) {
	p := filepath.Join(t.TempDir(), "nonexistent.pem")
	cmd := newCanonicalBootstrapDirectCmd()
	cmd.SetOut(&bytes.Buffer{})
	if err := cmd.Flags().Set("bundle", p); err != nil {
		t.Fatalf("set flag: %v", err)
	}
	err := cmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// TestNewCanonicalBootstrapDirectCmd_ValidFile exercises the success path.
func TestNewCanonicalBootstrapDirectCmd_ValidFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(p, []byte("PEM-data"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := newCanonicalBootstrapDirectCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	if err := cmd.Flags().Set("bundle", p); err != nil {
		t.Fatalf("set flag: %v", err)
	}
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "Direct CA bundle accepted") {
		t.Errorf("expected acceptance message, got: %q", buf.String())
	}
}

// =============================================================================
// bootstrap_trust.go — trustConfigFromFile and autoParamsFromResolverScope (0%)
// =============================================================================

// TestTrustConfigFromFile_EmptyPath exercises the empty-path early return.
func TestTrustConfigFromFile_EmptyPath(t *testing.T) {
	cfg, err := trustConfigFromFile("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Error("expected nil config for empty path")
	}
}

// TestTrustConfigFromFile_MissingFile exercises the load-error path.
func TestTrustConfigFromFile_MissingFile(t *testing.T) {
	_, err := trustConfigFromFile("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// TestAutoParamsFromResolverScope_NilScope exercises the nil-scope guard.
func TestAutoParamsFromResolverScope_NilScope(t *testing.T) {
	params := &autoBootstrapParams{}
	// Must not panic.
	autoParamsFromResolverScope(params, nil)
}

// TestAutoParamsFromResolverScope_FilledScope exercises all the fill-in
// branches: serverURL, dane hostname+dns, noise key+addr, spki pin.
func TestAutoParamsFromResolverScope_FilledScope(t *testing.T) {
	params := &autoBootstrapParams{}
	sc := &trustresolver.ScopeConfig{
		ServerURL: "https://xkms.example.com",
		Hostname:  "xkms.example.com",
		DANE: &trustresolver.DANEConfig{
			DNSServer: "8.8.8.8:53",
		},
		Noise: &trustresolver.NoiseConfig{
			ServerStaticKey:     "base64key==",
			ServerP256StaticKey: "04p256key",
			ServerAddr:          "xkms.example.com:8444",
		},
		SPKI: &trustresolver.SPKIConfig{
			Pin: "sha256/abcdef==",
		},
	}

	autoParamsFromResolverScope(params, sc)

	if params.serverURL != "https://xkms.example.com" {
		t.Errorf("serverURL = %q, want https://xkms.example.com", params.serverURL)
	}
	if params.daneHostname != "xkms.example.com" {
		t.Errorf("daneHostname = %q, want xkms.example.com", params.daneHostname)
	}
	if params.daneDNSServer != "8.8.8.8:53" {
		t.Errorf("daneDNSServer = %q, want 8.8.8.8:53", params.daneDNSServer)
	}
	if params.p256Key != "04p256key" {
		t.Errorf("p256Key = %q, want 04p256key", params.p256Key)
	}
	if params.noiseKey != "base64key==" {
		t.Errorf("noiseKey = %q, want base64key==", params.noiseKey)
	}
	if params.noiseAddr != "xkms.example.com:8444" {
		t.Errorf("noiseAddr = %q, want xkms.example.com:8444", params.noiseAddr)
	}
	if params.spkiPin != "sha256/abcdef==" {
		t.Errorf("spkiPin = %q, want sha256/abcdef==", params.spkiPin)
	}
}

// TestAutoParamsFromResolverScope_NoOverwrite verifies that existing params
// values are NOT overwritten by scope values.
func TestAutoParamsFromResolverScope_NoOverwrite(t *testing.T) {
	params := &autoBootstrapParams{
		serverURL:     "https://existing.example.com",
		daneHostname:  "existing.example.com",
		daneDNSServer: "1.1.1.1:53",
		noiseKey:      "existing-key",
		noiseAddr:     "existing.example.com:9000",
		spkiPin:       "existing-pin",
	}
	sc := &trustresolver.ScopeConfig{
		ServerURL: "https://new.example.com",
		Hostname:  "new.example.com",
		DANE: &trustresolver.DANEConfig{
			DNSServer: "8.8.8.8:53",
		},
		Noise: &trustresolver.NoiseConfig{
			ServerStaticKey: "new-key",
			ServerAddr:      "new.example.com:9000",
		},
		SPKI: &trustresolver.SPKIConfig{
			Pin: "new-pin",
		},
	}

	autoParamsFromResolverScope(params, sc)

	if params.serverURL != "https://existing.example.com" {
		t.Errorf("serverURL overwritten: %q", params.serverURL)
	}
	if params.spkiPin != "existing-pin" {
		t.Errorf("spkiPin overwritten: %q", params.spkiPin)
	}
}

// =============================================================================
// barrier.go — printBarrierStatus, printBarrierShamirResult,
//              printBarrierRekeyResult, printBarrierRecoveryKeys (22-31%)
// =============================================================================

// =============================================================================
// admin.go — enrollMTLSAdmin additional paths (40%)
// =============================================================================

// TestEnrollMTLSAdmin_LoadCertError exercises the loadEnrollmentCert error path.
func TestEnrollMTLSAdmin_LoadCertError(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("cert-file", "/nonexistent/cert.pem", "")
	cmd.Flags().String("display-name", "", "")

	cfg := &Config{
		OutputFormat: "text",
		ClientFactory: func(*Config) (client.Client, error) {
			return nil, errors.New("should not reach factory")
		},
	}
	printer := NewPrinter("text", &bytes.Buffer{})

	err := enrollMTLSAdmin(cmd, "admin", cfg, printer, "")
	if err == nil {
		t.Fatal("expected error when cert file does not exist")
	}
}

// =============================================================================
// admin.go — enrollMTLSAdmin success + error paths (40%)
// =============================================================================

// mockAdminClient embeds mockBackendsClient and allows overriding the
// Connect, Close, CreateUser, and BindUserCert methods — the four
// methods exercised by enrollMTLSAdmin.
type mockAdminClient struct {
	mockBackendsClient
	connectErr    error
	closeErr      error
	createUserErr error
	bindCertErr   error
}

func (m *mockAdminClient) Connect(_ context.Context) error { return m.connectErr }
func (m *mockAdminClient) Close() error                    { return m.closeErr }

func (m *mockAdminClient) CreateUser(_ context.Context, _ *client.CreateUserRequest) (*client.GetUserResponse, error) {
	return nil, m.createUserErr
}

func (m *mockAdminClient) BindUserCert(_ context.Context, _, _ string, _ int64) error {
	return m.bindCertErr
}

// newAdminTestCmd builds a minimal cobra command with the flags that
// enrollMTLSAdmin reads: --display-name and --cert-file.
func newAdminTestCmd(certFile, displayName string) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("cert-file", certFile, "")
	cmd.Flags().String("display-name", displayName, "")
	return cmd
}

// TestEnrollMTLSAdmin_CreateClientError exercises the CreateClient failure path.
func TestEnrollMTLSAdmin_CreateClientError(t *testing.T) {
	certPEM := makeSelfSignedCert(t, "admin-user")
	p := filepath.Join(t.TempDir(), "admin.pem")
	if err := os.WriteFile(p, certPEM, 0600); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		OutputFormat: "text",
		ClientFactory: func(*Config) (client.Client, error) {
			return nil, errors.New("factory error")
		},
	}
	cmd := newAdminTestCmd(p, "Admin User")
	printer := NewPrinter("text", &bytes.Buffer{})

	err := enrollMTLSAdmin(cmd, "admin", cfg, printer, "")
	if err == nil {
		t.Fatal("expected error when CreateClient fails")
	}
	if !strings.Contains(err.Error(), "failed to create client") {
		t.Errorf("error %q does not mention create client", err.Error())
	}
}

// TestEnrollMTLSAdmin_ConnectError exercises the Connect failure path.
func TestEnrollMTLSAdmin_ConnectError(t *testing.T) {
	certPEM := makeSelfSignedCert(t, "admin-user")
	p := filepath.Join(t.TempDir(), "admin.pem")
	if err := os.WriteFile(p, certPEM, 0600); err != nil {
		t.Fatal(err)
	}

	mock := &mockAdminClient{connectErr: errors.New("connect refused")}
	cfg := &Config{
		OutputFormat: "text",
		ClientFactory: func(*Config) (client.Client, error) {
			return mock, nil
		},
	}
	cmd := newAdminTestCmd(p, "")
	printer := NewPrinter("text", &bytes.Buffer{})

	err := enrollMTLSAdmin(cmd, "admin", cfg, printer, "")
	if err == nil {
		t.Fatal("expected error when Connect fails")
	}
	if !strings.Contains(err.Error(), "failed to connect") {
		t.Errorf("error %q does not mention connect", err.Error())
	}
}

// TestEnrollMTLSAdmin_CreateUserError exercises the CreateUser failure path.
func TestEnrollMTLSAdmin_CreateUserError(t *testing.T) {
	certPEM := makeSelfSignedCert(t, "admin-user")
	p := filepath.Join(t.TempDir(), "admin.pem")
	if err := os.WriteFile(p, certPEM, 0600); err != nil {
		t.Fatal(err)
	}

	mock := &mockAdminClient{createUserErr: errors.New("already exists")}
	cfg := &Config{
		OutputFormat: "text",
		ClientFactory: func(*Config) (client.Client, error) {
			return mock, nil
		},
	}
	cmd := newAdminTestCmd(p, "Admin User")
	printer := NewPrinter("text", &bytes.Buffer{})

	err := enrollMTLSAdmin(cmd, "admin", cfg, printer, "")
	if err == nil {
		t.Fatal("expected error when CreateUser fails")
	}
	if !strings.Contains(err.Error(), "failed to create admin") {
		t.Errorf("error %q does not mention create admin", err.Error())
	}
}

// TestEnrollMTLSAdmin_BindCertError exercises the BindUserCert failure path.
func TestEnrollMTLSAdmin_BindCertError(t *testing.T) {
	certPEM := makeSelfSignedCert(t, "admin-user")
	p := filepath.Join(t.TempDir(), "admin.pem")
	if err := os.WriteFile(p, certPEM, 0600); err != nil {
		t.Fatal(err)
	}

	mock := &mockAdminClient{bindCertErr: errors.New("bind failed")}
	cfg := &Config{
		OutputFormat: "text",
		ClientFactory: func(*Config) (client.Client, error) {
			return mock, nil
		},
	}
	cmd := newAdminTestCmd(p, "")
	printer := NewPrinter("text", &bytes.Buffer{})

	err := enrollMTLSAdmin(cmd, "admin", cfg, printer, "")
	if err == nil {
		t.Fatal("expected error when BindUserCert fails")
	}
	if !strings.Contains(err.Error(), "failed to bind cert") {
		t.Errorf("error %q does not mention bind cert", err.Error())
	}
}

// TestEnrollMTLSAdmin_SuccessTextFormat exercises the success path with text output.
func TestEnrollMTLSAdmin_SuccessTextFormat(t *testing.T) {
	certPEM := makeSelfSignedCert(t, "admin-user")
	p := filepath.Join(t.TempDir(), "admin.pem")
	if err := os.WriteFile(p, certPEM, 0600); err != nil {
		t.Fatal(err)
	}

	mock := &mockAdminClient{}
	cfg := &Config{
		OutputFormat: "text",
		ClientFactory: func(*Config) (client.Client, error) {
			return mock, nil
		},
	}
	cmd := newAdminTestCmd(p, "Admin User")
	var out bytes.Buffer
	printer := NewPrinter("text", &out)

	if err := enrollMTLSAdmin(cmd, "admin", cfg, printer, ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestEnrollMTLSAdmin_SuccessJSONFormat exercises the success path with JSON output.
func TestEnrollMTLSAdmin_SuccessJSONFormat(t *testing.T) {
	certPEM := makeSelfSignedCert(t, "admin-user")
	p := filepath.Join(t.TempDir(), "admin.pem")
	if err := os.WriteFile(p, certPEM, 0600); err != nil {
		t.Fatal(err)
	}

	mock := &mockAdminClient{}
	cfg := &Config{
		OutputFormat: "json",
		ClientFactory: func(*Config) (client.Client, error) {
			return mock, nil
		},
	}
	cmd := newAdminTestCmd(p, "")
	var out bytes.Buffer
	printer := NewPrinter("json", &out)

	if err := enrollMTLSAdmin(cmd, "admin@example.com", cfg, printer, ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out.String(), "fingerprint") {
		t.Errorf("expected fingerprint in JSON output, got: %q", out.String())
	}
}

// =============================================================================
// admin.go — loadEnrollmentCert no-source path (66%)
// =============================================================================

// TestLoadEnrollmentCert_NoCertNoModule exercises the ErrNoCertificateSource path
// when neither --cert-file nor PKCS11Module is configured.
func TestLoadEnrollmentCert_NoCertNoModule(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("cert-file", "", "")

	cfg := &Config{PKCS11Module: ""}

	_, err := loadEnrollmentCert(cmd, cfg)
	if err == nil {
		t.Fatal("expected error when no cert source is configured")
	}
	if !errors.Is(err, ErrNoCertificateSource) {
		t.Errorf("want ErrNoCertificateSource, got %T: %v", err, err)
	}
}

// TestLoadEnrollmentCert_PKCS11Error exercises the PKCS#11 error path.
// Providing a non-existent module path causes NewPKCS11TLSConfig to error.
func TestLoadEnrollmentCert_PKCS11Error(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("cert-file", "", "")

	cfg := &Config{PKCS11Module: "/nonexistent/pkcs11.so"}

	_, err := loadEnrollmentCert(cmd, cfg)
	if err == nil {
		t.Fatal("expected error for non-existent PKCS#11 module")
	}
	if !strings.Contains(err.Error(), "PKCS") && !strings.Contains(err.Error(), "pkcs") && !strings.Contains(err.Error(), "failed") {
		t.Errorf("error %q does not mention pkcs11 or failed", err.Error())
	}
}

// =============================================================================
// auth_factor_handlers.go — runXKMSAuthFactorList parse error (87.5%)
// =============================================================================

// TestRunXKMSAuthFactorList_InvalidUserID exercises the non-numeric user ID path.
func TestRunXKMSAuthFactorList_InvalidUserID(t *testing.T) {
	err := runXKMSAuthFactorList(context.Background(), "not-a-number")
	var iue *InvalidUserIDError
	if !errors.As(err, &iue) {
		t.Fatalf("want *InvalidUserIDError, got %T: %v", err, err)
	}
}

// =============================================================================
// auth_factor_handlers.go — runXKMSAuthFactorAdd RPC error path (77.8%)
// =============================================================================

// TestRunXKMSAuthFactorAdd_RPCError exercises the cl.AddAuthFactor error path.
func TestRunXKMSAuthFactorAdd_RPCError(t *testing.T) {
	restore := SetUserAuthFactorClientFactory(func(_ context.Context) (qrdbtransport.UserAuthFactorClient, func() error, error) {
		return &addErrorMock{err: errors.New("rpc add failed")}, func() error { return nil }, nil
	})
	defer restore()

	err := runXKMSAuthFactorAdd(context.Background(), &authFactorAddFlags{
		user:          "1",
		factorType:    "fido2",
		label:         "yk",
		credentialHex: "deadbeef",
	})
	if err == nil {
		t.Fatal("expected error from AddAuthFactor RPC")
	}
	if !strings.Contains(err.Error(), "rpc add failed") {
		t.Errorf("error %q does not mention rpc error", err.Error())
	}
}

// =============================================================================
// auth_factor_handlers.go — runXKMSAuthFactorRemove RPC error path (72.7%)
// =============================================================================

// TestRunXKMSAuthFactorRemove_RPCError exercises the RemoveAuthFactor error path.
func TestRunXKMSAuthFactorRemove_RPCError(t *testing.T) {
	restore := SetUserAuthFactorClientFactory(func(_ context.Context) (qrdbtransport.UserAuthFactorClient, func() error, error) {
		return &removeErrorMock{err: errors.New("rpc remove failed")}, func() error { return nil }, nil
	})
	defer restore()

	err := runXKMSAuthFactorRemove(context.Background(), "factor-abc", false)
	if err == nil {
		t.Fatal("expected error from RemoveAuthFactor RPC")
	}
}

// TestRunXKMSAuthFactorRemove_Success exercises the success output path.
func TestRunXKMSAuthFactorRemove_Success(t *testing.T) {
	mock, restore := installMockFactory(t)
	defer restore()
	mock.factors["rm-1"] = &qrdbtransport.AuthFactorRecord{
		ID:           "rm-1",
		Type:         "fido2",
		RegisteredAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runXKMSAuthFactorRemove(context.Background(), "rm-1", false)

	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "OK") {
		t.Errorf("expected OK in output, got: %q", buf.String())
	}
}

// =============================================================================
// auth_factor_handlers.go — runXKMSAuthFactorRotate paths (65.2%)
// =============================================================================

// TestRunXKMSAuthFactorRotate_InvalidUserID exercises the user parse error.
func TestRunXKMSAuthFactorRotate_InvalidUserID(t *testing.T) {
	err := runXKMSAuthFactorRotate(context.Background(), "old-id", &authFactorAddFlags{
		user: "bad-user",
	})
	var iue *InvalidUserIDError
	if !errors.As(err, &iue) {
		t.Fatalf("want *InvalidUserIDError, got %T: %v", err, err)
	}
}

// TestRunXKMSAuthFactorRotate_ClientFactoryError exercises the factory error path.
func TestRunXKMSAuthFactorRotate_ClientFactoryError(t *testing.T) {
	restore := SetUserAuthFactorClientFactory(func(_ context.Context) (qrdbtransport.UserAuthFactorClient, func() error, error) {
		return nil, nil, errors.New("factory down")
	})
	defer restore()

	err := runXKMSAuthFactorRotate(context.Background(), "old-id", &authFactorAddFlags{
		factorType:    "fido2",
		label:         "yk",
		credentialHex: "deadbeef",
	})
	if err == nil {
		t.Fatal("expected error when factory fails")
	}
}

// TestRunXKMSAuthFactorRotate_BuildRequestError exercises the buildXKMSAddRequest error path.
func TestRunXKMSAuthFactorRotate_BuildRequestError(t *testing.T) {
	_, restore := installMockFactory(t)
	defer restore()

	err := runXKMSAuthFactorRotate(context.Background(), "old-id", &authFactorAddFlags{
		// Missing label triggers MissingLabelError inside buildXKMSAddRequest.
		factorType: "fido2",
	})
	var mle *MissingLabelError
	if !errors.As(err, &mle) {
		t.Fatalf("want *MissingLabelError, got %T: %v", err, err)
	}
}

// TestRunXKMSAuthFactorRotate_RPCError exercises the RotateAuthFactor RPC error.
func TestRunXKMSAuthFactorRotate_RPCError(t *testing.T) {
	restore := SetUserAuthFactorClientFactory(func(_ context.Context) (qrdbtransport.UserAuthFactorClient, func() error, error) {
		return &rotateErrorMock{err: errors.New("rotate rpc failed")}, func() error { return nil }, nil
	})
	defer restore()

	err := runXKMSAuthFactorRotate(context.Background(), "old-id", &authFactorAddFlags{
		factorType:    "fido2",
		label:         "yk",
		credentialHex: "deadbeef",
	})
	if err == nil {
		t.Fatal("expected error from RotateAuthFactor RPC")
	}
}

// TestRunXKMSAuthFactorRotate_Success exercises the success output path.
func TestRunXKMSAuthFactorRotate_Success(t *testing.T) {
	mock, restore := installMockFactory(t)
	defer restore()
	mock.factors["old-id"] = &qrdbtransport.AuthFactorRecord{
		ID:           "old-id",
		Type:         "fido2",
		Label:        "old-yk",
		UserID:       1,
		RegisteredAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runXKMSAuthFactorRotate(context.Background(), "old-id", &authFactorAddFlags{
		factorType:    "fido2",
		label:         "new-yk",
		credentialHex: "deadbeef",
	})

	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "Old factor revoked") {
		t.Errorf("expected 'Old factor revoked' in output, got: %q", buf.String())
	}
}

// =============================================================================
// auth_factor_handlers.go — buildXKMSLoginLookupKey mtls success path (75%)
// =============================================================================

// TestBuildXKMSLoginLookupKey_MtlsWithCert exercises the mtls path
// where a valid PEM certificate is provided.
func TestBuildXKMSLoginLookupKey_MtlsWithCert(t *testing.T) {
	certPEM := makeSelfSignedCert(t, "mtls-login")
	p := filepath.Join(t.TempDir(), "login.pem")
	if err := os.WriteFile(p, certPEM, 0600); err != nil {
		t.Fatal(err)
	}

	key, err := buildXKMSLoginLookupKey("mtls", p, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(key) == 0 {
		t.Error("expected non-empty lookup key for mtls")
	}
}

// =============================================================================
// Shared test helper
// =============================================================================

// ---------------------------------------------------------------------------
// Minimal error-injection mocks for auth factor RPC error paths.
// Each type implements qrdbtransport.UserAuthFactorClient by delegating all
// methods to a no-op inner mock and overriding exactly the one method that
// needs to return an error.
// ---------------------------------------------------------------------------

// addErrorMock returns an error from AddAuthFactor and delegates everything else.
type addErrorMock struct {
	loginWithExtrasMock
	err error
}

func (m *addErrorMock) AddAuthFactor(_ context.Context, _ *qrdbtransport.AuthFactorAddRequest) (*qrdbtransport.AuthFactorAddResponse, error) {
	return nil, m.err
}

// removeErrorMock returns an error from RemoveAuthFactor and delegates everything else.
type removeErrorMock struct {
	loginWithExtrasMock
	err error
}

func (m *removeErrorMock) RemoveAuthFactor(_ context.Context, _ *qrdbtransport.AuthFactorRemoveRequest) (*qrdbtransport.AuthFactorRemoveResponse, error) {
	return nil, m.err
}

// rotateErrorMock returns an error from RotateAuthFactor and delegates everything else.
type rotateErrorMock struct {
	loginWithExtrasMock
	err error
}

func (m *rotateErrorMock) RotateAuthFactor(_ context.Context, _ *qrdbtransport.AuthFactorRotateRequest) (*qrdbtransport.AuthFactorRotateResponse, error) {
	return nil, m.err
}

// makeSelfSignedCert generates a minimal self-signed ECDSA certificate and
// returns its PEM encoding. Used by tests that need a valid cert file.
func makeSelfSignedCert(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
