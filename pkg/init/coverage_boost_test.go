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

package initialize

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Cleanup - covers ceremony.go:257 (0.0% -> 100%)
// ---------------------------------------------------------------------------

func TestCleanup_SingleAdmin(t *testing.T) {
	svc, _ := initServiceSingleAdmin(t)
	require.Equal(t, StateOperational, svc.State())
	// Cleanup should not panic and should complete without error.
	svc.Cleanup()
}

func TestCleanup_MofN_DuringEnrollment(t *testing.T) {
	svc, _, _ := initServiceMofN(t, 2, 3)
	require.Equal(t, StateEnrolling, svc.State())
	// Cleanup destroys remaining shares during enrollment.
	svc.Cleanup()
}

func TestCleanup_BeforeInit(t *testing.T) {
	svc, err := NewCeremonyService(validConfig(), testBarrier(t), testCredService(t), testLogger())
	require.NoError(t, err)
	require.Equal(t, StateAwaitingInit, svc.State())
	// Cleanup on an uninitialized service should not panic.
	svc.Cleanup()
}

// ---------------------------------------------------------------------------
// base64ToHexSPKIPin - covers ceremony.go:284 (55.6% -> 100%)
// ---------------------------------------------------------------------------

func TestBase64ToHexSPKIPin_ValidStdEncoding(t *testing.T) {
	hash := sha256.Sum256([]byte("test-data"))
	b64 := base64.StdEncoding.EncodeToString(hash[:])

	hexPin, err := base64ToHexSPKIPin(b64)
	require.NoError(t, err)
	assert.Len(t, hexPin, 64) // SHA-256 = 32 bytes = 64 hex chars
}

func TestBase64ToHexSPKIPin_ValidRawStdEncoding(t *testing.T) {
	// Raw base64 (no padding) triggers the fallback decode path.
	hash := sha256.Sum256([]byte("test-data"))
	b64 := base64.RawStdEncoding.EncodeToString(hash[:])

	hexPin, err := base64ToHexSPKIPin(b64)
	require.NoError(t, err)
	assert.Len(t, hexPin, 64)
}

func TestBase64ToHexSPKIPin_InvalidBase64(t *testing.T) {
	// Not valid base64 at all -- both StdEncoding and RawStdEncoding fail.
	_, err := base64ToHexSPKIPin("!!!not-base64!!!")
	assert.ErrorIs(t, err, ErrInitFailed)
}

func TestBase64ToHexSPKIPin_WrongLength(t *testing.T) {
	// Valid base64 but decodes to wrong length (not 32 bytes).
	shortData := []byte("too-short")
	b64 := base64.StdEncoding.EncodeToString(shortData)

	_, err := base64ToHexSPKIPin(b64)
	assert.ErrorIs(t, err, ErrInitFailed)
}

// ---------------------------------------------------------------------------
// mapInitError - covers ceremony.go:302 (50.0% -> 100%)
// ---------------------------------------------------------------------------

func TestMapInitError_Nil(t *testing.T) {
	result := mapInitError(nil)
	assert.NoError(t, result)
}

func TestMapInitError_AlreadyInitialized(t *testing.T) {
	result := mapInitError(ErrAlreadyInitialized)
	assert.ErrorIs(t, result, ErrAlreadyInitialized)
}

func TestMapInitError_InitFailed(t *testing.T) {
	result := mapInitError(ErrInitFailed)
	assert.ErrorIs(t, result, ErrInitFailed)
}

func TestMapInitError_CertEncodeError(t *testing.T) {
	err := &CertEncodeError{Err: errors.New("encode failed")}
	result := mapInitError(err)
	assert.ErrorIs(t, result, ErrInitFailed)
}

func TestMapInitError_CSRParseError_Generic(t *testing.T) {
	err := &CSRParseError{Err: errors.New("parse failed")}
	result := mapInitError(err)
	assert.ErrorIs(t, result, ErrInitFailed)
}

func TestMapInitError_CSRParseError_WithInvalidCSR(t *testing.T) {
	err := &CSRParseError{Err: ErrInvalidCSR}
	result := mapInitError(err)
	assert.ErrorIs(t, result, ErrInvalidCSR)
}

func TestMapInitError_ShamirSplitError(t *testing.T) {
	err := &ShamirSplitError{Err: errors.New("split failed")}
	result := mapInitError(err)
	assert.ErrorIs(t, result, ErrInitFailed)
}

func TestMapInitError_ShareStoreError(t *testing.T) {
	err := &ShareStoreError{Err: errors.New("store failed")}
	result := mapInitError(err)
	assert.ErrorIs(t, result, ErrInitFailed)
}

func TestMapInitError_CABundleError(t *testing.T) {
	err := &CABundleError{Err: errors.New("bundle failed")}
	result := mapInitError(err)
	assert.ErrorIs(t, result, ErrInitFailed)
}

func TestMapInitError_UnknownError(t *testing.T) {
	unknownErr := errors.New("something unexpected")
	result := mapInitError(unknownErr)
	assert.Equal(t, unknownErr, result)
}

// ---------------------------------------------------------------------------
// mapClaimCertError - covers ceremony.go:347 (87.5% -> 100%)
// ---------------------------------------------------------------------------

func TestMapClaimCertError_Nil(t *testing.T) {
	result := mapClaimCertError(nil)
	assert.NoError(t, result)
}

func TestMapClaimCertError_ChallengeNotFound(t *testing.T) {
	result := mapClaimCertError(ErrChallengeNotFound)
	assert.ErrorIs(t, result, ErrChallengeVerificationFailed)
}

func TestMapClaimCertError_CABundleError(t *testing.T) {
	err := &CABundleError{Err: errors.New("bundle failed")}
	result := mapClaimCertError(err)
	assert.ErrorIs(t, result, ErrInitFailed)
}

func TestMapClaimCertError_UnknownError(t *testing.T) {
	unknownErr := errors.New("unexpected claim error")
	result := mapClaimCertError(unknownErr)
	assert.Equal(t, unknownErr, result)
}

// ---------------------------------------------------------------------------
// mapClaimShareError - covers ceremony.go:364 (80.0% -> 100%)
// ---------------------------------------------------------------------------

func TestMapClaimShareError_Nil(t *testing.T) {
	result := mapClaimShareError(nil)
	assert.NoError(t, result)
}

func TestMapClaimShareError_UserNotFound(t *testing.T) {
	result := mapClaimShareError(ErrUserNotFound)
	assert.ErrorIs(t, result, ErrShareNotFound)
}

func TestMapClaimShareError_UnknownError(t *testing.T) {
	unknownErr := errors.New("unexpected share error")
	result := mapClaimShareError(unknownErr)
	assert.Equal(t, unknownErr, result)
}

// ---------------------------------------------------------------------------
// mapSPKIPinError - covers ceremony.go:376 (75.0% -> 100%)
// ---------------------------------------------------------------------------

func TestMapSPKIPinError_Nil(t *testing.T) {
	result := mapSPKIPinError(nil)
	assert.NoError(t, result)
}

func TestMapSPKIPinError_CANotInitialized(t *testing.T) {
	result := mapSPKIPinError(ErrCANotInitialized)
	assert.ErrorIs(t, result, ErrInitFailed)
}

func TestMapSPKIPinError_CABundleError(t *testing.T) {
	err := &CABundleError{Err: errors.New("bundle failed")}
	result := mapSPKIPinError(err)
	assert.ErrorIs(t, result, ErrInitFailed)
}

func TestMapSPKIPinError_UnknownError(t *testing.T) {
	unknownErr := errors.New("unexpected pin error")
	result := mapSPKIPinError(unknownErr)
	assert.Equal(t, unknownErr, result)
}

// ---------------------------------------------------------------------------
// CAAdapter - IssueCertificate with SANs
// covers ca_adapter.go:62 (85.7% -> 100%)
// ---------------------------------------------------------------------------

func TestCAAdapter_IssueCertificate_WithSANs(t *testing.T) {
	mCA := newMockCA(t)
	adapter := NewCAAdapter(mCA)

	req := &qrdbsdk.IssueCertRequest{
		CommonName:   "test-cn",
		SANs:         []string{"dns1.example.com", "dns2.example.com"},
		ValidityDays: 365,
	}

	issued, err := adapter.IssueCertificate(req)
	require.NoError(t, err)
	assert.NotNil(t, issued)
	assert.NotNil(t, issued.Certificate)
	assert.NotEmpty(t, issued.CertPEM)
	assert.NotEmpty(t, issued.KeyPEM)
}

func TestCAAdapter_IssueCertificate_WithoutSANs(t *testing.T) {
	mCA := newMockCA(t)
	adapter := NewCAAdapter(mCA)

	req := &qrdbsdk.IssueCertRequest{
		CommonName:   "no-sans",
		ValidityDays: 365,
	}

	issued, err := adapter.IssueCertificate(req)
	require.NoError(t, err)
	assert.NotNil(t, issued)
	assert.NotNil(t, issued.Certificate)
}

func TestCAAdapter_IssueCertificate_Error(t *testing.T) {
	errCA := &errorCA{
		mockCA:       newMockCA(t),
		issueCertErr: errors.New("issuance failed"),
	}
	adapter := NewCAAdapter(errCA)

	req := &qrdbsdk.IssueCertRequest{
		CommonName:   "fail-cn",
		ValidityDays: 365,
	}

	_, err := adapter.IssueCertificate(req)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// CAAdapter - SignCSR, CACertificate, CABundle error delegation
// ---------------------------------------------------------------------------

func TestCAAdapter_SignCSR_Error(t *testing.T) {
	errCA := &errorCA{
		mockCA:     newMockCA(t),
		signCSRErr: errors.New("sign failed"),
	}
	adapter := NewCAAdapter(errCA)

	csrPEM, _ := generateTestCSR(t, "test-cn")
	_, err := adapter.SignCSR(csrPEM, &qrdbsdk.SignCSROptions{
		ValidityDays: 365,
	})
	assert.Error(t, err)
}

func TestCAAdapter_CACertificate_Error(t *testing.T) {
	errCA := &errorCA{
		mockCA:    newMockCA(t),
		caCertErr: errors.New("cert unavailable"),
	}
	adapter := NewCAAdapter(errCA)

	_, err := adapter.CACertificate()
	assert.Error(t, err)
}

func TestCAAdapter_CABundle_Error(t *testing.T) {
	errCA := &errorCA{
		mockCA:      newMockCA(t),
		caBundleErr: errors.New("bundle unavailable"),
	}
	adapter := NewCAAdapter(errCA)

	_, err := adapter.CABundle()
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Verify SANs mapping through the CA adapter boundary
// ---------------------------------------------------------------------------

type mockCAWithSANs struct {
	*mockCA
	lastSANs *ca.SubjectAlternativeNames
}

func (m *mockCAWithSANs) IssueCertificate(req *ca.CertificateRequest) (*ca.IssuedCertificate, error) {
	m.lastSANs = req.SANS
	return m.mockCA.IssueCertificate(req)
}

func TestCAAdapter_IssueCertificate_SANsPassedThrough(t *testing.T) {
	base := newMockCA(t)
	sanCA := &mockCAWithSANs{mockCA: base}
	adapter := NewCAAdapter(sanCA)

	req := &qrdbsdk.IssueCertRequest{
		CommonName: "with-sans",
		SANs:       []string{"foo.example.com", "bar.example.com"},
	}

	_, err := adapter.IssueCertificate(req)
	require.NoError(t, err)
	require.NotNil(t, sanCA.lastSANs)
	assert.Equal(t, []string{"foo.example.com", "bar.example.com"}, sanCA.lastSANs.DNS)
}

func TestCAAdapter_IssueCertificate_EmptySANsNotMapped(t *testing.T) {
	base := newMockCA(t)
	sanCA := &mockCAWithSANs{mockCA: base}
	adapter := NewCAAdapter(sanCA)

	req := &qrdbsdk.IssueCertRequest{
		CommonName: "no-sans",
	}

	_, err := adapter.IssueCertificate(req)
	require.NoError(t, err)
	assert.Nil(t, sanCA.lastSANs)
}
