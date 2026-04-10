package xkms

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockCeremonyService implements transport.InitCeremonyService for testing.
type mockCeremonyService struct {
	getInitStatusResp       *transport.InitStatusResponse
	claimCertBeginResp      *transport.ClaimCertBeginResponse
	claimCertCompleteResp   *transport.ClaimCertCompleteResponse
	claimShareResp          *transport.ClaimShareResponse
	signCSRInitResp         *transport.SignCSRInitResponse
	getInitStatusErr        error
	claimCertBeginErr       error
	claimCertCompleteErr    error
	claimShareErr           error
	signCSRInitErr          error
	claimCertBeginCalled    bool
	claimCertCompleteCalled bool
	claimShareCalled        bool
	signCSRInitCalled       bool
}

func (m *mockCeremonyService) GetInitStatus(ctx context.Context) (*transport.InitStatusResponse, error) {
	return m.getInitStatusResp, m.getInitStatusErr
}

func (m *mockCeremonyService) ClaimCertBegin(ctx context.Context, req *transport.ClaimCertBeginRequest) (*transport.ClaimCertBeginResponse, error) {
	m.claimCertBeginCalled = true
	return m.claimCertBeginResp, m.claimCertBeginErr
}

func (m *mockCeremonyService) ClaimCertComplete(ctx context.Context, req *transport.ClaimCertCompleteRequest) (*transport.ClaimCertCompleteResponse, error) {
	m.claimCertCompleteCalled = true
	return m.claimCertCompleteResp, m.claimCertCompleteErr
}

func (m *mockCeremonyService) ClaimShare(ctx context.Context, req *transport.ClaimShareRequest) (*transport.ClaimShareResponse, error) {
	m.claimShareCalled = true
	return m.claimShareResp, m.claimShareErr
}

func (m *mockCeremonyService) SignCSRInit(ctx context.Context, req *transport.SignCSRInitRequest) (*transport.SignCSRInitResponse, error) {
	m.signCSRInitCalled = true
	return m.signCSRInitResp, m.signCSRInitErr
}

func setupServiceWithMockCeremony(t *testing.T) (*XKMSService, *mockCeremonyService) {
	t.Helper()
	svc, _, _ := setupServiceWithProviders(t)
	mock := &mockCeremonyService{
		getInitStatusResp: &transport.InitStatusResponse{State: "operational"},
		claimCertBeginResp: &transport.ClaimCertBeginResponse{
			Nonce:     "aabbccdd",
			Username:  "alice",
			ExpiresAt: time.Now().Add(5 * time.Minute),
		},
		claimCertCompleteResp: &transport.ClaimCertCompleteResponse{
			CertPEM:   "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			CACertPEM: "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----",
		},
		claimShareResp: &transport.ClaimShareResponse{
			Share: json.RawMessage(`{"index":1,"value":"deadbeef"}`),
		},
		signCSRInitErr: errors.New("initialize: operation not implemented"),
	}
	svc.SetCeremonyService(mock)
	return svc, mock
}

// --- ErrNotConfigured guards (ceremonyService is nil) ---

func TestGetInitStatus_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GetInitStatus(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestClaimCertBegin_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.ClaimCertBegin(context.Background(), &transport.ClaimCertBeginRequest{
		Username: "alice",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestClaimCertComplete_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.ClaimCertComplete(context.Background(), &transport.ClaimCertCompleteRequest{
		Username:  "alice",
		Nonce:     "aabbccdd",
		Signature: "c2lnbmF0dXJl",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestClaimShare_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.ClaimShare(context.Background(), &transport.ClaimShareRequest{
		Username: "alice",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestSignCSRInit_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.SignCSRInit(context.Background(), &transport.SignCSRInitRequest{
		Username: "alice",
		SOPin:    "123456",
		CSRPEM:   "-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----",
		Role:     "so",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

// --- getCeremonyServicer type assertion failure ---

func TestGetCeremonyServicer_WrongType(t *testing.T) {
	svc, _, _ := setupServiceWithProviders(t)
	// Set ceremonyService to a value that does not implement
	// transport.InitCeremonyService to exercise the type assertion failure.
	svc.SetCeremonyService("not-a-ceremony-service")

	_, err := svc.GetInitStatus(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

// --- ErrNilRequest guards ---

func TestClaimCertBegin_NilRequest(t *testing.T) {
	svc, _ := setupServiceWithMockCeremony(t)

	_, err := svc.ClaimCertBegin(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

func TestClaimCertComplete_NilRequest(t *testing.T) {
	svc, _ := setupServiceWithMockCeremony(t)

	_, err := svc.ClaimCertComplete(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

func TestClaimShare_NilRequest(t *testing.T) {
	svc, _ := setupServiceWithMockCeremony(t)

	_, err := svc.ClaimShare(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

func TestSignCSRInit_NilRequest(t *testing.T) {
	svc, _ := setupServiceWithMockCeremony(t)

	_, err := svc.SignCSRInit(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

// --- Successful delegation tests ---

func TestGetInitStatus_Success(t *testing.T) {
	svc, _ := setupServiceWithMockCeremony(t)

	resp, err := svc.GetInitStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "operational", resp.State)
}

func TestClaimCertBegin_Success(t *testing.T) {
	svc, mock := setupServiceWithMockCeremony(t)

	resp, err := svc.ClaimCertBegin(context.Background(), &transport.ClaimCertBeginRequest{
		Username: "alice",
	})
	require.NoError(t, err)
	assert.True(t, mock.claimCertBeginCalled)
	assert.Equal(t, "alice", resp.Username)
	assert.Equal(t, "aabbccdd", resp.Nonce)
}

func TestClaimCertComplete_Success(t *testing.T) {
	svc, mock := setupServiceWithMockCeremony(t)

	resp, err := svc.ClaimCertComplete(context.Background(), &transport.ClaimCertCompleteRequest{
		Username:  "alice",
		Nonce:     "aabbccdd",
		Signature: "c2lnbmF0dXJl",
	})
	require.NoError(t, err)
	assert.True(t, mock.claimCertCompleteCalled)
	assert.Contains(t, resp.CertPEM, "BEGIN CERTIFICATE")
	assert.Contains(t, resp.CACertPEM, "BEGIN CERTIFICATE")
}

func TestClaimShare_Success(t *testing.T) {
	svc, mock := setupServiceWithMockCeremony(t)

	resp, err := svc.ClaimShare(context.Background(), &transport.ClaimShareRequest{
		Username: "alice",
	})
	require.NoError(t, err)
	assert.True(t, mock.claimShareCalled)
	assert.Contains(t, string(resp.Share), "deadbeef")
}

func TestSignCSRInit_DelegatesToAdapter(t *testing.T) {
	svc, mock := setupServiceWithMockCeremony(t)

	_, err := svc.SignCSRInit(context.Background(), &transport.SignCSRInitRequest{
		Username: "alice",
		SOPin:    "123456",
		CSRPEM:   "-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----",
		Role:     "so",
	})
	require.Error(t, err)
	assert.True(t, mock.signCSRInitCalled)
	assert.Contains(t, err.Error(), "not implemented")
}

// --- Delegation error propagation ---

func TestGetInitStatus_DelegateError(t *testing.T) {
	svc, _, _ := setupServiceWithProviders(t)
	mock := &mockCeremonyService{
		getInitStatusErr: errors.New("ceremony: internal error"),
	}
	svc.SetCeremonyService(mock)

	_, err := svc.GetInitStatus(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "internal error")
}

func TestClaimCertBegin_DelegateError(t *testing.T) {
	svc, _, _ := setupServiceWithProviders(t)
	mock := &mockCeremonyService{
		claimCertBeginErr: errors.New("ceremony: not in enrolling state"),
	}
	svc.SetCeremonyService(mock)

	_, err := svc.ClaimCertBegin(context.Background(), &transport.ClaimCertBeginRequest{
		Username: "alice",
	})
	require.Error(t, err)
	assert.True(t, mock.claimCertBeginCalled)
	assert.Contains(t, err.Error(), "not in enrolling state")
}
