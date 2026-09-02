// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package unix

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// --- protoToUserInfo ---

func TestProtoToUserInfo_Nil(t *testing.T) {
	result := protoToUserInfo(nil)
	assert.Equal(t, transport.UserInfo{}, result)
}

func TestProtoToUserInfo_Populated(t *testing.T) {
	u := &pb.UserInfo{
		Username:    "alice",
		Email:       "alice@example.com",
		DisplayName: "Alice Smith",
		Role:        "admin",
		Enabled:     true,
	}
	result := protoToUserInfo(u)
	assert.Equal(t, "alice", result.Username)
	// The canonical login key must survive the proto -> transport projection.
	// It was added to the server-side direction only, so a client read it back
	// empty for a user that has one (Codex, go-xkms #190).
	assert.Equal(t, "alice@example.com", result.Email)
	assert.Equal(t, "Alice Smith", result.DisplayName)
	assert.Equal(t, "admin", result.Role)
	assert.True(t, result.Enabled)
}

// --- Not-connected guards ---

func TestCreateUser_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).CreateUser(context.Background(), &transport.CreateUserRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestListUsers_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).ListUsers(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGetUser_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).GetUser(context.Background(), "alice")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestDeleteUser_NotConnected(t *testing.T) {
	err := newDisconnected(t).DeleteUser(context.Background(), "alice")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestEnableUser_NotConnected(t *testing.T) {
	err := newDisconnected(t).EnableUser(context.Background(), "alice")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestDisableUser_NotConnected(t *testing.T) {
	err := newDisconnected(t).DisableUser(context.Background(), "alice")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBindUserCert_NotConnected(t *testing.T) {
	err := newDisconnected(t).BindUserCert(context.Background(), "alice", "thumbprint", 0)
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestListUserCredentials_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).ListUserCredentials(context.Background(), "alice")
	assert.ErrorIs(t, err, ErrNotConnected)
}

// --- errServer implementations for user methods ---

func (s *errServer) CreateUser(context.Context, *pb.CreateUserRequest) (*pb.UserResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) ListUsers(context.Context, *pb.ListUsersRequest) (*pb.ListUsersResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) GetUser(context.Context, *pb.GetUserRequest) (*pb.UserResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) DeleteUser(context.Context, *pb.DeleteUserRequest) (*pb.DeleteUserResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) EnableUser(context.Context, *pb.EnableUserRequest) (*pb.UserResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) DisableUser(context.Context, *pb.DisableUserRequest) (*pb.UserResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) BindUserCert(context.Context, *pb.BindUserCertRequest) (*pb.UserResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) ListUserCredentials(context.Context, *pb.ListUserCredentialsRequest) (*pb.ListUserCredentialsResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}

func TestCreateUser_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.CreateUser(context.Background(), &transport.CreateUserRequest{Username: "bob"})
	require.Error(t, err)
}

func TestListUsers_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.ListUsers(context.Background())
	require.Error(t, err)
}

func TestGetUser_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.GetUser(context.Background(), "alice")
	require.Error(t, err)
}

func TestDeleteUser_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.DeleteUser(context.Background(), "alice")
	require.Error(t, err)
}

func TestEnableUser_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.EnableUser(context.Background(), "alice")
	require.Error(t, err)
}

func TestDisableUser_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.DisableUser(context.Background(), "alice")
	require.Error(t, err)
}

func TestBindUserCert_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.BindUserCert(context.Background(), "alice", "fp", 0)
	require.Error(t, err)
}

func TestListUserCredentials_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.ListUserCredentials(context.Background(), "alice")
	require.Error(t, err)
}

func (s *mockKeystoreServer) CreateUser(_ context.Context, req *pb.CreateUserRequest) (*pb.UserResponse, error) {
	return &pb.UserResponse{User: &pb.UserInfo{Username: req.Username, DisplayName: req.DisplayName, Role: req.Role, Enabled: true}}, nil
}

func (s *mockKeystoreServer) ListUsers(_ context.Context, _ *pb.ListUsersRequest) (*pb.ListUsersResponse, error) {
	return &pb.ListUsersResponse{Users: []*pb.UserInfo{
		{Username: "alice", DisplayName: "Alice", Role: "admin", Enabled: true},
	}}, nil
}

func (s *mockKeystoreServer) GetUser(_ context.Context, req *pb.GetUserRequest) (*pb.UserResponse, error) {
	return &pb.UserResponse{User: &pb.UserInfo{Username: req.Username, DisplayName: "Test User", Role: "user", Enabled: true}}, nil
}

func (s *mockKeystoreServer) DeleteUser(_ context.Context, _ *pb.DeleteUserRequest) (*pb.DeleteUserResponse, error) {
	return &pb.DeleteUserResponse{}, nil
}

func (s *mockKeystoreServer) EnableUser(_ context.Context, req *pb.EnableUserRequest) (*pb.UserResponse, error) {
	return &pb.UserResponse{User: &pb.UserInfo{Username: req.Username, Enabled: true}}, nil
}

func (s *mockKeystoreServer) DisableUser(_ context.Context, req *pb.DisableUserRequest) (*pb.UserResponse, error) {
	return &pb.UserResponse{User: &pb.UserInfo{Username: req.Username, Enabled: false}}, nil
}

func (s *mockKeystoreServer) BindUserCert(_ context.Context, _ *pb.BindUserCertRequest) (*pb.UserResponse, error) {
	return &pb.UserResponse{User: &pb.UserInfo{Username: "alice"}}, nil
}

func (s *mockKeystoreServer) ListUserCredentials(_ context.Context, _ *pb.ListUserCredentialsRequest) (*pb.ListUserCredentialsResponse, error) {
	return &pb.ListUserCredentialsResponse{Credentials: []*pb.UserCredential{
		{Id: "cred-1", Name: "YubiKey"},
	}}, nil
}

// --- mockKeystoreServer for GeneratePIVCSR (not in bufconn test) ---

func (s *mockKeystoreServer) GeneratePIVCSR(_ context.Context, req *pb.GeneratePIVCSRRequest) (*pb.GeneratePIVCSRResponse, error) {
	return &pb.GeneratePIVCSRResponse{Slot: req.Slot, Csr: []byte("-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----")}, nil
}

// --- User happy-path connected tests ---

func TestCreateUser_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.CreateUser(context.Background(), &transport.CreateUserRequest{
		Username: "alice", DisplayName: "Alice", Role: "admin",
	})
	require.NoError(t, err)
	assert.Equal(t, "alice", resp.User.Username)
}

func TestListUsers_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.ListUsers(context.Background())
	require.NoError(t, err)
	require.Len(t, resp.Users, 1)
	assert.Equal(t, "alice", resp.Users[0].Username)
}

func TestGetUser_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.GetUser(context.Background(), "alice")
	require.NoError(t, err)
	assert.Equal(t, "alice", resp.User.Username)
}

func TestDeleteUser_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	err := tr.DeleteUser(context.Background(), "alice")
	require.NoError(t, err)
}

func TestEnableUser_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	err := tr.EnableUser(context.Background(), "alice")
	require.NoError(t, err)
}

func TestDisableUser_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	err := tr.DisableUser(context.Background(), "alice")
	require.NoError(t, err)
}

func TestBindUserCert_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	err := tr.BindUserCert(context.Background(), "alice", "sha256-fingerprint", 9999999999)
	require.NoError(t, err)
}

func TestListUserCredentials_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.ListUserCredentials(context.Background(), "alice")
	require.NoError(t, err)
	require.Len(t, resp.Credentials, 1)
	assert.Equal(t, "cred-1", resp.Credentials[0].ID)
}

// --- GeneratePIVCSR server-error and happy-path ---

func TestGeneratePIVCSR_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.GeneratePIVCSR(context.Background(), &transport.GeneratePIVCSRRequest{})
	require.Error(t, err)
}

func TestGeneratePIVCSR_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	resp, err := tr.GeneratePIVCSR(context.Background(), &transport.GeneratePIVCSRRequest{
		Backend: "software", Slot: "9a", Subject: "CN=test",
	})
	require.NoError(t, err)
	assert.Equal(t, "9a", resp.Slot)
	assert.NotEmpty(t, resp.CSR)
}

// newTCGTransport builds a Transport whose HTTP client is backed by a
// roundTripFunc that returns canned TCG-CA JSON responses.  The gRPC client
// is nil — TCG methods use HTTP only, so no gRPC connection is needed.
func newTCGTransport(t *testing.T) *Transport {
	t.Helper()
	client := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			rec.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rec).Encode(map[string]interface{}{
				"certificate_pem": "Y2VydA==",
				"certificate_der": "Y2VydA==",
				"serial_number":   "1234",
				"iak_cert_der":    "aWFrLWNlcnQ=",
				"idevid_cert_der": "aWRldmlkLWNlcnQ=",
			})
			return rec.Result(), nil
		}),
	}
	cfg := transport.DefaultConfig()
	cfg.Address = "/tmp/test-tcg.sock"
	return &Transport{config: cfg, httpClient: client, connected: true}
}

// --- TCG certificate happy-path ---

func TestIssueEKCertificate_Connected(t *testing.T) {
	tr := newTCGTransport(t)
	resp, err := tr.IssueEKCertificate(context.Background(), &transport.IssueEKCertificateRequest{CommonName: "test-ek"})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.CertificatePEM)
}

func TestIssueAKCertificate_Connected(t *testing.T) {
	tr := newTCGTransport(t)
	resp, err := tr.IssueAKCertificate(context.Background(), &transport.IssueAKCertificateRequest{CommonName: "test-ak"})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.CertificatePEM)
}

func TestSignTCGCSR_Connected(t *testing.T) {
	tr := newTCGTransport(t)
	resp, err := tr.SignTCGCSR(context.Background(), &transport.SignTCGCSRRequest{CommonName: "test-device"})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.IAKCertDER)
}

func TestEnrollDevice_Connected(t *testing.T) {
	tr := newTCGTransport(t)
	resp, err := tr.EnrollDevice(context.Background(), &transport.EnrollDeviceRequest{CommonName: "test-device"})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.IAKCertDER)
}

// --- doRawRequest error paths ---

func TestDoRawRequest_MarshalError(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "/tmp/test.sock"
	tr := &Transport{
		config:     cfg,
		httpClient: &http.Client{},
		connected:  true,
	}
	// Pass a channel (non-JSON-serializable) to trigger marshal error.
	_, err := tr.doRawRequest(context.Background(), "POST", "/test", make(chan int))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to marshal request body")
}

func TestDoRawRequest_ServerErrorStatus(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			rec.WriteHeader(http.StatusInternalServerError)
			_, _ = rec.WriteString(`{"error":"internal error"}`)
			return rec.Result(), nil
		}),
	}
	cfg := transport.DefaultConfig()
	cfg.Address = "/tmp/test.sock"
	tr := &Transport{config: cfg, httpClient: client, connected: true}
	_, err := tr.doRawRequest(context.Background(), "GET", "/v1/init/status", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server returned status")
}

// --- REST-method error paths (HTTP server returns 500) ---

func TestGetInitStatus_HTTPError(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.GetInitStatus(context.Background())
	require.Error(t, err)
}

func TestClaimCertBegin_HTTPError(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.ClaimCertBegin(context.Background(), &transport.ClaimCertBeginRequest{})
	require.Error(t, err)
}

func TestClaimCertComplete_HTTPError(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.ClaimCertComplete(context.Background(), &transport.ClaimCertCompleteRequest{})
	require.Error(t, err)
}

func TestClaimShareBegin_HTTPError(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.ClaimShareBegin(context.Background(), &transport.ClaimShareBeginRequest{})
	require.Error(t, err)
}

func TestSignCSRInit_HTTPError(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.SignCSRInit(context.Background(), &transport.SignCSRInitRequest{})
	require.Error(t, err)
}

func TestSubmitCredential_HTTPError(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.SubmitCredential(context.Background(), &transport.CredentialSubmitRequest{})
	require.Error(t, err)
}

func TestGetCredentialStrategy_HTTPError(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.GetCredentialStrategy(context.Background())
	require.Error(t, err)
}

// --- Close with nil conn ---

func TestClose_NilConnSetsDisconnected(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "/tmp/test.sock"
	tr := &Transport{
		config:    cfg,
		connected: true,
	}
	// No conn set — Close should still set connected=false cleanly.
	err := tr.Close()
	require.NoError(t, err)
	assert.False(t, tr.connected)
}
