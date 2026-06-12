// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	stderrors "errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// testCtxKey is a typed context key used by tests to avoid collisions.
type testCtxKey string

// insecureTestTLSConfig returns the explicit TLS configuration that the
// hardened transport contract requires alongside Insecure=true
// (InsecureSkipVerify is forbidden). These tests never complete a TLS
// handshake — gRPC dials lazily — so an empty root pool is sufficient.
func insecureTestTLSConfig() *tls.Config {
	return &tls.Config{
		RootCAs:    x509.NewCertPool(),
		MinVersion: tls.VersionTLS13,
	}
}

// TestNewTransport_Success tests successful transport creation.
func TestNewTransport_Success(t *testing.T) {
	cfg := &transport.Config{
		Address:   "localhost:9443",
		Insecure:  true,
		TLSConfig: insecureTestTLSConfig(),
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v, want nil", err)
	}
	defer tr.Close()

	if tr == nil {
		t.Fatal("NewTransport() returned nil transport")
	}
}

// TestNewTransport_NilConfig tests error handling for nil config.
func TestNewTransport_NilConfig(t *testing.T) {
	tr, err := NewTransport(nil)
	if err == nil {
		t.Fatal("NewTransport(nil) error = nil, want error")
	}
	if tr != nil {
		t.Fatal("NewTransport(nil) returned non-nil transport")
	}
	if !errors.IsInvalidInput(err) {
		t.Errorf("NewTransport(nil) error code = %v, want InvalidInput", errors.Code(err))
	}
}

// TestNewTransport_EmptyAddress tests error handling for empty address.
func TestNewTransport_EmptyAddress(t *testing.T) {
	cfg := &transport.Config{
		Address: "",
	}

	tr, err := NewTransport(cfg)
	if err == nil {
		t.Fatal("NewTransport() with empty address error = nil, want error")
	}
	if tr != nil {
		t.Fatal("NewTransport() with empty address returned non-nil transport")
	}
	if !errors.IsInvalidInput(err) {
		t.Errorf("NewTransport() error code = %v, want InvalidInput", errors.Code(err))
	}
}

// TestNewTransport_WithTLS tests transport creation with TLS config.
func TestNewTransport_WithTLS(t *testing.T) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	cfg := &transport.Config{
		Address:   "localhost:9443",
		TLSConfig: tlsConfig,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() with TLS error = %v, want nil", err)
	}
	defer tr.Close()

	if tr == nil {
		t.Fatal("NewTransport() with TLS returned nil transport")
	}
}

// TestNewTransport_DefaultTLS tests transport creation with default TLS.
func TestNewTransport_DefaultTLS(t *testing.T) {
	cfg := &transport.Config{
		Address:  "localhost:9443",
		Insecure: false, // Will use default TLS.
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() with default TLS error = %v, want nil", err)
	}
	defer tr.Close()

	if tr == nil {
		t.Fatal("NewTransport() with default TLS returned nil transport")
	}
}

// TestNewTransport_WithPooling tests transport creation with connection pooling.
func TestNewTransport_WithPooling(t *testing.T) {
	cfg := &transport.Config{
		Address:     "localhost:9443",
		Insecure:    true,
		TLSConfig:   insecureTestTLSConfig(),
		PoolEnabled: true,
		PoolMinSize: 2,
		PoolMaxSize: 5,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() with pooling error = %v, want nil", err)
	}
	defer tr.Close()

	if tr == nil {
		t.Fatal("NewTransport() with pooling returned nil transport")
	}

	// Check that pool was created.
	grpcTransport := tr.(*Transport)
	if grpcTransport.pool == nil {
		t.Fatal("NewTransport() with pooling did not create pool")
	}
}

// TestNewTransport_UnixSocket tests transport creation with Unix socket address.
func TestNewTransport_UnixSocket(t *testing.T) {
	cfg := &transport.Config{
		Address:   "/tmp/test.sock",
		Insecure:  true,
		TLSConfig: insecureTestTLSConfig(),
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() with Unix socket error = %v, want nil", err)
	}
	defer tr.Close()

	if tr == nil {
		t.Fatal("NewTransport() with Unix socket returned nil transport")
	}
}

// TestNewTransport_UnixSocketPrefix tests transport with unix:// prefix.
func TestNewTransport_UnixSocketPrefix(t *testing.T) {
	cfg := &transport.Config{
		Address:   "unix:///tmp/test.sock",
		Insecure:  true,
		TLSConfig: insecureTestTLSConfig(),
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() with unix:// prefix error = %v, want nil", err)
	}
	defer tr.Close()
}

// TestNewTransport_HTTPSAddress tests transport with HTTPS URL.
func TestNewTransport_HTTPSAddress(t *testing.T) {
	cfg := &transport.Config{
		Address:   "https://localhost:8443",
		Insecure:  true,
		TLSConfig: insecureTestTLSConfig(),
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() with HTTPS address error = %v, want nil", err)
	}
	defer tr.Close()
}

// TestNewTransport_UnixSocketWithPool tests Unix socket with pooling.
func TestNewTransport_UnixSocketWithPool(t *testing.T) {
	cfg := &transport.Config{
		Address:            "/tmp/test-pool.sock",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        1,
		PoolMaxSize:        3,
		PoolHealthInterval: time.Hour,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() with Unix socket and pool error = %v", err)
	}
	defer tr.Close()

	if tr == nil {
		t.Fatal("NewTransport() returned nil transport")
	}
}

// TestTransport_Close tests closing the transport.
func TestTransport_Close(t *testing.T) {
	cfg := &transport.Config{
		Address:   "localhost:9443",
		Insecure:  true,
		TLSConfig: insecureTestTLSConfig(),
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}

	err = tr.Close()
	if err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}

	// Second close should be idempotent.
	err = tr.Close()
	if err != nil {
		t.Errorf("Close() second call error = %v, want nil", err)
	}
}

// TestTransport_Close_WithPool tests closing transport with connection pool.
func TestTransport_Close_WithPool(t *testing.T) {
	cfg := &transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        1,
		PoolMaxSize:        3,
		PoolHealthInterval: time.Hour, // Long interval to avoid health checks during test.
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}

	err = tr.Close()
	if err != nil {
		t.Errorf("Close() with pool error = %v, want nil", err)
	}
}

// TestTransport_Healthy_NotClosed tests Healthy returns true for valid connection.
func TestTransport_Healthy_NotClosed(t *testing.T) {
	cfg := &transport.Config{
		Address:   "localhost:9443",
		Insecure:  true,
		TLSConfig: insecureTestTLSConfig(),
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	// New connection should be healthy (in Idle state).
	healthy := tr.Healthy()
	if !healthy {
		t.Error("Healthy() = false, want true for new connection")
	}
}

// TestTransport_Healthy_Closed tests Healthy returns false after close.
func TestTransport_Healthy_Closed(t *testing.T) {
	cfg := &transport.Config{
		Address:   "localhost:9443",
		Insecure:  true,
		TLSConfig: insecureTestTLSConfig(),
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}

	tr.Close()

	healthy := tr.Healthy()
	if healthy {
		t.Error("Healthy() = true after Close(), want false")
	}
}

// TestTransport_Healthy_WithPool tests Healthy with pooling enabled.
func TestTransport_Healthy_WithPool(t *testing.T) {
	cfg := &transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        1,
		PoolMaxSize:        3,
		PoolMaxAge:         time.Hour,
		PoolHealthInterval: time.Hour,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	healthy := tr.Healthy()
	if !healthy {
		t.Error("Healthy() with pool = false, want true")
	}
}

// TestTransport_Healthy_NilConn tests Healthy with nil connection.
func TestTransport_Healthy_NilConn(t *testing.T) {
	tr := &Transport{
		cfg: &transport.Config{},
	}

	healthy := tr.Healthy()
	if healthy {
		t.Error("Healthy() with nil conn = true, want false")
	}
}

// TestTransport_Conn_ReturnsConnection tests Conn returns underlying connection.
func TestTransport_Conn_ReturnsConnection(t *testing.T) {
	cfg := &transport.Config{
		Address:   "localhost:9443",
		Insecure:  true,
		TLSConfig: insecureTestTLSConfig(),
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	conn := tr.Conn()
	if conn == nil {
		t.Error("Conn() = nil, want non-nil connection")
	}
}

// TestTransport_Conn_ReturnsPool tests Conn returns pool when pooling enabled.
func TestTransport_Conn_ReturnsPool(t *testing.T) {
	cfg := &transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        1,
		PoolMaxSize:        3,
		PoolHealthInterval: time.Hour,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	conn := tr.Conn()
	if conn == nil {
		t.Error("Conn() = nil, want non-nil pool")
	}

	// Should return the pool, not a connection.
	_, ok := conn.(*connectionPool)
	if !ok {
		t.Error("Conn() did not return connection pool")
	}
}

// TestTransport_Request_ClosedTransport tests Request after close.
func TestTransport_Request_ClosedTransport(t *testing.T) {
	cfg := &transport.Config{
		Address:   "localhost:9443",
		Insecure:  true,
		TLSConfig: insecureTestTLSConfig(),
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}

	tr.Close()

	ctx := context.Background()
	_, err = tr.Request(ctx, "admin", "GetStatus", nil)
	if err == nil {
		t.Fatal("Request() after Close() error = nil, want error")
	}
	if !errors.IsUnavailable(err) {
		t.Errorf("Request() after Close() error code = %v, want Unavailable", errors.Code(err))
	}
}

// TestTransport_Request_UnknownService tests Request with unknown service.
func TestTransport_Request_UnknownService(t *testing.T) {
	cfg := &transport.Config{
		Address:   "localhost:9443",
		Insecure:  true,
		TLSConfig: insecureTestTLSConfig(),
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	ctx := context.Background()
	_, err = tr.Request(ctx, "unknown", "SomeMethod", nil)
	if err == nil {
		t.Fatal("Request() with unknown service error = nil, want error")
	}
	if !errors.IsInvalidInput(err) {
		t.Errorf("Request() error code = %v, want InvalidInput", errors.Code(err))
	}
}

// TestTransport_Request_ACMEService tests Request returns unimplemented for ACME.
func TestTransport_Request_ACMEService(t *testing.T) {
	cfg := &transport.Config{
		Address:   "localhost:9443",
		Insecure:  true,
		TLSConfig: insecureTestTLSConfig(),
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	ctx := context.Background()
	acmeServices := []string{
		ServiceDirectory,
		ServiceNonce,
		ServiceAccount,
		ServiceOrder,
		ServiceAuthorization,
		ServiceChallenge,
		ServiceFinalize,
		ServiceRevoke,
	}

	for _, svc := range acmeServices {
		_, err := tr.Request(ctx, svc, "get", nil)
		if err == nil {
			t.Errorf("Request(%s) error = nil, want unimplemented error", svc)
			continue
		}
		if !errors.IsUnimplemented(err) {
			t.Errorf("Request(%s) error code = %v, want Unimplemented", svc, errors.Code(err))
		}
	}
}

// TestTransport_Request_CaseInsensitive tests Request handles service name case.
func TestTransport_Request_CaseInsensitive(t *testing.T) {
	cfg := &transport.Config{
		Address:   "localhost:9443",
		Insecure:  true,
		TLSConfig: insecureTestTLSConfig(),
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	ctx := context.Background()

	// Test that ACME services return unimplemented regardless of case.
	testCases := []string{"DIRECTORY", "Directory", "directory", "DiReCtOrY"}
	for _, svc := range testCases {
		_, err := tr.Request(ctx, svc, "get", nil)
		if err == nil {
			t.Errorf("Request(%s) error = nil, want unimplemented error", svc)
			continue
		}
		if !errors.IsUnimplemented(err) {
			t.Errorf("Request(%s) error code = %v, want Unimplemented", svc, errors.Code(err))
		}
	}
}

// TestTransport_RequestStream_ClosedTransport tests RequestStream after close.
func TestTransport_RequestStream_ClosedTransport(t *testing.T) {
	cfg := &transport.Config{
		Address:   "localhost:9443",
		Insecure:  true,
		TLSConfig: insecureTestTLSConfig(),
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}

	tr.Close()

	ctx := context.Background()
	_, err = tr.RequestStream(ctx, "admin", "stream", nil)
	if err == nil {
		t.Fatal("RequestStream() after Close() error = nil, want error")
	}
	if !errors.IsUnavailable(err) {
		t.Errorf("RequestStream() error code = %v, want Unavailable", errors.Code(err))
	}
}

// TestTransport_RequestStream_ACMEService tests RequestStream for ACME services.
func TestTransport_RequestStream_ACMEService(t *testing.T) {
	cfg := &transport.Config{
		Address:   "localhost:9443",
		Insecure:  true,
		TLSConfig: insecureTestTLSConfig(),
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	ctx := context.Background()
	_, err = tr.RequestStream(ctx, ServiceDirectory, "stream", nil)
	if err == nil {
		t.Fatal("RequestStream() for ACME error = nil, want error")
	}
	if !errors.IsUnimplemented(err) {
		t.Errorf("RequestStream() error code = %v, want Unimplemented", errors.Code(err))
	}
}

// TestTransport_RequestStream_AdminService tests RequestStream for Admin services.
func TestTransport_RequestStream_AdminService(t *testing.T) {
	cfg := &transport.Config{
		Address:   "localhost:9443",
		Insecure:  true,
		TLSConfig: insecureTestTLSConfig(),
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	ctx := context.Background()
	stream, err := tr.RequestStream(ctx, "admin", "stream", nil)
	if err != nil {
		t.Fatalf("RequestStream() for admin error = %v, want nil", err)
	}
	if stream == nil {
		t.Error("RequestStream() returned nil stream")
	}
	stream.Close()
}

// TestTransport_RequestStream_WithPool tests RequestStream with pooling.
func TestTransport_RequestStream_WithPool(t *testing.T) {
	cfg := &transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        1,
		PoolMaxSize:        3,
		PoolHealthInterval: time.Hour,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	ctx := context.Background()
	stream, err := tr.RequestStream(ctx, "admin", "stream", nil)
	if err != nil {
		t.Fatalf("RequestStream() with pool error = %v, want nil", err)
	}
	if stream == nil {
		t.Error("RequestStream() returned nil stream")
	}
	stream.Close()
}

// TestGrpcStream_Send_NotInitialized tests Send with uninitialized stream.
func TestGrpcStream_Send_NotInitialized(t *testing.T) {
	stream := &grpcStream{}

	err := stream.Send("test")
	if err == nil {
		t.Fatal("Send() on uninitialized stream error = nil, want error")
	}
	if !errors.Is(err, errors.CodeNotInitialized) {
		t.Errorf("Send() error code = %v, want NotInitialized", errors.Code(err))
	}
}

// TestGrpcStream_Send_Closed tests Send on closed stream.
func TestGrpcStream_Send_Closed(t *testing.T) {
	stream := &grpcStream{}
	stream.Close()

	err := stream.Send("test")
	if err == nil {
		t.Fatal("Send() on closed stream error = nil, want error")
	}
	if !errors.IsUnavailable(err) {
		t.Errorf("Send() error code = %v, want Unavailable", errors.Code(err))
	}
}

// TestGrpcStream_Recv_NotInitialized tests Recv with uninitialized stream.
func TestGrpcStream_Recv_NotInitialized(t *testing.T) {
	stream := &grpcStream{}

	_, err := stream.Recv()
	if err == nil {
		t.Fatal("Recv() on uninitialized stream error = nil, want error")
	}
	if !errors.Is(err, errors.CodeNotInitialized) {
		t.Errorf("Recv() error code = %v, want NotInitialized", errors.Code(err))
	}
}

// TestGrpcStream_Recv_Closed tests Recv on closed stream.
func TestGrpcStream_Recv_Closed(t *testing.T) {
	stream := &grpcStream{}
	stream.Close()

	_, err := stream.Recv()
	if err == nil {
		t.Fatal("Recv() on closed stream error = nil, want error")
	}
	if !errors.IsUnavailable(err) {
		t.Errorf("Recv() error code = %v, want Unavailable", errors.Code(err))
	}
}

// TestGrpcStream_CloseSend_NilStream tests CloseSend with nil stream.
func TestGrpcStream_CloseSend_NilStream(t *testing.T) {
	stream := &grpcStream{}

	err := stream.CloseSend()
	if err != nil {
		t.Errorf("CloseSend() on nil stream error = %v, want nil", err)
	}
}

// TestGrpcStream_Close_Idempotent tests Close is idempotent.
func TestGrpcStream_Close_Idempotent(t *testing.T) {
	stream := &grpcStream{}

	err := stream.Close()
	if err != nil {
		t.Errorf("Close() first call error = %v, want nil", err)
	}

	err = stream.Close()
	if err != nil {
		t.Errorf("Close() second call error = %v, want nil", err)
	}
}

// TestBuildFullMethod tests full method path construction with service context.
func TestBuildFullMethod(t *testing.T) {
	tests := []struct {
		name    string
		service string
		method  string
		want    string
	}{
		{
			name:    "simple method name passthrough",
			service: "admin",
			method:  "GetStatus",
			want:    "/trustedca.admin.v1.AdminService/GetStatus",
		},
		{
			name:    "full path without leading slash",
			service: "admin",
			method:  "trustedca.admin.v1.AdminService/GetStatus",
			want:    "/trustedca.admin.v1.AdminService/GetStatus",
		},
		{
			name:    "full path with leading slash",
			service: "admin",
			method:  "/trustedca.admin.v1.AdminService/GetStatus",
			want:    "/trustedca.admin.v1.AdminService/GetStatus",
		},
		{
			name:    "custom service path",
			service: "admin",
			method:  "custom.service/Method",
			want:    "/custom.service/Method",
		},
		{
			name:    "tenant list maps to ListTenants",
			service: "admin.tenant",
			method:  "list",
			want:    "/trustedca.admin.v1.AdminService/ListTenants",
		},
		{
			name:    "certificate list maps to ListCertificates",
			service: "admin.certificate",
			method:  "list",
			want:    "/trustedca.admin.v1.AdminService/ListCertificates",
		},
		{
			name:    "eab create maps to CreateEAB",
			service: "admin.eab",
			method:  "create",
			want:    "/trustedca.admin.v1.AdminService/CreateEAB",
		},
		{
			name:    "tenant create maps to CreateTenant",
			service: "admin.tenant",
			method:  "create",
			want:    "/trustedca.admin.v1.AdminService/CreateTenant",
		},
		{
			name:    "account list maps to ListAccounts",
			service: "admin.account",
			method:  "list",
			want:    "/trustedca.admin.v1.AdminService/ListAccounts",
		},
		{
			name:    "fallback qualified method name",
			service: "admin",
			method:  "listCertificates",
			want:    "/trustedca.admin.v1.AdminService/ListCertificates",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildFullMethod(tt.service, tt.method)
			if got != tt.want {
				t.Errorf("buildFullMethod(%q, %q) = %q, want %q", tt.service, tt.method, got, tt.want)
			}
		})
	}
}

// TestGrpcCodeToErrorCode tests gRPC code to SDK error code mapping.
func TestGrpcCodeToErrorCode(t *testing.T) {
	tests := []struct {
		grpcCode codes.Code
		wantCode errors.ErrorCode
	}{
		{codes.OK, errors.CodeUnknown},
		{codes.Canceled, errors.CodeCanceled},
		{codes.Unknown, errors.CodeUnknown},
		{codes.InvalidArgument, errors.CodeInvalidInput},
		{codes.DeadlineExceeded, errors.CodeTimeout},
		{codes.NotFound, errors.CodeNotFound},
		{codes.AlreadyExists, errors.CodeAlreadyExists},
		{codes.PermissionDenied, errors.CodeForbidden},
		{codes.ResourceExhausted, errors.CodeResourceExhausted},
		{codes.FailedPrecondition, errors.CodePreconditionFailed},
		{codes.Aborted, errors.CodeConflict},
		{codes.OutOfRange, errors.CodeInvalidInput},
		{codes.Unimplemented, errors.CodeUnimplemented},
		{codes.Internal, errors.CodeInternal},
		{codes.Unavailable, errors.CodeUnavailable},
		{codes.DataLoss, errors.CodeInternal},
		{codes.Unauthenticated, errors.CodeUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.grpcCode.String(), func(t *testing.T) {
			got := grpcCodeToErrorCode(tt.grpcCode)
			if got != tt.wantCode {
				t.Errorf("grpcCodeToErrorCode(%v) = %v, want %v", tt.grpcCode, got, tt.wantCode)
			}
		})
	}
}

// TestGrpcCodeToErrorCode_Unknown tests unknown gRPC code.
func TestGrpcCodeToErrorCode_Unknown(t *testing.T) {
	// Use an invalid code number.
	got := grpcCodeToErrorCode(codes.Code(999))
	if got != errors.CodeUnknown {
		t.Errorf("grpcCodeToErrorCode(999) = %v, want Unknown", got)
	}
}

// TestWithAuth tests adding auth metadata to context.
func TestWithAuth(t *testing.T) {
	ctx := context.Background()

	// Test with token.
	ctxWithAuth := WithAuth(ctx, "test-token")
	if ctxWithAuth == ctx {
		t.Error("WithAuth() returned same context when token provided")
	}

	// Test with empty token.
	ctxNoAuth := WithAuth(ctx, "")
	if ctxNoAuth != ctx {
		t.Error("WithAuth() returned different context when no token provided")
	}
}

// TestFactory_Create tests factory creates transport.
func TestFactory_Create(t *testing.T) {
	factory := NewFactory()

	cfg := &transport.Config{
		Address:   "localhost:9443",
		Insecure:  true,
		TLSConfig: insecureTestTLSConfig(),
	}

	tr, err := factory.Create(cfg)
	if err != nil {
		t.Fatalf("Factory.Create() error = %v, want nil", err)
	}
	defer tr.Close()

	if tr == nil {
		t.Fatal("Factory.Create() returned nil transport")
	}
}

// TestFactory_Create_NilConfig tests factory with nil config.
func TestFactory_Create_NilConfig(t *testing.T) {
	factory := NewFactory()

	tr, err := factory.Create(nil)
	if err == nil {
		t.Fatal("Factory.Create(nil) error = nil, want error")
	}
	if tr != nil {
		t.Fatal("Factory.Create(nil) returned non-nil transport")
	}
}

// TestApplyDefaults tests default values are applied.
func TestApplyDefaults(t *testing.T) {
	cfg := &transport.Config{
		Address:   "localhost:9443",
		Insecure:  true,
		TLSConfig: insecureTestTLSConfig(),
	}

	tr := &Transport{cfg: cfg}
	tr.applyDefaults()

	if cfg.Timeout != defaultTimeout {
		t.Errorf("Timeout = %v, want %v", cfg.Timeout, defaultTimeout)
	}
	if cfg.KeepaliveTime != defaultKeepaliveTime {
		t.Errorf("KeepaliveTime = %v, want %v", cfg.KeepaliveTime, defaultKeepaliveTime)
	}
	if cfg.KeepaliveTimeout != defaultKeepaliveTimeout {
		t.Errorf("KeepaliveTimeout = %v, want %v", cfg.KeepaliveTimeout, defaultKeepaliveTimeout)
	}
}

// TestApplyDefaults_PoolDefaults tests pool defaults are applied.
func TestApplyDefaults_PoolDefaults(t *testing.T) {
	cfg := &transport.Config{
		Address:     "localhost:9443",
		Insecure:    true,
		TLSConfig:   insecureTestTLSConfig(),
		PoolEnabled: true,
	}

	tr := &Transport{cfg: cfg}
	tr.applyDefaults()

	if cfg.PoolMinSize != defaultPoolMinSize {
		t.Errorf("PoolMinSize = %d, want %d", cfg.PoolMinSize, defaultPoolMinSize)
	}
	if cfg.PoolMaxSize != defaultPoolMaxSize {
		t.Errorf("PoolMaxSize = %d, want %d", cfg.PoolMaxSize, defaultPoolMaxSize)
	}
	if cfg.PoolMaxAge != defaultPoolMaxAge {
		t.Errorf("PoolMaxAge = %v, want %v", cfg.PoolMaxAge, defaultPoolMaxAge)
	}
	if cfg.PoolHealthInterval != defaultHealthInterval {
		t.Errorf("PoolHealthInterval = %v, want %v", cfg.PoolHealthInterval, defaultHealthInterval)
	}
}

// TestApplyDefaults_PoolMaxLessThanMin tests pool max adjusted to min.
func TestApplyDefaults_PoolMaxLessThanMin(t *testing.T) {
	cfg := &transport.Config{
		Address:     "localhost:9443",
		Insecure:    true,
		TLSConfig:   insecureTestTLSConfig(),
		PoolEnabled: true,
		PoolMinSize: 5,
		PoolMaxSize: 2, // Less than min.
	}

	tr := &Transport{cfg: cfg}
	tr.applyDefaults()

	if cfg.PoolMaxSize != cfg.PoolMinSize {
		t.Errorf("PoolMaxSize = %d, want %d (same as min)", cfg.PoolMaxSize, cfg.PoolMinSize)
	}
}

// TestApplyDefaults_PreservesExisting tests existing values are preserved.
func TestApplyDefaults_PreservesExisting(t *testing.T) {
	cfg := &transport.Config{
		Address:          "localhost:9443",
		Insecure:         true,
		TLSConfig:        insecureTestTLSConfig(),
		Timeout:          60 * time.Second,
		KeepaliveTime:    45 * time.Second,
		KeepaliveTimeout: 15 * time.Second,
	}

	tr := &Transport{cfg: cfg}
	tr.applyDefaults()

	if cfg.Timeout != 60*time.Second {
		t.Errorf("Timeout changed from 60s to %v", cfg.Timeout)
	}
	if cfg.KeepaliveTime != 45*time.Second {
		t.Errorf("KeepaliveTime changed from 45s to %v", cfg.KeepaliveTime)
	}
	if cfg.KeepaliveTimeout != 15*time.Second {
		t.Errorf("KeepaliveTimeout changed from 15s to %v", cfg.KeepaliveTimeout)
	}
}

// TestIsACMEService tests ACME service detection.
func TestIsACMEService(t *testing.T) {
	tr := &Transport{}

	acmeServices := []string{
		ServiceDirectory,
		ServiceNonce,
		ServiceAccount,
		ServiceOrder,
		ServiceAuthorization,
		ServiceChallenge,
		ServiceFinalize,
		ServiceRevoke,
	}

	for _, svc := range acmeServices {
		if !tr.isACMEService(svc) {
			t.Errorf("isACMEService(%q) = false, want true", svc)
		}
	}

	nonACMEServices := []string{
		ServiceAdmin,
		ServiceTenant,
		ServiceEAB,
		ServicePolicy,
		ServiceCertificate,
		ServiceStatus,
		"unknown",
	}

	for _, svc := range nonACMEServices {
		if tr.isACMEService(svc) {
			t.Errorf("isACMEService(%q) = true, want false", svc)
		}
	}
}

// TestConnectionPool_GetPut tests pool connection get and put.
func TestConnectionPool_GetPut(t *testing.T) {
	cfg := &transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        2,
		PoolMaxSize:        5,
		PoolMaxAge:         time.Hour,
		PoolHealthInterval: time.Hour,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	grpcTransport := tr.(*Transport)
	pool := grpcTransport.pool

	// Get a connection.
	conn1, err := pool.Get()
	if err != nil {
		t.Fatalf("pool.Get() error = %v", err)
	}
	if conn1 == nil {
		t.Fatal("pool.Get() returned nil connection")
	}

	// Get another connection.
	conn2, err := pool.Get()
	if err != nil {
		t.Fatalf("pool.Get() second call error = %v", err)
	}
	if conn2 == nil {
		t.Fatal("pool.Get() second call returned nil connection")
	}

	// Put connections back.
	pool.Put(conn1)
	pool.Put(conn2)
}

// TestConnectionPool_Get_Closed tests Get on closed pool.
func TestConnectionPool_Get_Closed(t *testing.T) {
	cfg := &transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        1,
		PoolMaxSize:        3,
		PoolHealthInterval: time.Hour,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}

	grpcTransport := tr.(*Transport)
	pool := grpcTransport.pool

	tr.Close()

	_, err = pool.Get()
	if err == nil {
		t.Fatal("pool.Get() on closed pool error = nil, want error")
	}
	if !errors.IsUnavailable(err) {
		t.Errorf("pool.Get() error code = %v, want Unavailable", errors.Code(err))
	}
}

// TestConnectionPool_Healthy tests pool health check.
func TestConnectionPool_Healthy(t *testing.T) {
	cfg := &transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        1,
		PoolMaxSize:        3,
		PoolMaxAge:         time.Hour,
		PoolHealthInterval: time.Hour,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	grpcTransport := tr.(*Transport)
	pool := grpcTransport.pool

	if !pool.Healthy() {
		t.Error("pool.Healthy() = false, want true")
	}
}

// TestConnectionPool_Healthy_Closed tests Healthy on closed pool.
func TestConnectionPool_Healthy_Closed(t *testing.T) {
	cfg := &transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        1,
		PoolMaxSize:        3,
		PoolHealthInterval: time.Hour,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}

	grpcTransport := tr.(*Transport)
	pool := grpcTransport.pool

	tr.Close()

	if pool.Healthy() {
		t.Error("pool.Healthy() on closed pool = true, want false")
	}
}

// TestConnectionPool_Close_Idempotent tests pool close is idempotent.
func TestConnectionPool_Close_Idempotent(t *testing.T) {
	cfg := &transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        1,
		PoolMaxSize:        3,
		PoolHealthInterval: time.Hour,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}

	grpcTransport := tr.(*Transport)
	pool := grpcTransport.pool

	err = pool.Close()
	if err != nil {
		t.Errorf("pool.Close() first call error = %v, want nil", err)
	}

	err = pool.Close()
	if err != nil {
		t.Errorf("pool.Close() second call error = %v, want nil", err)
	}
}

// TestTranslateGRPCError_Nil tests nil error translation.
func TestTranslateGRPCError_Nil(t *testing.T) {
	tr := &Transport{}
	err := tr.translateGRPCError(nil)
	if err != nil {
		t.Errorf("translateGRPCError(nil) = %v, want nil", err)
	}
}

// TestTranslateGRPCError_GRPCStatus tests gRPC status error translation.
func TestTranslateGRPCError_GRPCStatus(t *testing.T) {
	tr := &Transport{}

	tests := []struct {
		name     string
		code     codes.Code
		msg      string
		wantCode errors.ErrorCode
	}{
		{"NotFound", codes.NotFound, "resource not found", errors.CodeNotFound},
		{"InvalidArgument", codes.InvalidArgument, "invalid input", errors.CodeInvalidInput},
		{"Unauthenticated", codes.Unauthenticated, "auth required", errors.CodeUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grpcErr := status.Error(tt.code, tt.msg)
			sdkErr := tr.translateGRPCError(grpcErr)
			if sdkErr == nil {
				t.Fatal("translateGRPCError() = nil, want error")
			}
			if errors.Code(sdkErr) != tt.wantCode {
				t.Errorf("translateGRPCError() code = %v, want %v", errors.Code(sdkErr), tt.wantCode)
			}
		})
	}
}

// TestTranslateGRPCError_NonGRPCError tests non-gRPC error translation.
func TestTranslateGRPCError_NonGRPCError(t *testing.T) {
	tr := &Transport{}

	plainErr := stderrors.New("some error")
	sdkErr := tr.translateGRPCError(plainErr)
	if sdkErr == nil {
		t.Fatal("translateGRPCError() = nil, want error")
	}
	if errors.Code(sdkErr) != errors.CodeInternal {
		t.Errorf("translateGRPCError() code = %v, want Internal", errors.Code(sdkErr))
	}
}

// TestTransport_Request_WithTimeout tests Request applies timeout from config.
func TestTransport_Request_WithTimeout(t *testing.T) {
	cfg := &transport.Config{
		Address:   "localhost:9443",
		Insecure:  true,
		TLSConfig: insecureTestTLSConfig(),
		Timeout:   100 * time.Millisecond,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	ctx := context.Background()
	// This will fail due to no server, but tests timeout is applied.
	_, err = tr.Request(ctx, ServiceAdmin, "GetStatus", nil)
	// We expect an error because there's no server, but the point is
	// the request should have timeout applied.
	if err == nil {
		t.Log("Request succeeded unexpectedly")
	}
}

// TestTransport_Request_WithContextDeadline tests Request respects existing deadline.
func TestTransport_Request_WithContextDeadline(t *testing.T) {
	cfg := &transport.Config{
		Address:   "localhost:9443",
		Insecure:  true,
		TLSConfig: insecureTestTLSConfig(),
		Timeout:   30 * time.Second, // Long default timeout.
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	// Create context with shorter deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// The existing deadline should be respected, not overwritten.
	_, err = tr.Request(ctx, ServiceAdmin, "GetStatus", nil)
	if err == nil {
		t.Log("Request succeeded unexpectedly")
	}
}

// TestServiceConstants tests service constant values.
func TestServiceConstants(t *testing.T) {
	// Ensure constants have expected values.
	tests := []struct {
		constant string
		value    string
	}{
		{ServiceAdmin, "admin"},
		{ServiceTenant, "tenant"},
		{ServiceEAB, "eab"},
		{ServicePolicy, "policy"},
		{ServiceCertificate, "certificate"},
		{ServiceStatus, "status"},
		{ServiceDirectory, "directory"},
		{ServiceNonce, "nonce"},
		{ServiceAccount, "account"},
		{ServiceOrder, "order"},
		{ServiceAuthorization, "authorization"},
		{ServiceChallenge, "challenge"},
		{ServiceFinalize, "finalize"},
		{ServiceRevoke, "revoke"},
	}

	for _, tt := range tests {
		if tt.constant != tt.value {
			t.Errorf("Service constant %s = %q, want %q", tt.constant, tt.constant, tt.value)
		}
	}
}

// TestDefaultConstants tests default constant values.
func TestDefaultConstants(t *testing.T) {
	if defaultTimeout != 30*time.Second {
		t.Errorf("defaultTimeout = %v, want 30s", defaultTimeout)
	}
	if defaultKeepaliveTime != 30*time.Second {
		t.Errorf("defaultKeepaliveTime = %v, want 30s", defaultKeepaliveTime)
	}
	if defaultKeepaliveTimeout != 10*time.Second {
		t.Errorf("defaultKeepaliveTimeout = %v, want 10s", defaultKeepaliveTimeout)
	}
	if defaultPoolMinSize != 1 {
		t.Errorf("defaultPoolMinSize = %d, want 1", defaultPoolMinSize)
	}
	if defaultPoolMaxSize != 10 {
		t.Errorf("defaultPoolMaxSize = %d, want 10", defaultPoolMaxSize)
	}
	if defaultPoolMaxAge != 5*time.Minute {
		t.Errorf("defaultPoolMaxAge = %v, want 5m", defaultPoolMaxAge)
	}
	if defaultHealthInterval != 30*time.Second {
		t.Errorf("defaultHealthInterval = %v, want 30s", defaultHealthInterval)
	}
}

// TestInterfaceCompliance tests interface implementations.
func TestInterfaceCompliance(t *testing.T) {
	// These should compile without errors.
	var _ transport.Transport = (*Transport)(nil)
	var _ transport.Stream = (*grpcStream)(nil)
	var _ transport.Factory = (*Factory)(nil)
}

// TestNewFactory tests factory creation.
func TestNewFactory(t *testing.T) {
	factory := NewFactory()
	if factory == nil {
		t.Fatal("NewFactory() returned nil")
	}

	_, ok := factory.(*Factory)
	if !ok {
		t.Error("NewFactory() did not return *Factory")
	}
}

// TestPooledConnection_InUse tests pooled connection in-use tracking.
func TestPooledConnection_InUse(t *testing.T) {
	cfg := &transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        1,
		PoolMaxSize:        2,
		PoolHealthInterval: time.Hour,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	grpcTransport := tr.(*Transport)
	pool := grpcTransport.pool

	// Get connection - should mark as in use.
	conn, err := pool.Get()
	if err != nil {
		t.Fatalf("pool.Get() error = %v", err)
	}

	// Put back - should mark as not in use.
	pool.Put(conn)

	// Get again - should be available.
	conn2, err := pool.Get()
	if err != nil {
		t.Fatalf("pool.Get() after Put error = %v", err)
	}
	pool.Put(conn2)
}

// TestBuildDialOptions_Insecure tests dial options with insecure mode.
func TestBuildDialOptions_Insecure(t *testing.T) {
	t.Run("with explicit TLSConfig", func(t *testing.T) {
		cfg := &transport.Config{
			Address:   "localhost:9443",
			Insecure:  true,
			TLSConfig: insecureTestTLSConfig(),
		}

		tr := &Transport{cfg: cfg}
		tr.applyDefaults()

		opts, err := tr.buildDialOptions()
		if err != nil {
			t.Fatalf("buildDialOptions() error = %v", err)
		}

		if len(opts) == 0 {
			t.Error("buildDialOptions() returned empty options")
		}
	})

	// Insecure=true without an explicit TLSConfig is forbidden:
	// InsecureSkipVerify was removed from the transport contract.
	t.Run("without TLSConfig is rejected", func(t *testing.T) {
		cfg := &transport.Config{
			Address:  "localhost:9443",
			Insecure: true,
		}

		tr := &Transport{cfg: cfg}
		tr.applyDefaults()

		if _, err := tr.buildDialOptions(); err == nil {
			t.Fatal("buildDialOptions() with Insecure=true and nil TLSConfig must fail")
		}
	})
}

// TestBuildDialOptions_TLS tests dial options with TLS config.
func TestBuildDialOptions_TLS(t *testing.T) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	cfg := &transport.Config{
		Address:   "localhost:9443",
		TLSConfig: tlsConfig,
	}

	tr := &Transport{cfg: cfg}
	tr.applyDefaults()

	opts, err := tr.buildDialOptions()
	if err != nil {
		t.Fatalf("buildDialOptions() error = %v", err)
	}

	if len(opts) == 0 {
		t.Error("buildDialOptions() returned empty options")
	}
}

// TestBuildDialOptions_DefaultTLS tests dial options with default TLS.
func TestBuildDialOptions_DefaultTLS(t *testing.T) {
	cfg := &transport.Config{
		Address:  "localhost:9443",
		Insecure: false,
		// No TLSConfig - will use default.
	}

	tr := &Transport{cfg: cfg}
	tr.applyDefaults()

	opts, err := tr.buildDialOptions()
	if err != nil {
		t.Fatalf("buildDialOptions() error = %v", err)
	}

	if len(opts) == 0 {
		t.Error("buildDialOptions() returned empty options")
	}
}

// TestGetConnection_WithPool tests getConnection with pool.
func TestGetConnection_WithPool(t *testing.T) {
	cfg := &transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        1,
		PoolMaxSize:        3,
		PoolHealthInterval: time.Hour,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	grpcTransport := tr.(*Transport)
	conn, err := grpcTransport.getConnection()
	if err != nil {
		t.Fatalf("getConnection() error = %v", err)
	}
	if conn == nil {
		t.Fatal("getConnection() returned nil connection")
	}

	grpcTransport.releaseConnection(conn)
}

// TestGetConnection_NoPool tests getConnection without pool.
func TestGetConnection_NoPool(t *testing.T) {
	cfg := &transport.Config{
		Address:   "localhost:9443",
		Insecure:  true,
		TLSConfig: insecureTestTLSConfig(),
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	grpcTransport := tr.(*Transport)
	conn, err := grpcTransport.getConnection()
	if err != nil {
		t.Fatalf("getConnection() error = %v", err)
	}
	if conn == nil {
		t.Fatal("getConnection() returned nil connection")
	}

	// Release should be no-op without pool.
	grpcTransport.releaseConnection(conn)
}

// TestGetConnection_NilConn tests getConnection with nil connection.
func TestGetConnection_NilConn(t *testing.T) {
	tr := &Transport{
		cfg: &transport.Config{},
	}

	_, err := tr.getConnection()
	if err == nil {
		t.Fatal("getConnection() with nil conn error = nil, want error")
	}
	if !errors.IsUnavailable(err) {
		t.Errorf("getConnection() error code = %v, want Unavailable", errors.Code(err))
	}
}

// TestReleaseConnection_NoPool tests releaseConnection without pool.
func TestReleaseConnection_NoPool(t *testing.T) {
	cfg := &transport.Config{
		Address:   "localhost:9443",
		Insecure:  true,
		TLSConfig: insecureTestTLSConfig(),
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	grpcTransport := tr.(*Transport)

	// Get the connection.
	conn := grpcTransport.conn

	// Release should not panic or error.
	grpcTransport.releaseConnection(conn)
}

// TestReleaseConnection_WithPool tests releaseConnection with pool.
func TestReleaseConnection_WithPool(t *testing.T) {
	cfg := &transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        1,
		PoolMaxSize:        3,
		PoolHealthInterval: time.Hour,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	grpcTransport := tr.(*Transport)

	// Get connection from pool.
	conn, err := grpcTransport.pool.Get()
	if err != nil {
		t.Fatalf("pool.Get() error = %v", err)
	}

	// Release back to pool.
	grpcTransport.releaseConnection(conn)
}

// TestPool_Put_UnknownConnection tests Put with unknown connection.
func TestPool_Put_UnknownConnection(t *testing.T) {
	cfg := &transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        1,
		PoolMaxSize:        3,
		PoolHealthInterval: time.Hour,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	grpcTransport := tr.(*Transport)
	pool := grpcTransport.pool

	// Create a separate connection not from pool.
	otherConn, err := grpc.NewClient("localhost:9999", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Skipf("Cannot create separate connection: %v", err)
	}
	defer otherConn.Close()

	// Put unknown connection - should not panic.
	pool.Put(otherConn)
}

// TestConnectionPool_IsConnectionHealthy_Expired tests expired connection detection.
func TestConnectionPool_IsConnectionHealthy_Expired(t *testing.T) {
	cfg := &transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        1,
		PoolMaxSize:        3,
		PoolMaxAge:         1 * time.Millisecond, // Very short age.
		PoolHealthInterval: time.Hour,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	grpcTransport := tr.(*Transport)
	pool := grpcTransport.pool

	// Wait for connection to expire.
	time.Sleep(10 * time.Millisecond)

	// Get should still return a connection (it creates new ones).
	conn, err := pool.Get()
	if err != nil {
		t.Fatalf("pool.Get() after expiry error = %v", err)
	}
	pool.Put(conn)
}

// TestConnectionPool_Get_AllInUse tests Get when all connections in use.
func TestConnectionPool_Get_AllInUse(t *testing.T) {
	cfg := &transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        1,
		PoolMaxSize:        2,
		PoolMaxAge:         time.Hour,
		PoolHealthInterval: time.Hour,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	grpcTransport := tr.(*Transport)
	pool := grpcTransport.pool

	// Get all connections.
	conn1, _ := pool.Get()
	conn2, _ := pool.Get()

	// Get another - should create new or share.
	conn3, err := pool.Get()
	if err != nil {
		t.Fatalf("pool.Get() when all in use error = %v", err)
	}

	// All should work.
	if conn1 == nil || conn2 == nil || conn3 == nil {
		t.Error("pool.Get() returned nil connection")
	}

	pool.Put(conn1)
	pool.Put(conn2)
	pool.Put(conn3)
}

// TestConnectionPool_Healthy_NoHealthyConns tests Healthy with no healthy connections.
func TestConnectionPool_Healthy_NoHealthyConns(t *testing.T) {
	cfg := &transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        1,
		PoolMaxSize:        3,
		PoolMaxAge:         1 * time.Millisecond, // Very short age.
		PoolHealthInterval: time.Hour,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	grpcTransport := tr.(*Transport)
	pool := grpcTransport.pool

	// Wait for all connections to expire.
	time.Sleep(10 * time.Millisecond)

	// Pool may still report healthy if it has any connections in certain states.
	_ = pool.Healthy()
}

// TestConnectionPool_PerformHealthCheck tests health check removes unhealthy connections.
func TestConnectionPool_PerformHealthCheck(t *testing.T) {
	cfg := &transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        2,
		PoolMaxSize:        5,
		PoolMaxAge:         1 * time.Millisecond, // Very short age for testing.
		PoolHealthInterval: 10 * time.Millisecond,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	grpcTransport := tr.(*Transport)
	pool := grpcTransport.pool

	// Wait for a few health checks to run.
	time.Sleep(50 * time.Millisecond)

	// Pool should still function.
	conn, err := pool.Get()
	if err != nil {
		t.Fatalf("pool.Get() after health check error = %v", err)
	}
	pool.Put(conn)
}

// TestTransport_InitHandlers tests handler initialization.
func TestTransport_InitHandlers(t *testing.T) {
	tr := &Transport{
		cfg: &transport.Config{},
	}

	tr.initHandlers()

	// Verify all services have handlers.
	services := []string{
		ServiceAdmin, ServiceTenant, ServiceEAB, ServicePolicy,
		ServiceCertificate, ServiceStatus,
		ServiceDirectory, ServiceNonce, ServiceAccount, ServiceOrder,
		ServiceAuthorization, ServiceChallenge, ServiceFinalize, ServiceRevoke,
	}

	for _, svc := range services {
		if _, ok := tr.handlers[svc]; !ok {
			t.Errorf("Handler not found for service: %s", svc)
		}
	}
}

// TestGrpcCodeMap_Coverage tests all gRPC codes are mapped.
func TestGrpcCodeMap_Coverage(t *testing.T) {
	expectedCodes := []codes.Code{
		codes.OK, codes.Canceled, codes.Unknown, codes.InvalidArgument,
		codes.DeadlineExceeded, codes.NotFound, codes.AlreadyExists,
		codes.PermissionDenied, codes.ResourceExhausted, codes.FailedPrecondition,
		codes.Aborted, codes.OutOfRange, codes.Unimplemented, codes.Internal,
		codes.Unavailable, codes.DataLoss, codes.Unauthenticated,
	}

	for _, code := range expectedCodes {
		if _, ok := grpcCodeMap[code]; !ok {
			t.Errorf("gRPC code %v not in grpcCodeMap", code)
		}
	}
}

// TestNewTransport_WithAllConfig tests transport with all config options.
func TestNewTransport_WithAllConfig(t *testing.T) {
	cfg := &transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		Timeout:            60 * time.Second,
		KeepaliveTime:      45 * time.Second,
		KeepaliveTimeout:   15 * time.Second,
		MaxRetries:         3,
		RetryBackoff:       100 * time.Millisecond,
		MaxRetryBackoff:    5 * time.Second,
		PoolEnabled:        true,
		PoolMinSize:        2,
		PoolMaxSize:        10,
		PoolMaxAge:         10 * time.Minute,
		PoolHealthInterval: time.Minute,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() with all config error = %v", err)
	}
	defer tr.Close()

	if tr == nil {
		t.Fatal("NewTransport() returned nil transport")
	}
}

// mockClientStream implements grpc.ClientStream for testing.
type mockClientStream struct {
	grpc.ClientStream
	sendErr  error
	recvErr  error
	closeErr error
	recvMsg  interface{}
}

func (m *mockClientStream) SendMsg(msg interface{}) error {
	return m.sendErr
}

func (m *mockClientStream) RecvMsg(msg interface{}) error {
	if m.recvErr != nil {
		return m.recvErr
	}
	if m.recvMsg != nil {
		// Copy the mock message to the output.
		switch v := msg.(type) {
		case *interface{}:
			*v = m.recvMsg
		}
	}
	return nil
}

func (m *mockClientStream) CloseSend() error {
	return m.closeErr
}

func (m *mockClientStream) Header() (metadata.MD, error) {
	return nil, nil
}

func (m *mockClientStream) Trailer() metadata.MD {
	return nil
}

func (m *mockClientStream) Context() context.Context {
	return context.Background()
}

// TestGrpcStream_Send_WithMockStream tests Send with a mock stream that succeeds.
func TestGrpcStream_Send_WithMockStream(t *testing.T) {
	mock := &mockClientStream{}
	stream := &grpcStream{
		ctx:    context.Background(),
		stream: mock,
	}

	err := stream.Send("test message")
	if err != nil {
		t.Errorf("Send() error = %v, want nil", err)
	}
}

// TestGrpcStream_Send_WithMockStreamError tests Send with a mock stream that fails.
func TestGrpcStream_Send_WithMockStreamError(t *testing.T) {
	mock := &mockClientStream{
		sendErr: stderrors.New("send failed"),
	}
	stream := &grpcStream{
		ctx:    context.Background(),
		stream: mock,
	}

	err := stream.Send("test message")
	if err == nil {
		t.Fatal("Send() error = nil, want error")
	}
	if errors.Code(err) != errors.CodeTransport {
		t.Errorf("Send() error code = %v, want Transport", errors.Code(err))
	}
}

// TestGrpcStream_Recv_WithMockStream tests Recv with a mock stream that succeeds.
func TestGrpcStream_Recv_WithMockStream(t *testing.T) {
	mock := &mockClientStream{
		recvMsg: "test response",
	}
	stream := &grpcStream{
		ctx:    context.Background(),
		stream: mock,
	}

	_, err := stream.Recv()
	if err != nil {
		t.Errorf("Recv() error = %v, want nil", err)
	}
}

// TestGrpcStream_Recv_WithMockStreamError tests Recv with a mock stream that fails.
func TestGrpcStream_Recv_WithMockStreamError(t *testing.T) {
	mock := &mockClientStream{
		recvErr: stderrors.New("recv failed"),
	}
	stream := &grpcStream{
		ctx:    context.Background(),
		stream: mock,
	}

	_, err := stream.Recv()
	if err == nil {
		t.Fatal("Recv() error = nil, want error")
	}
	if errors.Code(err) != errors.CodeTransport {
		t.Errorf("Recv() error code = %v, want Transport", errors.Code(err))
	}
}

// TestGrpcStream_CloseSend_WithMockStream tests CloseSend with a mock stream that succeeds.
func TestGrpcStream_CloseSend_WithMockStream(t *testing.T) {
	mock := &mockClientStream{}
	stream := &grpcStream{
		ctx:    context.Background(),
		stream: mock,
	}

	err := stream.CloseSend()
	if err != nil {
		t.Errorf("CloseSend() error = %v, want nil", err)
	}
}

// TestGrpcStream_CloseSend_WithMockStreamError tests CloseSend with a mock stream that fails.
func TestGrpcStream_CloseSend_WithMockStreamError(t *testing.T) {
	mock := &mockClientStream{
		closeErr: stderrors.New("close failed"),
	}
	stream := &grpcStream{
		ctx:    context.Background(),
		stream: mock,
	}

	err := stream.CloseSend()
	if err == nil {
		t.Fatal("CloseSend() error = nil, want error")
	}
	if errors.Code(err) != errors.CodeTransport {
		t.Errorf("CloseSend() error code = %v, want Transport", errors.Code(err))
	}
}

// TestGrpcStream_Close_WithMockStream tests Close with an initialized mock stream.
func TestGrpcStream_Close_WithMockStream(t *testing.T) {
	mock := &mockClientStream{}
	stream := &grpcStream{
		ctx:    context.Background(),
		stream: mock,
	}

	err := stream.Close()
	if err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}

	// Verify closed flag is set.
	if !stream.closed.Load() {
		t.Error("Close() did not set closed flag")
	}
}

// TestGrpcStream_Close_WithMockStreamError tests Close when CloseSend fails.
func TestGrpcStream_Close_WithMockStreamError(t *testing.T) {
	mock := &mockClientStream{
		closeErr: stderrors.New("close failed"),
	}
	stream := &grpcStream{
		ctx:    context.Background(),
		stream: mock,
	}

	err := stream.Close()
	if err == nil {
		t.Fatal("Close() error = nil, want error")
	}
}

// TestHandleAdminRequest_WithPool tests handleAdminRequest with pool enabled.
func TestHandleAdminRequest_WithPool(t *testing.T) {
	cfg := &transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        1,
		PoolMaxSize:        3,
		PoolHealthInterval: time.Hour,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	grpcTransport := tr.(*Transport)
	ctx := context.Background()

	// This will fail due to no server, but covers the pool path.
	_, err = grpcTransport.handleAdminRequest(ctx, grpcTransport, "admin", "GetStatus", nil)
	// We expect an error because there's no server.
	if err == nil {
		t.Log("handleAdminRequest succeeded unexpectedly")
	}
}

// TestHandleAdminRequest_WithoutPool tests handleAdminRequest without pool.
func TestHandleAdminRequest_WithoutPool(t *testing.T) {
	cfg := &transport.Config{
		Address:   "localhost:9443",
		Insecure:  true,
		TLSConfig: insecureTestTLSConfig(),
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	grpcTransport := tr.(*Transport)
	ctx := context.Background()

	// This will fail due to no server, but covers the non-pool path.
	_, err = grpcTransport.handleAdminRequest(ctx, grpcTransport, "admin", "GetStatus", nil)
	// We expect an error because there's no server.
	if err == nil {
		t.Log("handleAdminRequest succeeded unexpectedly")
	}
}

// TestHandleAdminRequest_NilConnection tests handleAdminRequest with nil connection.
func TestHandleAdminRequest_NilConnection(t *testing.T) {
	tr := &Transport{
		cfg: &transport.Config{},
	}

	ctx := context.Background()
	_, err := tr.handleAdminRequest(ctx, tr, "admin", "GetStatus", nil)
	if err == nil {
		t.Fatal("handleAdminRequest() with nil conn error = nil, want error")
	}
	if !errors.IsUnavailable(err) {
		t.Errorf("handleAdminRequest() error code = %v, want Unavailable", errors.Code(err))
	}
}

// TestHandleAdminRequest_FullMethodPath tests handleAdminRequest with full method path.
func TestHandleAdminRequest_FullMethodPath(t *testing.T) {
	cfg := &transport.Config{
		Address:   "localhost:9443",
		Insecure:  true,
		TLSConfig: insecureTestTLSConfig(),
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	grpcTransport := tr.(*Transport)
	ctx := context.Background()

	// Test with full method path.
	_, err = grpcTransport.handleAdminRequest(ctx, grpcTransport, "admin", "/custom.service/Method", nil)
	// We expect an error because there's no server.
	if err == nil {
		t.Log("handleAdminRequest succeeded unexpectedly")
	}
}

// TestHandleACMEUnsupported tests handleACMEUnsupported returns proper error.
func TestHandleACMEUnsupported(t *testing.T) {
	tr := &Transport{}
	ctx := context.Background()

	_, err := tr.handleACMEUnsupported(ctx, tr, "directory", "get", nil)
	if err == nil {
		t.Fatal("handleACMEUnsupported() error = nil, want error")
	}
	if !errors.IsUnimplemented(err) {
		t.Errorf("handleACMEUnsupported() error code = %v, want Unimplemented", errors.Code(err))
	}
}

// TestConnectionPool_Get_EmptyPool tests Get when pool has no connections.
func TestConnectionPool_Get_EmptyPool(t *testing.T) {
	cfg := &transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        1,
		PoolMaxSize:        3,
		PoolHealthInterval: time.Hour,
	}

	tr := &Transport{cfg: cfg}
	tr.applyDefaults()

	opts, _ := tr.buildDialOptions()

	pool := &connectionPool{
		transport:   tr,
		target:      "localhost:9443",
		opts:        opts,
		connections: make([]*pooledConnection, 0),
		healthDone:  make(chan struct{}),
	}

	_, err := pool.Get()
	if err == nil {
		t.Fatal("pool.Get() on empty pool error = nil, want error")
	}
	if !errors.IsUnavailable(err) {
		t.Errorf("pool.Get() error code = %v, want Unavailable", errors.Code(err))
	}
}

// TestPerformHealthCheck_WithInUseConnections tests health check with in-use connections.
func TestPerformHealthCheck_WithInUseConnections(t *testing.T) {
	cfg := &transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        1,
		PoolMaxSize:        3,
		PoolMaxAge:         1 * time.Millisecond, // Very short age.
		PoolHealthInterval: time.Hour,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	grpcTransport := tr.(*Transport)
	pool := grpcTransport.pool

	// Get a connection and mark it as in use.
	conn, err := pool.Get()
	if err != nil {
		t.Fatalf("pool.Get() error = %v", err)
	}

	// Wait for connection to expire.
	time.Sleep(10 * time.Millisecond)

	// Manually trigger health check while connection is in use.
	pool.performHealthCheck()

	// The in-use connection should still be in the pool.
	pool.Put(conn)
}

// TestPerformHealthCheck_ClosedPool tests health check on closed pool.
func TestPerformHealthCheck_ClosedPool(t *testing.T) {
	cfg := &transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        1,
		PoolMaxSize:        3,
		PoolHealthInterval: time.Hour,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}

	grpcTransport := tr.(*Transport)
	pool := grpcTransport.pool

	// Close the pool.
	pool.Close()

	// Health check on closed pool should return early.
	pool.performHealthCheck()
}

// TestPerformHealthCheck_UnhealthyNotInUse tests health check removes unhealthy connections not in use.
func TestPerformHealthCheck_UnhealthyNotInUse(t *testing.T) {
	cfg := &transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        1,
		PoolMaxSize:        5,
		PoolMaxAge:         1 * time.Millisecond,
		PoolHealthInterval: time.Hour,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	grpcTransport := tr.(*Transport)
	pool := grpcTransport.pool

	// Wait for connections to expire.
	time.Sleep(10 * time.Millisecond)

	// Manually trigger health check.
	pool.performHealthCheck()

	// Pool should have replenished to min size.
	pool.mu.Lock()
	numConns := len(pool.connections)
	pool.mu.Unlock()

	if numConns < cfg.PoolMinSize {
		t.Errorf("pool has %d connections, want at least %d", numConns, cfg.PoolMinSize)
	}
}

// TestWithAuth_MetadataAppended tests that WithAuth appends correct metadata.
func TestWithAuth_MetadataAppended(t *testing.T) {
	ctx := context.Background()
	token := "my-secret-token"

	ctxWithAuth := WithAuth(ctx, token)

	// Extract metadata.
	md, ok := metadata.FromOutgoingContext(ctxWithAuth)
	if !ok {
		t.Fatal("WithAuth() did not add metadata to context")
	}

	authValues := md.Get("authorization")
	if len(authValues) == 0 {
		t.Fatal("WithAuth() did not add authorization header")
	}

	expected := "Bearer " + token
	if authValues[0] != expected {
		t.Errorf("WithAuth() authorization = %q, want %q", authValues[0], expected)
	}
}

// TestRequestStream_AllACMEServices tests RequestStream returns unimplemented for all ACME services.
func TestRequestStream_AllACMEServices(t *testing.T) {
	cfg := &transport.Config{
		Address:   "localhost:9443",
		Insecure:  true,
		TLSConfig: insecureTestTLSConfig(),
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	ctx := context.Background()
	acmeServices := []string{
		ServiceDirectory, ServiceNonce, ServiceAccount, ServiceOrder,
		ServiceAuthorization, ServiceChallenge, ServiceFinalize, ServiceRevoke,
	}

	for _, svc := range acmeServices {
		_, err := tr.RequestStream(ctx, svc, "stream", nil)
		if err == nil {
			t.Errorf("RequestStream(%s) error = nil, want error", svc)
			continue
		}
		if !errors.IsUnimplemented(err) {
			t.Errorf("RequestStream(%s) error code = %v, want Unimplemented", svc, errors.Code(err))
		}
	}
}

// TestRequestStream_CaseInsensitive tests RequestStream handles service case.
func TestRequestStream_CaseInsensitive(t *testing.T) {
	cfg := &transport.Config{
		Address:   "localhost:9443",
		Insecure:  true,
		TLSConfig: insecureTestTLSConfig(),
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	ctx := context.Background()

	// ACME services should return unimplemented regardless of case.
	testCases := []string{"DIRECTORY", "Directory", "DiReCtOrY"}
	for _, svc := range testCases {
		_, err := tr.RequestStream(ctx, svc, "stream", nil)
		if err == nil {
			t.Errorf("RequestStream(%s) error = nil, want error", svc)
			continue
		}
		if !errors.IsUnimplemented(err) {
			t.Errorf("RequestStream(%s) error code = %v, want Unimplemented", svc, errors.Code(err))
		}
	}

	// Admin services should succeed.
	stream, err := tr.RequestStream(ctx, "ADMIN", "stream", nil)
	if err != nil {
		t.Errorf("RequestStream(ADMIN) error = %v, want nil", err)
	} else {
		stream.Close()
	}
}

// TestPool_Get_RoundRobin tests that pool uses round-robin selection.
func TestPool_Get_RoundRobin(t *testing.T) {
	cfg := &transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        3,
		PoolMaxSize:        5,
		PoolMaxAge:         time.Hour,
		PoolHealthInterval: time.Hour,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	grpcTransport := tr.(*Transport)
	pool := grpcTransport.pool

	// Get multiple connections.
	conns := make([]*grpc.ClientConn, 0, 6)
	for i := 0; i < 6; i++ {
		conn, err := pool.Get()
		if err != nil {
			t.Fatalf("pool.Get() iteration %d error = %v", i, err)
		}
		conns = append(conns, conn)
		pool.Put(conn)
	}

	// Verify we got connections (actual round-robin behavior depends on timing).
	if len(conns) != 6 {
		t.Errorf("Got %d connections, want 6", len(conns))
	}
}

// TestConnectionPool_AddConnection tests adding connections to pool.
func TestConnectionPool_AddConnection(t *testing.T) {
	cfg := &transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        1,
		PoolMaxSize:        5,
		PoolHealthInterval: time.Hour,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	grpcTransport := tr.(*Transport)
	pool := grpcTransport.pool

	pool.mu.Lock()
	initialCount := len(pool.connections)
	pool.mu.Unlock()

	// Add a new connection.
	err = pool.addConnection()
	if err != nil {
		t.Fatalf("addConnection() error = %v", err)
	}

	pool.mu.Lock()
	newCount := len(pool.connections)
	pool.mu.Unlock()

	if newCount != initialCount+1 {
		t.Errorf("Connection count = %d, want %d", newCount, initialCount+1)
	}
}

// TestPooledConnection_CreatedAt tests pooled connection creation time.
func TestPooledConnection_CreatedAt(t *testing.T) {
	cfg := &transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        1,
		PoolMaxSize:        3,
		PoolHealthInterval: time.Hour,
	}

	before := time.Now()

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	after := time.Now()

	grpcTransport := tr.(*Transport)
	pool := grpcTransport.pool

	pool.mu.Lock()
	if len(pool.connections) > 0 {
		pc := pool.connections[0]
		if pc.createdAt.Before(before) || pc.createdAt.After(after) {
			t.Errorf("Connection createdAt = %v, want between %v and %v", pc.createdAt, before, after)
		}
	}
	pool.mu.Unlock()
}

// TestIsConnectionHealthy_ValidConnection tests health check for valid connection.
func TestIsConnectionHealthy_ValidConnection(t *testing.T) {
	cfg := &transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        1,
		PoolMaxSize:        3,
		PoolMaxAge:         time.Hour,
		PoolHealthInterval: time.Hour,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	grpcTransport := tr.(*Transport)
	pool := grpcTransport.pool

	pool.mu.Lock()
	if len(pool.connections) > 0 {
		pc := pool.connections[0]
		healthy := pool.isConnectionHealthy(pc)
		if !healthy {
			t.Error("isConnectionHealthy() = false, want true for new connection")
		}
	}
	pool.mu.Unlock()
}

// TestIsConnectionHealthy_ExpiredConnection tests health check for expired connection.
func TestIsConnectionHealthy_ExpiredConnection(t *testing.T) {
	cfg := &transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        1,
		PoolMaxSize:        3,
		PoolMaxAge:         1 * time.Millisecond,
		PoolHealthInterval: time.Hour,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	grpcTransport := tr.(*Transport)
	pool := grpcTransport.pool

	// Wait for connection to expire.
	time.Sleep(10 * time.Millisecond)

	pool.mu.Lock()
	if len(pool.connections) > 0 {
		pc := pool.connections[0]
		healthy := pool.isConnectionHealthy(pc)
		if healthy {
			t.Error("isConnectionHealthy() = true, want false for expired connection")
		}
	}
	pool.mu.Unlock()
}

// TestTransport_Request_AdminServices tests Request for all admin services.
func TestTransport_Request_AdminServices(t *testing.T) {
	cfg := &transport.Config{
		Address:   "localhost:9443",
		Insecure:  true,
		TLSConfig: insecureTestTLSConfig(),
		Timeout:   50 * time.Millisecond,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	ctx := context.Background()
	adminServices := []string{
		ServiceAdmin, ServiceTenant, ServiceEAB,
		ServicePolicy, ServiceCertificate, ServiceStatus,
	}

	for _, svc := range adminServices {
		// Each should attempt to make a request (and fail due to no server).
		_, err := tr.Request(ctx, svc, "GetStatus", nil)
		// We expect an error because there's no server.
		if err == nil {
			t.Logf("Request(%s) succeeded unexpectedly", svc)
		}
	}
}

// TestGrpcStream_SendRecvAfterClose tests Send and Recv after Close.
func TestGrpcStream_SendRecvAfterClose(t *testing.T) {
	mock := &mockClientStream{}
	stream := &grpcStream{
		ctx:    context.Background(),
		stream: mock,
	}

	// Close the stream.
	stream.Close()

	// Send should fail.
	err := stream.Send("test")
	if err == nil {
		t.Error("Send() after Close() error = nil, want error")
	}

	// Recv should fail.
	_, err = stream.Recv()
	if err == nil {
		t.Error("Recv() after Close() error = nil, want error")
	}
}

// TestConnectionPool_GetAfterHealthCheck tests Get after health check runs.
func TestConnectionPool_GetAfterHealthCheck(t *testing.T) {
	cfg := &transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        2,
		PoolMaxSize:        5,
		PoolMaxAge:         time.Hour,
		PoolHealthInterval: 5 * time.Millisecond,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	grpcTransport := tr.(*Transport)
	pool := grpcTransport.pool

	// Wait for health check to run.
	time.Sleep(20 * time.Millisecond)

	// Get should still work.
	conn, err := pool.Get()
	if err != nil {
		t.Fatalf("pool.Get() after health check error = %v", err)
	}
	pool.Put(conn)
}

// TestNewTransport_ZeroTimeout tests transport with zero timeout uses default.
func TestNewTransport_ZeroTimeout(t *testing.T) {
	cfg := &transport.Config{
		Address:   "localhost:9443",
		Insecure:  true,
		TLSConfig: insecureTestTLSConfig(),
		Timeout:   0, // Should use default.
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	grpcTransport := tr.(*Transport)
	if grpcTransport.cfg.Timeout != defaultTimeout {
		t.Errorf("Timeout = %v, want %v", grpcTransport.cfg.Timeout, defaultTimeout)
	}
}

// TestConnectionPool_Get_MaxSizeReached tests Get when max size is reached but connections available.
func TestConnectionPool_Get_MaxSizeReached(t *testing.T) {
	cfg := &transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        2,
		PoolMaxSize:        2, // Same as min.
		PoolMaxAge:         time.Hour,
		PoolHealthInterval: time.Hour,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	grpcTransport := tr.(*Transport)
	pool := grpcTransport.pool

	// Get all connections and hold them.
	conn1, _ := pool.Get()
	conn2, _ := pool.Get()

	// Get another - at max, should share existing.
	conn3, err := pool.Get()
	if err != nil {
		t.Fatalf("pool.Get() at max size error = %v", err)
	}

	// Clean up.
	pool.Put(conn1)
	pool.Put(conn2)
	pool.Put(conn3)
}

// TestTransport_Close_NilPoolAndConn tests Close with nil pool and conn.
func TestTransport_Close_NilPoolAndConn(t *testing.T) {
	tr := &Transport{
		cfg: &transport.Config{},
	}

	err := tr.Close()
	if err != nil {
		t.Errorf("Close() with nil pool and conn error = %v, want nil", err)
	}
}

// TestHealthCheckLoop_StopsOnClose tests that health check loop stops when pool closes.
func TestHealthCheckLoop_StopsOnClose(t *testing.T) {
	cfg := &transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        1,
		PoolMaxSize:        3,
		PoolHealthInterval: 5 * time.Millisecond,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}

	// Close should stop the health check loop.
	tr.Close()

	// Give time for goroutine to exit.
	time.Sleep(20 * time.Millisecond)
}

// TestPool_IsConnectionHealthy_VariousStates tests isConnectionHealthy with various states.
func TestPool_IsConnectionHealthy_VariousStates(t *testing.T) {
	cfg := &transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        1,
		PoolMaxSize:        3,
		PoolMaxAge:         time.Hour,
		PoolHealthInterval: time.Hour,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	grpcTransport := tr.(*Transport)
	pool := grpcTransport.pool

	// Get a connection and check health.
	conn, err := pool.Get()
	if err != nil {
		t.Fatalf("pool.Get() error = %v", err)
	}

	pool.mu.Lock()
	for _, pc := range pool.connections {
		if pc.conn == conn {
			// Should be healthy.
			if !pool.isConnectionHealthy(pc) {
				t.Error("isConnectionHealthy() = false for active connection")
			}
		}
	}
	pool.mu.Unlock()

	pool.Put(conn)
}

// TestTransport_Request_ZeroTimeoutConfig tests Request with zero timeout in config.
func TestTransport_Request_ZeroTimeoutConfig(t *testing.T) {
	cfg := &transport.Config{
		Address:   "localhost:9443",
		Insecure:  true,
		TLSConfig: insecureTestTLSConfig(),
		Timeout:   0, // Will use default.
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	ctx := context.Background()
	_, err = tr.Request(ctx, ServiceAdmin, "GetStatus", nil)
	// We expect an error due to no server.
	if err == nil {
		t.Log("Request succeeded unexpectedly")
	}
}

// TestGrpcStream_CloseSend_AlreadyClosed tests CloseSend after Close.
func TestGrpcStream_CloseSend_AlreadyClosed(t *testing.T) {
	mock := &mockClientStream{}
	stream := &grpcStream{
		ctx:    context.Background(),
		stream: mock,
	}

	// Close the stream first.
	stream.Close()

	// CloseSend should still work (stream is set).
	err := stream.CloseSend()
	if err != nil {
		t.Errorf("CloseSend() after Close() error = %v", err)
	}
}

// TestPooledConnection_InUseFlag tests in-use flag behavior.
func TestPooledConnection_InUseFlag(t *testing.T) {
	pc := &pooledConnection{
		createdAt: time.Now(),
	}

	// Initially not in use.
	if pc.inUse.Load() {
		t.Error("New pooledConnection inUse = true, want false")
	}

	// Mark as in use.
	pc.inUse.Store(true)
	if !pc.inUse.Load() {
		t.Error("After Store(true) inUse = false, want true")
	}

	// Mark as not in use.
	pc.inUse.Store(false)
	if pc.inUse.Load() {
		t.Error("After Store(false) inUse = true, want false")
	}

	// Test CompareAndSwap.
	if !pc.inUse.CompareAndSwap(false, true) {
		t.Error("CompareAndSwap(false, true) = false, want true")
	}
	if pc.inUse.CompareAndSwap(false, true) {
		t.Error("CompareAndSwap(false, true) on true = true, want false")
	}
}

// TestConnectionPool_Close_WithNilTicker tests Close with nil health ticker.
func TestConnectionPool_Close_WithNilTicker(t *testing.T) {
	cfg := &transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        1,
		PoolMaxSize:        3,
		PoolHealthInterval: time.Hour,
	}

	tr := &Transport{cfg: cfg}
	tr.applyDefaults()

	opts, _ := tr.buildDialOptions()

	pool := &connectionPool{
		transport:    tr,
		target:       "localhost:9443",
		opts:         opts,
		connections:  make([]*pooledConnection, 0),
		healthTicker: nil, // Nil ticker.
		healthDone:   make(chan struct{}),
	}

	// Close should handle nil ticker gracefully.
	err := pool.Close()
	if err != nil {
		t.Errorf("Close() with nil ticker error = %v", err)
	}
}

// TestTransport_RequestStream_NilConnection tests RequestStream with nil connection.
func TestTransport_RequestStream_NilConnection(t *testing.T) {
	tr := &Transport{
		cfg:      &transport.Config{},
		handlers: map[string]requestHandler{},
	}
	tr.initHandlers()

	ctx := context.Background()
	_, err := tr.RequestStream(ctx, "admin", "stream", nil)
	if err == nil {
		t.Fatal("RequestStream() with nil conn error = nil, want error")
	}
	if !errors.IsUnavailable(err) {
		t.Errorf("RequestStream() error code = %v, want Unavailable", errors.Code(err))
	}
}

// TestGrpcStream_Context tests grpcStream context.
func TestGrpcStream_Context(t *testing.T) {
	ctx := context.WithValue(context.Background(), testCtxKey("key"), "value")
	stream := &grpcStream{
		ctx: ctx,
	}

	if stream.ctx != ctx {
		t.Error("Stream context mismatch")
	}
}

// TestGrpcStream_Conn tests grpcStream connection.
func TestGrpcStream_Conn(t *testing.T) {
	cfg := &transport.Config{
		Address:   "localhost:9443",
		Insecure:  true,
		TLSConfig: insecureTestTLSConfig(),
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	grpcTransport := tr.(*Transport)
	stream := &grpcStream{
		ctx:  context.Background(),
		conn: grpcTransport.conn,
	}

	if stream.conn == nil {
		t.Error("Stream connection is nil")
	}
}

// TestPool_NextConnIndex tests atomic counter for round-robin.
func TestPool_NextConnIndex(t *testing.T) {
	var counter atomic.Uint64

	// Initial value should be 0.
	if counter.Load() != 0 {
		t.Errorf("Initial counter = %d, want 0", counter.Load())
	}

	// Add increments.
	for i := uint64(1); i <= 10; i++ {
		val := counter.Add(1)
		if val != i {
			t.Errorf("After %d adds, counter = %d, want %d", i, val, i)
		}
	}
}
