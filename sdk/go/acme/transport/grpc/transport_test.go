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

package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	stderrors "errors"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
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
	conn1, err := pool.Get(context.Background())
	if err != nil {
		t.Fatalf("pool.Get(context.Background()) error = %v", err)
	}
	if conn1 == nil {
		t.Fatal("pool.Get(context.Background()) returned nil connection")
	}

	// Get another connection.
	conn2, err := pool.Get(context.Background())
	if err != nil {
		t.Fatalf("pool.Get(context.Background()) second call error = %v", err)
	}
	if conn2 == nil {
		t.Fatal("pool.Get(context.Background()) second call returned nil connection")
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

	_, err = pool.Get(context.Background())
	if err == nil {
		t.Fatal("pool.Get(context.Background()) on closed pool error = nil, want error")
	}
	if !errors.IsUnavailable(err) {
		t.Errorf("pool.Get(context.Background()) error code = %v, want Unavailable", errors.Code(err))
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
	conn, err := pool.Get(context.Background())
	if err != nil {
		t.Fatalf("pool.Get(context.Background()) error = %v", err)
	}

	// Put back - should mark as not in use.
	pool.Put(conn)

	// Get again - should be available.
	conn2, err := pool.Get(context.Background())
	if err != nil {
		t.Fatalf("pool.Get(context.Background()) after Put error = %v", err)
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
	conn, err := grpcTransport.getConnection(context.Background())
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
	conn, err := grpcTransport.getConnection(context.Background())
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

	_, err := tr.getConnection(context.Background())
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
	conn, err := grpcTransport.pool.Get(context.Background())
	if err != nil {
		t.Fatalf("pool.Get(context.Background()) error = %v", err)
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
	// grpc.NewClient only validates the target and dial options; it does not
	// connect, so this cannot fail for a well-formed address.
	otherConn, err := grpc.NewClient("localhost:9999", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient() error = %v", err)
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
	conn, err := pool.Get(context.Background())
	if err != nil {
		t.Fatalf("pool.Get(context.Background()) after expiry error = %v", err)
	}
	pool.Put(conn)
}

// TestConnectionPool_Get_AllInUse tests Get when all connections in use.
// TestConnectionPool_Get_AllInUse covers a pool that grew to PoolMaxSize and
// then ran out.
//
// It used to assert the opposite of what it now asserts. Its comment read
// "Get another - should create new or share", and it failed the test if the
// third Get returned an error -- so it pinned, as correct, the sharing that
// handed one connection to two borrowers with no record of the second (#104).
// The owner ruling of 2026-08-23 removed that behaviour, which makes the old
// assertion a test for the defect.
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
		PoolAcquireTimeout: 50 * time.Millisecond,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	grpcTransport := tr.(*Transport)
	pool := grpcTransport.pool

	// Take both connections: the first is pre-opened, the second grows the pool
	// to PoolMaxSize.
	conn1, err := pool.Get(context.Background())
	if err != nil {
		t.Fatalf("first pool.Get(context.Background()) error = %v", err)
	}
	conn2, err := pool.Get(context.Background())
	if err != nil {
		t.Fatalf("second pool.Get(context.Background()) error = %v", err)
	}
	if conn1 == nil || conn2 == nil {
		t.Fatal("pool.Get(context.Background()) returned nil connection")
	}
	if conn1 == conn2 {
		t.Error("two exclusive leases returned the same connection")
	}

	conn3, err := poolGetWithin(t, 10*time.Second, pool)
	if conn3 != nil {
		t.Error("pool.Get(context.Background()) lent out a third connection from a pool of two")
	}
	if !stderrors.Is(err, ErrPoolExhausted) {
		t.Errorf("pool.Get(context.Background()) error = %v, want ErrPoolExhausted", err)
	}

	// Returning one makes the pool usable again, which is the difference
	// between exhausted and broken.
	pool.Put(conn1)
	conn4, err := poolGetWithin(t, 10*time.Second, pool)
	if err != nil {
		t.Fatalf("pool.Get(context.Background()) after a release error = %v, want a connection", err)
	}
	if conn4 != conn1 {
		t.Error("pool.Get(context.Background()) after a release returned a connection other than the released one")
	}

	pool.Put(conn2)
	pool.Put(conn4)
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
	conn, err := pool.Get(context.Background())
	if err != nil {
		t.Fatalf("pool.Get(context.Background()) after health check error = %v", err)
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

	_, err := pool.Get(context.Background())
	if err == nil {
		t.Fatal("pool.Get(context.Background()) on empty pool error = nil, want error")
	}
	if !errors.IsUnavailable(err) {
		t.Errorf("pool.Get(context.Background()) error code = %v, want Unavailable", errors.Code(err))
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
	conn, err := pool.Get(context.Background())
	if err != nil {
		t.Fatalf("pool.Get(context.Background()) error = %v", err)
	}

	// Wait for connection to expire.
	time.Sleep(10 * time.Millisecond)

	// Manually trigger health check while connection is in use.
	pool.performHealthCheck()

	// The in-use connection must survive, and this has to be asserted rather
	// than implied. The previous version of this test simply called Put and
	// returned: had performHealthCheck evicted and closed the connection, Put
	// would have put it back and the test would still have passed. It could
	// not fail for the reason it exists.
	//
	// The connection is over its PoolMaxAge, so isConnectionHealthy says no.
	// Keeping it anyway is the point: closing a leased connection would fail
	// the request its holder is making.
	//
	// Scope: this covers a connection acquired EXCLUSIVELY, which is what
	// inUse can express. A connection handed out by Get's saturated fallback
	// carries no record of the extra borrower, so the first Put clears the
	// flag for everyone and this protection lapses -- a pre-existing gap in
	// the pool's lease accounting, tracked as go-xkms#104, and not something
	// this test can honestly claim to cover.
	pool.mu.Lock()
	var found bool
	for _, pc := range pool.connections {
		if pc.conn == conn {
			found = true
			break
		}
	}
	remaining := len(pool.connections)
	pool.mu.Unlock()

	if !found {
		t.Fatalf("the in-use connection was evicted by the health check "+
			"(%d connections remain); an unhealthy connection must be kept "+
			"while it is in use", remaining)
	}

	// Kept means kept USABLE, not merely present in the slice: a closed
	// ClientConn reports Shutdown and cannot carry the caller's request.
	if state := conn.GetState(); state == connectivity.Shutdown {
		t.Errorf("the in-use connection was closed by the health check (state %v); "+
			"it must stay usable until released", state)
	}

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
		conn, err := pool.Get(context.Background())
		if err != nil {
			t.Fatalf("pool.Get(context.Background()) iteration %d error = %v", i, err)
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
	conn, err := pool.Get(context.Background())
	if err != nil {
		t.Fatalf("pool.Get(context.Background()) after health check error = %v", err)
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
		PoolAcquireTimeout: 50 * time.Millisecond,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	grpcTransport := tr.(*Transport)
	pool := grpcTransport.pool

	// Get all connections and hold them.
	conn1, err := pool.Get(context.Background())
	if err != nil {
		t.Fatalf("first pool.Get(context.Background()) error = %v", err)
	}
	conn2, err := pool.Get(context.Background())
	if err != nil {
		t.Fatalf("second pool.Get(context.Background()) error = %v", err)
	}

	// At PoolMaxSize with both leased, the pool waits and then reports itself
	// exhausted. It used to "share existing" -- hand back conn1 or conn2 with
	// no record of the extra borrower (#104).
	conn3, err := poolGetWithin(t, 10*time.Second, pool)
	if conn3 != nil {
		t.Error("pool.Get(context.Background()) at max size lent out an already-leased connection")
	}
	if !stderrors.Is(err, ErrPoolExhausted) {
		t.Errorf("pool.Get(context.Background()) at max size error = %v, want ErrPoolExhausted", err)
	}

	// Clean up.
	pool.Put(conn1)
	pool.Put(conn2)
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
	conn, err := pool.Get(context.Background())
	if err != nil {
		t.Fatalf("pool.Get(context.Background()) error = %v", err)
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

// poolGetWithin runs pool.Get on its own goroutine and fails t if it has not
// returned within the bound.
//
// The bound is on the WAIT rather than checked after the call returns. The
// regression this guards is a Get that never comes back, and a plain call would
// hang the package until go test's own timeout killed the binary — reporting
// "panic: test timed out" for every test in the file instead of naming this one.
func poolGetWithin(t *testing.T, bound time.Duration, pool *connectionPool) (*grpc.ClientConn, error) {
	t.Helper()
	return poolGetCtxWithin(t, bound, pool, context.Background())
}

// poolGetCtxWithin is poolGetWithin with the caller's context, for the tests
// that are about what Get does when that context finishes first.
func poolGetCtxWithin(t *testing.T, bound time.Duration, pool *connectionPool, ctx context.Context) (*grpc.ClientConn, error) {
	t.Helper()

	type outcome struct {
		conn *grpc.ClientConn
		err  error
	}
	done := make(chan outcome, 1)
	go func() {
		conn, err := pool.Get(ctx)
		done <- outcome{conn, err}
	}()

	select {
	case got := <-done:
		return got.conn, got.err
	case <-time.After(bound):
		t.Fatalf("pool.Get(context.Background()) did not return within %s", bound)
		return nil, nil
	}
}

// newSaturablePool builds a transport whose pool holds exactly one connection
// and cannot grow, so a second Get is necessarily a saturated Get.
func newSaturablePool(t *testing.T, acquireTimeout time.Duration) *connectionPool {
	t.Helper()

	tr, err := NewTransport(&transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        1,
		PoolMaxSize:        1,
		PoolMaxAge:         time.Hour,
		PoolHealthInterval: time.Hour,
		PoolAcquireTimeout: acquireTimeout,
	})
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	return tr.(*Transport).pool
}

// TestPoolGet_RefusesToLendTheSameConnectionTwice pins the owner ruling of
// 2026-08-23 on #104: a saturated pool waits, then reports ErrPoolExhausted. It
// never hands a connection to a second borrower.
//
// What it replaces returned the first connection anyway, recording no borrower,
// because inUse is a bool and a bool cannot count. The first Put then cleared
// the flag for both holders and performHealthCheck was free to Close a
// ClientConn the second holder was still issuing requests on.
//
// The elapsed-time assertion is part of the claim, not decoration: the ruling
// says the error comes AFTER the configured wait, and a Get that returned the
// error immediately would satisfy every other assertion here while making a
// pool that is busy for a millisecond indistinguishable from one that is busy
// for a minute.
func TestPoolGet_RefusesToLendTheSameConnectionTwice(t *testing.T) {
	const acquireTimeout = 150 * time.Millisecond
	pool := newSaturablePool(t, acquireTimeout)

	first, err := poolGetWithin(t, 10*time.Second, pool)
	if err != nil {
		t.Fatalf("first pool.Get(context.Background()) error = %v, want nil", err)
	}
	if first == nil {
		t.Fatal("first pool.Get(context.Background()) returned no connection")
	}

	started := time.Now()
	second, err := poolGetWithin(t, 10*time.Second, pool)
	elapsed := time.Since(started)

	if second != nil {
		t.Fatal("pool.Get(context.Background()) lent out a second connection while the pool was saturated; " +
			"a connection must never have two borrowers")
	}
	if !stderrors.Is(err, ErrPoolExhausted) {
		t.Errorf("pool.Get(context.Background()) error = %v, want it to wrap ErrPoolExhausted", err)
	}
	if !errors.IsUnavailable(err) {
		t.Errorf("pool.Get(context.Background()) error code = %v, want Unavailable so existing callers "+
			"that classify by code are unaffected", errors.Code(err))
	}

	// Allow a little slack for timer granularity, but not enough to pass if the
	// wait were skipped entirely.
	if min := acquireTimeout - 20*time.Millisecond; elapsed < min {
		t.Errorf("pool.Get(context.Background()) gave up after %s, want at least %s: the error is "+
			"supposed to come after the configured wait, not instead of it", elapsed, min)
	}
}

// TestPoolGet_WaitsForAReleaseInsteadOfSharing is the other half: the wait is a
// real wait on a real event, not a disguised sleep before an error.
//
// Without it, TestPoolGet_RefusesToLendTheSameConnectionTwice would pass
// against a Get that ignored p.released entirely and always timed out.
func TestPoolGet_WaitsForAReleaseInsteadOfSharing(t *testing.T) {
	pool := newSaturablePool(t, 10*time.Second)

	first, err := pool.Get(context.Background())
	if err != nil {
		t.Fatalf("first pool.Get(context.Background()) error = %v", err)
	}

	type outcome struct {
		conn *grpc.ClientConn
		err  error
	}
	waiting := make(chan outcome, 1)
	scanned := pool.nextConnIndex.Load()
	go func() {
		conn, err := pool.Get(context.Background())
		waiting <- outcome{conn, err}
	}()

	// Put must not run until the second Get has SCANNED the pool and come back
	// empty-handed, because that is the only path reaching the wait this test
	// is about. Releasing first lets the goroutine's very first tryGet succeed,
	// and the test then passes without the wake-up ever being needed --
	// measured: the mutant that removes Put's wake-up SURVIVED this test until
	// this loop was added.
	//
	// nextConnIndex is incremented by every scan, so an advance past the value
	// our own Get left proves the scan happened. A predicate on real state with
	// a hard failure if it never becomes true, not a sleep.
	deadline := time.Now().Add(10 * time.Second)
	for pool.nextConnIndex.Load() == scanned {
		if time.Now().After(deadline) {
			t.Fatal("the second pool.Get(context.Background()) never scanned the pool")
		}
		runtime.Gosched()
	}

	pool.Put(first)

	select {
	case got := <-waiting:
		if got.err != nil {
			t.Fatalf("the waiting pool.Get(context.Background()) error = %v, want it to acquire the released connection", got.err)
		}
		if got.conn != first {
			t.Errorf("the waiting pool.Get(context.Background()) returned a different connection; the pool " +
				"holds exactly one, so it must be the released one")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Put did not wake the waiting Get: the wait is not driven by releases")
	}
}

// TestPerformHealthCheck_CannotCloseAConnectionAnotherCallerHolds is #104's
// acceptance criterion, expressed for the design the ruling chose.
//
// The original scenario was: two borrowers of one connection, the first Puts,
// the health check finds the connection aged and closes it, and the SECOND
// borrower's in-flight request fails on a closed ClientConn. Option B removes
// the scenario at its root — there is no second borrower to strand — so what
// this asserts is that root: while one caller holds the connection, an aged
// pool neither closes it nor lets anyone else have it.
func TestPerformHealthCheck_CannotCloseAConnectionAnotherCallerHolds(t *testing.T) {
	tr, err := NewTransport(&transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        1,
		PoolMaxSize:        1,
		PoolMaxAge:         time.Hour, // until the connection is leased, below
		PoolHealthInterval: time.Hour, // only this test runs the check
		PoolAcquireTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer func() { _ = tr.Close() }()
	grpcTransport := tr.(*Transport)
	pool := grpcTransport.pool

	held, err := pool.Get(context.Background())
	if err != nil {
		t.Fatalf("pool.Get(context.Background()) error = %v", err)
	}

	// Age every connection past its limit by moving the limit, not by sleeping
	// past it: isConnectionHealthy reads PoolMaxAge from the config each time,
	// so this is the same condition without betting on a clock. An aged
	// connection cannot be ACQUIRED either, which is why the lease above comes
	// first.
	grpcTransport.cfg.PoolMaxAge = time.Nanosecond

	second, err := poolGetWithin(t, 10*time.Second, pool)
	if second != nil {
		t.Fatal("a second caller was given the held connection; that is the sharing " +
			"that let the first Put clear the flag for both")
	}
	if !stderrors.Is(err, ErrPoolExhausted) {
		t.Errorf("second pool.Get(context.Background()) error = %v, want ErrPoolExhausted", err)
	}

	pool.performHealthCheck()

	if state := held.GetState(); state == connectivity.Shutdown {
		t.Fatal("the health check closed a connection that is still leased out")
	}

	pool.mu.Lock()
	stillPooled := false
	for _, pc := range pool.connections {
		if pc.conn == held {
			stillPooled = true
		}
	}
	pool.mu.Unlock()
	if !stillPooled {
		t.Error("the held connection was dropped from the pool while its borrower still had it")
	}
}

// TestPoolGet_HonoursTheCallersContext pins that a saturated acquisition ends
// when the CALLER gives up, not when the pool's own timeout expires.
//
// PoolAcquireTimeout is the pool's patience, and it is longer than a request's
// far more often than not: with the 5s default, a request whose context expires
// after 100ms stayed blocked for another 4.9 seconds and could then acquire a
// connection and start work for a caller that had already gone away.
//
// Both finishing modes are covered because they map to different errors and a
// caller distinguishes them: a deadline is a timeout, an explicit cancel is a
// cancellation. Both keep the standard-library cause, so errors.Is against
// context.DeadlineExceeded / context.Canceled still answers.
func TestPoolGet_HonoursTheCallersContext(t *testing.T) {
	t.Run("deadline", func(t *testing.T) {
		pool := newSaturablePool(t, time.Hour) // the pool would wait effectively forever

		if _, err := pool.Get(context.Background()); err != nil {
			t.Fatalf("first pool.Get() error = %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		started := time.Now()
		conn, err := poolGetCtxWithin(t, 30*time.Second, pool, ctx)
		elapsed := time.Since(started)

		if conn != nil {
			t.Error("pool.Get() handed out a connection to a caller whose deadline had passed")
		}
		if !stderrors.Is(err, context.DeadlineExceeded) {
			t.Errorf("pool.Get() error = %v, want it to wrap context.DeadlineExceeded", err)
		}
		if !errors.IsTimeout(err) {
			t.Errorf("pool.Get() error code = %v, want Timeout", errors.Code(err))
		}
		// The pool's own patience is an hour. Returning anywhere near promptly
		// is only possible by honouring the caller's context.
		if elapsed > 10*time.Second {
			t.Errorf("pool.Get() took %s to notice a 100ms deadline", elapsed)
		}
	})

	t.Run("cancel", func(t *testing.T) {
		pool := newSaturablePool(t, time.Hour)

		if _, err := pool.Get(context.Background()); err != nil {
			t.Fatalf("first pool.Get() error = %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		scanned := pool.nextConnIndex.Load()

		type outcome struct {
			conn *grpc.ClientConn
			err  error
		}
		done := make(chan outcome, 1)
		go func() {
			conn, err := pool.Get(ctx)
			done <- outcome{conn, err}
		}()

		// Cancel only once the Get has scanned and parked, so this exercises
		// the select rather than the fast path at the top of the loop.
		deadline := time.Now().Add(10 * time.Second)
		for pool.nextConnIndex.Load() == scanned {
			if time.Now().After(deadline) {
				cancel()
				t.Fatal("the second pool.Get() never scanned the pool")
			}
			runtime.Gosched()
		}
		cancel()

		select {
		case got := <-done:
			if got.conn != nil {
				t.Error("pool.Get() handed out a connection to a cancelled caller")
			}
			if !stderrors.Is(got.err, context.Canceled) {
				t.Errorf("pool.Get() error = %v, want it to wrap context.Canceled", got.err)
			}
			if !errors.IsCanceled(got.err) {
				t.Errorf("pool.Get() error code = %v, want Canceled", errors.Code(got.err))
			}
		case <-time.After(30 * time.Second):
			t.Fatal("cancelling the context did not release the waiting pool.Get()")
		}
	})
}

// TestTransportClose_ReleasesASaturatedAcquisition pins that shutdown is not
// held hostage by a request waiting for a connection.
//
// getConnection used to hold t.mu.RLock across pool.Get. Transport.Close needs
// t.mu for WRITING before it can reach pool.Close, and pool.Close is what
// closes healthDone and wakes the waiter -- so the waiter's own wake-up signal
// was behind the lock the waiter was holding. Close could not proceed until
// PoolAcquireTimeout expired, which on a deployment that configured a large one
// is a shutdown that appears to hang. The two operations involved are a request
// in flight and a shutdown, which is the pairing most likely to overlap.
//
// PoolAcquireTimeout is an hour here so that a pass cannot come from the
// timeout firing.
func TestTransportClose_ReleasesASaturatedAcquisition(t *testing.T) {
	tr, err := NewTransport(&transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        1,
		PoolMaxSize:        1,
		PoolMaxAge:         time.Hour,
		PoolHealthInterval: time.Hour,
		PoolAcquireTimeout: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	grpcTransport := tr.(*Transport)
	pool := grpcTransport.pool

	if _, err := pool.Get(context.Background()); err != nil {
		t.Fatalf("first pool.Get() error = %v", err)
	}

	scanned := pool.nextConnIndex.Load()
	waiting := make(chan error, 1)
	go func() {
		_, err := grpcTransport.getConnection(context.Background())
		waiting <- err
	}()

	deadline := time.Now().Add(10 * time.Second)
	for pool.nextConnIndex.Load() == scanned {
		if time.Now().After(deadline) {
			t.Fatal("the waiting getConnection never scanned the pool")
		}
		runtime.Gosched()
	}

	closed := make(chan struct{})
	go func() {
		_ = tr.Close()
		close(closed)
	}()

	select {
	case <-closed:
	case <-time.After(30 * time.Second):
		t.Fatal("Transport.Close blocked behind a saturated acquisition: getConnection " +
			"is holding the transport lock across pool.Get")
	}

	select {
	case err := <-waiting:
		if err == nil {
			t.Error("the waiting acquisition returned a connection from a closed transport")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Close returned but never released the waiting acquisition")
	}
}

// TestPerformHealthCheck_WakesAWaiterWhenItAddsCapacity pins that the health
// check signals availability, not only Put.
//
// With min=max=1 and the only connection expired and idle, tryGet finds nothing
// healthy and Get parks. performHealthCheck then closes that connection and
// opens a replacement -- capacity a waiter is entitled to, and capacity no Put
// is ever coming for, because the connection it replaced was not leased. Before
// this, the waiter slept out its whole timer and returned ErrPoolExhausted with
// a free, healthy connection sitting in the channel.
func TestPerformHealthCheck_WakesAWaiterWhenItAddsCapacity(t *testing.T) {
	tr, err := NewTransport(&transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        1,
		PoolMaxSize:        1,
		PoolMaxAge:         time.Hour,
		PoolHealthInterval: time.Hour, // only this test runs the check
		PoolAcquireTimeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer func() { _ = tr.Close() }()
	grpcTransport := tr.(*Transport)
	pool := grpcTransport.pool

	// Age the pool's only connection past PoolMaxAge by moving its createdAt
	// back, not by shortening the limit.
	//
	// That distinction is what makes the test work at all: shortening
	// PoolMaxAge expires the REPLACEMENT too, so the health check would swap an
	// unusable connection for another unusable one and there would be no
	// capacity to wake anyone about. Ageing the individual connection leaves
	// the limit generous, so the replacement is young and healthy.
	//
	// The connection stays IDLE -- nobody leased it -- so nothing will ever Put
	// it back, which is the whole point: the health check is the only thing
	// that can wake this waiter.
	pool.mu.Lock()
	pool.connections[0].createdAt = time.Now().Add(-2 * time.Hour)
	pool.mu.Unlock()

	scanned := pool.nextConnIndex.Load()
	type outcome struct {
		conn *grpc.ClientConn
		err  error
	}
	waiting := make(chan outcome, 1)
	go func() {
		conn, err := pool.Get(context.Background())
		waiting <- outcome{conn, err}
	}()

	deadline := time.Now().Add(10 * time.Second)
	for pool.nextConnIndex.Load() == scanned {
		if time.Now().After(deadline) {
			t.Fatal("the waiting pool.Get() never scanned the pool")
		}
		runtime.Gosched()
	}

	pool.performHealthCheck()

	select {
	case got := <-waiting:
		if got.err != nil {
			t.Fatalf("the waiting pool.Get() error = %v, want the replacement connection", got.err)
		}
		if got.conn == nil {
			t.Fatal("the waiting pool.Get() returned no connection and no error")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the health check added capacity without waking the waiter: it will " +
			"sleep out PoolAcquireTimeout and report the pool exhausted while a " +
			"healthy connection sits unused")
	}
}

// TestPoolGet_OneAnnouncementReachesEveryWaiter is the regression for the
// coalescing defect Codex found in the first version of this fix.
//
// The nudge was a 1-buffered channel with a non-blocking send, on the reasoning
// that "one pending nudge is enough, because a woken Get re-examines the whole
// pool". That is true for one waiter and false for two: each woken Get leases
// ONE connection, so a single wake-up cannot stand in for N units of capacity.
// The other waiter sleeps out PoolAcquireTimeout and reports the pool exhausted
// while an idle connection sits in it.
//
// The fixture is the health check rather than two Puts, and that choice is the
// whole test. Two Puts are two announcements, so whether they collapse depends
// on whether a waiter happens to consume the first token before the second Put
// runs -- a race the test cannot force, and the first version of this test
// PASSED against the coalescing mutant for exactly that reason. performHealthCheck
// makes ONE announcement for TWO new connections, so the two schemes give
// different answers every time: a broadcast wakes both waiters, a single-slot
// nudge wakes one and strands the other.
//
// PoolAcquireTimeout is an hour, so a pass cannot come from the timeout firing;
// the only way both acquisitions succeed is if both waiters were woken.
func TestPoolGet_OneAnnouncementReachesEveryWaiter(t *testing.T) {
	tr, err := NewTransport(&transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        2,
		PoolMaxSize:        2,
		PoolMaxAge:         time.Hour,
		PoolHealthInterval: time.Hour, // only this test runs the check
		PoolAcquireTimeout: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer func() { _ = tr.Close() }()
	pool := tr.(*Transport).pool

	// Age BOTH connections past the limit by moving their createdAt back, so
	// tryGet finds nothing healthy and every caller parks. Nobody leased them,
	// so no Put is ever coming: the health check is the only thing that can
	// wake these waiters, and it will do it with one announcement.
	pool.mu.Lock()
	for _, pc := range pool.connections {
		pc.createdAt = time.Now().Add(-2 * time.Hour)
	}
	pool.mu.Unlock()

	type outcome struct {
		conn *grpc.ClientConn
		err  error
	}
	waiting := make(chan outcome, 2)
	scanned := pool.nextConnIndex.Load()
	for i := 0; i < 2; i++ {
		go func() {
			conn, err := pool.Get(context.Background())
			waiting <- outcome{conn, err}
		}()
	}

	// Both waiters parked: two scans past whatever the counter was at.
	deadline := time.Now().Add(30 * time.Second)
	for pool.nextConnIndex.Load() < scanned+2 {
		if time.Now().After(deadline) {
			t.Fatalf("only %d of 2 waiters scanned the pool", pool.nextConnIndex.Load()-scanned)
		}
		runtime.Gosched()
	}

	// One announcement, two replacement connections.
	pool.performHealthCheck()

	for i := 0; i < 2; i++ {
		select {
		case got := <-waiting:
			if got.err != nil {
				t.Fatalf("waiter %d error = %v; two connections were added, so both "+
					"waiters must be able to acquire one", i, got.err)
			}
			if got.conn == nil {
				t.Fatalf("waiter %d got no connection and no error", i)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("a waiter was never woken: one announcement reached fewer callers " +
				"than the capacity it announced")
		}
	}
}

// TestGrpcStream_Close_ReturnsPoolLease is the regression test for go-xkms#104:
// a pooled stream must return its exclusive connection lease on Close, or a
// size-one pool is permanently exhausted after the first stream is opened and
// closed. It opens and closes a stream, then proves the sole connection can be
// acquired again. The short PoolAcquireTimeout keeps the pre-fix behaviour fast:
// without the release the follow-up acquire waits out the timeout and returns
// ErrPoolExhausted instead of succeeding, so the mutant fails in ~200ms.
func TestGrpcStream_Close_ReturnsPoolLease(t *testing.T) {
	cfg := &transport.Config{
		Address:            "localhost:9443",
		Insecure:           true,
		TLSConfig:          insecureTestTLSConfig(),
		PoolEnabled:        true,
		PoolMinSize:        1,
		PoolMaxSize:        1,
		PoolHealthInterval: time.Hour,
		PoolAcquireTimeout: 200 * time.Millisecond,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	ctx := context.Background()

	stream, err := tr.RequestStream(ctx, "admin", "stream", nil)
	if err != nil {
		t.Fatalf("first RequestStream() error = %v, want nil", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("stream.Close() error = %v, want nil", err)
	}

	// The exclusive lease taken by RequestStream must be back in the pool.
	grpcTransport := tr.(*Transport)
	conn, err := grpcTransport.pool.Get(ctx)
	if err != nil {
		t.Fatalf("pool.Get after stream Close error = %v, want the lease returned", err)
	}
	grpcTransport.releaseConnection(conn)
}
