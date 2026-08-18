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

package apimodule

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// TestNewModule_NilResolver proves construction fails closed with the
// typed error when no service resolver is supplied: a module that can never
// reach the XKMSService must not register a dead surface.
func TestNewModule_NilResolver(t *testing.T) {
	m, err := NewModule(nil)
	require.Error(t, err)
	assert.Nil(t, m)

	var nilResolver *NilServiceResolverError
	assert.True(t, errors.As(err, &nilResolver), "error must be the typed *NilServiceResolverError, got %T", err)
	assert.NotEmpty(t, err.Error())
}

// TestModule_Name pins the unique module name qrdb's WithModule
// duplicate detection keys on.
func TestModule_Name(t *testing.T) {
	m, err := NewModule(func() *xkms.XKMSService { return nil })
	require.NoError(t, err)
	assert.Equal(t, "xkms", m.Name())
	assert.Equal(t, ModuleName, m.Name())
}

// TestModule_LifecycleNoOps proves Start and Stop are the inherited
// BaseModule no-ops: the XKMSService lifecycle is owned by pkg/server, so the
// module must neither fail nor perform work in either hook.
func TestModule_LifecycleNoOps(t *testing.T) {
	m, err := NewModule(func() *xkms.XKMSService { return nil })
	require.NoError(t, err)

	assert.NoError(t, m.Start(context.Background()))
	assert.NoError(t, m.Stop(context.Background()))
	// Idempotent: a second Stop (LIFO shutdown retries) is also a no-op.
	assert.NoError(t, m.Stop(context.Background()))
}

// TestModule_RegisterGRPC_RegistersFullKeystoreSurface proves
// RegisterGRPC attaches the WHOLESALE KeystoreService: the registered service
// name and per-method set are identical to the generated service descriptor.
func TestModule_RegisterGRPC_RegistersFullKeystoreSurface(t *testing.T) {
	m, err := NewModule(func() *xkms.XKMSService { return nil })
	require.NoError(t, err)

	server := grpc.NewServer()
	m.RegisterGRPC(server)

	info, ok := server.GetServiceInfo()[pb.KeystoreService_ServiceDesc.ServiceName]
	require.True(t, ok, "KeystoreService must be registered under %s", pb.KeystoreService_ServiceDesc.ServiceName)

	require.Len(t, info.Methods, len(pb.KeystoreService_ServiceDesc.Methods),
		"the registered method set must be the full generated surface")
	registered := make(map[string]struct{}, len(info.Methods))
	for _, method := range info.Methods {
		registered[method.Name] = struct{}{}
	}
	for _, md := range pb.KeystoreService_ServiceDesc.Methods {
		_, found := registered[md.MethodName]
		assert.True(t, found, "generated method %q missing from the registered surface", md.MethodName)
	}
}

// startBufconnModule registers the module on a bufconn-backed gRPC server and
// returns a connected KeystoreService client.
func startBufconnModule(t *testing.T, m *Module) pb.KeystoreServiceClient {
	t.Helper()

	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	m.RegisterGRPC(server)
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(server.Stop)

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return pb.NewKeystoreServiceClient(conn)
}

// TestModule_LateBinding is the ordering regression test: xkmsd
// constructs the embedded qrdb node (which registers this module) long before
// the XKMSService is composed. An RPC arriving before the resolver yields a
// service must answer Unavailable — never a nil dereference — and the same
// registration must start serving once the resolver resolves, without
// re-registration.
func TestModule_LateBinding(t *testing.T) {
	var svc atomic.Pointer[xkms.XKMSService]
	m, err := NewModule(func() *xkms.XKMSService { return svc.Load() })
	require.NoError(t, err)

	client := startBufconnModule(t, m)
	ctx := context.Background()

	// Phase 1: the service is not composed yet — fail-safe Unavailable.
	_, err = client.Health(ctx, &pb.HealthRequest{})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code(),
		"an RPC before composition must answer Unavailable, got %v", st.Code())

	// Phase 2: composition completes; the SAME registration now serves.
	svc.Store(&xkms.XKMSService{})
	resp, err := client.Health(ctx, &pb.HealthRequest{})
	require.NoError(t, err, "the late-bound service must serve without re-registration")
	assert.Equal(t, "healthy", resp.Status)
}

// TestModule_LateBinding_ConcurrentFirstUse exercises the lock-free
// bind: many concurrent first RPCs race the memoizing CompareAndSwap and every
// one must succeed against a single coherent service.
func TestModule_LateBinding_ConcurrentFirstUse(t *testing.T) {
	m, err := NewModule(func() *xkms.XKMSService { return &xkms.XKMSService{} })
	require.NoError(t, err)

	client := startBufconnModule(t, m)

	const callers = 16
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, callErr := client.Health(context.Background(), &pb.HealthRequest{})
			errs <- callErr
		}()
	}
	wg.Wait()
	close(errs)
	for callErr := range errs {
		assert.NoError(t, callErr)
	}
}

// TestModule_SSHClientResolver_BoundAtServiceBind proves the SSH
// auxiliary wiring mirrors the Unix listener's SetSSHClient: the SSH resolver
// runs when (and only when) the service binds — never before the XKMSService
// resolves, which is what keeps xkmsd's sync.Once SSH construction from
// latching nil.
func TestModule_SSHClientResolver_BoundAtServiceBind(t *testing.T) {
	var svc atomic.Pointer[xkms.XKMSService]
	var sshResolved atomic.Int32
	m, err := NewModule(
		func() *xkms.XKMSService { return svc.Load() },
		WithSSHClient(func() sdkssh.Client {
			sshResolved.Add(1)
			return nil // subsystem unavailable; SSH RPCs answer Unavailable
		}),
	)
	require.NoError(t, err)

	client := startBufconnModule(t, m)
	ctx := context.Background()

	// Unresolved service: the SSH resolver must NOT have run.
	_, _ = client.Health(ctx, &pb.HealthRequest{})
	assert.Equal(t, int32(0), sshResolved.Load(),
		"SSH resolver must not run before the XKMSService resolves")

	// Service binds on the next RPC: the SSH resolver runs exactly once.
	svc.Store(&xkms.XKMSService{})
	_, err = client.Health(ctx, &pb.HealthRequest{})
	require.NoError(t, err)
	assert.Equal(t, int32(1), sshResolved.Load(),
		"SSH resolver must run exactly once, at service bind")

	// Subsequent RPCs reuse the memoized service; no re-resolution.
	_, err = client.Health(ctx, &pb.HealthRequest{})
	require.NoError(t, err)
	assert.Equal(t, int32(1), sshResolved.Load())
}

// TestNewModule_RegistersRoleGrants proves module construction contributes
// the full derived xkms permission set into qrdb's role-grant registry for
// the Admin and Owner roles — the grants the first-boot administrator's
// authorization depends on once qrdb's authorizer enforces module routes on
// the unified server. Representative permissions cover each declaration
// surface: the gRPC proto options, the REST route table, and the MCP method
// specs.
func TestNewModule_RegistersRoleGrants(t *testing.T) {
	_, err := NewModule(func() *xkms.XKMSService { return nil })
	require.NoError(t, err)

	for _, perm := range []qrdbsdk.Permission{
		"backends:list", // gRPC proto option surface
		"keys:sign",     // REST route table surface
		"keys:create",   // shared crypto surface
	} {
		assert.True(t, qrdbsdk.HasPermissionRoleGrant(qrdbsdk.PermissionRoleAdmin, perm),
			"admin must hold %s", perm)
		assert.True(t, qrdbsdk.HasPermissionRoleGrant(qrdbsdk.RoleNameOwner, perm),
			"owner must hold %s", perm)
	}

	// Role creation validates grants against the global permission
	// registry, so the contributed permissions must be registered too —
	// an unregistered grant fails first boot.
	assert.True(t, qrdbsdk.IsPermissionRegistered("keys:sign"))

	// The SoD invariant: the Security Officer role receives nothing from xkms.
	assert.False(t, qrdbsdk.HasPermissionRoleGrant("so", "keys:sign"))
}
