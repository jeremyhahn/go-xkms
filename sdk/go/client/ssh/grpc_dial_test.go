// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package ssh_test

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	googlegrpc "google.golang.org/grpc"

	apigrpc "github.com/jeremyhahn/go-xkms/pkg/api/grpc"
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// newGRPCSSHServerFixture boots a real KeystoreService (pkg/api/grpc,
// the production RPC implementation, not the fakeKeystore test double used
// by the wire-marshalling tests elsewhere in this package) backed by an
// embedded SSH client over an in-memory storage.Backend, listening on lis.
// Session.Dial needs genuine cryptographic signing and host-key
// verification, which fakeKeystore's canned responses cannot provide.
func newGRPCSSHServerFixture(t *testing.T, lis net.Listener) {
	t.Helper()
	backend, err := storage.NewMemoryBackend()
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	embedded, err := sdkssh.NewEmbedded(sdkssh.EmbeddedOptions{Backend: backend})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	svc := apigrpc.NewService(nil, nil, nil)
	svc.SetSSHClient(embedded)

	srv := googlegrpc.NewServer()
	pb.RegisterKeystoreServiceServer(srv, svc)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(lis)
	}()
	t.Cleanup(func() {
		srv.Stop()
		<-done
		_ = embedded.Close()
	})
}

// newGRPCSSHFixture wires the real KeystoreService to a TCP loopback
// listener and returns an SDK gRPC Client bound to it.
func newGRPCSSHFixture(t *testing.T) sdkssh.Client {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	newGRPCSSHServerFixture(t, lis)

	client, err := sdkssh.NewGRPC(sdkssh.GRPCOptions{Endpoint: lis.Addr().String()})
	if err != nil {
		t.Fatalf("NewGRPC: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// TestGRPCSessionDial_Success dials the gRPC client's Session sub-client
// against a real in-process SSH server, authenticating through the
// forward-signing proxy served by the real KeystoreService RPCs.
func TestGRPCSessionDial_Success(t *testing.T) {
	client := newGRPCSSHFixture(t)
	target := newTargetSSHServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	genned, err := client.Keys().Generate(ctx, sdkssh.GenerateRequest{
		Scope: "user", Owner: "alice", Name: "ssh", Algorithm: "ed25519",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	host, port := target.hostPort()
	if err := client.KnownHosts().Add(ctx, sdkssh.AddKnownHostRequest{
		Scope: "user", Owner: "alice", Host: host,
		PublicKey: authorizedKeyLine(target.signer.PublicKey()),
	}); err != nil {
		t.Fatalf("KnownHosts.Add: %v", err)
	}

	sess, err := client.Session().Dial(ctx, sdkssh.SessionDialRequest{
		KeyScope: "user", KeyOwner: "alice", KeyName: genned.Name,
		Host: host, Port: port, User: "testuser", TimeoutSeconds: 5,
	})
	if err != nil {
		t.Fatalf("Session.Dial: %v", err)
	}
	defer func() { _ = sess.Close() }()

	stdout, _, err := sess.Run(ctx, "echo hello")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(string(stdout), "echo hello") {
		t.Fatalf("unexpected stdout: %q", stdout)
	}
}

// TestGRPCSessionDial_UnknownHostRefused asserts host-key verification
// fails closed for an unpinned host.
func TestGRPCSessionDial_UnknownHostRefused(t *testing.T) {
	client := newGRPCSSHFixture(t)
	target := newTargetSSHServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	genned, err := client.Keys().Generate(ctx, sdkssh.GenerateRequest{
		Scope: "user", Owner: "alice", Name: "ssh", Algorithm: "ed25519",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	host, port := target.hostPort()

	_, err = client.Session().Dial(ctx, sdkssh.SessionDialRequest{
		KeyScope: "user", KeyOwner: "alice", KeyName: genned.Name,
		Host: host, Port: port, User: "testuser", TimeoutSeconds: 5,
	})
	if err == nil {
		t.Fatal("expected dial to fail for an unpinned host")
	}
	var notFound *sdkssh.NotFoundError
	if !errors.As(err, &notFound) {
		t.Fatalf("expected *NotFoundError in the chain, got %T: %v", err, err)
	}
}

// TestGRPCSessionDial_HostKeyMismatchRefused asserts host-key verification
// fails closed with a typed *MismatchError for a MITM-indicating mismatch.
func TestGRPCSessionDial_HostKeyMismatchRefused(t *testing.T) {
	client := newGRPCSSHFixture(t)
	target := newTargetSSHServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	genned, err := client.Keys().Generate(ctx, sdkssh.GenerateRequest{
		Scope: "user", Owner: "alice", Name: "ssh", Algorithm: "ed25519",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	host, port := target.hostPort()
	if err := client.KnownHosts().Add(ctx, sdkssh.AddKnownHostRequest{
		Scope: "user", Owner: "alice", Host: host,
		PublicKey: decoyHostKeyLine(t),
	}); err != nil {
		t.Fatalf("KnownHosts.Add: %v", err)
	}

	_, err = client.Session().Dial(ctx, sdkssh.SessionDialRequest{
		KeyScope: "user", KeyOwner: "alice", KeyName: genned.Name,
		Host: host, Port: port, User: "testuser", TimeoutSeconds: 5,
	})
	if err == nil {
		t.Fatal("expected dial to fail for a mismatched host key")
	}
	var mismatch *sdkssh.MismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("expected *MismatchError in the chain, got %T: %v", err, err)
	}
}

// TestGRPCSessionDial_SignerErrorPropagates deletes the authentication key
// before dialing so resolving the remote-signer proxy fails; the failure
// must reach the caller rather than being swallowed.
func TestGRPCSessionDial_SignerErrorPropagates(t *testing.T) {
	client := newGRPCSSHFixture(t)
	target := newTargetSSHServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	genned, err := client.Keys().Generate(ctx, sdkssh.GenerateRequest{
		Scope: "user", Owner: "alice", Name: "ssh", Algorithm: "ed25519",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	host, port := target.hostPort()
	if err := client.KnownHosts().Add(ctx, sdkssh.AddKnownHostRequest{
		Scope: "user", Owner: "alice", Host: host,
		PublicKey: authorizedKeyLine(target.signer.PublicKey()),
	}); err != nil {
		t.Fatalf("KnownHosts.Add: %v", err)
	}
	if err := client.Keys().Delete(ctx, sdkssh.DeleteKeyRequest{
		Scope: "user", Owner: "alice", Name: genned.Name,
	}); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err = client.Session().Dial(ctx, sdkssh.SessionDialRequest{
		KeyScope: "user", KeyOwner: "alice", KeyName: genned.Name,
		Host: host, Port: port, User: "testuser", TimeoutSeconds: 5,
	})
	if err == nil {
		t.Fatal("expected dial to fail when the signing key no longer exists")
	}
	// The gRPC server maps the embedded keys-store not-found error to
	// codes.NotFound (go-xkms#769), and the client decodes that back into a
	// typed *NotFoundError that still carries the original message.
	var notFound *sdkssh.NotFoundError
	if !errors.As(err, &notFound) {
		t.Fatalf("expected *NotFoundError in the chain, got %T: %v", err, err)
	}
	if !strings.Contains(notFound.Error(), "key not found") {
		t.Fatalf("expected the underlying key-not-found failure to propagate, got: %v", notFound)
	}
}

// TestUnixSessionDial_Success proves the "unix" scheme dispatched by
// NewClientForServer (gRPC over a Unix domain socket) reaches the same
// Session.Dial implementation as TCP gRPC: NewClientForServer builds a
// plaintext GRPCOptions for the socket path and grpcSessionClient.Dial has
// no transport-specific branch, so this exercises the identical code path
// end-to-end over a real UDS listener.
func TestUnixSessionDial_Success(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "xkms-ssh.sock")
	lis, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	newGRPCSSHServerFixture(t, lis)
	t.Cleanup(func() { _ = os.Remove(sockPath) })

	client, err := sdkssh.NewClientForServer("unix://"+sockPath, "", "")
	if err != nil {
		t.Fatalf("NewClientForServer: %v", err)
	}
	defer func() { _ = client.Close() }()

	target := newTargetSSHServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	genned, err := client.Keys().Generate(ctx, sdkssh.GenerateRequest{
		Scope: "user", Owner: "alice", Name: "ssh", Algorithm: "ed25519",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	host, port := target.hostPort()
	if err := client.KnownHosts().Add(ctx, sdkssh.AddKnownHostRequest{
		Scope: "user", Owner: "alice", Host: host,
		PublicKey: authorizedKeyLine(target.signer.PublicKey()),
	}); err != nil {
		t.Fatalf("KnownHosts.Add: %v", err)
	}

	sess, err := client.Session().Dial(ctx, sdkssh.SessionDialRequest{
		KeyScope: "user", KeyOwner: "alice", KeyName: genned.Name,
		Host: host, Port: port, User: "testuser", TimeoutSeconds: 5,
	})
	if err != nil {
		t.Fatalf("Session.Dial: %v", err)
	}
	defer func() { _ = sess.Close() }()

	stdout, _, err := sess.Run(ctx, "echo hello")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(string(stdout), "echo hello") {
		t.Fatalf("unexpected stdout: %q", stdout)
	}
}
