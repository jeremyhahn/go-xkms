// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package grpc

import (
	"context"
	"testing"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	sshbackend "github.com/jeremyhahn/go-xkms/pkg/ssh/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// newSSHService builds a Service with an embedded SSH client backed by an
// in-memory software backend, exercising the server-side SSH RPC path.
func newSSHService(t *testing.T) *Service {
	t.Helper()
	kp, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	if err != nil {
		t.Fatalf("software.NewBackend: %v", err)
	}
	provider, err := sshbackend.New(sshbackend.ResolverFunc(func(_ context.Context, _ string) (types.KeyProvider, error) {
		return kp, nil
	}))
	if err != nil {
		t.Fatalf("sshbackend.New: %v", err)
	}
	client, err := sdkssh.NewEmbedded(sdkssh.EmbeddedOptions{Backend: storage.New(), BackendProvider: provider})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	svc := NewService(nil, nil, nil)
	svc.SetSSHClient(client)
	return svc
}

func TestService_SSHGenerateListSignDelete(t *testing.T) {
	ctx := context.Background()
	svc := newSSHService(t)

	// Generate a backend-backed key.
	genResp, err := svc.SSHGenerateKey(ctx, &pb.SSHGenerateKeyRequest{
		Scope:     "user",
		Owner:     "alice",
		Name:      "grpc-key",
		Algorithm: "ecdsa-p256",
		Backend:   "software",
	})
	if err != nil {
		t.Fatalf("SSHGenerateKey: %v", err)
	}
	if genResp.GetKey().GetBackend() != "software" {
		t.Fatalf("expected backend=software, got %q", genResp.GetKey().GetBackend())
	}

	// List shows it.
	listResp, err := svc.SSHListKeys(ctx, &pb.SSHListKeysRequest{Scope: "user", Owner: "alice"})
	if err != nil {
		t.Fatalf("SSHListKeys: %v", err)
	}
	if len(listResp.GetKeys()) != 1 {
		t.Fatalf("expected 1 key, got %d", len(listResp.GetKeys()))
	}

	// Export the public key.
	pubResp, err := svc.SSHExportPublic(ctx, &pb.SSHKeyRef{Scope: "user", Owner: "alice", Name: "grpc-key"})
	if err != nil {
		t.Fatalf("SSHExportPublic: %v", err)
	}
	if pubResp.GetLine() == "" {
		t.Fatal("expected non-empty public key line")
	}

	// Sign a digest through the backend.
	signResp, err := svc.SSHSign(ctx, &pb.SSHSignRequest{
		Key:    &pb.SSHKeyRef{Scope: "user", Owner: "alice", Name: "grpc-key"},
		Digest: []byte("payload to sign"),
	})
	if err != nil {
		t.Fatalf("SSHSign: %v", err)
	}
	if len(signResp.GetBlob()) == 0 {
		t.Fatal("expected non-empty signature blob")
	}

	// Delete it.
	if _, err := svc.SSHDeleteKey(ctx, &pb.SSHKeyRef{Scope: "user", Owner: "alice", Name: "grpc-key"}); err != nil {
		t.Fatalf("SSHDeleteKey: %v", err)
	}
	listResp, err = svc.SSHListKeys(ctx, &pb.SSHListKeysRequest{Scope: "user", Owner: "alice"})
	if err != nil {
		t.Fatalf("SSHListKeys after delete: %v", err)
	}
	if len(listResp.GetKeys()) != 0 {
		t.Fatalf("expected 0 keys after delete, got %d", len(listResp.GetKeys()))
	}
}

func TestService_SSHUnavailableWhenUnset(t *testing.T) {
	ctx := context.Background()
	svc := NewService(nil, nil, nil) // no SSH client wired
	if _, err := svc.SSHGenerateKey(ctx, &pb.SSHGenerateKeyRequest{Scope: "user", Owner: "a", Name: "k", Algorithm: "ed25519"}); err == nil {
		t.Fatal("expected Unavailable error when SSH client is not configured")
	}
}
