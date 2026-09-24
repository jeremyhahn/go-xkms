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

package grpc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	pkgauthorized "github.com/jeremyhahn/go-xkms/pkg/ssh/authorized"
	pkgkeys "github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	pkgknownhosts "github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
)

// TestService_SSHGetKey_MissingReturnsNotFound proves the embedded key
// store's *pkgkeys.KeyNotFoundError -- which previously fell through
// sshStatus's type switch to codes.Internal -- now reports codes.NotFound
// (#769).
func TestService_SSHGetKey_MissingReturnsNotFound(t *testing.T) {
	svc := newSSHService(t)

	_, err := svc.SSHGetKey(context.Background(), &pb.SSHKeyRef{Scope: "user", Owner: "alice", Name: "ghost"})
	if err == nil {
		t.Fatal("expected an error for a missing key")
	}
	if got := status.Code(err); got != codes.NotFound {
		t.Fatalf("code = %v, want NotFound", got)
	}
}

// TestService_SSHAddKnownHost_DuplicateReturnsAlreadyExists proves the
// embedded known_hosts store's *pkgknownhosts.DuplicateError reports
// codes.AlreadyExists rather than falling through to codes.Internal.
func TestService_SSHAddKnownHost_DuplicateReturnsAlreadyExists(t *testing.T) {
	svc := newSSHService(t)
	ctx := context.Background()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	sshPub, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	req := &pb.SSHAddKnownHostRequest{
		Scope: "user", Owner: "alice", Host: "git.example.com",
		PublicKey: string(gossh.MarshalAuthorizedKey(sshPub)),
	}

	if _, err := svc.SSHAddKnownHost(ctx, req); err != nil {
		t.Fatalf("first SSHAddKnownHost: %v", err)
	}
	_, err = svc.SSHAddKnownHost(ctx, req)
	if err == nil {
		t.Fatal("expected an error re-pinning the same host")
	}
	if got := status.Code(err); got != codes.AlreadyExists {
		t.Fatalf("code = %v, want AlreadyExists", got)
	}
}

// TestService_SSHRemoveKnownHost_MissingReturnsNotFound covers the
// known_hosts sibling of the keys-store NotFound case.
func TestService_SSHRemoveKnownHost_MissingReturnsNotFound(t *testing.T) {
	svc := newSSHService(t)

	_, err := svc.SSHRemoveKnownHost(context.Background(), &pb.SSHRemoveKnownHostRequest{
		Scope: "user", Owner: "alice", Host: "ghost.example.com",
	})
	if err == nil {
		t.Fatal("expected an error removing a pin that does not exist")
	}
	if got := status.Code(err); got != codes.NotFound {
		t.Fatalf("code = %v, want NotFound", got)
	}
}

// TestService_SSHRemoveAuthorizedKey_MissingReturnsNotFound covers the
// authorized_keys sibling of the keys-store NotFound case.
func TestService_SSHRemoveAuthorizedKey_MissingReturnsNotFound(t *testing.T) {
	svc := newSSHService(t)

	_, err := svc.SSHRemoveAuthorizedKey(context.Background(), &pb.SSHAuthorizedKeyRef{
		Scope: "service", Owner: "svc", Name: "ghost",
	})
	if err == nil {
		t.Fatal("expected an error removing an authorized_keys entry that does not exist")
	}
	if got := status.Code(err); got != codes.NotFound {
		t.Fatalf("code = %v, want NotFound", got)
	}
}

// TestSSHStatus_MappingTable exercises sshStatus directly against one
// representative error per class, including the classes no gRPC RPC
// currently returns server-side (known_hosts.MismatchError has no Verify
// RPC over gRPC today -- KnownHostsClient.Verify resolves it client-side via
// List -- but sshStatus must still classify it correctly for the day a
// server-side verify path exists, and so the mapping table stays provably
// correct independent of which RPCs currently exercise it).
func TestSSHStatus_MappingTable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want codes.Code
	}{
		{"keys_not_found", &pkgkeys.KeyNotFoundError{ID: "k"}, codes.NotFound},
		{"known_hosts_not_found", &pkgknownhosts.NotFoundError{Host: "h"}, codes.NotFound},
		{"authorized_not_found", &pkgauthorized.NotFoundError{Name: "n"}, codes.NotFound},
		{"known_hosts_duplicate", &pkgknownhosts.DuplicateError{Host: "h"}, codes.AlreadyExists},
		{"authorized_duplicate", &pkgauthorized.DuplicateError{Name: "n"}, codes.AlreadyExists},
		{"known_hosts_mismatch", &pkgknownhosts.MismatchError{Host: "h", Expected: "a", Received: "b"}, codes.FailedPrecondition},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := sshStatus(tc.err)
			if got := status.Code(err); got != tc.want {
				t.Errorf("code = %v, want %v", got, tc.want)
			}
			if !strings.Contains(status.Convert(err).Message(), tc.err.Error()) {
				t.Errorf("message %q lost the underlying error detail %q", status.Convert(err).Message(), tc.err.Error())
			}
		})
	}
}

// TestSSHStatus_UnknownErrorStaysInternalWithoutLeakingDetail proves an
// error sshStatus's table does not recognize maps to codes.Internal without
// echoing the error's own text: an unclassified error may wrap
// storage-backend detail (a filesystem path, a driver error) that must not
// reach an RPC caller.
func TestSSHStatus_UnknownErrorStaysInternalWithoutLeakingDetail(t *testing.T) {
	sensitive := errors.New("open /var/lib/xkms/data/secret-envelope.json: permission denied")

	err := sshStatus(sensitive)
	if got := status.Code(err); got != codes.Internal {
		t.Fatalf("code = %v, want Internal", got)
	}
	if msg := status.Convert(err).Message(); strings.Contains(msg, "secret-envelope.json") {
		t.Errorf("internal detail leaked to the RPC caller: %q", msg)
	}
}

// TestSSHStatus_Nil proves sshStatus(nil) returns nil rather than an OK
// status error, so callers can pass it straight through without a nil
// check.
func TestSSHStatus_Nil(t *testing.T) {
	if err := sshStatus(nil); err != nil {
		t.Fatalf("sshStatus(nil) = %v, want nil", err)
	}
}
