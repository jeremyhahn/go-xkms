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
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
)

// TestAuthzDeny_SSHMethods proves every SSH RPC refuses an unauthorized
// principal.
//
// This surface shipped with NO authorization gates at all: service_ssh.go
// called s.authorize zero times, while the QUIC
// transport gated the identical operations with ssh:read / ssh:write /
// ssh:delete. Any authenticated principal could generate, sign with, and
// delete SSH keys and mutate authorized_keys over gRPC. A gate with no
// negative test is how that survived, so each RPC is asserted individually
// rather than through a single representative call.
//
// The service is deliberately built with a nil sshClient. An RPC that checked
// availability before authorization would return Unavailable here, so
// requiring PermissionDenied also pins the gate's position: it must run
// first, and an unauthorized caller must not learn whether the SSH subsystem
// is even configured.
func TestAuthzDeny_SSHMethods(t *testing.T) {
	svc := newDeniedService()
	require.Nil(t, svc.sshClient, "sshClient must be nil so Unavailable would mask a missing gate")
	ctx := deniedCtx()

	tests := []struct {
		name string
		fn   func() error
	}{
		{"SSHGenerateKey", func() error {
			_, err := svc.SSHGenerateKey(ctx, &pb.SSHGenerateKeyRequest{Name: "k"})
			return err
		}},
		{"SSHImportKey", func() error {
			_, err := svc.SSHImportKey(ctx, &pb.SSHImportKeyRequest{Name: "k"})
			return err
		}},
		{"SSHListKeys", func() error {
			_, err := svc.SSHListKeys(ctx, &pb.SSHListKeysRequest{})
			return err
		}},
		{"SSHGetKey", func() error {
			_, err := svc.SSHGetKey(ctx, &pb.SSHKeyRef{Name: "k"})
			return err
		}},
		{"SSHDeleteKey", func() error {
			_, err := svc.SSHDeleteKey(ctx, &pb.SSHKeyRef{Name: "k"})
			return err
		}},
		{"SSHExportPublic", func() error {
			_, err := svc.SSHExportPublic(ctx, &pb.SSHKeyRef{Name: "k"})
			return err
		}},
		{"SSHSign", func() error {
			_, err := svc.SSHSign(ctx, &pb.SSHSignRequest{Key: &pb.SSHKeyRef{Name: "k"}})
			return err
		}},
		{"SSHAddKnownHost", func() error {
			_, err := svc.SSHAddKnownHost(ctx, &pb.SSHAddKnownHostRequest{Host: "h"})
			return err
		}},
		{"SSHListKnownHosts", func() error {
			_, err := svc.SSHListKnownHosts(ctx, &pb.SSHListKnownHostsRequest{})
			return err
		}},
		{"SSHRemoveKnownHost", func() error {
			_, err := svc.SSHRemoveKnownHost(ctx, &pb.SSHRemoveKnownHostRequest{Host: "h"})
			return err
		}},
		{"SSHAddAuthorizedKey", func() error {
			_, err := svc.SSHAddAuthorizedKey(ctx, &pb.SSHAddAuthorizedKeyRequest{Name: "k"})
			return err
		}},
		{"SSHListAuthorizedKeys", func() error {
			_, err := svc.SSHListAuthorizedKeys(ctx, &pb.SSHListAuthorizedKeysRequest{})
			return err
		}},
		{"SSHRemoveAuthorizedKey", func() error {
			_, err := svc.SSHRemoveAuthorizedKey(ctx, &pb.SSHAuthorizedKeyRef{Name: "k"})
			return err
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			require.Error(t, err, "%s must refuse an unauthorized principal", tt.name)
			assert.Equal(t, codes.PermissionDenied, status.Code(err),
				"%s must deny with PermissionDenied, not %v", tt.name, status.Code(err))
		})
	}
}

// TestNoSSHConsoleRPC is the regression test for the decision that xkmsd never
// terminates an SSH session on any transport. The gRPC service (which the Unix
// socket transport also serves) once carried an SSHConsole bidi stream; it was
// removed because it let an authorized caller make the appliance dial an
// arbitrary host and proxy an interactive shell through it. The vault signs SSH
// authentication challenges (SSHSign) and the client runs the session.
func TestNoSSHConsoleRPC(t *testing.T) {
	svcType := reflect.TypeOf(&Service{})
	for i := range svcType.NumMethod() {
		name := svcType.Method(i).Name
		assert.NotContains(t, strings.ToLower(name), "console",
			"gRPC service must not expose an SSH console RPC, found %s", name)
	}
}
