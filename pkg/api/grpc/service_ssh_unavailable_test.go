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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
)

// TestSSHHandlers_UnavailableWithNoClient proves every SSH RPC handler fails
// closed with codes.Unavailable when no SSH client is wired (SetSSHClient
// never called) rather than dereferencing the nil s.sshClient. Before this,
// most of these thirteen handlers' "not configured" branch had no direct
// test at all: only the handful exercised end to end in
// TestService_SSHGenerateListSignDelete (against a real embedded client)
// had any coverage, and none of them proved the fail-closed path a
// deployment with SSH disabled actually takes on every request.
func TestSSHHandlers_UnavailableWithNoClient(t *testing.T) {
	svc := newTestService()
	ctx := context.Background()

	tests := []struct {
		name string
		call func() error
	}{
		{"SSHGenerateKey", func() error {
			_, err := svc.SSHGenerateKey(ctx, &pb.SSHGenerateKeyRequest{})
			return err
		}},
		{"SSHImportKey", func() error {
			_, err := svc.SSHImportKey(ctx, &pb.SSHImportKeyRequest{})
			return err
		}},
		{"SSHListKeys", func() error {
			_, err := svc.SSHListKeys(ctx, &pb.SSHListKeysRequest{})
			return err
		}},
		{"SSHGetKey", func() error {
			_, err := svc.SSHGetKey(ctx, &pb.SSHKeyRef{})
			return err
		}},
		{"SSHDeleteKey", func() error {
			_, err := svc.SSHDeleteKey(ctx, &pb.SSHKeyRef{})
			return err
		}},
		{"SSHExportPublic", func() error {
			_, err := svc.SSHExportPublic(ctx, &pb.SSHKeyRef{})
			return err
		}},
		{"SSHSign", func() error {
			_, err := svc.SSHSign(ctx, &pb.SSHSignRequest{})
			return err
		}},
		{"SSHAddKnownHost", func() error {
			_, err := svc.SSHAddKnownHost(ctx, &pb.SSHAddKnownHostRequest{})
			return err
		}},
		{"SSHListKnownHosts", func() error {
			_, err := svc.SSHListKnownHosts(ctx, &pb.SSHListKnownHostsRequest{})
			return err
		}},
		{"SSHRemoveKnownHost", func() error {
			_, err := svc.SSHRemoveKnownHost(ctx, &pb.SSHRemoveKnownHostRequest{})
			return err
		}},
		{"SSHAddAuthorizedKey", func() error {
			_, err := svc.SSHAddAuthorizedKey(ctx, &pb.SSHAddAuthorizedKeyRequest{})
			return err
		}},
		{"SSHListAuthorizedKeys", func() error {
			_, err := svc.SSHListAuthorizedKeys(ctx, &pb.SSHListAuthorizedKeysRequest{})
			return err
		}},
		{"SSHRemoveAuthorizedKey", func() error {
			_, err := svc.SSHRemoveAuthorizedKey(ctx, &pb.SSHAuthorizedKeyRef{})
			return err
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call()
			st, ok := status.FromError(err)
			require.True(t, ok, "expected a gRPC status error, got %v", err)
			assert.Equal(t, codes.Unavailable, st.Code())
		})
	}
}
