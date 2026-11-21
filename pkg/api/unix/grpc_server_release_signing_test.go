// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package unix

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/refvalue"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/releasesigningtest"
)

// TestReleaseSigning_OverTheSocket signs a CoRIM over the Unix socket: the
// peer's (system) tenant key signs, and a peer without the sign permission is
// refused.
func TestReleaseSigning_OverTheSocket(t *testing.T) {
	corim := releasesigningtest.UnsignedCoRIM(t)
	req := &pb.SignReleaseCoRIMRequest{Repository: releasesigningtest.Repository, Corim: corim}

	f := releasesigningtest.New(t, qrdbsdk.SystemTenantID, releasesigningtest.SignPermission)
	client := startReleaseSigningServer(t, f)
	resp, err := client.SignReleaseCoRIM(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, appraisal.ReleaseSigningKeyID, resp.GetKeyId())
	verified, err := refvalue.VerifySigned(resp.GetSignedCorim(), refvalue.VerifyOptions{PublicKey: f.ReleaseKey})
	require.NoError(t, err)
	assert.Equal(t, releasesigningtest.Repository, verified.Signer)

	f = releasesigningtest.New(t, qrdbsdk.SystemTenantID, "attestation_signing_keys:get")
	client = startReleaseSigningServer(t, f)
	_, err = client.SignReleaseCoRIM(context.Background(), req)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func startReleaseSigningServer(t *testing.T, f *releasesigningtest.Fixture) pb.KeystoreServiceClient {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "xkms-sign-*")
	require.NoError(t, err)
	socketPath := filepath.Join(tmpDir, "sign.sock")
	server, err := NewGRPCServer(&GRPCConfig{SocketPath: socketPath, XKMSService: f.Service})
	require.NoError(t, err)
	go func() { _ = server.Start() }()
	waitForGRPCServerReady(t, server, socketPath)
	conn, err := grpc.NewClient("unix://"+socketPath, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Stop(ctx)
		_ = os.RemoveAll(tmpDir)
	})
	return pb.NewKeystoreServiceClient(conn)
}
