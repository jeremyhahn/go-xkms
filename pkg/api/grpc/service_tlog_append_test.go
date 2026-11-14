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

//go:build qrdb_vlog

package grpc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/ca/tlog"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tlogtest"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

const appendCaller = "spiffe://acme/svc/billing"

// newTransparencyLogAppendService returns a Service whose xkms service
// appends to a real, empty transparency log.
func newTransparencyLogAppendService(t *testing.T) (*Service, *tlogtest.Fixture) {
	t.Helper()
	ca, err := testutil.GenerateTestCA()
	require.NoError(t, err)
	f := tlogtest.New(t, ca.Key, ca.Cert)
	svc := &xkms.XKMSService{}
	svc.SetTransparencyLog(f.Log)
	return NewService(nil, nil, svc), f
}

// peerCallerContext returns ctx as a gRPC call over a mutual TLS connection
// whose verified client certificate carries uris as its URI SANs.
func peerCallerContext(t *testing.T, ctx context.Context, uris ...string) context.Context {
	t.Helper()
	state, err := testutil.VerifiedClientState(uris...)
	require.NoError(t, err)
	return peer.NewContext(ctx, &peer.Peer{AuthInfo: credentials.TLSInfo{State: *state}})
}

func TestAppendTransparencyLogExternal_RecordsThePeersSPIFFEID(t *testing.T) {
	s, f := newTransparencyLogAppendService(t)
	ctx := peerCallerContext(t, f.Ctx, "https://acme.example/profile", appendCaller)

	resp, err := s.AppendTransparencyLogExternal(ctx, &pb.AppendTransparencyLogExternalRequest{Payload: []byte("invoice 7")})
	require.NoError(t, err)
	require.Equal(t, uint64(0), resp.GetIndex(), "the first entry of an empty log")

	entry, err := s.GetTransparencyLogEntry(f.Ctx, &pb.GetTransparencyLogEntryRequest{Index: resp.GetIndex()})
	require.NoError(t, err)
	decoded, err := tlog.Unmarshal(entry.GetEntry())
	require.NoError(t, err)
	require.Equal(t, tlog.External{SPIFFEID: appendCaller, Payload: []byte("invoice 7")}, decoded)
}

func TestAppendTransparencyLogExternal_Unavailable(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	require.NoError(t, err)
	f := tlogtest.New(t, ca.Key, ca.Cert)
	ctx := peerCallerContext(t, f.Ctx, appendCaller)

	tests := map[string]*Service{
		"no xkms service": NewService(nil, nil, nil),
		"no log":          NewService(nil, nil, &xkms.XKMSService{}),
	}
	for name, s := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := s.AppendTransparencyLogExternal(ctx, &pb.AppendTransparencyLogExternalRequest{Payload: []byte("invoice 7")})
			require.Equal(t, codes.Unavailable, status.Code(err), "%v", err)
		})
	}
}

func TestAppendTransparencyLogExternal_Unauthenticated(t *testing.T) {
	s, f := newTransparencyLogAppendService(t)

	tests := map[string]context.Context{
		"no TLS":            f.Ctx,
		"no SPIFFE ID":      peerCallerContext(t, f.Ctx, "https://acme.example/profile"),
		"two SPIFFE IDs":    peerCallerContext(t, f.Ctx, appendCaller, "spiffe://acme/svc/payroll"),
		"no URI SAN at all": peerCallerContext(t, f.Ctx),
	}
	for name, ctx := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := s.AppendTransparencyLogExternal(ctx, &pb.AppendTransparencyLogExternalRequest{Payload: []byte("invoice 7")})
			require.Equal(t, codes.Unauthenticated, status.Code(err), "%v", err)
		})
	}
	require.Equal(t, uint64(0), tlogtest.Size(f.Ctx, t, f.Log), "a refused append records nothing")
}

func TestAppendTransparencyLogExternal_InvalidPayload(t *testing.T) {
	s, f := newTransparencyLogAppendService(t)
	ctx := peerCallerContext(t, f.Ctx, appendCaller)

	tests := map[string][]byte{
		"empty":     nil,
		"oversized": make([]byte, 1<<16),
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := s.AppendTransparencyLogExternal(ctx, &pb.AppendTransparencyLogExternalRequest{Payload: payload})
			require.Equal(t, codes.InvalidArgument, status.Code(err), "%v", err)
		})
	}
}
