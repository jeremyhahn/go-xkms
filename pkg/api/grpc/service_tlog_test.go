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
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tlogtest"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// transparencyLogReadCall runs one of the log's read verbs on s, discarding
// its response, so the error mappings share one table.
type transparencyLogReadCall func(ctx context.Context, s *Service) error

// transparencyLogReadVerbs calls each read verb with in-range arguments for a
// log of at least two entries.
var transparencyLogReadVerbs = map[string]transparencyLogReadCall{
	"head": func(ctx context.Context, s *Service) error {
		_, err := s.GetTransparencyLogHead(ctx, &pb.GetTransparencyLogHeadRequest{})
		return err
	},
	"entry": func(ctx context.Context, s *Service) error {
		_, err := s.GetTransparencyLogEntry(ctx, &pb.GetTransparencyLogEntryRequest{Index: 0})
		return err
	},
	"inclusion proof": func(ctx context.Context, s *Service) error {
		_, err := s.GetTransparencyLogInclusionProof(ctx, &pb.GetTransparencyLogInclusionProofRequest{Index: 0, TreeSize: 2})
		return err
	},
	"consistency proof": func(ctx context.Context, s *Service) error {
		_, err := s.GetTransparencyLogConsistencyProof(ctx, &pb.GetTransparencyLogConsistencyProofRequest{FirstSize: 1, SecondSize: 2})
		return err
	},
}

// newPopulatedTransparencyLogService returns a service over a log holding
// two external entries.
func newPopulatedTransparencyLogService(t *testing.T) (*Service, *tlogtest.Fixture) {
	t.Helper()
	s, f := newTransparencyLogAppendService(t)
	ctx := peerCallerContext(t, f.Ctx, appendCaller)
	for _, payload := range []string{"invoice 7", "invoice 8"} {
		_, err := s.AppendTransparencyLogExternal(ctx, &pb.AppendTransparencyLogExternalRequest{Payload: []byte(payload)})
		require.NoError(t, err)
	}
	return s, f
}

func TestGetTransparencyLogHead_ReportsTheTree(t *testing.T) {
	s, f := newPopulatedTransparencyLogService(t)

	resp, err := s.GetTransparencyLogHead(f.Ctx, &pb.GetTransparencyLogHeadRequest{})
	require.NoError(t, err)
	require.Equal(t, uint64(2), resp.GetSize())
	require.NotEmpty(t, resp.GetOrigin())
	require.NotEmpty(t, resp.GetRootHash())
	require.NotEmpty(t, resp.GetCheckpoint())
}

func TestGetTransparencyLogEntry_ReturnsTheEntry(t *testing.T) {
	s, f := newPopulatedTransparencyLogService(t)

	resp, err := s.GetTransparencyLogEntry(f.Ctx, &pb.GetTransparencyLogEntryRequest{Index: 1})
	require.NoError(t, err)
	require.Equal(t, uint64(1), resp.GetIndex())
	require.NotEmpty(t, resp.GetEntry())
}

func TestGetTransparencyLogInclusionProof_ProvesTheEntry(t *testing.T) {
	s, f := newPopulatedTransparencyLogService(t)

	resp, err := s.GetTransparencyLogInclusionProof(f.Ctx, &pb.GetTransparencyLogInclusionProofRequest{Index: 0, TreeSize: 2})
	require.NoError(t, err)
	require.Equal(t, uint64(0), resp.GetIndex())
	require.Equal(t, uint64(2), resp.GetTreeSize())
	require.Len(t, resp.GetHashes(), 1, "a two-leaf tree proves a leaf with its sibling")
}

func TestGetTransparencyLogConsistencyProof_ProvesTheGrowth(t *testing.T) {
	s, f := newPopulatedTransparencyLogService(t)

	resp, err := s.GetTransparencyLogConsistencyProof(f.Ctx, &pb.GetTransparencyLogConsistencyProofRequest{FirstSize: 1, SecondSize: 2})
	require.NoError(t, err)
	require.Equal(t, uint64(1), resp.GetFirstSize())
	require.Equal(t, uint64(2), resp.GetSecondSize())
	require.NotEmpty(t, resp.GetHashes())
}

func TestTransparencyLogReadVerbs_Unavailable(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	require.NoError(t, err)
	f := tlogtest.New(t, ca.Key, ca.Cert)

	services := map[string]*Service{
		"no xkms service": NewService(nil, nil, nil),
		"no log":          NewService(nil, nil, &xkms.XKMSService{}),
	}
	for serviceName, s := range services {
		for verb, call := range transparencyLogReadVerbs {
			t.Run(serviceName+"/"+verb, func(t *testing.T) {
				err := call(f.Ctx, s)
				require.Equal(t, codes.Unavailable, status.Code(err), "%v", err)
			})
		}
	}
}

func TestTransparencyLogReadVerbs_OutOfRange(t *testing.T) {
	s, f := newPopulatedTransparencyLogService(t)

	tests := map[string]transparencyLogReadCall{
		"entry past the tree": func(ctx context.Context, s *Service) error {
			_, err := s.GetTransparencyLogEntry(ctx, &pb.GetTransparencyLogEntryRequest{Index: 2})
			return err
		},
		"inclusion index at the tree size": func(ctx context.Context, s *Service) error {
			_, err := s.GetTransparencyLogInclusionProof(ctx, &pb.GetTransparencyLogInclusionProofRequest{Index: 2, TreeSize: 2})
			return err
		},
		"inclusion tree size past the tree": func(ctx context.Context, s *Service) error {
			_, err := s.GetTransparencyLogInclusionProof(ctx, &pb.GetTransparencyLogInclusionProofRequest{Index: 0, TreeSize: 3})
			return err
		},
		"consistency first size past the second": func(ctx context.Context, s *Service) error {
			_, err := s.GetTransparencyLogConsistencyProof(ctx, &pb.GetTransparencyLogConsistencyProofRequest{FirstSize: 2, SecondSize: 1})
			return err
		},
		"consistency second size past the tree": func(ctx context.Context, s *Service) error {
			_, err := s.GetTransparencyLogConsistencyProof(ctx, &pb.GetTransparencyLogConsistencyProofRequest{FirstSize: 1, SecondSize: 3})
			return err
		},
	}
	for name, call := range tests {
		t.Run(name, func(t *testing.T) {
			err := call(f.Ctx, s)
			require.Equal(t, codes.InvalidArgument, status.Code(err), "%v", err)
		})
	}
}

func TestTransparencyLogReadVerbs_MissingLogIsInternal(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	require.NoError(t, err)
	f := tlogtest.New(t, ca.Key, ca.Cert)
	svc := &xkms.XKMSService{}
	svc.SetTransparencyLog(f.Missing)
	s := NewService(nil, nil, svc)

	for verb, call := range transparencyLogReadVerbs {
		t.Run(verb, func(t *testing.T) {
			err := call(f.Ctx, s)
			require.Equal(t, codes.Internal, status.Code(err), "%v", err)
		})
	}
}
