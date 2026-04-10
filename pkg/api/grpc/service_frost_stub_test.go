//go:build !frost

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
	"testing"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestFrostStubs tests all FROST stub methods return unimplemented
func TestFrostStubs(t *testing.T) {
	service := NewService(nil, nil)

	t.Run("FrostGenerateKey returns unimplemented", func(t *testing.T) {
		resp, err := service.FrostGenerateKey(context.Background(), &pb.FrostGenerateKeyRequest{})
		if err == nil {
			t.Fatal("Expected error")
		}
		if resp != nil {
			t.Error("Expected nil response")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.Unimplemented {
			t.Errorf("Expected Unimplemented, got %v", st.Code())
		}
	})

	t.Run("FrostImportKey returns unimplemented", func(t *testing.T) {
		resp, err := service.FrostImportKey(context.Background(), &pb.FrostImportKeyRequest{})
		if err == nil {
			t.Fatal("Expected error")
		}
		if resp != nil {
			t.Error("Expected nil response")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.Unimplemented {
			t.Errorf("Expected Unimplemented, got %v", st.Code())
		}
	})

	t.Run("FrostListKeys returns unimplemented", func(t *testing.T) {
		resp, err := service.FrostListKeys(context.Background(), &pb.FrostListKeysRequest{})
		if err == nil {
			t.Fatal("Expected error")
		}
		if resp != nil {
			t.Error("Expected nil response")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.Unimplemented {
			t.Errorf("Expected Unimplemented, got %v", st.Code())
		}
	})

	t.Run("FrostGetKey returns unimplemented", func(t *testing.T) {
		resp, err := service.FrostGetKey(context.Background(), &pb.FrostGetKeyRequest{})
		if err == nil {
			t.Fatal("Expected error")
		}
		if resp != nil {
			t.Error("Expected nil response")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.Unimplemented {
			t.Errorf("Expected Unimplemented, got %v", st.Code())
		}
	})

	t.Run("FrostDeleteKey returns unimplemented", func(t *testing.T) {
		resp, err := service.FrostDeleteKey(context.Background(), &pb.FrostDeleteKeyRequest{})
		if err == nil {
			t.Fatal("Expected error")
		}
		if resp != nil {
			t.Error("Expected nil response")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.Unimplemented {
			t.Errorf("Expected Unimplemented, got %v", st.Code())
		}
	})

	t.Run("FrostGenerateNonces returns unimplemented", func(t *testing.T) {
		resp, err := service.FrostGenerateNonces(context.Background(), &pb.FrostGenerateNoncesRequest{})
		if err == nil {
			t.Fatal("Expected error")
		}
		if resp != nil {
			t.Error("Expected nil response")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.Unimplemented {
			t.Errorf("Expected Unimplemented, got %v", st.Code())
		}
	})

	t.Run("FrostSignRound returns unimplemented", func(t *testing.T) {
		resp, err := service.FrostSignRound(context.Background(), &pb.FrostSignRoundRequest{})
		if err == nil {
			t.Fatal("Expected error")
		}
		if resp != nil {
			t.Error("Expected nil response")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.Unimplemented {
			t.Errorf("Expected Unimplemented, got %v", st.Code())
		}
	})

	t.Run("FrostAggregate returns unimplemented", func(t *testing.T) {
		resp, err := service.FrostAggregate(context.Background(), &pb.FrostAggregateRequest{})
		if err == nil {
			t.Fatal("Expected error")
		}
		if resp != nil {
			t.Error("Expected nil response")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.Unimplemented {
			t.Errorf("Expected Unimplemented, got %v", st.Code())
		}
	})

	t.Run("FrostVerify returns unimplemented", func(t *testing.T) {
		resp, err := service.FrostVerify(context.Background(), &pb.FrostVerifyRequest{})
		if err == nil {
			t.Fatal("Expected error")
		}
		if resp != nil {
			t.Error("Expected nil response")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.Unimplemented {
			t.Errorf("Expected Unimplemented, got %v", st.Code())
		}
	})
}
