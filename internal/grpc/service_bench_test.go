// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package grpc

import (
	"context"
	"fmt"
	"testing"

	pb "github.com/jeremyhahn/go-keychain/api/proto/keychainv1"
	"github.com/jeremyhahn/go-keychain/pkg/backend/software"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/storage/memory"
)

// createBenchmarkService creates a gRPC service for benchmarking
func createBenchmarkService(b *testing.B) *Service {
	b.Helper()

	keyStorage := memory.New()
	config := &software.Config{
		KeyStorage: keyStorage,
	}

	backend, err := software.NewBackend(config)
	if err != nil {
		b.Fatalf("Failed to create backend: %v", err)
	}

	ks, err := keychain.New(&keychain.Config{
		Backend: backend,
	})
	if err != nil {
		b.Fatalf("Failed to create keystore: %v", err)
	}

	manager := NewBackendRegistry()
	_ = manager.Register("software", ks)

	return NewService(manager)
}

// BenchmarkGRPC_Health benchmarks the health check
func BenchmarkGRPC_Health(b *testing.B) {
	service := createBenchmarkService(b)
	ctx := context.Background()
	req := &pb.HealthRequest{}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := service.Health(ctx, req)
		if err != nil {
			b.Fatalf("Health() failed: %v", err)
		}
	}
}

// BenchmarkGRPC_ListBackends benchmarks listing backends
func BenchmarkGRPC_ListBackends(b *testing.B) {
	service := createBenchmarkService(b)
	ctx := context.Background()
	req := &pb.ListBackendsRequest{}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := service.ListBackends(ctx, req)
		if err != nil {
			b.Fatalf("ListBackends() failed: %v", err)
		}
	}
}

// BenchmarkGRPC_GetBackendInfo benchmarks getting backend info
func BenchmarkGRPC_GetBackendInfo(b *testing.B) {
	service := createBenchmarkService(b)
	ctx := context.Background()
	req := &pb.GetBackendInfoRequest{
		Name: "software",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := service.GetBackendInfo(ctx, req)
		if err != nil {
			b.Fatalf("GetBackendInfo() failed: %v", err)
		}
	}
}

// BenchmarkGRPC_GenerateKeyRSA benchmarks RSA key generation
func BenchmarkGRPC_GenerateKeyRSA(b *testing.B) {
	keySizes := []int{2048, 3072, 4096}

	for _, keySize := range keySizes {
		b.Run(fmt.Sprintf("RSA-%d", keySize), func(b *testing.B) {
			service := createBenchmarkService(b)
			ctx := context.Background()

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				req := &pb.GenerateKeyRequest{
					KeyId:   fmt.Sprintf("bench-rsa-%d", i),
					Backend: "software",
					KeyType: "rsa",
					KeySize: int32(keySize),
				}

				_, err := service.GenerateKey(ctx, req)
				if err != nil {
					b.Fatalf("GenerateKey() failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkGRPC_GenerateKeyECDSA benchmarks ECDSA key generation
func BenchmarkGRPC_GenerateKeyECDSA(b *testing.B) {
	curves := []string{"P256", "P384", "P521"}

	for _, curve := range curves {
		b.Run(fmt.Sprintf("ECDSA-%s", curve), func(b *testing.B) {
			service := createBenchmarkService(b)
			ctx := context.Background()

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				req := &pb.GenerateKeyRequest{
					KeyId:   fmt.Sprintf("bench-ecdsa-%d", i),
					Backend: "software",
					KeyType: "ecdsa",
					Curve:   curve,
				}

				_, err := service.GenerateKey(ctx, req)
				if err != nil {
					b.Fatalf("GenerateKey() failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkGRPC_GenerateKeyEd25519 benchmarks Ed25519 key generation
func BenchmarkGRPC_GenerateKeyEd25519(b *testing.B) {
	service := createBenchmarkService(b)
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req := &pb.GenerateKeyRequest{
			KeyId:   fmt.Sprintf("bench-ed25519-%d", i),
			Backend: "software",
			KeyType: "ed25519",
		}

		_, err := service.GenerateKey(ctx, req)
		if err != nil {
			b.Fatalf("GenerateKey() failed: %v", err)
		}
	}
}

// BenchmarkGRPC_SignData benchmarks signing operations
func BenchmarkGRPC_SignData(b *testing.B) {
	service := createBenchmarkService(b)
	ctx := context.Background()

	// Pre-generate key
	genReq := &pb.GenerateKeyRequest{
		KeyId:   "bench-sign",
		Backend: "software",
		KeyType: "ecdsa",
		Curve:   "P256",
	}

	_, err := service.GenerateKey(ctx, genReq)
	if err != nil {
		b.Fatalf("GenerateKey() failed: %v", err)
	}

	data := []byte("benchmark data to sign")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req := &pb.SignRequest{
			KeyId:   "bench-sign",
			Backend: "software",
			Data:    data,
		}

		_, err := service.Sign(ctx, req)
		if err != nil {
			b.Fatalf("Sign() failed: %v", err)
		}
	}
}

// BenchmarkGRPC_GetKey benchmarks key retrieval
func BenchmarkGRPC_GetKey(b *testing.B) {
	service := createBenchmarkService(b)
	ctx := context.Background()

	// Pre-generate key
	genReq := &pb.GenerateKeyRequest{
		KeyId:   "bench-getkey",
		Backend: "software",
		KeyType: "ecdsa",
		Curve:   "P256",
	}

	_, err := service.GenerateKey(ctx, genReq)
	if err != nil {
		b.Fatalf("GenerateKey() failed: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req := &pb.GetKeyRequest{
			KeyId:   "bench-getkey",
			Backend: "software",
		}

		_, err := service.GetKey(ctx, req)
		if err != nil {
			b.Fatalf("GetKey() failed: %v", err)
		}
	}
}

// BenchmarkGRPC_ListKeys benchmarks listing keys
func BenchmarkGRPC_ListKeys(b *testing.B) {
	counts := []int{10, 100}

	for _, count := range counts {
		b.Run(fmt.Sprintf("%dKeys", count), func(b *testing.B) {
			service := createBenchmarkService(b)
			ctx := context.Background()

			// Pre-generate keys
			for i := 0; i < count; i++ {
				req := &pb.GenerateKeyRequest{
					KeyId:   fmt.Sprintf("bench-list-%d", i),
					Backend: "software",
					KeyType: "ecdsa",
					Curve:   "P256",
				}

				_, err := service.GenerateKey(ctx, req)
				if err != nil {
					b.Fatalf("GenerateKey() failed: %v", err)
				}
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				req := &pb.ListKeysRequest{
					Backend: "software",
				}

				_, err := service.ListKeys(ctx, req)
				if err != nil {
					b.Fatalf("ListKeys() failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkGRPC_ConcurrentOperations benchmarks concurrent gRPC operations
func BenchmarkGRPC_ConcurrentOperations(b *testing.B) {
	service := createBenchmarkService(b)
	ctx := context.Background()

	// Pre-generate key
	genReq := &pb.GenerateKeyRequest{
		KeyId:   "bench-concurrent",
		Backend: "software",
		KeyType: "ecdsa",
		Curve:   "P256",
	}

	_, err := service.GenerateKey(ctx, genReq)
	if err != nil {
		b.Fatalf("GenerateKey() failed: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(testPB *testing.PB) {
		for testPB.Next() {
			req := &pb.GetKeyRequest{
				KeyId:   "bench-concurrent",
				Backend: "software",
			}

			_, err := service.GetKey(ctx, req)
			if err != nil {
				b.Fatalf("GetKey() failed: %v", err)
			}
		}
	})
}

// Note: Symmetric encryption benchmarks are not included because the gRPC API
// does not currently expose Encrypt() - only Decrypt() for asymmetric decryption.

// BenchmarkGRPC_DeleteKey benchmarks key deletion
func BenchmarkGRPC_DeleteKey(b *testing.B) {
	service := createBenchmarkService(b)
	ctx := context.Background()

	// Pre-generate keys
	for i := 0; i < b.N; i++ {
		req := &pb.GenerateKeyRequest{
			KeyId:   fmt.Sprintf("bench-delete-%d", i),
			Backend: "software",
			KeyType: "ecdsa",
			Curve:   "P256",
		}

		_, err := service.GenerateKey(ctx, req)
		if err != nil {
			b.Fatalf("GenerateKey() failed: %v", err)
		}
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req := &pb.DeleteKeyRequest{
			KeyId:   fmt.Sprintf("bench-delete-%d", i),
			Backend: "software",
		}

		_, err := service.DeleteKey(ctx, req)
		if err != nil {
			b.Fatalf("DeleteKey() failed: %v", err)
		}
	}
}
