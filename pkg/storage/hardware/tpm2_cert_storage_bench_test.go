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

//go:build !integration

package hardware

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
)

// BenchmarkTPM2_SaveCert benchmarks certificate save with various sizes
func BenchmarkTPM2_SaveCert(b *testing.B) {
	// TPM has size limits, so we test smaller sizes
	sizes := []int{1, 2}

	for _, sizeKB := range sizes {
		b.Run(fmt.Sprintf("%dKB", sizeKB), func(b *testing.B) {
			storage := newBenchMockTPM2Storage()
			cert, err := generateBenchCert(sizeKB)
			if err != nil {
				b.Fatalf("Failed to generate test certificate: %v", err)
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				id := fmt.Sprintf("cert-%d", i)
				if err := storage.SaveCert(id, cert); err != nil {
					b.Fatalf("SaveCert failed: %v", err)
				}
			}

			b.SetBytes(int64(len(cert.Raw)))
		})
	}
}

// BenchmarkTPM2_GetCert benchmarks certificate retrieval
func BenchmarkTPM2_GetCert(b *testing.B) {
	storage := newBenchMockTPM2Storage()
	cert, err := generateBenchCert(1)
	if err != nil {
		b.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Pre-populate (TPM has limited capacity, so use fewer certs)
	for i := 0; i < 4; i++ {
		id := fmt.Sprintf("cert-%d", i)
		_ = storage.SaveCert(id, cert)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		id := fmt.Sprintf("cert-%d", i%4)
		_, err := storage.GetCert(id)
		if err != nil {
			b.Fatalf("GetCert failed: %v", err)
		}
	}

	b.SetBytes(int64(len(cert.Raw)))
}

// BenchmarkTPM2_DeleteCert benchmarks certificate deletion
func BenchmarkTPM2_DeleteCert(b *testing.B) {
	storage := newBenchMockTPM2Storage()
	cert, err := generateBenchCert(1)
	if err != nil {
		b.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Pre-populate
	for i := 0; i < b.N; i++ {
		id := fmt.Sprintf("cert-%d", i)
		_ = storage.SaveCert(id, cert)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		id := fmt.Sprintf("cert-%d", i)
		if err := storage.DeleteCert(id); err != nil {
			b.Fatalf("DeleteCert failed: %v", err)
		}
	}
}

// BenchmarkTPM2_SaveCertChain benchmarks certificate chain save
func BenchmarkTPM2_SaveCertChain(b *testing.B) {
	// TPM has size constraints, test smaller chains
	chainSizes := []int{2, 3}

	for _, chainSize := range chainSizes {
		b.Run(fmt.Sprintf("%dCerts", chainSize), func(b *testing.B) {
			storage := newBenchMockTPM2Storage()

			// Generate small certificate chain to fit in TPM NV RAM
			chain := make([]*x509.Certificate, chainSize)
			var totalSize int64
			for i := 0; i < chainSize; i++ {
				// Use smaller certs for chains to fit in 2KB limit
				cert, err := generateBenchCert(1)
				if err != nil {
					b.Fatalf("Failed to generate chain certificate: %v", err)
				}
				chain[i] = cert
				totalSize += int64(len(cert.Raw))
			}

			// Skip if chain is too large
			var pemSize int
			for _, cert := range chain {
				pemBlock := pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: cert.Raw,
				})
				pemSize += len(pemBlock)
			}
			if pemSize > storage.maxSize {
				b.Skipf("Chain too large (%d bytes) for TPM NV RAM (%d bytes)", pemSize, storage.maxSize)
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				id := fmt.Sprintf("chain-%d", i)
				if err := storage.SaveCertChain(id, chain); err != nil {
					b.Fatalf("SaveCertChain failed: %v", err)
				}
			}

			b.SetBytes(totalSize)
		})
	}
}

// BenchmarkTPM2_GetCertChain benchmarks certificate chain retrieval
func BenchmarkTPM2_GetCertChain(b *testing.B) {

	storage := newBenchMockTPM2Storage()
	// Generate small chain
	chainSize := 2
	chain := make([]*x509.Certificate, chainSize)
	var totalSize int64
	for i := 0; i < chainSize; i++ {
		cert, err := generateBenchCert(1)
		if err != nil {
			b.Fatalf("Failed to generate chain certificate: %v", err)
		}
		chain[i] = cert
		totalSize += int64(len(cert.Raw))
	}

	// Pre-populate chains
	for i := 0; i < 4; i++ {
		id := fmt.Sprintf("chain-%d", i)
		_ = storage.SaveCertChain(id, chain)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		id := fmt.Sprintf("chain-%d", i%4)
		_, err := storage.GetCertChain(id)
		if err != nil {
			b.Fatalf("GetCertChain failed: %v", err)
		}
	}

	b.SetBytes(totalSize)
}

// BenchmarkTPM2_ListCerts benchmarks listing with limited capacity
func BenchmarkTPM2_ListCerts(b *testing.B) {
	// TPM has limited capacity, test with realistic counts
	counts := []int{2, 4}

	for _, count := range counts {
		b.Run(fmt.Sprintf("%dCerts", count), func(b *testing.B) {
			storage := newBenchMockTPM2Storage()
			cert, err := generateBenchCert(1)
			if err != nil {
				b.Fatalf("Failed to generate test certificate: %v", err)
			}

			// Pre-populate
			for i := 0; i < count; i++ {
				id := fmt.Sprintf("cert-%d", i)
				_ = storage.SaveCert(id, cert)
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_, err := storage.ListCerts()
				if err != nil {
					b.Fatalf("ListCerts failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkTPM2_NVIndexAllocation benchmarks NV index allocation overhead
func BenchmarkTPM2_NVIndexAllocation(b *testing.B) {
	cert, err := generateBenchCert(1)
	storage := newBenchMockTPM2Storage()
	if err != nil {
		b.Fatalf("Failed to generate test certificate: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Simulate NV index allocation and write
		id := fmt.Sprintf("cert-%d", i)
		if err := storage.SaveCert(id, cert); err != nil {
			b.Fatalf("SaveCert failed: %v", err)
		}
	}

	b.SetBytes(int64(len(cert.Raw)))
}

// BenchmarkTPM2_ChunkedIO benchmarks chunked I/O performance
func BenchmarkTPM2_ChunkedIO(b *testing.B) {

	// Test with 1KB chunks (typical TPM chunk size)
	cert, err := generateBenchCert(1)
	if err != nil {
		b.Fatalf("Failed to generate test certificate: %v", err)
	}

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Simulate chunked write
		const chunkSize = 1024
		for offset := 0; offset < len(pemData); offset += chunkSize {
			end := offset + chunkSize
			if end > len(pemData) {
				end = len(pemData)
			}
			_ = pemData[offset:end] // Simulate write operation
		}
	}

	b.SetBytes(int64(len(pemData)))
}

// BenchmarkTPM2_ConcurrentReads benchmarks concurrent read operations
func BenchmarkTPM2_ConcurrentReads(b *testing.B) {
	storage := newBenchMockTPM2Storage()
	cert, err := generateBenchCert(1)
	if err != nil {
		b.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Pre-populate with limited certs
	for i := 0; i < 4; i++ {
		id := fmt.Sprintf("cert-%d", i)
		_ = storage.SaveCert(id, cert)
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			id := fmt.Sprintf("cert-%d", i%4)
			_, err := storage.GetCert(id)
			if err != nil {
				b.Fatalf("GetCert failed: %v", err)
			}
			i++
		}
	})

	b.SetBytes(int64(len(cert.Raw)))
}

// BenchmarkTPM2_PEMEncodeDecode benchmarks PEM encoding/decoding overhead
func BenchmarkTPM2_PEMEncodeDecode(b *testing.B) {
	cert, err := generateBenchCert(1)
	if err != nil {
		b.Fatalf("Failed to generate test certificate: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Encode
		pemData := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})

		// Decode
		block, _ := pem.Decode(pemData)
		if block == nil {
			b.Fatal("Failed to decode PEM")
		}
	}

	b.SetBytes(int64(len(cert.Raw)))
}

// BenchmarkTPM2_CapacityCheck benchmarks capacity checking operations
func BenchmarkTPM2_CapacityCheck(b *testing.B) {
	storage := newBenchMockTPM2Storage()
	cert, err := generateBenchCert(1)
	if err != nil {
		b.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Pre-populate
	for i := 0; i < 4; i++ {
		id := fmt.Sprintf("cert-%d", i)
		_ = storage.SaveCert(id, cert)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Check capacity by listing
		ids, err := storage.ListCerts()
		if err != nil {
			b.Fatalf("ListCerts failed: %v", err)
		}
		_ = len(ids)
	}
}
