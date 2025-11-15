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

//go:build pkcs11 && !integration

package hardware

import (
	"crypto/x509"
	"fmt"
	"testing"
)

// BenchmarkPKCS11_SaveCert benchmarks certificate save operations with various sizes
func BenchmarkPKCS11_SaveCert(b *testing.B) {
	sizes := []int{1, 2, 4} // 1KB, 2KB, 4KB

	for _, sizeKB := range sizes {
		b.Run(fmt.Sprintf("%dKB", sizeKB), func(b *testing.B) {
			storage := newBenchMockPKCS11Storage()
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

// BenchmarkPKCS11_GetCert benchmarks certificate retrieval operations
func BenchmarkPKCS11_GetCert(b *testing.B) {
	storage := newBenchMockPKCS11Storage()
	cert, err := generateBenchCert(2) // 2KB cert
	if err != nil {
		b.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Pre-populate with certificates
	for i := 0; i < 100; i++ {
		id := fmt.Sprintf("cert-%d", i)
		storage.SaveCert(id, cert)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		id := fmt.Sprintf("cert-%d", i%100)
		_, err := storage.GetCert(id)
		if err != nil {
			b.Fatalf("GetCert failed: %v", err)
		}
	}

	b.SetBytes(int64(len(cert.Raw)))
}

// BenchmarkPKCS11_DeleteCert benchmarks certificate deletion operations
func BenchmarkPKCS11_DeleteCert(b *testing.B) {
	storage := newBenchMockPKCS11Storage()
	cert, err := generateBenchCert(2) // 2KB cert
	if err != nil {
		b.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Pre-populate with certificates
	for i := 0; i < b.N; i++ {
		id := fmt.Sprintf("cert-%d", i)
		storage.SaveCert(id, cert)
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

// BenchmarkPKCS11_SaveCertChain benchmarks certificate chain save operations
func BenchmarkPKCS11_SaveCertChain(b *testing.B) {
	chainSizes := []int{2, 3, 5}

	for _, chainSize := range chainSizes {
		b.Run(fmt.Sprintf("%dCerts", chainSize), func(b *testing.B) {
			storage := newBenchMockPKCS11Storage()

			// Generate certificate chain
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

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				id := fmt.Sprintf("chain-%d", i)
				// Save each cert in chain individually (PKCS11 approach)
				for j, cert := range chain {
					chainID := fmt.Sprintf("%s-%d", id, j)
					if err := storage.SaveCert(chainID, cert); err != nil {
						b.Fatalf("SaveCert failed: %v", err)
					}
				}
			}

			b.SetBytes(totalSize)
		})
	}
}

// BenchmarkPKCS11_GetCertChain benchmarks certificate chain retrieval
func BenchmarkPKCS11_GetCertChain(b *testing.B) {
	storage := newBenchMockPKCS11Storage()

	// Generate and save a certificate chain
	chainSize := 3
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
	for i := 0; i < 100; i++ {
		baseID := fmt.Sprintf("chain-%d", i)
		for j, cert := range chain {
			chainID := fmt.Sprintf("%s-%d", baseID, j)
			storage.SaveCert(chainID, cert)
		}
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		baseID := fmt.Sprintf("chain-%d", i%100)
		// Retrieve each cert in chain
		for j := 0; j < chainSize; j++ {
			chainID := fmt.Sprintf("%s-%d", baseID, j)
			_, err := storage.GetCert(chainID)
			if err != nil {
				b.Fatalf("GetCert failed: %v", err)
			}
		}
	}

	b.SetBytes(totalSize)
}

// BenchmarkPKCS11_ListCerts benchmarks listing operations with various counts
func BenchmarkPKCS11_ListCerts(b *testing.B) {
	counts := []int{10, 50, 100}

	for _, count := range counts {
		b.Run(fmt.Sprintf("%dCerts", count), func(b *testing.B) {
			storage := newBenchMockPKCS11Storage()
			cert, err := generateBenchCert(1)
			if err != nil {
				b.Fatalf("Failed to generate test certificate: %v", err)
			}

			// Pre-populate with certificates
			for i := 0; i < count; i++ {
				id := fmt.Sprintf("cert-%d", i)
				storage.SaveCert(id, cert)
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

// BenchmarkPKCS11_ConcurrentReads benchmarks concurrent read operations
func BenchmarkPKCS11_ConcurrentReads(b *testing.B) {
	storage := newBenchMockPKCS11Storage()
	cert, err := generateBenchCert(2)
	if err != nil {
		b.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Pre-populate with certificates
	for i := 0; i < 100; i++ {
		id := fmt.Sprintf("cert-%d", i)
		storage.SaveCert(id, cert)
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			id := fmt.Sprintf("cert-%d", i%100)
			_, err := storage.GetCert(id)
			if err != nil {
				b.Fatalf("GetCert failed: %v", err)
			}
			i++
		}
	})

	b.SetBytes(int64(len(cert.Raw)))
}

// BenchmarkPKCS11_ConcurrentWrites benchmarks concurrent write operations
func BenchmarkPKCS11_ConcurrentWrites(b *testing.B) {
	storage := newBenchMockPKCS11Storage()
	cert, err := generateBenchCert(2)
	if err != nil {
		b.Fatalf("Failed to generate test certificate: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	var counter int64
	b.RunParallel(func(pb *testing.PB) {
		localCounter := 0
		for pb.Next() {
			id := fmt.Sprintf("cert-%d-%d", b.N, localCounter)
			if err := storage.SaveCert(id, cert); err != nil {
				b.Fatalf("SaveCert failed: %v", err)
			}
			localCounter++
		}
		counter += int64(localCounter)
	})

	b.SetBytes(int64(len(cert.Raw)))
}

// BenchmarkPKCS11_CertExists benchmarks existence check operations
func BenchmarkPKCS11_CertExists(b *testing.B) {
	storage := newBenchMockPKCS11Storage()
	cert, err := generateBenchCert(1)
	if err != nil {
		b.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Pre-populate
	for i := 0; i < 100; i++ {
		id := fmt.Sprintf("cert-%d", i)
		storage.SaveCert(id, cert)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		id := fmt.Sprintf("cert-%d", i%100)
		_, err := storage.GetCert(id)
		if err != nil {
			b.Fatalf("Exists check failed: %v", err)
		}
	}
}

// BenchmarkPKCS11_MixedOperations benchmarks realistic mixed workload
func BenchmarkPKCS11_MixedOperations(b *testing.B) {
	storage := newBenchMockPKCS11Storage()
	cert, err := generateBenchCert(2)
	if err != nil {
		b.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Pre-populate
	for i := 0; i < 50; i++ {
		id := fmt.Sprintf("cert-%d", i)
		storage.SaveCert(id, cert)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		switch i % 4 {
		case 0: // Read (50%)
			id := fmt.Sprintf("cert-%d", i%50)
			storage.GetCert(id)
		case 1: // Write (25%)
			id := fmt.Sprintf("cert-new-%d", i)
			storage.SaveCert(id, cert)
		case 2: // Delete (12.5%)
			id := fmt.Sprintf("cert-new-%d", i-1)
			storage.DeleteCert(id)
		case 3: // List (12.5%)
			storage.ListCerts()
		}
	}

	b.SetBytes(int64(len(cert.Raw)))
}
