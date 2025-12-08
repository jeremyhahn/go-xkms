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
	"fmt"
	"testing"
)

// BenchmarkComparison_SaveCert compares SaveCert across all storage types
func BenchmarkComparison_SaveCert(b *testing.B) {
	cert, err := generateBenchCert(2)
	if err != nil {
		b.Fatalf("Failed to generate test certificate: %v", err)
	}

	b.Run("PKCS11", func(b *testing.B) {
		storage := newBenchMockPKCS11Storage()
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

	b.Run("TPM2", func(b *testing.B) {
		storage := newBenchMockTPM2Storage()
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

	b.Run("External", func(b *testing.B) {
		storage := newBenchMockExternalStorage()
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

	b.Run("Hybrid_HardwareSuccess", func(b *testing.B) {
		hardware := newBenchMockHardwareStorage(1000)
		external := newBenchMockExternalStorage()
		hybrid, _ := NewHybridCertStorage(hardware, external)

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			id := fmt.Sprintf("cert-%d", i)
			if err := hybrid.SaveCert(id, cert); err != nil {
				b.Fatalf("SaveCert failed: %v", err)
			}
		}
		b.SetBytes(int64(len(cert.Raw)))
	})

	b.Run("Hybrid_HardwareFull", func(b *testing.B) {
		hardware := newBenchMockHardwareStorage(0) // Force failover
		external := newBenchMockExternalStorage()
		hybrid, _ := NewHybridCertStorage(hardware, external)

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			id := fmt.Sprintf("cert-%d", i)
			if err := hybrid.SaveCert(id, cert); err != nil {
				b.Fatalf("SaveCert failed: %v", err)
			}
		}
		b.SetBytes(int64(len(cert.Raw)))
	})
}

// BenchmarkComparison_GetCert compares GetCert across all storage types
func BenchmarkComparison_GetCert(b *testing.B) {
	cert, err := generateBenchCert(2)
	if err != nil {
		b.Fatalf("Failed to generate test certificate: %v", err)
	}

	b.Run("PKCS11", func(b *testing.B) {
		storage := newBenchMockPKCS11Storage()
		// Pre-populate
		for i := 0; i < 100; i++ {
			id := fmt.Sprintf("cert-%d", i)
			_ = storage.SaveCert(id, cert)
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
	})

	b.Run("TPM2", func(b *testing.B) {
		storage := newBenchMockTPM2Storage()
		// Pre-populate (limited)
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
	})

	b.Run("External", func(b *testing.B) {
		storage := newBenchMockExternalStorage()
		// Pre-populate
		for i := 0; i < 100; i++ {
			id := fmt.Sprintf("cert-%d", i)
			_ = storage.SaveCert(id, cert)
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
	})

	b.Run("Hybrid_FromHardware", func(b *testing.B) {
		hardware := newBenchMockHardwareStorage(1000)
		external := newBenchMockExternalStorage()
		hybrid, _ := NewHybridCertStorage(hardware, external)

		// Pre-populate hardware
		for i := 0; i < 100; i++ {
			id := fmt.Sprintf("cert-%d", i)
			_ = hybrid.SaveCert(id, cert)
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			id := fmt.Sprintf("cert-%d", i%100)
			_, err := hybrid.GetCert(id)
			if err != nil {
				b.Fatalf("GetCert failed: %v", err)
			}
		}
		b.SetBytes(int64(len(cert.Raw)))
	})

	b.Run("Hybrid_FromExternal", func(b *testing.B) {
		hardware := newBenchMockHardwareStorage(0)
		external := newBenchMockExternalStorage()
		hybrid, _ := NewHybridCertStorage(hardware, external)

		// Pre-populate external
		for i := 0; i < 100; i++ {
			id := fmt.Sprintf("cert-%d", i)
			_ = external.SaveCert(id, cert)
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			id := fmt.Sprintf("cert-%d", i%100)
			_, err := hybrid.GetCert(id)
			if err != nil {
				b.Fatalf("GetCert failed: %v", err)
			}
		}
		b.SetBytes(int64(len(cert.Raw)))
	})
}

// BenchmarkComparison_DeleteCert compares DeleteCert across all storage types
func BenchmarkComparison_DeleteCert(b *testing.B) {
	cert, err := generateBenchCert(2)
	if err != nil {
		b.Fatalf("Failed to generate test certificate: %v", err)
	}

	b.Run("PKCS11", func(b *testing.B) {
		storage := newBenchMockPKCS11Storage()
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
	})

	b.Run("TPM2", func(b *testing.B) {
		storage := newBenchMockTPM2Storage()
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
	})

	b.Run("External", func(b *testing.B) {
		storage := newBenchMockExternalStorage()
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
	})

	b.Run("Hybrid", func(b *testing.B) {
		hardware := newBenchMockHardwareStorage(b.N)
		external := newBenchMockExternalStorage()
		hybrid, _ := NewHybridCertStorage(hardware, external)

		// Pre-populate both
		for i := 0; i < b.N; i++ {
			id := fmt.Sprintf("cert-%d", i)
			_ = hardware.SaveCert(id, cert)
			_ = external.SaveCert(id, cert)
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			id := fmt.Sprintf("cert-%d", i)
			if err := hybrid.DeleteCert(id); err != nil {
				b.Fatalf("DeleteCert failed: %v", err)
			}
		}
	})
}

// BenchmarkComparison_ListCerts compares ListCerts across all storage types
func BenchmarkComparison_ListCerts(b *testing.B) {
	cert, err := generateBenchCert(2)
	if err != nil {
		b.Fatalf("Failed to generate test certificate: %v", err)
	}

	counts := []int{10, 50}

	for _, count := range counts {
		b.Run(fmt.Sprintf("PKCS11_%dCerts", count), func(b *testing.B) {
			storage := newBenchMockPKCS11Storage()
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

		// TPM2 only test with small counts
		if count <= 10 {
			b.Run(fmt.Sprintf("TPM2_%dCerts", count), func(b *testing.B) {
				storage := newBenchMockTPM2Storage()
				actualCount := count
				if actualCount > 4 {
					actualCount = 4 // TPM capacity limit
				}
				for i := 0; i < actualCount; i++ {
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

		b.Run(fmt.Sprintf("External_%dCerts", count), func(b *testing.B) {
			storage := newBenchMockExternalStorage()
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

		b.Run(fmt.Sprintf("Hybrid_%dCerts", count), func(b *testing.B) {
			hardware := newBenchMockHardwareStorage(count / 2)
			external := newBenchMockExternalStorage()
			hybrid, _ := NewHybridCertStorage(hardware, external)

			// Populate both
			for i := 0; i < count; i++ {
				id := fmt.Sprintf("cert-%d", i)
				_ = hybrid.SaveCert(id, cert)
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_, err := hybrid.ListCerts()
				if err != nil {
					b.Fatalf("ListCerts failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkComparison_ConcurrentReads compares concurrent read performance
func BenchmarkComparison_ConcurrentReads(b *testing.B) {
	cert, err := generateBenchCert(2)
	if err != nil {
		b.Fatalf("Failed to generate test certificate: %v", err)
	}

	b.Run("PKCS11", func(b *testing.B) {
		storage := newBenchMockPKCS11Storage()
		for i := 0; i < 100; i++ {
			id := fmt.Sprintf("cert-%d", i)
			_ = storage.SaveCert(id, cert)
		}

		b.ResetTimer()
		b.ReportAllocs()

		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				id := fmt.Sprintf("cert-%d", i%100)
				_, _ = storage.GetCert(id)
				i++
			}
		})
		b.SetBytes(int64(len(cert.Raw)))
	})

	b.Run("TPM2", func(b *testing.B) {
		storage := newBenchMockTPM2Storage()
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
				_, _ = storage.GetCert(id)
				i++
			}
		})
		b.SetBytes(int64(len(cert.Raw)))
	})

	b.Run("External", func(b *testing.B) {
		storage := newBenchMockExternalStorage()
		for i := 0; i < 100; i++ {
			id := fmt.Sprintf("cert-%d", i)
			_ = storage.SaveCert(id, cert)
		}

		b.ResetTimer()
		b.ReportAllocs()

		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				id := fmt.Sprintf("cert-%d", i%100)
				_, _ = storage.GetCert(id)
				i++
			}
		})
		b.SetBytes(int64(len(cert.Raw)))
	})

	b.Run("Hybrid", func(b *testing.B) {
		hardware := newBenchMockHardwareStorage(50)
		external := newBenchMockExternalStorage()
		hybrid, _ := NewHybridCertStorage(hardware, external)

		for i := 0; i < 50; i++ {
			id := fmt.Sprintf("hw-cert-%d", i)
			_ = hardware.SaveCert(id, cert)
		}
		for i := 0; i < 50; i++ {
			id := fmt.Sprintf("ext-cert-%d", i)
			_ = external.SaveCert(id, cert)
		}

		b.ResetTimer()
		b.ReportAllocs()

		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				var id string
				if i%2 == 0 {
					id = fmt.Sprintf("hw-cert-%d", i%50)
				} else {
					id = fmt.Sprintf("ext-cert-%d", i%50)
				}
				_, _ = hybrid.GetCert(id)
				i++
			}
		})
		b.SetBytes(int64(len(cert.Raw)))
	})
}

// BenchmarkComparison_Throughput measures maximum throughput for each backend
func BenchmarkComparison_Throughput(b *testing.B) {
	cert, err := generateBenchCert(2)
	if err != nil {
		b.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Measure ops/sec for mixed workload
	b.Run("PKCS11_Mixed", func(b *testing.B) {
		storage := newBenchMockPKCS11Storage()
		for i := 0; i < 50; i++ {
			id := fmt.Sprintf("cert-%d", i)
			_ = storage.SaveCert(id, cert)
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			switch i % 4 {
			case 0, 1:
				_, _ = storage.GetCert(fmt.Sprintf("cert-%d", i%50))
			case 2:
				_ = storage.SaveCert(fmt.Sprintf("new-%d", i), cert)
			case 3:
				_, _ = storage.ListCerts()
			}
		}
	})

	b.Run("TPM2_Mixed", func(b *testing.B) {
		storage := newBenchMockTPM2Storage()
		for i := 0; i < 4; i++ {
			id := fmt.Sprintf("cert-%d", i)
			_ = storage.SaveCert(id, cert)
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			switch i % 4 {
			case 0, 1:
				_, _ = storage.GetCert(fmt.Sprintf("cert-%d", i%4))
			case 2:
				_ = storage.SaveCert(fmt.Sprintf("new-%d", i), cert)
			case 3:
				_, _ = storage.ListCerts()
			}
		}
	})

	b.Run("External_Mixed", func(b *testing.B) {
		storage := newBenchMockExternalStorage()
		for i := 0; i < 50; i++ {
			id := fmt.Sprintf("cert-%d", i)
			_ = storage.SaveCert(id, cert)
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			switch i % 4 {
			case 0, 1:
				_, _ = storage.GetCert(fmt.Sprintf("cert-%d", i%50))
			case 2:
				_ = storage.SaveCert(fmt.Sprintf("new-%d", i), cert)
			case 3:
				_, _ = storage.ListCerts()
			}
		}
	})

	b.Run("Hybrid_Mixed", func(b *testing.B) {
		hardware := newBenchMockHardwareStorage(100)
		external := newBenchMockExternalStorage()
		hybrid, _ := NewHybridCertStorage(hardware, external)

		for i := 0; i < 50; i++ {
			id := fmt.Sprintf("cert-%d", i)
			_ = hybrid.SaveCert(id, cert)
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			switch i % 4 {
			case 0, 1:
				_, _ = hybrid.GetCert(fmt.Sprintf("cert-%d", i%50))
			case 2:
				_ = hybrid.SaveCert(fmt.Sprintf("new-%d", i), cert)
			case 3:
				_, _ = hybrid.ListCerts()
			}
		}
	})
}
