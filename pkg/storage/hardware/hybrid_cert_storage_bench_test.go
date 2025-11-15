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

//go:build (tpm2 || pkcs11) && !integration

package hardware

import (
	"fmt"
	"testing"
)

// BenchmarkHybrid_SaveCert_HardwareSuccess benchmarks successful hardware save
func BenchmarkHybrid_SaveCert_HardwareSuccess(b *testing.B) {
	hardware := newBenchMockHardwareStorage(1000) // Large capacity
	external := newBenchMockExternalStorage()

	hybrid, err := NewHybridCertStorage(hardware, external)
	if err != nil {
		b.Fatalf("Failed to create hybrid storage: %v", err)
	}

	cert, err := generateBenchCert(2)
	if err != nil {
		b.Fatalf("Failed to generate test certificate: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		id := fmt.Sprintf("cert-%d", i)
		if err := hybrid.SaveCert(id, cert); err != nil {
			b.Fatalf("SaveCert failed: %v", err)
		}
	}

	b.SetBytes(int64(len(cert.Raw)))
}

// BenchmarkHybrid_SaveCert_HardwareFull_Failover benchmarks failover to external
func BenchmarkHybrid_SaveCert_HardwareFull_Failover(b *testing.B) {
	hardware := newBenchMockHardwareStorage(0) // No capacity - immediate failover
	external := newBenchMockExternalStorage()

	hybrid, err := NewHybridCertStorage(hardware, external)
	if err != nil {
		b.Fatalf("Failed to create hybrid storage: %v", err)
	}

	cert, err := generateBenchCert(2)
	if err != nil {
		b.Fatalf("Failed to generate test certificate: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		id := fmt.Sprintf("cert-%d", i)
		if err := hybrid.SaveCert(id, cert); err != nil {
			b.Fatalf("SaveCert failed: %v", err)
		}
	}

	b.SetBytes(int64(len(cert.Raw)))
}

// BenchmarkHybrid_GetCert_FromHardware benchmarks retrieval from hardware
func BenchmarkHybrid_GetCert_FromHardware(b *testing.B) {
	hardware := newBenchMockHardwareStorage(1000)
	external := newBenchMockExternalStorage()

	hybrid, err := NewHybridCertStorage(hardware, external)
	if err != nil {
		b.Fatalf("Failed to create hybrid storage: %v", err)
	}

	cert, err := generateBenchCert(2)
	if err != nil {
		b.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Pre-populate hardware
	for i := 0; i < 100; i++ {
		id := fmt.Sprintf("cert-%d", i)
		hybrid.SaveCert(id, cert)
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
}

// BenchmarkHybrid_GetCert_FromExternal_Failover benchmarks external failover read
func BenchmarkHybrid_GetCert_FromExternal_Failover(b *testing.B) {
	hardware := newBenchMockHardwareStorage(0) // Empty hardware
	external := newBenchMockExternalStorage()

	hybrid, err := NewHybridCertStorage(hardware, external)
	if err != nil {
		b.Fatalf("Failed to create hybrid storage: %v", err)
	}

	cert, err := generateBenchCert(2)
	if err != nil {
		b.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Pre-populate external only
	for i := 0; i < 100; i++ {
		id := fmt.Sprintf("cert-%d", i)
		external.SaveCert(id, cert)
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
}

// BenchmarkHybrid_ListCerts_MergedResults benchmarks merged list operations
func BenchmarkHybrid_ListCerts_MergedResults(b *testing.B) {
	hardware := newBenchMockHardwareStorage(50)
	external := newBenchMockExternalStorage()

	hybrid, err := NewHybridCertStorage(hardware, external)
	if err != nil {
		b.Fatalf("Failed to create hybrid storage: %v", err)
	}

	cert, err := generateBenchCert(1)
	if err != nil {
		b.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Populate both storages
	for i := 0; i < 50; i++ {
		id := fmt.Sprintf("hw-cert-%d", i)
		hardware.SaveCert(id, cert)
	}
	for i := 0; i < 50; i++ {
		id := fmt.Sprintf("ext-cert-%d", i)
		external.SaveCert(id, cert)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := hybrid.ListCerts()
		if err != nil {
			b.Fatalf("ListCerts failed: %v", err)
		}
	}
}

// BenchmarkHybrid_DeleteCert_BothStorages benchmarks deletion from both
func BenchmarkHybrid_DeleteCert_BothStorages(b *testing.B) {
	hardware := newBenchMockHardwareStorage(1000)
	external := newBenchMockExternalStorage()

	hybrid, err := NewHybridCertStorage(hardware, external)
	if err != nil {
		b.Fatalf("Failed to create hybrid storage: %v", err)
	}

	cert, err := generateBenchCert(1)
	if err != nil {
		b.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Pre-populate both storages with same IDs
	for i := 0; i < b.N; i++ {
		id := fmt.Sprintf("cert-%d", i)
		hardware.SaveCert(id, cert)
		external.SaveCert(id, cert)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		id := fmt.Sprintf("cert-%d", i)
		if err := hybrid.DeleteCert(id); err != nil {
			b.Fatalf("DeleteCert failed: %v", err)
		}
	}
}

// BenchmarkHybrid_ConcurrentReads benchmarks concurrent hybrid reads
func BenchmarkHybrid_ConcurrentReads(b *testing.B) {
	hardware := newBenchMockHardwareStorage(50)
	external := newBenchMockExternalStorage()

	hybrid, err := NewHybridCertStorage(hardware, external)
	if err != nil {
		b.Fatalf("Failed to create hybrid storage: %v", err)
	}

	cert, err := generateBenchCert(2)
	if err != nil {
		b.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Populate both storages
	for i := 0; i < 50; i++ {
		id := fmt.Sprintf("hw-cert-%d", i)
		hardware.SaveCert(id, cert)
	}
	for i := 0; i < 50; i++ {
		id := fmt.Sprintf("ext-cert-%d", i)
		external.SaveCert(id, cert)
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
			_, err := hybrid.GetCert(id)
			if err != nil {
				b.Fatalf("GetCert failed: %v", err)
			}
			i++
		}
	})

	b.SetBytes(int64(len(cert.Raw)))
}

// BenchmarkHybrid_ConcurrentWrites benchmarks concurrent hybrid writes
func BenchmarkHybrid_ConcurrentWrites(b *testing.B) {
	hardware := newBenchMockHardwareStorage(1000)
	external := newBenchMockExternalStorage()

	hybrid, err := NewHybridCertStorage(hardware, external)
	if err != nil {
		b.Fatalf("Failed to create hybrid storage: %v", err)
	}

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
			if err := hybrid.SaveCert(id, cert); err != nil {
				b.Fatalf("SaveCert failed: %v", err)
			}
			localCounter++
		}
		counter += int64(localCounter)
	})

	b.SetBytes(int64(len(cert.Raw)))
}

// BenchmarkHybrid_CapacityTransition benchmarks behavior during capacity transition
func BenchmarkHybrid_CapacityTransition(b *testing.B) {
	// Small hardware capacity to force transition
	hardware := newBenchMockHardwareStorage(10)
	external := newBenchMockExternalStorage()

	hybrid, err := NewHybridCertStorage(hardware, external)
	if err != nil {
		b.Fatalf("Failed to create hybrid storage: %v", err)
	}

	cert, err := generateBenchCert(1)
	if err != nil {
		b.Fatalf("Failed to generate test certificate: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		id := fmt.Sprintf("cert-%d", i)
		// First 10 go to hardware, rest to external
		if err := hybrid.SaveCert(id, cert); err != nil {
			b.Fatalf("SaveCert failed: %v", err)
		}
	}

	b.SetBytes(int64(len(cert.Raw)))
}

// BenchmarkHybrid_MixedOperations benchmarks realistic mixed workload
func BenchmarkHybrid_MixedOperations(b *testing.B) {
	hardware := newBenchMockHardwareStorage(100)
	external := newBenchMockExternalStorage()

	hybrid, err := NewHybridCertStorage(hardware, external)
	if err != nil {
		b.Fatalf("Failed to create hybrid storage: %v", err)
	}

	cert, err := generateBenchCert(2)
	if err != nil {
		b.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Pre-populate
	for i := 0; i < 50; i++ {
		id := fmt.Sprintf("cert-%d", i)
		hybrid.SaveCert(id, cert)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		switch i % 5 {
		case 0, 1: // Read (40%)
			id := fmt.Sprintf("cert-%d", i%50)
			hybrid.GetCert(id)
		case 2: // Write (20%)
			id := fmt.Sprintf("cert-new-%d", i)
			hybrid.SaveCert(id, cert)
		case 3: // Delete (20%)
			id := fmt.Sprintf("cert-new-%d", i-1)
			hybrid.DeleteCert(id)
		case 4: // List (20%)
			hybrid.ListCerts()
		}
	}

	b.SetBytes(int64(len(cert.Raw)))
}
