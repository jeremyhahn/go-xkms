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

package aead

import (
	"crypto/fips140"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/cpu"
)

func TestHasAESNI(t *testing.T) {
	// This test verifies the CPU detection logic works
	// The actual result depends on the test machine's CPU
	hasAES := HasAESNI()

	// Verify it matches the expected value for the architecture
	switch runtime.GOARCH {
	case "amd64":
		if hasAES != cpu.X86.HasAES {
			t.Errorf("HasAESNI() = %v, want %v (from cpu.X86.HasAES)", hasAES, cpu.X86.HasAES)
		}
	case "arm64":
		if hasAES != cpu.ARM64.HasAES {
			t.Errorf("HasAESNI() = %v, want %v (from cpu.ARM64.HasAES)", hasAES, cpu.ARM64.HasAES)
		}
	default:
		// Other architectures should return false
		if hasAES {
			t.Errorf("HasAESNI() = true on unsupported architecture %s, want false", runtime.GOARCH)
		}
	}

	// Log the result for informational purposes
	t.Logf("CPU architecture: %s, AES-NI support: %v", runtime.GOARCH, hasAES)
}

// withAESNI pins the CPU-capability input for the duration of a test so the
// no-AES-NI path is exercised on machines that do have AES-NI.
func withAESNI(t *testing.T, present bool) {
	t.Helper()
	original := hasAESNI
	hasAESNI = func() bool { return present }
	t.Cleanup(func() { hasAESNI = original })
}

// TestSelectAESGCM asserts the full decision table. Taking its inputs as
// parameters lets this cover combinations the test machine cannot produce,
// notably FIPS mode on a CPU without AES-NI.
func TestSelectAESGCM(t *testing.T) {
	tests := []struct {
		name             string
		isHardwareBacked bool
		aesni            bool
		fipsMode         bool
		want             bool
	}{
		{"software, no AES-NI, no FIPS uses ChaCha20", false, false, false, false},
		{"software, AES-NI, no FIPS uses AES", false, true, false, true},
		{"software, no AES-NI, FIPS uses AES", false, false, true, true},
		{"software, AES-NI, FIPS uses AES", false, true, true, true},
		{"hardware, no AES-NI, no FIPS uses AES", true, false, false, true},
		{"hardware, AES-NI, no FIPS uses AES", true, true, false, true},
		{"hardware, no AES-NI, FIPS uses AES", true, false, true, true},
		{"hardware, AES-NI, FIPS uses AES", true, true, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selectAESGCM(tt.isHardwareBacked, tt.aesni, tt.fipsMode)
			if got != tt.want {
				t.Errorf("selectAESGCM(hw=%v, aesni=%v, fips=%v) = %v, want %v",
					tt.isHardwareBacked, tt.aesni, tt.fipsMode, got, tt.want)
			}
		})
	}
}

// TestSelectAESGCM_FIPSNeverSelectsChaCha states the compliance property on its
// own: whatever else is true, FIPS mode forces AES-GCM.
func TestSelectAESGCM_FIPSNeverSelectsChaCha(t *testing.T) {
	for _, hw := range []bool{false, true} {
		for _, aesni := range []bool{false, true} {
			if !selectAESGCM(hw, aesni, true) {
				t.Errorf("selectAESGCM(hw=%v, aesni=%v, fips=true) = false, want true "+
					"(ChaCha20-Poly1305 is not FIPS-approved)", hw, aesni)
			}
		}
	}
}

// TestFIPSRequiresAES is the compliance assertion for go-xkms #21:
// fipsRequiresAES is exactly crypto/fips140.Enabled, so this asserts the real
// stdlib outcome under GODEBUG=fips140=on and =only rather than a predicate
// of this package's own. crypto/fips140.Enabled is fixed when the process
// starts, so the on/only cases re-exec, mirroring
// pkg/quantum/mlkem512.TestNewAndCreate_RefuseUnderFIPS.
func TestFIPSRequiresAES(t *testing.T) {
	t.Run("no GODEBUG", func(t *testing.T) {
		if fipsRequiresAES() {
			t.Error("fipsRequiresAES() = true with no GODEBUG set and a non-FIPS test build, want false")
		}
	})

	for _, godebug := range []string{"fips140=on", "fips140=only"} {
		t.Run(godebug, func(t *testing.T) {
			if os.Getenv("XKMS_FIPS_SUBPROCESS") == "1" {
				if !fipsRequiresAES() {
					t.Fatal("fipsRequiresAES() = false, want true")
				}
				return
			}

			cmd := exec.Command(os.Args[0], "-test.run=TestFIPSRequiresAES/"+godebug, "-test.v")
			cmd.Env = append(os.Environ(), "XKMS_FIPS_SUBPROCESS=1", "GODEBUG="+godebug)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%s subprocess failed: %v\n%s", godebug, err, out)
			}
			if !strings.Contains(string(out), "PASS") {
				t.Errorf("%s subprocess did not pass:\n%s", godebug, out)
			}
		})
	}
}

// TestSelectOptimal_FIPSModeNoAESNI is the verification the audit asked for:
// on a CPU without AES-NI — the one path that used to return ChaCha20 — a
// FIPS-mode run selects AES-256-GCM instead. crypto/fips140.Enabled is fixed
// when the process starts, so this re-execs under GODEBUG=fips140=on to
// assert the real stdlib-driven outcome rather than a predicate of this
// package's own (go-xkms #21).
func TestSelectOptimal_FIPSModeNoAESNI(t *testing.T) {
	if os.Getenv("XKMS_FIPS_SUBPROCESS") == "1" {
		withAESNI(t, false)

		if got := SelectOptimal(false); got != AES256GCM {
			t.Errorf("SelectOptimal(false) = %s in FIPS mode without AES-NI, want %s", got, AES256GCM)
		}
		if got := SelectOptimalBackend(false); got != BackendAES256GCM {
			t.Errorf("SelectOptimalBackend(false) = %s in FIPS mode without AES-NI, want %s",
				got, BackendAES256GCM)
		}
		if IsChaCha(SelectOptimal(false)) || IsChaCha(SelectOptimalBackend(false)) {
			t.Error("FIPS-mode selection returned a ChaCha variant")
		}
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestSelectOptimal_FIPSModeNoAESNI", "-test.v")
	cmd.Env = append(os.Environ(), "XKMS_FIPS_SUBPROCESS=1", "GODEBUG=fips140=on")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fips140=on subprocess failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "PASS") {
		t.Errorf("fips140=on subprocess did not pass:\n%s", out)
	}
}

func TestSelectOptimal(t *testing.T) {
	// A FIPS-active process can never select ChaCha20, whatever this test run
	// inherited, so the software/no-AES-NI expectation depends on the real
	// stdlib signal rather than being hard-coded to the non-FIPS case.
	softwareNoAESNI := ChaCha20Poly1305
	softwareNoAESNIBackend := BackendChaCha20Poly1305
	if fips140.Enabled() {
		softwareNoAESNI = AES256GCM
		softwareNoAESNIBackend = BackendAES256GCM
	}

	tests := []struct {
		name             string
		isHardwareBacked bool
		aesni            bool
		want             string
		wantBackend      string
	}{
		{
			name:             "Hardware-backed key always uses AES-256-GCM",
			isHardwareBacked: true,
			aesni:            false,
			want:             AES256GCM,
			wantBackend:      BackendAES256GCM,
		},
		{
			name:             "Software key with AES-NI uses AES-256-GCM",
			isHardwareBacked: false,
			aesni:            true,
			want:             AES256GCM,
			wantBackend:      BackendAES256GCM,
		},
		{
			name:             "Software key without AES-NI uses ChaCha20-Poly1305 outside FIPS",
			isHardwareBacked: false,
			aesni:            false,
			want:             softwareNoAESNI,
			wantBackend:      softwareNoAESNIBackend,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withAESNI(t, tt.aesni)

			if got := SelectOptimal(tt.isHardwareBacked); got != tt.want {
				t.Errorf("SelectOptimal(%v) = %v, want %v (AES-NI: %v)",
					tt.isHardwareBacked, got, tt.want, tt.aesni)
			}
			if got := SelectOptimalBackend(tt.isHardwareBacked); got != tt.wantBackend {
				t.Errorf("SelectOptimalBackend(%v) = %v, want %v (AES-NI: %v)",
					tt.isHardwareBacked, got, tt.wantBackend, tt.aesni)
			}
		})
	}
}

func TestSelectOptimal_HardwareBackedAlwaysAES(t *testing.T) {
	// Hardware-backed keys should ALWAYS use AES regardless of CPU
	result := SelectOptimal(true)
	if result != AES256GCM {
		t.Errorf("SelectOptimal(true) = %s, want %s (hardware-backed should always use AES)",
			result, AES256GCM)
	}
}

func TestIsAESGCM(t *testing.T) {
	tests := []struct {
		algorithm string
		want      bool
	}{
		// JWE format
		{AES128GCM, true},
		{AES192GCM, true},
		{AES256GCM, true},
		{ChaCha20Poly1305, false},
		{XChaCha20Poly1305, false},
		// Backend format
		{BackendAES128GCM, true},
		{BackendAES192GCM, true},
		{BackendAES256GCM, true},
		{BackendChaCha20Poly1305, false},
		{BackendXChaCha20Poly1305, false},
		// Unknown
		{"unknown", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			if got := IsAESGCM(tt.algorithm); got != tt.want {
				t.Errorf("IsAESGCM(%q) = %v, want %v", tt.algorithm, got, tt.want)
			}
		})
	}
}

func TestIsChaCha(t *testing.T) {
	tests := []struct {
		algorithm string
		want      bool
	}{
		// JWE format
		{ChaCha20Poly1305, true},
		{XChaCha20Poly1305, true},
		{AES128GCM, false},
		{AES192GCM, false},
		{AES256GCM, false},
		// Backend format
		{BackendChaCha20Poly1305, true},
		{BackendXChaCha20Poly1305, true},
		{BackendAES128GCM, false},
		{BackendAES192GCM, false},
		{BackendAES256GCM, false},
		// Unknown
		{"unknown", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			if got := IsChaCha(tt.algorithm); got != tt.want {
				t.Errorf("IsChaCha(%q) = %v, want %v", tt.algorithm, got, tt.want)
			}
		})
	}
}

func TestToJWE(t *testing.T) {
	tests := []struct {
		name     string
		backend  string
		expected string
	}{
		{"AES-128-GCM", BackendAES128GCM, AES128GCM},
		{"AES-192-GCM", BackendAES192GCM, AES192GCM},
		{"AES-256-GCM", BackendAES256GCM, AES256GCM},
		{"ChaCha20-Poly1305", BackendChaCha20Poly1305, ChaCha20Poly1305},
		{"XChaCha20-Poly1305", BackendXChaCha20Poly1305, XChaCha20Poly1305},
		{"Already JWE format", AES256GCM, AES256GCM},
		{"Unknown algorithm", "unknown", "unknown"},
		{"Empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ToJWE(tt.backend)
			if result != tt.expected {
				t.Errorf("ToJWE(%q) = %q, want %q", tt.backend, result, tt.expected)
			}
		})
	}
}

func TestToBackend(t *testing.T) {
	tests := []struct {
		name     string
		jwe      string
		expected string
	}{
		{"A128GCM", AES128GCM, BackendAES128GCM},
		{"A192GCM", AES192GCM, BackendAES192GCM},
		{"A256GCM", AES256GCM, BackendAES256GCM},
		{"ChaCha20-Poly1305", ChaCha20Poly1305, BackendChaCha20Poly1305},
		{"XChaCha20-Poly1305", XChaCha20Poly1305, BackendXChaCha20Poly1305},
		{"Already backend format", BackendAES256GCM, BackendAES256GCM},
		{"Unknown algorithm", "unknown", "unknown"},
		{"Empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ToBackend(tt.jwe)
			if result != tt.expected {
				t.Errorf("ToBackend(%q) = %q, want %q", tt.jwe, result, tt.expected)
			}
		})
	}
}

func TestRoundTripConversion(t *testing.T) {
	algorithms := []string{
		BackendAES128GCM,
		BackendAES192GCM,
		BackendAES256GCM,
		BackendChaCha20Poly1305,
		BackendXChaCha20Poly1305,
	}

	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			// Backend -> JWE -> Backend
			jwe := ToJWE(alg)
			backend := ToBackend(jwe)
			if backend != alg {
				t.Errorf("Round trip failed: %q -> %q -> %q", alg, jwe, backend)
			}
		})
	}
}

// TestConstantValues ensures the constant values match expected formats
func TestConstantValues(t *testing.T) {
	// JWE format constants
	jweTests := []struct {
		constant string
		expected string
	}{
		{AES128GCM, "A128GCM"},
		{AES192GCM, "A192GCM"},
		{AES256GCM, "A256GCM"},
		{ChaCha20Poly1305, "ChaCha20-Poly1305"},
		{XChaCha20Poly1305, "XChaCha20-Poly1305"},
	}

	for _, tt := range jweTests {
		if tt.constant != tt.expected {
			t.Errorf("JWE constant mismatch: got %q, want %q", tt.constant, tt.expected)
		}
	}

	// Backend format constants
	backendTests := []struct {
		constant string
		expected string
	}{
		{BackendAES128GCM, "aes128-gcm"},
		{BackendAES192GCM, "aes192-gcm"},
		{BackendAES256GCM, "aes256-gcm"},
		{BackendChaCha20Poly1305, "chacha20-poly1305"},
		{BackendXChaCha20Poly1305, "xchacha20-poly1305"},
	}

	for _, tt := range backendTests {
		if tt.constant != tt.expected {
			t.Errorf("Backend constant mismatch: got %q, want %q", tt.constant, tt.expected)
		}
	}
}

// Benchmark tests
func BenchmarkHasAESNI(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = HasAESNI()
	}
}

func BenchmarkSelectOptimal(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = SelectOptimal(false)
	}
}

func BenchmarkSelectOptimalBackend(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = SelectOptimalBackend(false)
	}
}

func BenchmarkIsAESGCM(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = IsAESGCM(AES256GCM)
	}
}

func BenchmarkToJWE(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = ToJWE(BackendAES256GCM)
	}
}

func BenchmarkToBackend(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = ToBackend(AES256GCM)
	}
}
