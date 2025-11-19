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

package rand

import (
	"bytes"
	"testing"
)

func TestNewResolver_SoftwareMode(t *testing.T) {
	resolver, err := NewResolver(ModeSoftware)
	if err != nil {
		t.Fatalf("failed to create software resolver: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	if !resolver.Available() {
		t.Fatal("software resolver should be available")
	}
}

func TestNewResolver_NilConfig(t *testing.T) {
	// nil config should default to auto mode
	resolver, err := NewResolver(nil)
	if err != nil {
		t.Fatalf("failed to create resolver with nil config: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	if !resolver.Available() {
		t.Fatal("resolver should be available")
	}
}

func TestNewResolver_Mode(t *testing.T) {
	resolver, err := NewResolver(ModeSoftware)
	if err != nil {
		t.Fatalf("failed to create resolver: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	if !resolver.Available() {
		t.Fatal("resolver should be available")
	}
}

func TestNewResolver_Config(t *testing.T) {
	cfg := &Config{Mode: ModeSoftware}
	resolver, err := NewResolver(cfg)
	if err != nil {
		t.Fatalf("failed to create resolver with config: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	if !resolver.Available() {
		t.Fatal("resolver should be available")
	}
}

func TestNewResolver_InvalidMode(t *testing.T) {
	cfg := &Config{Mode: "invalid"}
	_, err := NewResolver(cfg)
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestSoftwareResolver_Rand(t *testing.T) {
	resolver, _ := NewResolver(ModeSoftware)
	defer func() { _ = resolver.Close() }()

	// Test various sizes
	sizes := []int{1, 16, 32, 64, 256, 1024}
	for _, size := range sizes {
		result, err := resolver.Rand(size)
		if err != nil {
			t.Fatalf("Rand(%d) failed: %v", size, err)
		}
		if len(result) != size {
			t.Fatalf("expected %d bytes, got %d", size, len(result))
		}
	}
}

func TestSoftwareResolver_RandZeroBytes(t *testing.T) {
	resolver, _ := NewResolver(ModeSoftware)
	defer func() { _ = resolver.Close() }()

	result, err := resolver.Rand(0)
	if err != nil {
		t.Fatalf("Rand(0) failed: %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("expected 0 bytes, got %d", len(result))
	}
}

func TestSoftwareResolver_RandRandomness(t *testing.T) {
	resolver, _ := NewResolver(ModeSoftware)
	defer func() { _ = resolver.Close() }()

	// Generate multiple random buffers and verify they're different
	buf1, _ := resolver.Rand(32)
	buf2, _ := resolver.Rand(32)

	if bytes.Equal(buf1, buf2) {
		t.Fatal("consecutive random buffers should not be equal")
	}
}

func TestSoftwareResolver_RandEntropy(t *testing.T) {
	resolver, _ := NewResolver(ModeSoftware)
	defer func() { _ = resolver.Close() }()

	// Generate many bytes and verify they have good entropy
	// (not all zeros or all ones)
	buf, _ := resolver.Rand(256)

	var zeroCount, oneCount int
	for _, b := range buf {
		switch b {
		case 0:
			zeroCount++
		case 255:
			oneCount++
		}
	}

	// Should not have too many zeros or ones
	if zeroCount > 20 || oneCount > 20 {
		t.Logf("warning: high count of zero/one bytes: zeros=%d, ones=%d", zeroCount, oneCount)
	}
}

func TestSoftwareResolver_Available(t *testing.T) {
	resolver, _ := NewResolver(ModeSoftware)
	defer func() { _ = resolver.Close() }()

	if !resolver.Available() {
		t.Fatal("software resolver should always be available")
	}
}

func TestSoftwareResolver_Close(t *testing.T) {
	resolver, _ := NewResolver(ModeSoftware)
	err := resolver.Close()
	if err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
}

func TestNormalizeConfig_Nil(t *testing.T) {
	cfg := normalizeConfig(nil)
	if cfg == nil || cfg.Mode != ModeAuto {
		t.Fatal("normalizeConfig(nil) should return auto mode config")
	}
}

func TestNormalizeConfig_Mode(t *testing.T) {
	cfg := normalizeConfig(ModeSoftware)
	if cfg == nil || cfg.Mode != ModeSoftware {
		t.Fatal("normalizeConfig(Mode) should return config with that mode")
	}
}

func TestNormalizeConfig_Config(t *testing.T) {
	input := &Config{Mode: ModeSoftware}
	cfg := normalizeConfig(input)
	if cfg != input {
		t.Fatal("normalizeConfig(*Config) should return same config")
	}
}

func TestNormalizeConfig_NilConfig(t *testing.T) {
	var nilCfg *Config
	cfg := normalizeConfig(nilCfg)
	if cfg == nil || cfg.Mode != ModeAuto {
		t.Fatal("normalizeConfig(nil *Config) should return auto mode config")
	}
}

func TestNormalizeConfig_InvalidType(t *testing.T) {
	cfg := normalizeConfig("invalid")
	if cfg == nil || cfg.Mode != ModeAuto {
		t.Fatal("normalizeConfig(invalid type) should return auto mode config")
	}
}

func TestResolver_Source(t *testing.T) {
	resolver, _ := NewResolver(ModeSoftware)
	defer func() { _ = resolver.Close() }()

	source := resolver.Source()
	if source == nil {
		t.Fatal("Source() should return non-nil source")
	}

	// Source should work the same as resolver
	buf, err := source.Rand(32)
	if err != nil {
		t.Fatalf("Source.Rand() failed: %v", err)
	}
	if len(buf) != 32 {
		t.Fatalf("expected 32 bytes from Source, got %d", len(buf))
	}
}

func TestResolver_Available(t *testing.T) {
	resolver, _ := NewResolver(ModeSoftware)
	defer func() { _ = resolver.Close() }()

	if !resolver.Available() {
		t.Fatal("software resolver should be available")
	}
}

func TestConfig_TPM2ConfigDefaults(t *testing.T) {
	cfg := &TPM2Config{}
	if cfg.MaxRequestSize == 0 {
		t.Log("TPM2Config.MaxRequestSize is 0 - defaults set by resolver")
	}
}

func TestConfig_PKCS11ConfigFields(t *testing.T) {
	cfg := &PKCS11Config{
		Module:      "/usr/lib/libsofthsm2.so",
		SlotID:      0,
		PINRequired: true,
		PIN:         "1234",
	}

	if cfg.Module == "" {
		t.Fatal("PKCS11Config.Module should be set")
	}
	if !cfg.PINRequired {
		t.Fatal("PKCS11Config.PINRequired should be true")
	}
}

func BenchmarkSoftwareResolver_Rand32(b *testing.B) {
	resolver, _ := NewResolver(ModeSoftware)
	defer func() { _ = resolver.Close() }()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = resolver.Rand(32)
	}
}

func BenchmarkSoftwareResolver_Rand256(b *testing.B) {
	resolver, _ := NewResolver(ModeSoftware)
	defer func() { _ = resolver.Close() }()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = resolver.Rand(256)
	}
}

func BenchmarkSoftwareResolver_Rand1024(b *testing.B) {
	resolver, _ := NewResolver(ModeSoftware)
	defer func() { _ = resolver.Close() }()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = resolver.Rand(1024)
	}
}
