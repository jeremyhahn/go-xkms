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

// Package rand provides a configurable random number generation (RNG) system
// for cryptographic operations with support for multiple sources including
// hardware-backed RNG from TPM2, PKCS#11, and software-based sources.
//
// # Overview
//
// This package allows applications to:
//   - Automatically detect and use available hardware RNG sources (auto mode)
//   - Explicitly select a specific RNG source (software, TPM2, PKCS#11)
//   - Configure hardware RNG with source-specific settings
//   - Fall back to software RNG when hardware is unavailable
//   - Validate RNG behavior through testing and development scenarios
//
// # RNG Sources
//
// The package supports four RNG sources:
//   - Auto: Automatically selects the best available RNG (hardware > software)
//   - Software: Uses crypto/rand (stdlib secure random)
//   - TPM2: Uses Trusted Platform Module 2.0 hardware RNG
//   - PKCS11: Uses PKCS#11 hardware security module RNG
//
// # Security Benefits
//
// Hardware RNG provides advantages over software-based approaches:
//   - True randomness from hardware entropy sources (not pseudo-random)
//   - Certified random number generation (NIST/FIPS compliance)
//   - Protection against timing attacks and side-channel analysis
//   - Better performance for bulk random generation
//   - Compliance with security standards and regulations
//
// # Configuration
//
// Applications configure the RNG system at startup:
//
//	import "github.com/jeremyhahn/go-keychain/pkg/crypto/rand"
//
//	// Auto mode: automatically use best available hardware
//	rng, _ := rand.NewResolver(rand.ModeAuto)
//	randomBytes, _ := rng.Rand(32)
//
//	// Explicit hardware: force TPM2 RNG
//	cfg := &rand.Config{Mode: rand.ModeTPM2}
//	rng, _ := rand.NewResolver(cfg)
//	randomBytes, _ := rng.Rand(64)
//
//	// Fallback on failure: try TPM2, fall back to software
//	rng, _ := rand.NewResolver(&rand.Config{
//	    Mode:         rand.ModeAuto,
//	    FallbackMode: rand.ModeSoftware,
//	})
//	randomBytes, _ := rng.Rand(32)
//
// # Usage Patterns
//
// ## Key Generation
//
// For key generation, auto mode is recommended. Hardware RNG provides
// better entropy for initial key material:
//
//	rng, _ := rand.NewResolver(rand.ModeAuto)
//	// Use rng for key seed generation
//
// ## Nonce/IV Generation
//
// Nonces must be unique per key/message combination. For high-volume
// nonce generation, software RNG is typically sufficient and faster:
//
//	rng, _ := rand.NewResolver(rand.ModeSoftware)
//	// Use rng for nonce generation
//
// ## FIPS/Security Compliance
//
// Organizations requiring FIPS 140-2 or NIST compliance should:
//   - Use hardware RNG with appropriate certification
//   - Configure with target PKCS#11 or TPM2 device
//   - Document the hardware security module used
//   - Validate RNG output periodically
//
// # Error Handling
//
// RNG sources may fail for various reasons:
//   - Hardware unavailable or uninitialized
//   - Insufficient entropy (rare with modern systems)
//   - Device communication errors
//   - Permission/access restrictions
//
// Configuration can specify a fallback mode to handle failures gracefully.
//
// # Performance Considerations
//
// RNG performance characteristics:
//   - Software RNG: Very fast, suitable for bulk operations
//   - TPM2 RNG: Moderate speed, subject to TPM rate limiting
//   - PKCS#11 RNG: Depends on hardware, typically moderate speed
//
// For performance-sensitive operations, consider:
//   - Generating a seed with hardware RNG
//   - Using a CSPRNG (crypto/rand) for derived values
//   - Batching RNG operations to reduce round-trips
//
// # Testing and Development
//
// For testing/development scenarios where deterministic randomness is useful,
// consider a test mode configuration (though not exposed for security reasons
// - never use in production):
//
//	// In test code only
//	rng, _ := rand.NewResolver(rand.ModeSoftware)
//	// Note: No deterministic seed mode for security
//
// # Thread Safety
//
// All Resolver implementations are thread-safe and can be safely shared
// across goroutines.
package rand

import (
	"crypto/rand"
	"fmt"
)

// Mode specifies which RNG source to use.
type Mode string

const (
	// ModeAuto automatically selects the best available RNG.
	// Preference order: TPM2 > PKCS#11 > Software
	ModeAuto Mode = "auto"

	// ModeSoftware uses crypto/rand (stdlib secure random)
	ModeSoftware Mode = "software"

	// ModeTPM2 uses Trusted Platform Module 2.0 hardware RNG
	ModeTPM2 Mode = "tpm2"

	// ModePKCS11 uses PKCS#11 hardware security module RNG
	ModePKCS11 Mode = "pkcs11"
)

// Config contains RNG configuration.
type Config struct {
	// Mode specifies the primary RNG source to use.
	// Defaults to ModeAuto if not specified.
	Mode Mode

	// FallbackMode specifies the RNG source to use if primary mode fails.
	// If not specified, failures are returned as errors.
	// Typical usage: Mode=ModeTPM2, FallbackMode=ModeSoftware
	FallbackMode Mode

	// TPM2Config contains TPM2-specific configuration (if Mode=ModeTPM2).
	// If nil, defaults are used.
	TPM2Config *TPM2Config

	// PKCS11Config contains PKCS#11-specific configuration (if Mode=ModePKCS11).
	// If nil, defaults are used.
	PKCS11Config *PKCS11Config
}

// TPM2Config contains configuration for TPM2 RNG.
type TPM2Config struct {
	// Device path to the TPM device (default: "/dev/tpm0")
	// Ignored when UseSimulator is true
	Device string

	// MaxRequestSize limits the maximum bytes to request per RNG call.
	// TPM2 has limits on how much entropy can be generated per request.
	// Default: 32 bytes (recommended by TPM2 spec)
	MaxRequestSize int

	// UseSimulator indicates whether to connect to a TPM simulator
	// instead of a hardware device. When true, SimulatorHost and
	// SimulatorPort are used to establish TCP connection.
	UseSimulator bool

	// SimulatorType specifies which TPM simulator to use.
	// Supported values: "swtpm", "embedded"
	// Default: "swtpm"
	SimulatorType string

	// SimulatorHost is the hostname or IP address of the TPM simulator.
	// Used when UseSimulator is true.
	// Default: "localhost"
	SimulatorHost string

	// SimulatorPort is the TCP port of the TPM simulator.
	// Used when UseSimulator is true.
	// Default: 2321 (standard SWTPM port)
	SimulatorPort int
}

// PKCS11Config contains configuration for PKCS#11 RNG.
type PKCS11Config struct {
	// Module path to the PKCS#11 library (e.g., /usr/lib/libsofthsm2.so)
	Module string

	// SlotID specifies the PKCS#11 slot containing the RNG
	SlotID uint

	// PINRequired indicates if the slot requires PIN authentication
	PINRequired bool

	// PIN is the authentication PIN (if PINRequired is true)
	PIN string
}

// Source represents a random number generator.
type Source interface {
	// Rand returns n random bytes.
	// Returns an error if the RNG is unavailable or fails.
	Rand(n int) ([]byte, error)

	// Available returns true if this RNG source is available and ready.
	Available() bool

	// Close closes the RNG and releases any resources.
	Close() error
}

// Resolver provides the main interface for generating random numbers.
// Applications should create a Resolver at startup and reuse it.
//
// Resolver implements io.Reader, making it compatible with crypto/rand.Reader
// and usable anywhere an io.Reader is expected for random number generation.
type Resolver interface {
	// Rand returns n random bytes from the configured RNG source.
	// If the primary source fails and FallbackMode is configured,
	// tries the fallback source.
	// Returns an error if all sources fail.
	Rand(n int) ([]byte, error)

	// Read implements io.Reader, making this Resolver usable as a drop-in
	// replacement for crypto/rand.Reader. This allows hardware-backed RNG
	// to be used with standard library functions like rsa.GenerateKey,
	// ecdsa.GenerateKey, and x509.CreateCertificate.
	Read(p []byte) (n int, err error)

	// Source returns the underlying RNG Source being used.
	// Useful for testing and debugging.
	Source() Source

	// Available returns true if at least one RNG source is available.
	Available() bool

	// Close closes the resolver and releases any resources.
	Close() error
}

// NewResolver creates a new RNG resolver with the given configuration.
// If config is nil or empty, auto mode is used.
//
// Returns an error if the primary mode is unavailable and no fallback
// is configured.
func NewResolver(config interface{}) (Resolver, error) {
	cfg := normalizeConfig(config)
	return newResolver(cfg)
}

// normalizeConfig converts various config types to *Config.
func normalizeConfig(config interface{}) *Config {
	if config == nil {
		return &Config{Mode: ModeAuto}
	}

	switch v := config.(type) {
	case Mode:
		return &Config{Mode: v}
	case *Config:
		if v == nil {
			return &Config{Mode: ModeAuto}
		}
		if v.Mode == "" {
			v.Mode = ModeAuto
		}
		return v
	default:
		return &Config{Mode: ModeAuto}
	}
}

// newResolver creates the actual resolver implementation.
func newResolver(cfg *Config) (Resolver, error) {
	mode := cfg.Mode
	if mode == "" {
		mode = ModeAuto
	}

	switch mode {
	case ModeAuto:
		return newAutoResolver(cfg)
	case ModeSoftware:
		return newSoftwareResolver()
	case ModeTPM2:
		return newTPM2Resolver(cfg.TPM2Config)
	case ModePKCS11:
		return newPKCS11Resolver(cfg.PKCS11Config)
	default:
		return nil, fmt.Errorf("unknown RNG mode: %s", mode)
	}
}

// SoftwareResolver uses crypto/rand from the Go standard library.
type SoftwareResolver struct{}

var _ Resolver = (*SoftwareResolver)(nil)

func newSoftwareResolver() (Resolver, error) {
	return &SoftwareResolver{}, nil
}

func (s *SoftwareResolver) Rand(n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := rand.Read(buf)
	return buf, err
}

// Read implements io.Reader for compatibility with crypto/rand.Reader.
// This allows the SoftwareResolver to be used with standard library
// functions that expect an io.Reader for randomness.
func (s *SoftwareResolver) Read(p []byte) (n int, err error) {
	return rand.Read(p)
}

func (s *SoftwareResolver) Source() Source {
	return &softwareSource{}
}

func (s *SoftwareResolver) Available() bool {
	return true // crypto/rand always available
}

func (s *SoftwareResolver) Close() error {
	return nil // Nothing to close
}

type softwareSource struct{}

func (s *softwareSource) Rand(n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := rand.Read(buf)
	return buf, err
}

func (s *softwareSource) Available() bool {
	return true
}

func (s *softwareSource) Close() error {
	return nil
}
