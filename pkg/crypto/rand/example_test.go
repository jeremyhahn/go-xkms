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
	"crypto"
	"fmt"
	"log"
)

// ExampleNewResolver_auto demonstrates using auto mode RNG selection.
// Auto mode automatically selects the best available RNG source:
// TPM2 > PKCS#11 > Software
func ExampleNewResolver_auto() {
	// Create resolver with auto mode (default)
	resolver, err := NewResolver(ModeAuto)
	if err != nil {
		log.Fatal(err)
	}
	defer resolver.Close()

	// Generate random bytes for key material
	randomBytes, err := resolver.Rand(32)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Generated %d random bytes using auto mode\n", len(randomBytes))
	// Output: Generated 32 random bytes using auto mode
}

// ExampleNewResolver_software demonstrates using software RNG.
// Useful for nonce/IV generation and development/testing scenarios.
func ExampleNewResolver_software() {
	// Explicitly use software RNG (crypto/rand)
	resolver, err := NewResolver(ModeSoftware)
	if err != nil {
		log.Fatal(err)
	}
	defer resolver.Close()

	// Generate random bytes for nonce
	nonce, err := resolver.Rand(12)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Generated %d-byte nonce using software RNG\n", len(nonce))
	// Output: Generated 12-byte nonce using software RNG
}

// ExampleNewResolver_mode demonstrates passing a Mode directly.
// You can pass either a Mode constant or a Config struct.
func ExampleNewResolver_mode() {
	// Pass Mode directly
	resolver, err := NewResolver(ModeSoftware)
	if err != nil {
		log.Fatal(err)
	}
	defer resolver.Close()

	randomBytes, err := resolver.Rand(16)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Generated %d random bytes\n", len(randomBytes))
	// Output: Generated 16 random bytes
}

// ExampleNewResolver_fallback demonstrates configuring a fallback RNG.
// If the primary RNG fails, automatically fall back to software RNG.
func ExampleNewResolver_fallback() {
	// Configure with fallback: try TPM2, fall back to software
	cfg := &Config{
		Mode:         ModeAuto,     // Try best available
		FallbackMode: ModeSoftware, // Fall back to software
	}

	resolver, err := NewResolver(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer resolver.Close()

	// Will use best available, with fallback to software
	randomBytes, err := resolver.Rand(32)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Generated %d random bytes with fallback\n", len(randomBytes))
	// Output: Generated 32 random bytes with fallback
}

// ExampleNewResolver_keyGeneration demonstrates using RNG for key generation.
// Hardware RNG is recommended for generating initial key material.
func ExampleNewResolver_keyGeneration() {
	// Use auto mode for key generation - prefer hardware RNG
	resolver, err := NewResolver(ModeAuto)
	if err != nil {
		log.Fatal(err)
	}
	defer resolver.Close()

	// Generate seed for asymmetric key
	seed, err := resolver.Rand(32)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Generated key seed: %d bytes from %v\n",
		len(seed), resolver.Source())
	// Output: Generated key seed: 32 bytes from &{}
}

// ExampleNewResolver_nonceGeneration demonstrates using RNG for nonce generation.
// Software RNG is typically sufficient for nonce generation.
func ExampleNewResolver_nonceGeneration() {
	// Use software RNG for nonce - fast enough for many operations
	resolver, err := NewResolver(ModeSoftware)
	if err != nil {
		log.Fatal(err)
	}
	defer resolver.Close()

	// Generate 96-bit nonce for AES-GCM
	nonce, err := resolver.Rand(12)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Generated AES-GCM nonce: %d bytes\n", len(nonce))
	// Output: Generated AES-GCM nonce: 12 bytes
}

// ExampleNewResolver_bulkOperations demonstrates efficient bulk random generation.
// Requesting larger amounts at once is more efficient than many small requests.
func ExampleNewResolver_bulkOperations() {
	resolver, err := NewResolver(ModeSoftware)
	if err != nil {
		log.Fatal(err)
	}
	defer resolver.Close()

	// Generate 256 bytes at once for multiple operations
	randomPool, err := resolver.Rand(256)
	if err != nil {
		log.Fatal(err)
	}

	// Split pool for different uses
	seed := randomPool[0:32]   // Key seed
	nonce := randomPool[32:44] // AES-GCM nonce
	salt := randomPool[44:76]  // KDF salt

	fmt.Printf("Generated pool: seed=%d, nonce=%d, salt=%d\n",
		len(seed), len(nonce), len(salt))
	// Output: Generated pool: seed=32, nonce=12, salt=32
}

// ExampleResolver_source demonstrates accessing the underlying RNG source.
// Useful for testing, debugging, and understanding which RNG is being used.
func ExampleResolver_source() {
	resolver, err := NewResolver(ModeSoftware)
	if err != nil {
		log.Fatal(err)
	}
	defer resolver.Close()

	// Get underlying source for testing or debugging
	source := resolver.Source()

	randomBytes, err := source.Rand(32)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Generated %d bytes from source directly\n", len(randomBytes))
	// Output: Generated 32 bytes from source directly
}

// ExampleResolver_available demonstrates checking RNG availability.
// Before using critical RNG operations, check if the source is available.
func ExampleResolver_available() {
	resolver, err := NewResolver(ModeAuto)
	if err != nil {
		log.Fatal(err)
	}
	defer resolver.Close()

	if resolver.Available() {
		randomBytes, _ := resolver.Rand(32)
		fmt.Printf("RNG available, generated %d bytes\n", len(randomBytes))
	} else {
		fmt.Println("RNG not available")
	}
	// Output: RNG available, generated 32 bytes
}

// ExampleConfig_tpm2 demonstrates configuring TPM2 RNG with custom settings.
// For advanced users who need fine-grained control over TPM2 behavior.
func ExampleConfig_tpm2() {
	cfg := &Config{
		Mode: ModeTPM2,
		TPM2Config: &TPM2Config{
			Device:         "/dev/tpm0",
			MaxRequestSize: 32, // TPM2 spec default
		},
	}

	resolver, err := NewResolver(cfg)
	if err != nil {
		// Hardware not available, fall back to software
		resolver, _ = NewResolver(ModeSoftware)
	}
	defer resolver.Close()

	randomBytes, _ := resolver.Rand(64)
	fmt.Printf("Generated %d bytes using available RNG\n", len(randomBytes))
	// Output: Generated 64 bytes using available RNG
}

// ExampleConfig_pkcs11 demonstrates configuring PKCS#11 RNG.
// For use with hardware security modules and smart cards.
func ExampleConfig_pkcs11() {
	cfg := &Config{
		Mode: ModePKCS11,
		PKCS11Config: &PKCS11Config{
			Module:      "/usr/lib/libsofthsm2.so",
			SlotID:      0,
			PINRequired: true,
			PIN:         "1234",
		},
	}

	resolver, err := NewResolver(cfg)
	if err != nil {
		// Hardware not available, fall back to software
		resolver, _ = NewResolver(ModeSoftware)
	}
	defer resolver.Close()

	randomBytes, _ := resolver.Rand(32)
	fmt.Printf("Generated %d bytes using available RNG\n", len(randomBytes))
	// Output: Generated 32 bytes using available RNG
}

// ExampleNewResolver_securityBestPractices demonstrates recommended usage patterns.
// This shows how to securely initialize RNG for cryptographic operations.
func ExampleNewResolver_securityBestPractices() {
	// 1. Initialize RNG at application startup
	resolver, err := NewResolver(&Config{
		Mode:         ModeAuto,     // Try hardware first
		FallbackMode: ModeSoftware, // Fall back to software
	})
	if err != nil {
		log.Fatal(err)
	}
	defer resolver.Close()

	// 2. Verify RNG is available before critical operations
	if !resolver.Available() {
		log.Fatal("RNG not available")
	}

	// 3. Use appropriate sizes for security level
	// AES-256 requires 256 bits = 32 bytes
	seed, _ := resolver.Rand(32)

	// HMAC-SHA256 requires 32 bytes minimum
	hmacKey, _ := resolver.Rand(32)

	// AES-GCM requires 96-bit nonce
	nonce, _ := resolver.Rand(12)

	fmt.Printf("Generated seed=%d, hmacKey=%d, nonce=%d bytes\n",
		len(seed), len(hmacKey), len(nonce))
	// Output: Generated seed=32, hmacKey=32, nonce=12 bytes
}

// ExampleNewResolver_errorHandling demonstrates proper error handling.
// Always check errors when generating random numbers.
func ExampleNewResolver_errorHandling() {
	resolver, err := NewResolver(ModeSoftware)
	if err != nil {
		fmt.Printf("Failed to create resolver: %v\n", err)
		return
	}
	defer resolver.Close()

	// Check error for each Rand call
	randomBytes, err := resolver.Rand(32)
	if err != nil {
		fmt.Printf("Random generation failed: %v\n", err)
		return
	}

	fmt.Printf("Successfully generated %d bytes\n", len(randomBytes))
	// Output: Successfully generated 32 bytes
}

// ExampleNewResolver_complianceConsiderations demonstrates FIPS/NIST compliance setup.
// For organizations requiring certified random number generation.
func ExampleNewResolver_complianceConsiderations() {
	// For FIPS 140-2 compliance, use hardware RNG with certification
	cfg := &Config{
		Mode: ModePKCS11, // Use certified PKCS#11 HSM
		PKCS11Config: &PKCS11Config{
			Module: "/usr/lib/libcloudhsm_client.so", // CloudHSM or similar
			SlotID: 0,
		},
	}

	resolver, err := NewResolver(cfg)
	if err != nil {
		// Hardware not available in test environment
		resolver, _ = NewResolver(ModeSoftware)
	}
	defer resolver.Close()

	// Use available RNG (FIPS-certified in production)
	randomBytes, _ := resolver.Rand(32)
	fmt.Printf("Generated %d bytes using available RNG\n", len(randomBytes))
	// Output: Generated 32 bytes using available RNG
}

// ExampleNewResolver_differentSizes demonstrates generating various random sizes.
// Different operations require different amounts of randomness.
func ExampleNewResolver_differentSizes() {
	resolver, _ := NewResolver(ModeSoftware)
	defer resolver.Close()

	// AES-128 key
	aes128, _ := resolver.Rand(16)

	// AES-256 key
	aes256, _ := resolver.Rand(32)

	// ChaCha20Poly1305 key
	chacha, _ := resolver.Rand(32)

	// HMAC-SHA256 key (minimum)
	hmac, _ := resolver.Rand(32)

	// RSA-2048 seed
	rsa2048Seed, _ := resolver.Rand(64)

	fmt.Printf("AES-128=%d, AES-256=%d, ChaCha=%d, HMAC=%d, RSA2048=%d\n",
		len(aes128), len(aes256), len(chacha), len(hmac), len(rsa2048Seed))
	// Output: AES-128=16, AES-256=32, ChaCha=32, HMAC=32, RSA2048=64
}

// ExampleNewResolver_cryptographicHashInput demonstrates using RNG for hash input.
// Hash functions can act as KDFs (Key Derivation Functions) when given random salt.
func ExampleNewResolver_cryptographicHashInput() {
	resolver, _ := NewResolver(ModeSoftware)
	defer resolver.Close()

	// Generate random salt for password hashing (bcrypt, scrypt, argon2)
	salt, _ := resolver.Rand(16)

	// Generate random input for HKDF
	ikm, _ := resolver.Rand(32)

	// Generate random salt for HKDF
	hkdfSalt, _ := resolver.Rand(32)

	fmt.Printf("Generated salt=%d, ikm=%d, hkdfSalt=%d\n",
		len(salt), len(ikm), len(hkdfSalt))
	// Output: Generated salt=16, ikm=32, hkdfSalt=32
}

// ExampleNewResolver_documentedRNGBehavior shows how to document RNG configuration.
// This is useful for security audits and compliance documentation.
func ExampleNewResolver_documentedRNGBehavior() {
	// Initialize with explicit configuration for documentation
	cfg := &Config{
		Mode: ModeAuto,
		TPM2Config: &TPM2Config{
			Device:         "/dev/tpm0",
			MaxRequestSize: 32,
		},
		PKCS11Config: &PKCS11Config{
			Module: "/usr/lib/libsofthsm2.so",
			SlotID: 0,
		},
	}

	resolver, _ := NewResolver(cfg)
	defer resolver.Close()

	// Document RNG source for audit trail
	fmt.Printf("RNG Configuration:\n")
	fmt.Printf("- Primary Mode: %s\n", cfg.Mode)
	fmt.Printf("- TPM2 Device: %s\n", cfg.TPM2Config.Device)
	fmt.Printf("- PKCS#11 Module: %s\n", cfg.PKCS11Config.Module)
	fmt.Printf("- Available: %v\n", resolver.Available())

	randomBytes, _ := resolver.Rand(32)
	fmt.Printf("Generated %d bytes\n", len(randomBytes))
	// Output: RNG Configuration:
	// - Primary Mode: auto
	// - TPM2 Device: /dev/tpm0
	// - PKCS#11 Module: /usr/lib/libsofthsm2.so
	// - Available: true
	// Generated 32 bytes
}

// ExampleNewResolver_verifyHashAlgorithmCompatibility ensures proper RNG usage with different hash algorithms.
// Demonstrates how to use RNG for different cryptographic needs.
func ExampleNewResolver_verifyHashAlgorithmCompatibility() {
	resolver, _ := NewResolver(ModeSoftware)
	defer resolver.Close()

	// Generate random bytes for different algorithms
	sha256Rand, _ := resolver.Rand(32)  // SHA-256 output size
	sha512Rand, _ := resolver.Rand(64)  // SHA-512 output size
	blake2bRand, _ := resolver.Rand(64) // BLAKE2b-512 output size
	blake3Rand, _ := resolver.Rand(32)  // BLAKE3 default size

	_ = crypto.SHA256.HashFunc()

	fmt.Printf("SHA-256=%d, SHA-512=%d, BLAKE2b=%d, BLAKE3=%d\n",
		len(sha256Rand), len(sha512Rand), len(blake2bRand), len(blake3Rand))
	// Output: SHA-256=32, SHA-512=64, BLAKE2b=64, BLAKE3=32
}
