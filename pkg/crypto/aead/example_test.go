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

package aead_test

import (
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/crypto/aead"
)

// Example_autoSelection demonstrates automatic AEAD algorithm selection
// based on CPU capabilities.
func Example_autoSelection() {
	// Auto-select for software keys
	softwareAlg := aead.SelectOptimal(false)
	fmt.Printf("Software key algorithm: %s\n", softwareAlg)

	// Hardware-backed keys always use AES-256-GCM
	hardwareAlg := aead.SelectOptimal(true)
	fmt.Printf("Hardware key algorithm: %s\n", hardwareAlg)

	// Check CPU capabilities
	if aead.HasAESNI() {
		fmt.Println("CPU has AES-NI support")
	} else {
		fmt.Println("CPU does not have AES-NI support")
	}

	// Output depends on CPU capabilities:
	// On CPUs with AES-NI:
	//   Software key algorithm: A256GCM
	//   Hardware key algorithm: A256GCM
	//   CPU has AES-NI support
	// On CPUs without AES-NI:
	//   Software key algorithm: ChaCha20-Poly1305
	//   Hardware key algorithm: A256GCM
	//   CPU does not have AES-NI support
}

// Example_jweAutoDetection demonstrates automatic algorithm selection for JWE.
func Example_jweAutoDetection() {
	// Using empty string for algorithm enables auto-detection in JWE
	algorithm := ""

	// JWE will automatically select:
	// - A256GCM on CPUs with AES-NI
	// - A256GCM on any CPU (JWE doesn't support ChaCha20-Poly1305)
	fmt.Printf("JWE algorithm parameter: %q (empty = auto-detect)\n", algorithm)

	// The actual algorithm selected can be determined by:
	selected := aead.SelectOptimal(false)
	fmt.Printf("Selected algorithm: %s\n", selected)

	// Output depends on CPU capabilities
}

// Example_backendAlgorithms demonstrates backend-compatible algorithm names.
func Example_backendAlgorithms() {
	// Backend uses lowercase with hyphens
	backendAlg := aead.SelectOptimalBackend(false)
	fmt.Printf("Backend algorithm: %s\n", backendAlg)

	// Convert between JWE and backend formats
	jweAlg := aead.ToJWE(backendAlg)
	fmt.Printf("JWE algorithm: %s\n", jweAlg)

	// Convert back
	backAgain := aead.ToBackend(jweAlg)
	fmt.Printf("Back to backend: %s\n", backAgain)

	// Output depends on CPU capabilities:
	// On CPUs with AES-NI:
	//   Backend algorithm: aes256-gcm
	//   JWE algorithm: A256GCM
	//   Back to backend: aes256-gcm
	// On CPUs without AES-NI:
	//   Backend algorithm: chacha20-poly1305
	//   JWE algorithm: ChaCha20-Poly1305
	//   Back to backend: chacha20-poly1305
}

// Example_algorithmDetection demonstrates checking algorithm types.
func Example_algorithmDetection() {
	// Check if algorithm is AES-GCM
	if aead.IsAESGCM("A256GCM") {
		fmt.Println("A256GCM is AES-GCM")
	}

	if aead.IsAESGCM("aes128-gcm") {
		fmt.Println("aes128-gcm is AES-GCM")
	}

	// Check if algorithm is ChaCha
	if aead.IsChaCha("ChaCha20-Poly1305") {
		fmt.Println("ChaCha20-Poly1305 is ChaCha")
	}

	if aead.IsChaCha("chacha20-poly1305") {
		fmt.Println("chacha20-poly1305 is ChaCha")
	}

	// Output:
	// A256GCM is AES-GCM
	// aes128-gcm is AES-GCM
	// ChaCha20-Poly1305 is ChaCha
	// chacha20-poly1305 is ChaCha
}

// Example_hardwareOptimization demonstrates hardware-specific optimization.
func Example_hardwareOptimization() {
	// For TPM, PKCS#11, or cloud KMS - always use AES
	tpmAlg := aead.SelectOptimal(true)
	fmt.Printf("TPM/HSM algorithm: %s\n", tpmAlg)

	// Software keys adapt to CPU
	swAlg := aead.SelectOptimal(false)
	fmt.Printf("Software algorithm: %s\n", swAlg)

	// Hardware backends are optimized for AES
	// Output:
	// TPM/HSM algorithm: A256GCM
	// Software algorithm: <depends on CPU>
}
