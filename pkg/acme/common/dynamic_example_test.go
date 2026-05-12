// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package common_test

import (
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
)

func ExampleParseDynamicChallenge() {
	// Parse a dynamic challenge
	name, port, err := common.ParseDynamicChallenge("http-8080")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Dynamic: name=%s, port=%s\n", name, port)

	// Parse a standard challenge
	name, port, err = common.ParseDynamicChallenge("http-01")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Standard: name=%s, port=%s\n", name, port)

	// Output:
	// Dynamic: name=http, port=8080
	// Standard: name=http-01, port=
}

func ExampleIsDynamicChallenge() {
	// Check if challenge is dynamic
	fmt.Println(common.IsDynamicChallenge("http-8080"))
	fmt.Println(common.IsDynamicChallenge("http-01"))

	// Output:
	// true
	// false
}

func ExampleGetChallengePort() {
	// Get port for dynamic challenge
	fmt.Println(common.GetChallengePort("http-8080"))

	// Get default port for standard challenge
	fmt.Println(common.GetChallengePort("http-01"))

	// Get port for enroll challenge
	fmt.Println(common.GetChallengePort("enroll-01"))

	// Output:
	// 8080
	// 80
	// 8443
}

func ExampleNormalizeChallengeType() {
	// Normalize dynamic challenges to standard form
	fmt.Println(common.NormalizeChallengeType("http-8080"))
	fmt.Println(common.NormalizeChallengeType("enroll-8443"))

	// Standard challenges remain unchanged
	fmt.Println(common.NormalizeChallengeType("http-01"))

	// Output:
	// http-01
	// enroll-01
	// http-01
}

func ExampleFormatDynamicChallenge() {
	// Create dynamic challenge from base type and port
	fmt.Println(common.FormatDynamicChallenge("http", "8080"))
	fmt.Println(common.FormatDynamicChallenge("enroll", "8443"))

	// Output:
	// http-8080
	// enroll-8443
}

// Example demonstrating complete workflow
func ExampleParseDynamicChallenge_workflow() {
	challengeType := "http-8080"

	// Check if it's a dynamic challenge
	if common.IsDynamicChallenge(challengeType) {
		fmt.Printf("%s is a dynamic challenge\n", challengeType)

		// Parse it
		name, port, _ := common.ParseDynamicChallenge(challengeType)
		fmt.Printf("Base type: %s, Port: %s\n", name, port)

		// Get the normalized standard form
		normalized := common.NormalizeChallengeType(challengeType)
		fmt.Printf("Normalized: %s\n", normalized)

		// Reconstruct it
		reconstructed := common.FormatDynamicChallenge(name, port)
		fmt.Printf("Reconstructed: %s\n", reconstructed)
	}

	// Output:
	// http-8080 is a dynamic challenge
	// Base type: http, Port: 8080
	// Normalized: http-01
	// Reconstructed: http-8080
}
