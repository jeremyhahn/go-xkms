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

package server_test

import (
	"context"
	"log/slog"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/server"
)

// ExampleCAAValidator demonstrates how to create and use a CAA validator.
func ExampleCAAValidator() {
	// Create a CAA validator with custom configuration
	validator, err := server.NewCAAValidator(&server.CAAValidatorParams{
		Logger:   slog.Default(),
		Resolver: "8.8.8.8:53",    // Google DNS
		Timeout:  5 * time.Second, // DNS query timeout
		CAAIdentities: []string{
			"ca.example.com",
			"ca.example.net",
		},
	})
	if err != nil {
		// Handle error
		return
	}

	ctx := context.Background()

	// Validate a regular domain
	if err := validator.Validate(ctx, "example.com", false); err != nil {
		// CAA validation failed - certificate issuance should be denied
		return
	}

	// Validate a wildcard domain
	if err := validator.Validate(ctx, "example.com", true); err != nil {
		// CAA validation failed for wildcard
		return
	}

	// Output:
}

// ExampleCAAValidator_withACMEServer demonstrates integrating CAA validation
// with the ACME server.
func ExampleCAAValidator_withACMEServer() {
	// Create CAA validator
	caaValidator, err := server.NewCAAValidator(&server.CAAValidatorParams{
		Logger:        slog.Default(),
		Timeout:       5 * time.Second,
		CAAIdentities: []string{"ca.example.com"},
	})
	if err != nil {
		// Handle error
		return
	}

	// The validator will be passed to the ACME server handlers
	// via the Params.CAAValidator field when creating the REST service
	_ = caaValidator

	// Output:
}
