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

//go:build integration

package module

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
	"github.com/jeremyhahn/go-xkms/pkg/testing/pkcs11test"
)

// integrationModuleFactory creates a Module connected to a running xkms daemon
// via the transport configured in environment variables.
func integrationModuleFactory(t *testing.T) (*module.Module, func()) {
	t.Helper()

	env := SetupTestEnvironment(t, nil)
	return env.Module, func() {
		env.Teardown(t)
	}
}

// TestPKCS11V3Suite_Integration runs the shared PKCS#11 v3.0 conformance suite
// against a real xkms daemon accessible via the configured transport.
func TestPKCS11V3Suite_Integration(t *testing.T) {
	suite := pkcs11test.NewSuite(integrationModuleFactory)
	suite.RunAll(t)
}
