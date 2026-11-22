// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// Package xkmstest re-exports the go-xkms test-support helpers that SDK
// consumers' test suites need. It is for tests only: no production package
// imports it, so the helpers never reach a production binary. Keep the
// production SDK (package xkms) free of test helpers and add them here.
package xkmstest

import (
	"github.com/jeremyhahn/go-xkms/pkg/testing/enclavetest"
	"github.com/jeremyhahn/go-xkms/pkg/testing/fipstest"
	"github.com/jeremyhahn/go-xkms/pkg/testing/pkcs11test"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/barriertest"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/secrettest"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/vaulttest"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/vaulttest/vaultservice"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/tpm2test"
)

// SecretLiteral seals value as a literal secret, failing the test on error.
var SecretLiteral = secrettest.Literal

// RunWithEnclaveBudget reruns the test in a child process whose enclave
// allocator has the given budget; it returns true in the child.
var RunWithEnclaveBudget = enclavetest.RunWithBudget

// VaultSimulatedKey is the shared simulated FIDO2 security key for
// password-vault passkey tests.
type VaultSimulatedKey = vaulttest.SimulatedKey

// NewVaultSimulatedKey returns a simulated security key guarded by pin.
var NewVaultSimulatedKey = vaulttest.NewSimulatedKey

// VaultRelyingParty is the relying party the vault passkey tests enroll under.
const VaultRelyingParty = vaulttest.RelyingParty

// VaultTenant is the tenant the vault service fixture serves.
const VaultTenant = vaultservice.Tenant

// NewVaultService builds an in-process vault service fixture.
var NewVaultService = vaultservice.New

// NewBarrierRegistry returns a tenant barrier registry over an in-memory
// store, initialized with a test passphrase.
var NewBarrierRegistry = barriertest.NewRegistry

// NewPKCS11ModuleFactory creates a mock PKCS#11 module and its teardown func.
var NewPKCS11ModuleFactory = pkcs11test.NewModuleFactory

// NewPKCS11Suite constructs a PKCS#11 conformance test suite.
var NewPKCS11Suite = pkcs11test.NewSuite

// EnrollPlatformSRK enrolls the Platform SRK on a freshly provisioned
// simulator or swtpm. Provision creates only the TCG-standard keys, and xkms
// seals under the Platform SRK.
var EnrollPlatformSRK = tpm2test.EnrollPlatformSRK

// OutsideFIPS reports whether the test may use a non-approved algorithm; under
// fips140=only it reruns the test with fips140=off and returns false.
var OutsideFIPS = fipstest.OutsideFIPS

// OutsideFIPSAfterRefusal is OutsideFIPS after asserting err is the FIPS
// refusal (errors.Is want, or the module's own refusal when want is nil).
var OutsideFIPSAfterRefusal = fipstest.OutsideFIPSAfterRefusal
