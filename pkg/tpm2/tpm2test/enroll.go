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

// Package tpm2test provides shared TPM 2.0 simulator test-support helpers.
// It is a regular importable package rather than a *_test.go file, which is
// what lets it be shared across module boundaries (pkg/tpm2,
// pkg/backend/tpm2, pkg/trust/clusterca, test/integration/...); every
// _test.go file in Go is private to its own package and cannot be imported
// anywhere else. The package name signals its purpose the same way
// pkg/tpm2/mocks does: nothing outside a test should ever import it, and
// nothing in it does anything a production binary needs.
package tpm2test

import (
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
)

// EnrollPlatformSRK creates xkms's own Platform SRK on tpm if one does not
// already exist, using config's PlatformSRK/SSRK/EK sections exactly the way
// pkg/backend/tpm2.provisionSimulatorEKSRK provisions it on the simulator
// first-boot path. It is idempotent: if the Platform SRK is already present
// (TPM2.PlatformSRKAttributes resolves it), EnrollPlatformSRK returns nil
// without touching the TPM.
//
// TPM2.Provision (TCG-only: Endorsement Key + Shared SRK) never creates the
// Platform SRK. Every test that provisions a TPM and then goes on to seal,
// wrap, or otherwise exercise xkms's own TPM2 backend or Sealer must call
// this afterward: xkms's own sealing paths (pkg/backend/tpm2.Backend,
// pkg/tpm2.TPM2's Seal/Unseal) parent exclusively off the Platform SRK and
// refuse to fall back to the Shared SRK
// (pkg/backend/tpm2.resolveSRKAttributes,
// pkg/tpm2.defaultSealKeyAttributes/defaultUnsealKeyAttributes), so a TPM
// left at Provision's TCG-only state answers ErrInvalidPlatformSRKConfiguration
// or a bare TPM_RC_HANDLE for every one of those calls.
//
// This creates the Platform SRK with no password (an empty auth value),
// matching provisionSimulatorEKSRK: a test that specifically needs the
// operator-PIN-bound form exercised by production first-boot enrollment
// should use pkg/tpm2.PlatformKeyStore.Initialize/EnrollPlatformSRK
// directly instead, as pkg/tpm2's own simulator suite does.
func EnrollPlatformSRK(tpm pkgtpm2.TrustedPlatformModule, config *pkgtpm2.Config) error {
	if _, err := tpm.PlatformSRKAttributes(); err == nil {
		return nil
	}

	psrkAttrs, err := pkgtpm2.PlatformSRKAttributesFromConfig(config)
	if err != nil {
		return err
	}
	if ekAttrs, ekErr := tpm.EKAttributes(); ekErr == nil {
		psrkAttrs.Parent = ekAttrs
	}
	return tpm.CreateSRK(psrkAttrs)
}
