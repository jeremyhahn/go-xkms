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

package xkms

import (
	"github.com/jeremyhahn/go-xkms/pkg/pkcs11strategy"
	"github.com/jeremyhahn/go-xkms/pkg/preseal"
)

// Pre-barrier secrets and the PKCS#11 barrier strategy, re-exported so xkey
// seals and releases its token PIN, and builds its pkcs11 barrier strategy,
// through the same code xkmsd's node seal uses.

// PresealStore holds secrets needed before any barrier is unsealed (the
// PKCS#11 token PIN), sealed under the TPM's platform SRK and platform PCR
// policy.
type PresealStore = preseal.Store

// PresealTPM is the TPM surface a PresealStore seals under.
type PresealTPM = preseal.TPM

// OpenPreseal opens the pre-barrier secret store kept in dir, sealed under
// tpm.
var OpenPreseal = preseal.Open

// PresealPKCS11PIN names the PKCS#11 token user PIN in a PresealStore.
const PresealPKCS11PIN = preseal.PKCS11PIN

// Pre-barrier secret store errors.
type (
	// PresealNotFoundError reports that no secret is sealed under the name.
	PresealNotFoundError = preseal.NotFoundError

	// PresealRefusedError reports that the TPM refused to unseal the secret:
	// the platform PCR policy no longer matches.
	PresealRefusedError = preseal.RefusedError
)

// PKCS11StrategyBuildError reports which step of building a PKCS#11 barrier
// strategy failed.
type PKCS11StrategyBuildError = pkcs11strategy.BuildError

// BuildPKCS11StrategyWithSealedPIN releases the token PIN sealed in a
// PresealStore, logs in to the token and returns the PKCS#11 sealing
// strategy plus the closer that logs out. xkmsd's node seal builds its
// strategy through the same function.
var BuildPKCS11StrategyWithSealedPIN = pkcs11strategy.BuildWithSealedPIN

// ErrPKCS11StrategyNotCompiledIn is returned by
// BuildPKCS11StrategyWithSealedPIN in a build without the pkcs11 tag.
var ErrPKCS11StrategyNotCompiledIn = pkcs11strategy.ErrNotCompiledIn
