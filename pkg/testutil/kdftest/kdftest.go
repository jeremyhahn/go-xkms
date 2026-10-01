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

// Package kdftest holds CheapPassphraseParams, the Argon2id cost every
// package that builds a staticpw.TenantPasswordStoreManager in tests passes
// to staticpw.WithPassphraseKDFParams. It imports only pkg/crypto/kdf, a
// leaf package, so it carries none of staticpw's dependencies (down through
// pkg/seal to the transports) into packages, such as pkg/api/transport/quic,
// whose tests would otherwise form an import cycle through it.
package kdftest

import "github.com/jeremyhahn/go-xkms/pkg/crypto/kdf"

// CheapPassphraseParams returns an Argon2id cost cheap enough for tests that
// enroll or unlock a passphrase vault factor many times: the production
// cost (kdf.DefaultParams: 64 MiB, t=3, p=4) is expensive enough that many
// passphrase derivations, run in parallel across a package's tests, exhaust
// a CI worker's memory. The derivation is otherwise the production code
// path: the cost is recorded on the factor exactly as a real deployment's
// choice would be.
func CheapPassphraseParams() *kdf.KDFParams {
	return &kdf.KDFParams{Algorithm: kdf.AlgorithmArgon2id, Memory: 64, Time: 1, Threads: 1, KeyLength: 32}
}
