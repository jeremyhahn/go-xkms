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

package seal

import (
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// Compile-time interface check.
var _ SealingStrategy = (*SoftwareStrategy)(nil)

// SoftwareStrategy is go-quicraft's password-based sealing strategy, reached
// through the qrdb SDK. It is not xkms's to implement: xkms delegates the
// barrier and seal layer to go-qrdb wholesale and contributes only HARDWARE
// strategies (TPM2, PKCS#11, cloud KMS), each of which is a real
// implementation living beside this file.
//
// This was briefly a wrapper struct holding an inner strategy. The wrapper
// re-declared every method verbatim, and because it did not forward
// KDFVersion()/KDFParams() it hid the KDF accessors ChangePassword needs to
// carry a deployment's tuned work factor into the replacement — so every
// password change began failing when go-qrdb v0.18.0-alpha started requiring
// them. A wrapper that only forwards is a place for the two sides to drift.
type SoftwareStrategy = qrdbsdk.SoftwareStrategy

// NewSoftwareStrategy returns a passphrase strategy that binds its passphrase
// at each Seal/Unseal from Credentials.Secret rather than at construction.
//
// DEFERRED, not bound, and the distinction is load-bearing. qrdbsdk also
// exports NewSoftwareStrategy(passphrase []byte), which captures the
// passphrase once and thereafter IGNORES the credentials handed to
// UnsealRootKey — a wrong secret, the old secret and the right secret all
// unseal for the life of the process (go-qrdb#157). The two constructors
// differ in arity, so aliasing the wrong one fails to compile rather than
// failing silently.
var NewSoftwareStrategy = qrdbsdk.NewDeferredSoftwareStrategy
