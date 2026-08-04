// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package keys

import (
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// Algorithm identifies the public-key cryptosystem of a Key. The string
// values are the canonical identifiers used by Generate and surfaced in
// the stored envelope; they MUST NOT change without a storage
// migration.
type Algorithm string

// Canonical algorithm identifiers. The ECDSA variants encode the curve
// so callers don't need a second attribute to interpret them.
const (
	// AlgorithmEd25519 is EdDSA over Curve25519.
	AlgorithmEd25519 Algorithm = "ed25519"

	// AlgorithmRSA is RSA of the size supplied at generation (minimum 2048).
	AlgorithmRSA Algorithm = "rsa"

	// AlgorithmECDSAP256 is ECDSA over the NIST P-256 curve.
	AlgorithmECDSAP256 Algorithm = "ecdsa-p256"

	// AlgorithmECDSAP384 is ECDSA over the NIST P-384 curve.
	AlgorithmECDSAP384 Algorithm = "ecdsa-p384"

	// AlgorithmECDSAP521 is ECDSA over the NIST P-521 curve.
	AlgorithmECDSAP521 Algorithm = "ecdsa-p521"
)

// String returns the canonical algorithm name.
func (a Algorithm) String() string { return string(a) }

// supported reports whether a is one of the canonical algorithms the
// package can generate and sign.
func (a Algorithm) supported() bool {
	switch a {
	case AlgorithmEd25519, AlgorithmRSA, AlgorithmECDSAP256, AlgorithmECDSAP384, AlgorithmECDSAP521:
		return true
	default:
		return false
	}
}

// Key bundles the in-memory representation of an SSH key.
//
// Material holds the PEM-encoded private key sealed inside a
// secure.Secret — it is never on the Go heap in plaintext except inside
// a Buffer returned by Material.Open() and destroyed before the next
// allocation. PublicKey, Algorithm, Fingerprint, Scope, Owner, Name,
// CreatedAt, and Comment are non-sensitive metadata held in ordinary
// fields.
//
// Callers MUST call Destroy() when finished with a Key (typically via
// defer immediately after construction). Destroy is idempotent and safe
// on a nil receiver.
type Key struct {
	// Material is the encrypted-at-rest PEM (private key). nil for
	// public-only Key values produced by exporters.
	Material *secure.Secret

	// PublicKey is the parsed ssh.PublicKey. Non-sensitive — SSH public
	// keys are, by design, safe to expose.
	PublicKey ssh.PublicKey

	// Algorithm identifies the cryptosystem (see the Algorithm
	// constants).
	Algorithm Algorithm

	// Fingerprint is the OpenSSH SHA256 fingerprint ("SHA256:..."). It
	// is a deterministic hash of PublicKey and may be computed on demand
	// via the package-level Fingerprint() helper.
	Fingerprint string

	// Scope is the ownership scope (tenant / user / service) — see
	// pkg/ssh/scope.
	Scope scope.Scope

	// Owner is the scope-specific identifier (tenant ID, user ID, or
	// service ID). Non-sensitive.
	Owner string

	// Name is the human-visible key name, unique within (Scope, Owner).
	Name string

	// CreatedAt is the wall-clock time at which the key was generated
	// or imported.
	CreatedAt time.Time

	// Comment is the optional free-form comment stored with the public
	// key (OpenSSH emits it in authorized_keys lines). Never contains
	// sensitive material by convention.
	Comment string

	// BackendID identifies the crypto backend (e.g. "software", "tpm2",
	// "pkcs11", a cloud KMS, or a remote xkms backend) that holds the
	// private half of a backend-backed key. Empty for software keys whose
	// PEM lives in Material. When set, Material is nil and signing is
	// delegated to the backend via BackendSigner.
	BackendID string

	// BackendKeyID is the backend-scoped identifier (the key's CN) used to
	// resolve the crypto.Signer for a backend-backed key. Only meaningful
	// when BackendID is non-empty.
	BackendKeyID string
}

// IsBackendBacked reports whether the key's private half lives in an
// external crypto backend (TPM2 / PKCS#11 / cloud KMS / remote xkms)
// rather than in a sealed software PEM. Backend-backed keys carry no
// Material and delegate signing to the backend.
func (k *Key) IsBackendBacked() bool {
	return k != nil && k.BackendID != ""
}

// ID returns the canonical storage identifier for this key, computed
// from Scope/Owner/Name via scope.BuildKeyID. Returns an empty string on
// any validation failure — callers who need the error use
// scope.BuildKeyID directly.
func (k *Key) ID() string {
	if k == nil {
		return ""
	}
	id, err := scope.BuildKeyID(k.Scope, k.Owner, k.Name)
	if err != nil {
		return ""
	}
	return id
}

// Destroy wipes the underlying secure.Secret and releases its mlocked
// memory. Safe to call multiple times and on a nil receiver. Metadata
// fields are left untouched so diagnostic logs can still reference the
// key after destroy.
func (k *Key) Destroy() {
	if k == nil {
		return
	}
	if k.Material != nil {
		k.Material.Destroy()
		k.Material = nil
	}
}
