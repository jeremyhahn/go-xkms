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

package software

import (
	"crypto/x509"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// algorithmFamily names one of the mutually exclusive algorithm families a
// types.KeyAttributes may declare. The families and their order are taken from
// types.KeyAttributes.ID, which is what decides a key's storage identity.
type algorithmFamily string

const (
	familyX25519     algorithmFamily = "x25519"
	familyQuantum    algorithmFamily = "quantum"
	familyAsymmetric algorithmFamily = "asymmetric"
	familySymmetric  algorithmFamily = "symmetric"
)

// declaredAlgorithmFamilies reports every algorithm family attrs declares, in
// the precedence order types.KeyAttributes.ID uses to resolve them.
//
// A nil attrs declares nothing. So does a zero-valued one -- see
// requireSingleAlgorithmFamily for why that is deliberately not an error.
func declaredAlgorithmFamilies(attrs *types.KeyAttributes) []algorithmFamily {
	if attrs == nil {
		return nil
	}

	var families []algorithmFamily
	if attrs.X25519Attributes != nil {
		families = append(families, familyX25519)
	}
	if attrs.QuantumAttributes != nil {
		families = append(families, familyQuantum)
	}
	if attrs.KeyAlgorithm != x509.UnknownPublicKeyAlgorithm {
		families = append(families, familyAsymmetric)
	}
	if attrs.SymmetricAlgorithm != "" {
		families = append(families, familySymmetric)
	}
	return families
}

// requireSingleAlgorithmFamily refuses attributes that declare more than one
// algorithm family.
//
// # Why this backend needs the check and the others do not
//
// SoftwareBackend is the only backend that ROUTES on the family: DeleteKey,
// RotateKey, ImportKey, ExportKey and ExportKeyMaterial each pick a sub-backend
// by asking attrs.IsSymmetric() (or attrs.QuantumAttributes), and pkcs8Backend,
// symmetricBackend and quantumBackend all share one storage namespace --
// storage.KeyPath is a single flat "keys/{id}.key", with no per-sub-backend
// prefix. Every other backend uses IsSymmetric only as a fail-closed guard on a
// symmetric-only method, never as a fan-out.
//
// That routing reads a DIFFERENT field from the one that decides the key's
// identity. IsSymmetric consults SymmetricAlgorithm alone, while
// KeyAttributes.ID resolves X25519Attributes, then QuantumAttributes, then
// KeyAlgorithm, then SymmetricAlgorithm. So attributes naming two families are
// processed as one kind of key and addressed as another, and
// KeyAttributes.Validate does not object because it walks the same precedence
// as ID and stops at the first family it finds.
//
// Measured consequence, pinned by the regression tests in
// family_gate_regression_test.go: attributes carrying KeyAlgorithm=RSA with
// valid RSAAttributes AND SymmetricAlgorithm=aes256-gcm route to the symmetric
// backend, which then deletes -- or, through RotateKey, overwrites -- the RSA
// private key at the identifier ID() built from KeyAlgorithm. Both reported
// success while doing it.
//
// # Zero families is PERMITTED, deliberately
//
// This refuses only the plural case. An earlier attempt at this check
// (go-xkms PR #63, closed unmerged in favour of #247) refused attributes naming
// ZERO families as well, which made the MCP import tool unsatisfiable by any
// request shape -- the handler built attributes carrying little more than a
// common name, so every call failed with "must describe exactly one algorithm
// family but name []". A check a legitimate producer structurally cannot
// satisfy rejects working paths instead of catching wrong ones, which is the
// same reason validateKeyType does not compare the declared curve.
//
// Nothing here needs the zero case: attributes declaring no family resolve to
// the "unknown" identifier, which addresses no key that any producer writes.
func requireSingleAlgorithmFamily(attrs *types.KeyAttributes) error {
	families := declaredAlgorithmFamilies(attrs)
	if len(families) < 2 {
		return nil
	}

	names := make([]string, 0, len(families))
	for _, f := range families {
		names = append(names, string(f))
	}

	return &errs.Joined{
		Lead:   ErrContradictoryAlgorithmFamilies,
		Detail: strings.Join(names, " and "),
		Cause:  backend.ErrInvalidAttributes,
	}
}
