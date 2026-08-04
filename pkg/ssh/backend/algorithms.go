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

package backend

import (
	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// allSSHAlgorithms is the full set of SSH key algorithms buildAttrs knows how
// to translate into xkms key attributes.
var allSSHAlgorithms = []keys.Algorithm{
	keys.AlgorithmEd25519,
	keys.AlgorithmRSA,
	keys.AlgorithmECDSAP256,
	keys.AlgorithmECDSAP384,
	keys.AlgorithmECDSAP521,
}

// tpm2SSHAlgorithms is the subset of allSSHAlgorithms the TPM 2.0 backend can
// generate. TPM 2.0 has no native Ed25519 key object type — only
// TPM_ALG_RSA and TPM_ALG_ECC — so pkg/backend/tpm2.Backend.GenerateKey
// rejects any other KeyAlgorithm with tpm2.ErrUnsupportedKeyAlgorithm. See
// pkg/backend/tpm2/backend.go GenerateKey (the algorithm switch) and
// pkg/tpm2/ecdsa.go CreateECDSA (the supported curves: P-256/P-384/P-521).
var tpm2SSHAlgorithms = []keys.Algorithm{
	keys.AlgorithmRSA,
	keys.AlgorithmECDSAP256,
	keys.AlgorithmECDSAP384,
	keys.AlgorithmECDSAP521,
}

// SupportedAlgorithms returns the SSH key algorithms that can be generated on
// a backend of storeType, mirroring the KeyAlgorithm switch each xkms backend
// implements in its own GenerateKey method (pkg/backend/<type>/*.go). It is
// the single source of truth for algorithm compatibility so callers — the
// xkey GUI generate dialog, the CLI, and the SDK re-export in
// sdk/go/client/ssh — never duplicate or drift from this mapping.
//
// types.StoreSoftware, types.StorePKCS11, and types.StorePhone support the
// full algorithm set (Ed25519, RSA, ECDSA P-256/P-384/P-521). types.StoreTPM2
// is restricted to RSA and ECDSA (no Ed25519). Any other store type,
// including types.StoreUnknown (covers backend categories this package does
// not resolve to a store type, such as a remote xkms backend or the phone
// bridge category string), fails open to the full set: the backend itself
// remains authoritative and GenerateKey surfaces its own typed error when an
// algorithm is actually unsupported.
//
// The returned slice is a defensive copy; callers may freely mutate it.
func SupportedAlgorithms(storeType types.StoreType) []keys.Algorithm {
	switch storeType {
	case types.StoreTPM2:
		return append([]keys.Algorithm(nil), tpm2SSHAlgorithms...)
	default:
		return append([]keys.Algorithm(nil), allSSHAlgorithms...)
	}
}
