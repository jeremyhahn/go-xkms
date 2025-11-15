// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build !tpm2

package rand

import "fmt"

// newTPM2Resolver is a stub when TPM2 support is not compiled.
func newTPM2Resolver(config *TPM2Config) (Resolver, error) {
	return nil, fmt.Errorf("TPM2 support not compiled")
}

// tpm2Available returns false when TPM2 is not available.
func tpm2Available() bool {
	return false
}
