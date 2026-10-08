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

// Package secrettest builds secret values for tests.
package secrettest

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Literal seals value into a SecretValue (types.NewLiteralSecretValue),
// failing the test when it cannot be sealed.
// Literal seals value into a SecretValue (types.NewLiteralSecretValue),
// failing the test when it cannot be sealed. The value is cleared when the
// test ends, releasing its locked memory: a package that seals a secret per
// test would otherwise exhaust RLIMIT_MEMLOCK before its run completes.
// Literal seals value into a SecretValue (types.NewLiteralSecretValue),
// failing the test when it cannot be sealed.
func Literal(t testing.TB, value []byte) *types.SecretValue {
	t.Helper()
	sv, err := types.NewLiteralSecretValue(t.Context(), value)
	if err != nil {
		t.Fatalf("secrettest: seal a literal secret: %v", err)
	}
	return sv
}
