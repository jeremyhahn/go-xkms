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

package tpm2

import (
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// mustPassword builds a types.Password test fixture. It panics if the
// enclave allocation fails — a hard system condition (RLIMIT_MEMLOCK
// exhausted, no swap) that test fixtures are not expected to hit — rather
// than silently falling back to an empty (passwordless) auth value. This
// mirrors the production contract enforced by store.NewPassword and
// types.NewPassword after the enclave-allocation fix: a non-empty input
// that fails to allocate must never become a usable empty Password.
func mustPassword(b []byte) types.Password {
	pw, err := store.NewPassword(b)
	if err != nil {
		panic(err)
	}
	return pw
}
