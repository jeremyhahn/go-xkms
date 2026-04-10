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

//go:build !vault

package server

import (
	"log/slog"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func createVaultBackend(config BackendConfig) (types.KeyProvider, error) {
	slog.Warn("Vault backend not compiled in (use -tags vault)")
	return nil, &ErrNotCompiledIn{Backend: "vault", Tag: "vault"}
}
