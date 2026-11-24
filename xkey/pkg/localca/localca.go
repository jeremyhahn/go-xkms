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

// Package localca opens xkey's local embedded Certificate Authority: the CA
// that `xkey ca --local` and the xkey GUI serve when no xkms server is
// connected.
package localca

import (
	"path/filepath"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// NewClient opens the local CA under dataDir/ca, loading the CA persisted
// there or initializing a new one. keyStorage optionally holds the CA
// private keys (for example a barrier-prefixed backend); nil keeps them in
// plain files under dataDir/ca, the layout of `xkey ca --local`. The CA runs
// on an isolated embedded service, so the process-wide key service
// singleton is left untouched.
func NewClient(dataDir string, keyStorage xkmssdk.StorageBackend) (xkmssdk.Client, error) {
	return xkmssdk.NewEmbeddedClient(xkmssdk.EmbeddedServiceConfig{
		KeyDir:     filepath.Join(dataDir, "ca"),
		KeyStorage: keyStorage,
		CA:         xkmssdk.DefaultMultiIdentityCAConfig(),
		Isolated:   true,
	})
}
