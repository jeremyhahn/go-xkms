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

package resolver

import (
	"os"
	"path/filepath"
)

// InstallToSystemTrust writes the PEM-encoded CA bundle to the given
// certificate path. The caller is responsible for running OS-specific
// trust store update commands (e.g., update-ca-certificates) afterward.
//
// The parent directory is created with mode 0755 if it does not exist.
// The file is written with mode 0644.
func InstallToSystemTrust(bundlePEM []byte, certPath string) error {
	if len(bundlePEM) == 0 {
		return ErrCABundleEmpty{}
	}

	dir := filepath.Dir(certPath)
	if err := os.MkdirAll(dir, 0755); err != nil { // #nosec G301 - system trust store directories must be world-readable
		return &ErrWriteFailed{Path: dir, Err: err}
	}

	if err := os.WriteFile(certPath, bundlePEM, 0644); err != nil { // #nosec G306 - system trust anchors must be world-readable
		return &ErrWriteFailed{Path: certPath, Err: err}
	}

	return nil
}
