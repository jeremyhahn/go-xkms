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

package sshstore

// MissingDataDirError is returned by ResolveBackend when no barrier backend
// was supplied and dataDir is empty, so no plain-engine root can be resolved.
type MissingDataDirError struct{}

// Error implements the error interface.
func (e *MissingDataDirError) Error() string {
	return "sshstore: dataDir is required when no barrier backend is supplied"
}
