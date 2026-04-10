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

package xhome

import (
	"errors"
	"fmt"
)

// Sentinel errors for path resolution failures.
var (
	// ErrHomeNotResolved indicates that no valid xKey home directory
	// could be found via any resolution strategy.
	ErrHomeNotResolved = errors.New("xhome: could not resolve xKey home directory")

	// ErrRootNotDirectory indicates the resolved path exists but is
	// not a directory.
	ErrRootNotDirectory = errors.New("xhome: resolved path is not a directory")

	// ErrRootNotAccessible indicates the resolved directory cannot be
	// read by the current user.
	ErrRootNotAccessible = errors.New("xhome: resolved directory is not accessible")
)

// ResolveError provides context about a failed resolution attempt.
type ResolveError struct {
	Strategy string // Which strategy failed (env, binary, user, system)
	Path     string // The path that was attempted
	Err      error  // Underlying error
}

// Error returns the formatted error message.
func (e *ResolveError) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("xhome: %s resolution failed for %s: %v", e.Strategy, e.Path, e.Err)
	}
	return fmt.Sprintf("xhome: %s resolution failed: %v", e.Strategy, e.Err)
}

// Unwrap returns the underlying error.
func (e *ResolveError) Unwrap() error {
	return e.Err
}
