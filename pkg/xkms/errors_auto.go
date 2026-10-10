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

package xkms

import (
	"errors"
	"fmt"
)

var (
	// ErrFeatureNotCompiled is the sentinel every FeatureNotCompiledError
	// matches with errors.Is.
	ErrFeatureNotCompiled = errors.New("xkms: feature not compiled into this binary")

	// ErrBackendStorageUnresolved is the sentinel every BackendStorageError
	// matches with errors.Is.
	ErrBackendStorageUnresolved = errors.New("xkms: backend key storage could not be resolved")
)

// FeatureNotCompiledError reports a configuration that names a backend this
// binary was built without. Toggle is the Makefile WITH_* variable and Tag
// the build tag that compile the backend in; both are empty for a backend no
// build option registers.
type FeatureNotCompiledError struct {
	Feature string
	Toggle  string
	Tag     string
}

// Error names the missing feature and, when one exists, the toggle that
// compiles it in.
func (e *FeatureNotCompiledError) Error() string {
	if e.Toggle == "" {
		return fmt.Sprintf("xkms: backend %q is not compiled into this binary", e.Feature)
	}
	return fmt.Sprintf("xkms: backend %q is not compiled into this binary; build with %s=1 (build tag %q)",
		e.Feature, e.Toggle, e.Tag)
}

// Unwrap returns ErrFeatureNotCompiled.
func (e *FeatureNotCompiledError) Unwrap() error {
	return ErrFeatureNotCompiled
}

// BackendStorageError reports that AutoInitialize could not derive a
// backend's key storage from the configured Datastore.
type BackendStorageError struct {
	Backend string
	Err     error
}

// Error names the backend and the cause.
func (e *BackendStorageError) Error() string {
	return fmt.Sprintf("xkms: resolving key storage for backend %q: %v", e.Backend, e.Err)
}

// Unwrap returns ErrBackendStorageUnresolved and the underlying cause, so
// errors.Is matches either.
func (e *BackendStorageError) Unwrap() []error {
	return []error{ErrBackendStorageUnresolved, e.Err}
}
