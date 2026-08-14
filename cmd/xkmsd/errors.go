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

package main

import (
	"errors"
	"fmt"
)

// Sentinel errors for configuration reload and PID file handling.
var (
	// ErrConfigLoad is returned when the configuration file cannot be loaded.
	ErrConfigLoad = errors.New("failed to load configuration")

	// ErrConfigApply is returned when the server rejects a reloaded configuration.
	ErrConfigApply = errors.New("failed to apply configuration")

	// ErrPIDDirCreate is returned when the PID file directory cannot be created.
	ErrPIDDirCreate = errors.New("failed to create PID file directory")

	// ErrPIDFileWrite is returned when the PID file cannot be written.
	ErrPIDFileWrite = errors.New("failed to write PID file")
)

// WrappedError pairs a sentinel error with an underlying cause, rendering
// as "<sentinel>: <cause>". It exposes both errors to errors.Is/errors.As
// via Go 1.20+ multi-error unwrapping.
type WrappedError struct {
	// Sentinel is the classifying sentinel error.
	Sentinel error
	// Err is the underlying cause.
	Err error
}

// Error returns a human-readable description.
func (e *WrappedError) Error() string {
	return e.Sentinel.Error() + ": " + e.Err.Error()
}

// Unwrap returns both the sentinel and the underlying cause.
func (e *WrappedError) Unwrap() []error {
	return []error{e.Sentinel, e.Err}
}

// WrappedDetailError pairs a sentinel error with a contextual detail string
// and an optional underlying cause, rendering as "<sentinel>: <detail>" or
// "<sentinel>: <detail>: <cause>".
type WrappedDetailError struct {
	// Sentinel is the classifying sentinel error.
	Sentinel error
	// Detail is the contextual detail (for example a file path).
	Detail string
	// Err is the optional underlying cause.
	Err error
}

// Error returns a human-readable description.
func (e *WrappedDetailError) Error() string {
	msg := e.Sentinel.Error() + ": " + e.Detail
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

// Unwrap returns the sentinel and, when present, the underlying cause.
func (e *WrappedDetailError) Unwrap() []error {
	if e.Err != nil {
		return []error{e.Sentinel, e.Err}
	}
	return []error{e.Sentinel}
}

// InsecureReloadError is returned when a configuration reload is refused
// because the new configuration has compliance gaps. The refusal is
// unconditional: there is no development override.
type InsecureReloadError struct {
	// Gaps lists the compliance gaps detected in the new configuration.
	Gaps []string
}

// Error returns a human-readable description.
func (e *InsecureReloadError) Error() string {
	return fmt.Sprintf("refusing to reload an insecure configuration "+
		"(FedRAMP/PCI-DSS/HIPAA require encryption-at-rest, TLS, authentication, and a CA; "+
		"enable the reported settings or run `xkmsd init`): %v", e.Gaps)
}
