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

package main

// ConfigError is returned for desktop configuration/storage failures.
type ConfigError struct {
	Reason string
	Err    error
}

// Error implements the error interface.
func (e *ConfigError) Error() string {
	msg := "xkms-desktop: " + e.Reason
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

// Unwrap returns the underlying error.
func (e *ConfigError) Unwrap() error { return e.Err }

// GUIUnavailableError is returned when a binary built without the "desktop"
// tag is asked to launch the GUI.
type GUIUnavailableError struct{}

// Error implements the error interface.
func (e *GUIUnavailableError) Error() string {
	return "xkms-desktop: GUI support not compiled; rebuild with -tags desktop"
}
