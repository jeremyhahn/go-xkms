// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package connect

// InputError indicates a required Request field was empty.
type InputError struct {
	Field string
}

func (e *InputError) Error() string { return "ssh/connect: missing required field: " + e.Field }

// LaunchError wraps a failure setting up the connection (agent, known_hosts).
type LaunchError struct {
	Op  string
	Err error
}

func (e *LaunchError) Error() string { return "ssh/connect: " + e.Op + ": " + e.Err.Error() }
func (e *LaunchError) Unwrap() error { return e.Err }
