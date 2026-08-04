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

package sshlocal

// ConfigLoadError wraps a failure loading the operator's OpenSSH client
// configuration (~/.ssh/config, /etc/ssh/ssh_config). A missing file is not
// an error (see sshclient.LoadLocalSSHConfig) — this is reserved for a file
// that exists but cannot be parsed.
type ConfigLoadError struct {
	Err error
}

// Error implements the error interface.
func (e *ConfigLoadError) Error() string {
	return "sshlocal: load ssh_config: " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *ConfigLoadError) Unwrap() error { return e.Err }

// IdentityDiscoveryError wraps an unexpected failure while enumerating
// candidate identity files under ~/.ssh (see
// sshclient.DiscoverLocalIdentities — a missing file is never an error).
type IdentityDiscoveryError struct {
	Err error
}

// Error implements the error interface.
func (e *IdentityDiscoveryError) Error() string {
	return "sshlocal: discover identities: " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *IdentityDiscoveryError) Unwrap() error { return e.Err }
