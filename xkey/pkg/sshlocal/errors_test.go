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

import (
	"errors"
	"testing"
)

// TestConfigLoadError_ErrorAndUnwrap verifies the message format and that
// Unwrap returns exactly the wrapped cause for errors.Is/errors.As chains.
func TestConfigLoadError_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("malformed ssh_config")
	err := &ConfigLoadError{Err: cause}

	want := "sshlocal: load ssh_config: malformed ssh_config"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if got := errors.Unwrap(err); got != cause {
		t.Errorf("Unwrap() = %v, want %v", got, cause)
	}
	if !errors.Is(err, cause) {
		t.Errorf("errors.Is(err, cause) = false, want true")
	}
}

// TestIdentityDiscoveryError_ErrorAndUnwrap verifies the message format and
// that Unwrap returns exactly the wrapped cause.
func TestIdentityDiscoveryError_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("too many levels of symbolic links")
	err := &IdentityDiscoveryError{Err: cause}

	want := "sshlocal: discover identities: too many levels of symbolic links"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if got := errors.Unwrap(err); got != cause {
		t.Errorf("Unwrap() = %v, want %v", got, cause)
	}
	if !errors.Is(err, cause) {
		t.Errorf("errors.Is(err, cause) = false, want true")
	}
}
