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

package local_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/local"
)

func TestNilInputError(t *testing.T) {
	e := &local.NilInputError{Field: "identity"}
	if !strings.Contains(e.Error(), "identity") {
		t.Errorf("Error() missing field: %q", e.Error())
	}
}

func TestConfigParseError(t *testing.T) {
	inner := errors.New("boom")
	e := &local.ConfigParseError{Path: "/etc/ssh/ssh_config", Err: inner}
	if !strings.Contains(e.Error(), "/etc/ssh/ssh_config") {
		t.Errorf("Error() missing path: %q", e.Error())
	}
	if !errors.Is(e, inner) {
		t.Error("Unwrap did not expose the inner error")
	}
}

func TestAgentUnavailableError(t *testing.T) {
	inner := errors.New("connection refused")
	e := &local.AgentUnavailableError{Path: "/tmp/agent.sock", Err: inner}
	if !strings.Contains(e.Error(), "/tmp/agent.sock") {
		t.Errorf("Error() missing path: %q", e.Error())
	}
	if !errors.Is(e, inner) {
		t.Error("Unwrap did not expose the inner error")
	}
}

func TestAgentKeyNotFoundError(t *testing.T) {
	e := &local.AgentKeyNotFoundError{Fingerprint: "SHA256:abc123"}
	if !strings.Contains(e.Error(), "SHA256:abc123") {
		t.Errorf("Error() missing fingerprint: %q", e.Error())
	}
}

func TestIdentityReadError(t *testing.T) {
	inner := errors.New("permission denied")
	e := &local.IdentityReadError{Path: "/home/alice/.ssh/id_rsa", Err: inner}
	if !strings.Contains(e.Error(), "/home/alice/.ssh/id_rsa") {
		t.Errorf("Error() missing path: %q", e.Error())
	}
	if !errors.Is(e, inner) {
		t.Error("Unwrap did not expose the inner error")
	}
}

func TestHostNotConfiguredError(t *testing.T) {
	e := &local.HostNotConfiguredError{Alias: "example.com"}
	if !strings.Contains(e.Error(), "example.com") {
		t.Errorf("Error() missing alias: %q", e.Error())
	}
}
