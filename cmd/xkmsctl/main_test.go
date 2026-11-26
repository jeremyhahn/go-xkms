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
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/stretchr/testify/assert"
)

func TestRun_PrintsCommandError(t *testing.T) {
	rootCmd.SetArgs([]string{"key", "copy", "src", "dst", "--no-such-flag"})
	t.Cleanup(func() { rootCmd.SetArgs([]string{}) })

	var stderr bytes.Buffer
	code := run(&stderr)

	assert.Equal(t, 1, code)
	assert.Contains(t, stderr.String(), "unknown flag: --no-such-flag")
}

// TestMain opts the package's tests out of the mandatory-TLS guard: they
// build plaintext clients for the loopback defaults, the one use the
// opt-out exists for (ruling 152).
func TestMain(m *testing.M) {
	if err := os.Setenv(transport.EnvAllowInsecureTransport, "true"); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

func TestConfig_CreateClientRefusesPlaintextWithoutOptOut(t *testing.T) {
	t.Setenv(transport.EnvAllowInsecureTransport, "")

	for _, protocol := range []string{"grpc", "rest"} {
		t.Run(protocol, func(t *testing.T) {
			cfg := NewConfig()
			cfg.Protocol = protocol

			if _, err := cfg.CreateClient(); !errors.Is(err, transport.ErrInsecureTransport) {
				t.Fatalf("CreateClient(%s) error = %v, want ErrInsecureTransport", protocol, err)
			}
		})
	}
}
