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
	"testing"

	"github.com/spf13/cobra"
)

func TestResolveWebAuthnOrigin(t *testing.T) {
	tests := []struct {
		name    string
		flag    string
		server  string
		want    string
		wantErr error
	}{
		{"flag wins over server", "https://kms.example.com", "https://other.example.com:8443", "https://kms.example.com", nil},
		{"derived from https server", "", "https://kms.example.com:8443/api", "https://kms.example.com:8443", nil},
		{"derived from http server", "", "http://localhost:8080", "http://localhost:8080", nil},
		{"default unix socket has no origin", "", "", "", ErrWebAuthnOriginRequired},
		{"unix socket URL has no origin", "", "unix:///run/xkms.sock", "", ErrWebAuthnOriginRequired},
		{"grpc server has no origin", "", "grpcs://kms.example.com:9443", "", ErrWebAuthnOriginRequired},
		{"quic server has no origin", "", "quic://kms.example.com:8443", "", ErrWebAuthnOriginRequired},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := &cobra.Command{Use: "login"}
			addOriginFlag(cmd)
			if tc.flag != "" {
				if err := cmd.Flags().Set(originFlag, tc.flag); err != nil {
					t.Fatalf("set --%s: %v", originFlag, err)
				}
			}
			got, err := resolveWebAuthnOrigin(cmd, tc.server)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("origin = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestResolveWebAuthnOrigin_MissingFlagIsReported proves a verb wired without
// addOriginFlag reports the wiring defect rather than silently resolving no
// origin.
func TestResolveWebAuthnOrigin_MissingFlagIsReported(t *testing.T) {
	var flagErr *FlagReadError
	if _, err := resolveWebAuthnOrigin(&cobra.Command{Use: "login"}, "https://kms.example.com"); !errors.As(err, &flagErr) {
		t.Fatalf("error = %v, want *FlagReadError", err)
	}
}

// TestCeremonyVerbsDeclareOrigin proves every xkmsctl WebAuthn ceremony verb
// exposes --origin, the only way to name the origin over a non-http transport.
func TestCeremonyVerbsDeclareOrigin(t *testing.T) {
	for _, cmd := range []*cobra.Command{userRegisterCmd, userLoginCmd, adminCreateCmd} {
		if cmd.Flags().Lookup(originFlag) == nil {
			t.Errorf("%s does not declare --%s", cmd.CommandPath(), originFlag)
		}
	}
}
