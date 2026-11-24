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

package cmd

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"

	sshsdk "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// sshMTLSCommand is a command carrying the --server and TLS flags xkey ssh
// registers, with --server set and the given client credential flags.
func sshMTLSCommand(t *testing.T, server, cert, key string) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "ssh"}
	cmd.Flags().String("server", "", "")
	cmd.Flags().String(tlsCAFlagName, "", "")
	cmd.Flags().String(tlsCertFlagName, "", "")
	cmd.Flags().String(tlsKeyFlagName, "", "")
	for name, value := range map[string]string{"server": server, tlsCertFlagName: cert, tlsKeyFlagName: key} {
		if value == "" {
			continue
		}
		if err := cmd.Flags().Set(name, value); err != nil {
			t.Fatalf("set --%s: %v", name, err)
		}
	}
	return cmd
}

// TestSSHCmd_RegistersClientCertificateFlags pins the xkey ssh surface:
// --tls-cert and --tls-key are persistent, as --tls-ca is, so every verb
// inherits them.
func TestSSHCmd_RegistersClientCertificateFlags(t *testing.T) {
	for _, name := range []string{tlsCAFlagName, "tls-cert", "tls-key"} {
		if SSHCmd.PersistentFlags().Lookup(name) == nil {
			t.Fatalf("xkey ssh has no persistent --%s flag", name)
		}
	}
}

// TestSSHServerEndpoint_ClientCertificateFlags proves --tls-cert/--tls-key
// reach the endpoint the SDK client is built from, ahead of the
// XKMSD_TLS_CERT/XKMSD_TLS_KEY environment, which remains the fallback.
func TestSSHServerEndpoint_ClientCertificateFlags(t *testing.T) {
	withCLIHome(t)
	t.Setenv(envXKMSdToken, "test-token")
	t.Setenv(envXKMSdTLSCert, "/env/cert.pem")
	t.Setenv(envXKMSdTLSKey, "/env/key.pem")

	endpoint, remote, err := sshServerEndpoint(sshMTLSCommand(t, "grpcs://127.0.0.1:1", "/flag/cert.pem", "/flag/key.pem"))
	if err != nil || !remote {
		t.Fatalf("sshServerEndpoint: remote=%v err=%v", remote, err)
	}
	if endpoint.TLSCertFile != "/flag/cert.pem" || endpoint.TLSKeyFile != "/flag/key.pem" {
		t.Fatalf("flags: cert=%q key=%q, want the flag values", endpoint.TLSCertFile, endpoint.TLSKeyFile)
	}

	endpoint, _, err = sshServerEndpoint(sshMTLSCommand(t, "grpcs://127.0.0.1:1", "", ""))
	if err != nil {
		t.Fatalf("sshServerEndpoint: %v", err)
	}
	if endpoint.TLSCertFile != "/env/cert.pem" || endpoint.TLSKeyFile != "/env/key.pem" {
		t.Fatalf("env fallback: cert=%q key=%q, want the env values", endpoint.TLSCertFile, endpoint.TLSKeyFile)
	}
}

// TestSSHClient_ClientCertificateRefusals proves a half pair or an
// unreadable file refuses with a typed error while the client is built,
// before any connection (127.0.0.1:1 is never dialed).
func TestSSHClient_ClientCertificateRefusals(t *testing.T) {
	withCLIHome(t)
	t.Setenv(envXKMSdToken, "test-token")
	t.Setenv(envXKMSdTLSCert, "")
	t.Setenv(envXKMSdTLSKey, "")
	missing := filepath.Join(t.TempDir(), "missing.pem")

	cases := map[string]struct {
		cert, key string
		nilInput  bool
	}{
		"key without cert": {key: missing, nilInput: true},
		"cert without key": {cert: missing, nilInput: true},
		"unreadable pair":  {cert: missing, key: missing},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := sshClient(sshMTLSCommand(t, "grpcs://127.0.0.1:1", tc.cert, tc.key))
			if !errors.Is(err, ErrSSHClientConstruct) {
				t.Fatalf("got %v, want ErrSSHClientConstruct", err)
			}
			var nilErr *sshsdk.NilInputError
			var protoErr *sshsdk.ProtocolError
			if tc.nilInput && !errors.As(err, &nilErr) {
				t.Fatalf("got %v, want *NilInputError", err)
			}
			if !tc.nilInput && !errors.As(err, &protoErr) {
				t.Fatalf("got %v, want *ProtocolError", err)
			}
		})
	}
}
