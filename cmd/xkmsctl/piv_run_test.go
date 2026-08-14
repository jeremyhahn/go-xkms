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

// piv_run_test.go exercises the "xkmsctl piv" command tree's Run closures
// (list, get, store, delete, generate, import, export, csr), which read
// flags/args/files before delegating to the already-tested named functions.
// mockPIVClient (defined in piv_test.go) provides the client.Client surface.
package main

import (
	"path/filepath"
	"testing"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

func newPIVRunConfig(mock *mockPIVClient) *Config {
	return &Config{
		OutputFormat: "text",
		Backend:      "software",
		ClientFactory: func(*Config) (client.Client, error) {
			return mock, nil
		},
	}
}

func TestPIVListCmd_Run(t *testing.T) {
	mock := &mockPIVClient{listSlotsResp: &transport.ListPIVSlotsResponse{}}
	withGlobalConfig(t, newPIVRunConfig(mock))
	captureStdout(t, func() {
		pivListCmd.Run(pivListCmd, nil)
	})
}

func TestPIVGetCmd_Run(t *testing.T) {
	mock := &mockPIVClient{getCertResp: &transport.GetPIVCertificateResponse{Slot: "9a", Certificate: []byte("cert-bytes")}}
	withGlobalConfig(t, newPIVRunConfig(mock))
	cmd := pivGetCmd
	_ = cmd.Flags().Set("format", "")
	captureStdout(t, func() {
		cmd.Run(cmd, []string{"9a"})
	})
}

func TestPIVStoreCmd_MissingCertFile(t *testing.T) {
	withGlobalConfig(t, newPIVRunConfig(&mockPIVClient{}))
	cmd := pivStoreCmd
	_ = cmd.Flags().Set("cert-file", "")
	code := captureExit(t, func() {
		cmd.Run(cmd, []string{"9a"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestPIVStoreCmd_CertFileNotFound(t *testing.T) {
	withGlobalConfig(t, newPIVRunConfig(&mockPIVClient{}))
	cmd := pivStoreCmd
	_ = cmd.Flags().Set("cert-file", "/nonexistent/cert.pem")
	t.Cleanup(func() { _ = cmd.Flags().Set("cert-file", "") })
	code := captureExit(t, func() {
		cmd.Run(cmd, []string{"9a"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestPIVStoreCmd_Success(t *testing.T) {
	mock := &mockPIVClient{}
	withGlobalConfig(t, newPIVRunConfig(mock))
	p := writeCertFile(t, "piv-store")
	cmd := pivStoreCmd
	_ = cmd.Flags().Set("cert-file", p)
	_ = cmd.Flags().Set("format", "pem")
	t.Cleanup(func() {
		_ = cmd.Flags().Set("cert-file", "")
		_ = cmd.Flags().Set("format", "")
	})

	captureStdout(t, func() {
		cmd.Run(cmd, []string{"9a"})
	})
}

func TestPIVDeleteCmd_Run(t *testing.T) {
	mock := &mockPIVClient{}
	withGlobalConfig(t, newPIVRunConfig(mock))
	captureStdout(t, func() {
		pivDeleteCmd.Run(pivDeleteCmd, []string{"9a"})
	})
}

func TestPIVGenerateCmd_Run(t *testing.T) {
	mock := &mockPIVClient{generateKeyResp: &transport.GeneratePIVKeyResponse{
		Slot: "9a", Certificate: []byte("cert-bytes"), PublicKey: []byte("pub-bytes"),
	}}
	withGlobalConfig(t, newPIVRunConfig(mock))
	cmd := pivGenerateCmd
	_ = cmd.Flags().Set("algorithm", "ecdsap256")
	_ = cmd.Flags().Set("subject", "CN=piv-test")
	t.Cleanup(func() {
		_ = cmd.Flags().Set("algorithm", "")
		_ = cmd.Flags().Set("subject", "")
	})

	captureStdout(t, func() {
		cmd.Run(cmd, []string{"9a"})
	})
}

func TestPIVImportCmd_MissingCertFile(t *testing.T) {
	withGlobalConfig(t, newPIVRunConfig(&mockPIVClient{}))
	cmd := pivImportCmd
	_ = cmd.Flags().Set("cert-file", "")
	code := captureExit(t, func() {
		cmd.Run(cmd, []string{"9a"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestPIVImportCmd_CertFileNotFound(t *testing.T) {
	withGlobalConfig(t, newPIVRunConfig(&mockPIVClient{}))
	cmd := pivImportCmd
	_ = cmd.Flags().Set("cert-file", "/nonexistent/cert.pem")
	t.Cleanup(func() { _ = cmd.Flags().Set("cert-file", "") })
	code := captureExit(t, func() {
		cmd.Run(cmd, []string{"9a"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestPIVImportCmd_Success(t *testing.T) {
	mock := &mockPIVClient{}
	withGlobalConfig(t, newPIVRunConfig(mock))
	p := writeCertFile(t, "piv-import")
	cmd := pivImportCmd
	_ = cmd.Flags().Set("cert-file", p)
	t.Cleanup(func() { _ = cmd.Flags().Set("cert-file", "") })

	captureStdout(t, func() {
		cmd.Run(cmd, []string{"9a"})
	})
}

func TestPIVExportCmd_Run(t *testing.T) {
	mock := &mockPIVClient{exportCertResp: &transport.GetPIVCertificateResponse{Slot: "9a", Certificate: []byte("cert-bytes")}}
	withGlobalConfig(t, newPIVRunConfig(mock))
	cmd := pivExportCmd
	_ = cmd.Flags().Set("format", "")

	out := filepath.Join(t.TempDir(), "exported.pem")
	_ = out
	captureStdout(t, func() {
		cmd.Run(cmd, []string{"9a"})
	})
}

func TestPIVCSRCmd_Run(t *testing.T) {
	mock := &mockPIVClient{generateCSRResp: &transport.GeneratePIVCSRResponse{Slot: "9a", CSR: []byte("csr-bytes")}}
	withGlobalConfig(t, newPIVRunConfig(mock))
	cmd := pivCSRCmd
	_ = cmd.Flags().Set("subject", "CN=piv-csr-test")
	t.Cleanup(func() { _ = cmd.Flags().Set("subject", "") })

	captureStdout(t, func() {
		cmd.Run(cmd, []string{"9a"})
	})
}

func TestPIVCmd_ClientErrors(t *testing.T) {
	errCfg := newUserErrorConfig("text")
	tests := []struct {
		name string
		run  func()
	}{
		{"list", func() { pivListCmd.Run(pivListCmd, nil) }},
		{"get", func() { pivGetCmd.Run(pivGetCmd, []string{"9a"}) }},
		{"delete", func() { pivDeleteCmd.Run(pivDeleteCmd, []string{"9a"}) }},
		{"generate", func() { pivGenerateCmd.Run(pivGenerateCmd, []string{"9a"}) }},
		{"export", func() { pivExportCmd.Run(pivExportCmd, []string{"9a"}) }},
		{"csr", func() { pivCSRCmd.Run(pivCSRCmd, []string{"9a"}) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withGlobalConfig(t, errCfg)
			code := captureExit(t, tc.run)
			if code != 1 {
				t.Errorf("expected exit code 1, got %d", code)
			}
		})
	}
}
