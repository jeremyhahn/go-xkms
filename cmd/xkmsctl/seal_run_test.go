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

// seal_run_test.go exercises the "xkmsctl seal/unseal/can-seal" command
// tree's Run closures, which read args/flags/files before delegating to the
// already-tested named functions (sealData, unsealData, canSeal).
package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

func newSealRunConfig(mock *mockSealClient) *Config {
	return &Config{
		OutputFormat: "json",
		Backend:      "software",
		ClientFactory: func(*Config) (client.Client, error) {
			return mock, nil
		},
	}
}

func resetSealFlags(t *testing.T) {
	t.Helper()
	_ = sealCmd.Flags().Set("key-id", "")
	_ = sealCmd.Flags().Set("data-file", "")
	_ = sealCmd.Flags().Set("aad", "")
}

func resetUnsealFlags(t *testing.T) {
	t.Helper()
	_ = unsealDataCmd.Flags().Set("key-id", "")
	_ = unsealDataCmd.Flags().Set("ciphertext", "")
	_ = unsealDataCmd.Flags().Set("ciphertext-file", "")
	_ = unsealDataCmd.Flags().Set("nonce", "")
	_ = unsealDataCmd.Flags().Set("tag", "")
	_ = unsealDataCmd.Flags().Set("aad", "")
}

func TestSealCmd_Run_FromArg(t *testing.T) {
	resetSealFlags(t)
	t.Cleanup(func() { resetSealFlags(t) })
	mock := &mockSealClient{sealResp: &client.SealResponse{Backend: "software", Ciphertext: []byte("ct")}}
	withGlobalConfig(t, newSealRunConfig(mock))

	captureStdout(t, func() {
		sealCmd.Run(sealCmd, []string{"hello world"})
	})
}

func TestSealCmd_Run_FromDataFile(t *testing.T) {
	resetSealFlags(t)
	t.Cleanup(func() { resetSealFlags(t) })
	mock := &mockSealClient{sealResp: &client.SealResponse{Backend: "software", Ciphertext: []byte("ct")}}
	withGlobalConfig(t, newSealRunConfig(mock))

	p := filepath.Join(t.TempDir(), "data.bin")
	if err := os.WriteFile(p, []byte("file contents"), 0600); err != nil {
		t.Fatal(err)
	}
	_ = sealCmd.Flags().Set("data-file", p)

	captureStdout(t, func() {
		sealCmd.Run(sealCmd, nil)
	})
}

func TestSealCmd_Run_DataFileNotFound(t *testing.T) {
	resetSealFlags(t)
	t.Cleanup(func() { resetSealFlags(t) })
	withGlobalConfig(t, newSealRunConfig(&mockSealClient{}))
	_ = sealCmd.Flags().Set("data-file", "/nonexistent/data.bin")

	code := captureExit(t, func() {
		sealCmd.Run(sealCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestSealCmd_Run_NoDataProvided(t *testing.T) {
	resetSealFlags(t)
	t.Cleanup(func() { resetSealFlags(t) })
	withGlobalConfig(t, newSealRunConfig(&mockSealClient{}))

	code := captureExit(t, func() {
		sealCmd.Run(sealCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestUnsealDataCmd_Run_FromArg(t *testing.T) {
	resetUnsealFlags(t)
	t.Cleanup(func() { resetUnsealFlags(t) })
	mock := &mockSealClient{unsealResp: &client.UnsealResponse{Plaintext: []byte("pt")}}
	withGlobalConfig(t, newSealRunConfig(mock))

	ct := base64.StdEncoding.EncodeToString([]byte("ciphertext"))
	captureStdout(t, func() {
		unsealDataCmd.Run(unsealDataCmd, []string{ct})
	})
}

func TestUnsealDataCmd_Run_FromFlag(t *testing.T) {
	resetUnsealFlags(t)
	t.Cleanup(func() { resetUnsealFlags(t) })
	mock := &mockSealClient{unsealResp: &client.UnsealResponse{Plaintext: []byte("pt")}}
	withGlobalConfig(t, newSealRunConfig(mock))

	ct := base64.StdEncoding.EncodeToString([]byte("ciphertext"))
	nonce := base64.StdEncoding.EncodeToString([]byte("nonce"))
	tag := base64.StdEncoding.EncodeToString([]byte("tag"))
	_ = unsealDataCmd.Flags().Set("ciphertext", ct)
	_ = unsealDataCmd.Flags().Set("nonce", nonce)
	_ = unsealDataCmd.Flags().Set("tag", tag)
	_ = unsealDataCmd.Flags().Set("aad", "extra")

	captureStdout(t, func() {
		unsealDataCmd.Run(unsealDataCmd, nil)
	})
}

func TestUnsealDataCmd_Run_FromFile(t *testing.T) {
	resetUnsealFlags(t)
	t.Cleanup(func() { resetUnsealFlags(t) })
	mock := &mockSealClient{unsealResp: &client.UnsealResponse{Plaintext: []byte("pt")}}
	withGlobalConfig(t, newSealRunConfig(mock))

	ct := base64.StdEncoding.EncodeToString([]byte("ciphertext"))
	p := filepath.Join(t.TempDir(), "ct.b64")
	if err := os.WriteFile(p, []byte(ct), 0600); err != nil {
		t.Fatal(err)
	}
	_ = unsealDataCmd.Flags().Set("ciphertext-file", p)

	captureStdout(t, func() {
		unsealDataCmd.Run(unsealDataCmd, nil)
	})
}

func TestUnsealDataCmd_Run_FileNotFound(t *testing.T) {
	resetUnsealFlags(t)
	t.Cleanup(func() { resetUnsealFlags(t) })
	withGlobalConfig(t, newSealRunConfig(&mockSealClient{}))
	_ = unsealDataCmd.Flags().Set("ciphertext-file", "/nonexistent/ct.b64")

	code := captureExit(t, func() {
		unsealDataCmd.Run(unsealDataCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestUnsealDataCmd_Run_NoCiphertextProvided(t *testing.T) {
	resetUnsealFlags(t)
	t.Cleanup(func() { resetUnsealFlags(t) })
	withGlobalConfig(t, newSealRunConfig(&mockSealClient{}))

	code := captureExit(t, func() {
		unsealDataCmd.Run(unsealDataCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestUnsealDataCmd_Run_BadCiphertextBase64(t *testing.T) {
	resetUnsealFlags(t)
	t.Cleanup(func() { resetUnsealFlags(t) })
	withGlobalConfig(t, newSealRunConfig(&mockSealClient{}))

	code := captureExit(t, func() {
		unsealDataCmd.Run(unsealDataCmd, []string{"not-base64!!"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestUnsealDataCmd_Run_BadNonceBase64(t *testing.T) {
	resetUnsealFlags(t)
	t.Cleanup(func() { resetUnsealFlags(t) })
	withGlobalConfig(t, newSealRunConfig(&mockSealClient{}))
	ct := base64.StdEncoding.EncodeToString([]byte("ciphertext"))
	_ = unsealDataCmd.Flags().Set("nonce", "not-base64!!")

	code := captureExit(t, func() {
		unsealDataCmd.Run(unsealDataCmd, []string{ct})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestUnsealDataCmd_Run_BadTagBase64(t *testing.T) {
	resetUnsealFlags(t)
	t.Cleanup(func() { resetUnsealFlags(t) })
	withGlobalConfig(t, newSealRunConfig(&mockSealClient{}))
	ct := base64.StdEncoding.EncodeToString([]byte("ciphertext"))
	_ = unsealDataCmd.Flags().Set("tag", "not-base64!!")

	code := captureExit(t, func() {
		unsealDataCmd.Run(unsealDataCmd, []string{ct})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCanSealCmd_Run(t *testing.T) {
	mock := &mockSealClient{canSealResp: &client.CanSealResponse{CanSeal: true, Backend: "software"}}
	withGlobalConfig(t, newSealRunConfig(mock))

	captureStdout(t, func() {
		canSealCmd.Run(canSealCmd, nil)
	})
}
