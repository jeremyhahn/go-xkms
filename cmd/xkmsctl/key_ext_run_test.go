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

// key_ext_run_test.go exercises the hardware-capability key subcommands
// (attest, derive-ecdh, wrap-by-id, unwrap-by-id, export-material) against a
// mock implementing those SDK methods, covering happy paths, required-flag
// validation, and SDK error handling.
package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

var errKeyExtBoom = errors.New("boom")

// mockKeyExtClient implements the hardware-capability key operations; every
// other method comes from the embedded base.
type mockKeyExtClient struct {
	mockBackendsClient

	attestResp    *transport.AttestKeyResponse
	attestErr     error
	deriveResp    *transport.DeriveKeyECDHResponse
	deriveErr     error
	wrapResp      *transport.WrapKeyByIDResponse
	wrapErr       error
	unwrapResp    *transport.UnwrapKeyByIDResponse
	unwrapErr     error
	exportMatResp *transport.ExportKeyMaterialResponse
	exportMatErr  error

	gotAttestReq    *transport.AttestKeyRequest
	gotDeriveReq    *transport.DeriveKeyECDHRequest
	gotWrapReq      *transport.WrapKeyByIDRequest
	gotUnwrapReq    *transport.UnwrapKeyByIDRequest
	gotExportMatReq *transport.ExportKeyMaterialRequest
}

func (m *mockKeyExtClient) AttestKey(_ context.Context, req *transport.AttestKeyRequest) (*transport.AttestKeyResponse, error) {
	m.gotAttestReq = req
	return m.attestResp, m.attestErr
}

func (m *mockKeyExtClient) DeriveKeyECDH(_ context.Context, req *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error) {
	m.gotDeriveReq = req
	return m.deriveResp, m.deriveErr
}

func (m *mockKeyExtClient) WrapKeyByID(_ context.Context, req *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	m.gotWrapReq = req
	return m.wrapResp, m.wrapErr
}

func (m *mockKeyExtClient) UnwrapKeyByID(_ context.Context, req *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error) {
	m.gotUnwrapReq = req
	return m.unwrapResp, m.unwrapErr
}

func (m *mockKeyExtClient) ExportKeyMaterial(_ context.Context, req *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error) {
	m.gotExportMatReq = req
	return m.exportMatResp, m.exportMatErr
}

func newKeyExtConfig(mock *mockKeyExtClient) *Config {
	return &Config{
		OutputFormat: "text",
		ClientFactory: func(*Config) (client.Client, error) {
			return mock, nil
		},
	}
}

func TestKeyAttestCmd_Success(t *testing.T) {
	resetCmdFlags(t, keyAttestCmd)
	t.Cleanup(func() { resetCmdFlags(t, keyAttestCmd) })
	mock := &mockKeyExtClient{attestResp: &transport.AttestKeyResponse{
		Format: "tpm2", AttestationData: []byte("quote"), Signature: []byte("sig"),
	}}
	withGlobalConfig(t, newKeyExtConfig(mock))

	captureStdout(t, func() {
		keyAttestCmd.Run(keyAttestCmd, []string{"my-key"})
	})
	if mock.gotAttestReq == nil || mock.gotAttestReq.KeyID != "my-key" {
		t.Fatalf("AttestKey request mismatch: %+v", mock.gotAttestReq)
	}
	if len(mock.gotAttestReq.Nonce) != 32 {
		t.Errorf("expected a generated 32-byte nonce, got %d bytes", len(mock.gotAttestReq.Nonce))
	}
}

func TestKeyAttestCmd_Error(t *testing.T) {
	resetCmdFlags(t, keyAttestCmd)
	t.Cleanup(func() { resetCmdFlags(t, keyAttestCmd) })
	withGlobalConfig(t, newKeyExtConfig(&mockKeyExtClient{attestErr: errKeyExtBoom}))

	code := captureExit(t, func() {
		keyAttestCmd.Run(keyAttestCmd, []string{"my-key"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestKeyDeriveECDHCmd_RequiresPeerKey(t *testing.T) {
	resetCmdFlags(t, keyDeriveECDHCmd)
	t.Cleanup(func() { resetCmdFlags(t, keyDeriveECDHCmd) })
	withGlobalConfig(t, newKeyExtConfig(&mockKeyExtClient{}))

	code := captureExit(t, func() {
		keyDeriveECDHCmd.Run(keyDeriveECDHCmd, []string{"my-key"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1 without --peer-key, got %d", code)
	}
}

func TestKeyDeriveECDHCmd_Success(t *testing.T) {
	resetCmdFlags(t, keyDeriveECDHCmd)
	t.Cleanup(func() { resetCmdFlags(t, keyDeriveECDHCmd) })

	peerFile := filepath.Join(t.TempDir(), "peer.der")
	if err := os.WriteFile(peerFile, []byte("peer-public-key-bytes"), 0600); err != nil {
		t.Fatalf("write peer key: %v", err)
	}

	mock := &mockKeyExtClient{deriveResp: &transport.DeriveKeyECDHResponse{
		DerivedKey: []byte("derived-key-material"),
	}}
	withGlobalConfig(t, newKeyExtConfig(mock))
	_ = keyDeriveECDHCmd.Flags().Set("peer-key", peerFile)

	captureStdout(t, func() {
		keyDeriveECDHCmd.Run(keyDeriveECDHCmd, []string{"my-key"})
	})
	if mock.gotDeriveReq == nil {
		t.Fatalf("DeriveKeyECDH was not called")
	}
}

func TestKeyWrapByIDCmd_RequiresWrappingKey(t *testing.T) {
	resetCmdFlags(t, keyWrapByIDCmd)
	t.Cleanup(func() { resetCmdFlags(t, keyWrapByIDCmd) })
	withGlobalConfig(t, newKeyExtConfig(&mockKeyExtClient{}))

	code := captureExit(t, func() {
		keyWrapByIDCmd.Run(keyWrapByIDCmd, []string{"my-key"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1 without --wrapping-key, got %d", code)
	}
}

func TestKeyWrapByIDCmd_Success(t *testing.T) {
	resetCmdFlags(t, keyWrapByIDCmd)
	t.Cleanup(func() { resetCmdFlags(t, keyWrapByIDCmd) })
	mock := &mockKeyExtClient{wrapResp: &transport.WrapKeyByIDResponse{
		WrappedKey: []byte("wrapped"), Algorithm: "RSAES_OAEP_SHA_256",
	}}
	withGlobalConfig(t, newKeyExtConfig(mock))
	_ = keyWrapByIDCmd.Flags().Set("wrapping-key", "kek")

	captureStdout(t, func() {
		keyWrapByIDCmd.Run(keyWrapByIDCmd, []string{"my-key"})
	})
	if mock.gotWrapReq == nil {
		t.Fatalf("WrapKeyByID was not called")
	}
}

func TestKeyUnwrapByIDCmd_RequiresFlags(t *testing.T) {
	resetCmdFlags(t, keyUnwrapByIDCmd)
	t.Cleanup(func() { resetCmdFlags(t, keyUnwrapByIDCmd) })
	withGlobalConfig(t, newKeyExtConfig(&mockKeyExtClient{}))

	code := captureExit(t, func() {
		keyUnwrapByIDCmd.Run(keyUnwrapByIDCmd, []string{"new-key"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1 without required flags, got %d", code)
	}
}

func TestKeyUnwrapByIDCmd_Success(t *testing.T) {
	resetCmdFlags(t, keyUnwrapByIDCmd)
	t.Cleanup(func() { resetCmdFlags(t, keyUnwrapByIDCmd) })

	wrappedFile := filepath.Join(t.TempDir(), "wrapped.bin")
	if err := os.WriteFile(wrappedFile, []byte("wrapped-bytes"), 0600); err != nil {
		t.Fatalf("write wrapped file: %v", err)
	}

	mock := &mockKeyExtClient{unwrapResp: &transport.UnwrapKeyByIDResponse{
		KeyID: "new-key", Backend: "software", Success: true,
	}}
	withGlobalConfig(t, newKeyExtConfig(mock))
	_ = keyUnwrapByIDCmd.Flags().Set("wrapped-file", wrappedFile)
	_ = keyUnwrapByIDCmd.Flags().Set("unwrapping-key", "kek")

	captureStdout(t, func() {
		keyUnwrapByIDCmd.Run(keyUnwrapByIDCmd, []string{"new-key"})
	})
	if mock.gotUnwrapReq == nil {
		t.Fatalf("UnwrapKeyByID was not called")
	}
}

func TestKeyExportMaterialCmd_Success(t *testing.T) {
	resetCmdFlags(t, keyExportMaterialCmd)
	t.Cleanup(func() { resetCmdFlags(t, keyExportMaterialCmd) })
	mock := &mockKeyExtClient{exportMatResp: &transport.ExportKeyMaterialResponse{
		KeyMaterial: []byte("raw-key"), KeyType: "aes256-gcm",
	}}
	withGlobalConfig(t, newKeyExtConfig(mock))

	captureStdout(t, func() {
		keyExportMaterialCmd.Run(keyExportMaterialCmd, []string{"my-aes-key"})
	})
	if mock.gotExportMatReq == nil || mock.gotExportMatReq.KeyID != "my-aes-key" {
		t.Fatalf("ExportKeyMaterial request mismatch: %+v", mock.gotExportMatReq)
	}
}

func TestKeyExportMaterialCmd_Error(t *testing.T) {
	resetCmdFlags(t, keyExportMaterialCmd)
	t.Cleanup(func() { resetCmdFlags(t, keyExportMaterialCmd) })
	withGlobalConfig(t, newKeyExtConfig(&mockKeyExtClient{exportMatErr: errKeyExtBoom}))

	code := captureExit(t, func() {
		keyExportMaterialCmd.Run(keyExportMaterialCmd, []string{"my-aes-key"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}
