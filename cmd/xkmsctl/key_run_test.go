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

// key_run_test.go exercises the "xkmsctl key" command tree's Run closures
// (generate, list, get, delete, sign, verify, encrypt, decrypt,
// encrypt-asym, rotate, import, export, copy, get-import-params, wrap,
// unwrap), which are anonymous cobra closures that read flags/args and
// delegate to already well-tested named functions. mockKeyClient (defined
// in key_test.go) provides a full client.Client surface.
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

func newKeyRunConfig(format string, mock *mockKeyClient) *Config {
	return &Config{
		OutputFormat: format,
		Backend:      "software",
		ClientFactory: func(*Config) (client.Client, error) {
			return mock, nil
		},
	}
}

func TestKeyGenerateCmd_Run(t *testing.T) {
	mock := &mockKeyClient{generateKeyResp: &client.GenerateKeyResponse{KeyID: "k1"}}
	withGlobalConfig(t, newKeyRunConfig("text", mock))
	out := captureStdout(t, func() {
		keyGenerateCmd.Run(keyGenerateCmd, []string{"k1"})
	})
	if !strings.Contains(out, "k1") {
		t.Errorf("expected key id in output, got: %q", out)
	}
}

func TestKeyListCmd_Run(t *testing.T) {
	mock := &mockKeyClient{listKeysResp: &client.ListKeysResponse{}}
	withGlobalConfig(t, newKeyRunConfig("text", mock))
	captureStdout(t, func() {
		keyListCmd.Run(keyListCmd, nil)
	})
}

func TestKeyGetCmd_Run(t *testing.T) {
	mock := &mockKeyClient{getKeyResp: &client.GetKeyResponse{KeyInfo: client.KeyInfo{KeyID: "k1", KeyType: "tls"}}}
	withGlobalConfig(t, newKeyRunConfig("text", mock))
	out := captureStdout(t, func() {
		keyGetCmd.Run(keyGetCmd, []string{"k1"})
	})
	if !strings.Contains(out, "k1") {
		t.Errorf("expected key id in output, got: %q", out)
	}
}

func TestKeyDeleteCmd_Run(t *testing.T) {
	mock := &mockKeyClient{deleteKeyResp: &client.DeleteKeyResponse{Success: true}}
	withGlobalConfig(t, newKeyRunConfig("text", mock))
	out := captureStdout(t, func() {
		keyDeleteCmd.Run(keyDeleteCmd, []string{"k1"})
	})
	if !strings.Contains(out, "Successfully deleted") {
		t.Errorf("expected success message, got: %q", out)
	}
}

func TestKeySignCmd_Run(t *testing.T) {
	mock := &mockKeyClient{signResp: &client.SignResponse{Signature: []byte("sig")}}
	withGlobalConfig(t, newKeyRunConfig("text", mock))
	captureStdout(t, func() {
		keySignCmd.Run(keySignCmd, []string{"k1", "hello"})
	})
}

func TestKeyVerifyCmd_BadSignatureBase64(t *testing.T) {
	mock := &mockKeyClient{}
	withGlobalConfig(t, newKeyRunConfig("text", mock))
	code := captureExit(t, func() {
		keyVerifyCmd.Run(keyVerifyCmd, []string{"k1", "hello", "not-base64!!"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestKeyEncryptCmd_Run(t *testing.T) {
	mock := &mockKeyClient{encryptResp: &client.EncryptResponse{Ciphertext: []byte("ct"), Nonce: []byte("n"), Tag: []byte("tag")}}
	withGlobalConfig(t, newKeyRunConfig("text", mock))
	cmd := keyEncryptCmd
	_ = cmd.Flags().Set("aad", "extra")
	captureStdout(t, func() {
		cmd.Run(cmd, []string{"k1", "plaintext"})
	})
}

func TestKeyDecryptCmd_Run(t *testing.T) {
	mock := &mockKeyClient{decryptResp: &client.DecryptResponse{Plaintext: []byte("pt")}}
	withGlobalConfig(t, newKeyRunConfig("text", mock))
	cmd := keyDecryptCmd
	_ = cmd.Flags().Set("aad", "extra")
	_ = cmd.Flags().Set("nonce", "bm9uY2U=")
	_ = cmd.Flags().Set("tag", "dGFn")
	captureStdout(t, func() {
		cmd.Run(cmd, []string{"k1", "Y2lwaGVy"})
	})
}

func TestKeyDecryptCmd_BadCiphertextBase64(t *testing.T) {
	mock := &mockKeyClient{}
	withGlobalConfig(t, newKeyRunConfig("text", mock))
	cmd := keyDecryptCmd
	_ = cmd.Flags().Set("aad", "")
	_ = cmd.Flags().Set("nonce", "")
	_ = cmd.Flags().Set("tag", "")
	code := captureExit(t, func() {
		cmd.Run(cmd, []string{"k1", "not-base64!!"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestKeyDecryptCmd_BadNonceBase64(t *testing.T) {
	mock := &mockKeyClient{}
	withGlobalConfig(t, newKeyRunConfig("text", mock))
	cmd := keyDecryptCmd
	_ = cmd.Flags().Set("aad", "")
	_ = cmd.Flags().Set("nonce", "not-base64!!")
	_ = cmd.Flags().Set("tag", "")
	code := captureExit(t, func() {
		cmd.Run(cmd, []string{"k1", "Y2lwaGVy"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestKeyDecryptCmd_BadTagBase64(t *testing.T) {
	mock := &mockKeyClient{}
	withGlobalConfig(t, newKeyRunConfig("text", mock))
	cmd := keyDecryptCmd
	_ = cmd.Flags().Set("aad", "")
	_ = cmd.Flags().Set("nonce", "")
	_ = cmd.Flags().Set("tag", "not-base64!!")
	code := captureExit(t, func() {
		cmd.Run(cmd, []string{"k1", "Y2lwaGVy"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestKeyEncryptAsymCmd_Run(t *testing.T) {
	mock := &mockKeyClient{encryptAsymResp: &client.EncryptAsymResponse{Ciphertext: []byte("ct")}}
	withGlobalConfig(t, newKeyRunConfig("text", mock))
	captureStdout(t, func() {
		keyEncryptAsymCmd.Run(keyEncryptAsymCmd, []string{"k1", "plaintext"})
	})
}

func TestKeyCopyCmd_Run_DefaultDest(t *testing.T) {
	mock := &mockKeyClient{copyKeyResp: &client.CopyKeyResponse{}}
	withGlobalConfig(t, newKeyRunConfig("text", mock))
	out := captureStdout(t, func() {
		keyCopyCmd.Run(keyCopyCmd, []string{"k1"})
	})
	if !strings.Contains(out, "Successfully copied") {
		t.Errorf("expected success message, got: %q", out)
	}
}

func TestKeyCopyCmd_Run_ExplicitDest(t *testing.T) {
	mock := &mockKeyClient{copyKeyResp: &client.CopyKeyResponse{}}
	withGlobalConfig(t, newKeyRunConfig("text", mock))
	out := captureStdout(t, func() {
		keyCopyCmd.Run(keyCopyCmd, []string{"k1", "k2"})
	})
	if !strings.Contains(out, "k2") {
		t.Errorf("expected dest key id in output, got: %q", out)
	}
}

func TestKeyGetImportParamsCmd_Run_ToFile(t *testing.T) {
	mock := &mockKeyClient{getImportParamsResp: &client.GetImportParametersResponse{
		WrappingPublicKey: []byte("pubkey"),
	}}
	withGlobalConfig(t, newKeyRunConfig("text", mock))
	out := filepath.Join(t.TempDir(), "params.json")
	cmd := keyGetImportParamsCmd
	_ = cmd.Flags().Set("output", out)
	t.Cleanup(func() { _ = cmd.Flags().Set("output", "") })

	captureStdout(t, func() {
		cmd.Run(cmd, []string{"k1"})
	})
	if _, err := os.Stat(out); err != nil {
		t.Errorf("expected params file to be written: %v", err)
	}
}

// ---------------------------------------------------------------------------
// keyImportCmd (reads + parses a JSON WrappedKeyMaterial file)
// ---------------------------------------------------------------------------

func TestKeyImportCmd_FileNotFound(t *testing.T) {
	withGlobalConfig(t, newKeyRunConfig("text", &mockKeyClient{}))
	code := captureExit(t, func() {
		keyImportCmd.Run(keyImportCmd, []string{"k1", "/nonexistent/wrapped.json"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestKeyImportCmd_BadJSON(t *testing.T) {
	withGlobalConfig(t, newKeyRunConfig("text", &mockKeyClient{}))
	p := filepath.Join(t.TempDir(), "wrapped.json")
	if err := os.WriteFile(p, []byte("not-json"), 0600); err != nil {
		t.Fatal(err)
	}
	code := captureExit(t, func() {
		keyImportCmd.Run(keyImportCmd, []string{"k1", p})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

// TestKeyImportCmd_ExportabilityFlags proves --exportable and --sensitive
// reach the request, and that an omitted --exportable sends nothing so the
// server applies its write-once default.
func TestKeyImportCmd_ExportabilityFlags(t *testing.T) {
	writeWrapped := func(t *testing.T) string {
		t.Helper()
		data, err := json.Marshal(backend.WrappedKeyMaterial{WrappedKey: []byte("wrapped-bytes"), Algorithm: "RSAES_OAEP_SHA_256"})
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(t.TempDir(), "wrapped.json")
		if err := os.WriteFile(p, data, 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	resetFlags := func(t *testing.T) {
		t.Helper()
		t.Cleanup(func() {
			_ = keyImportCmd.Flags().Set("key-type", "")
			_ = keyImportCmd.Flags().Set("aes-key-size", "0")
			_ = keyImportCmd.Flags().Set("exportable", "true")
			_ = keyImportCmd.Flags().Set("sensitive", "false")
			keyImportCmd.Flags().Lookup("exportable").Changed = false
			keyImportCmd.Flags().Lookup("sensitive").Changed = false
		})
	}

	t.Run("explicit flags are sent", func(t *testing.T) {
		mock := &mockKeyClient{importKeyResp: &client.ImportKeyResponse{}}
		withGlobalConfig(t, newKeyRunConfig("text", mock))
		resetFlags(t)
		p := writeWrapped(t)
		for k, v := range map[string]string{"key-type": "aes", "aes-key-size": "256", "exportable": "false", "sensitive": "true"} {
			if err := keyImportCmd.Flags().Set(k, v); err != nil {
				t.Fatal(err)
			}
		}
		_ = captureStdout(t, func() { keyImportCmd.Run(keyImportCmd, []string{"k1", p}) })
		if mock.importKeyReq == nil {
			t.Fatal("ImportKey was never called")
		}
		if mock.importKeyReq.Exportable == nil || *mock.importKeyReq.Exportable {
			t.Errorf("Exportable = %v, want an explicit false", mock.importKeyReq.Exportable)
		}
		if !mock.importKeyReq.Sensitive {
			t.Error("Sensitive must reach the request")
		}
	})

	t.Run("omitted --exportable sends nothing", func(t *testing.T) {
		mock := &mockKeyClient{importKeyResp: &client.ImportKeyResponse{}}
		withGlobalConfig(t, newKeyRunConfig("text", mock))
		resetFlags(t)
		p := writeWrapped(t)
		for k, v := range map[string]string{"key-type": "aes", "aes-key-size": "256"} {
			if err := keyImportCmd.Flags().Set(k, v); err != nil {
				t.Fatal(err)
			}
		}
		_ = captureStdout(t, func() { keyImportCmd.Run(keyImportCmd, []string{"k1", p}) })
		if mock.importKeyReq == nil {
			t.Fatal("ImportKey was never called")
		}
		if mock.importKeyReq.Exportable != nil {
			t.Errorf("Exportable = %v, want nil so the server applies its default", *mock.importKeyReq.Exportable)
		}
	})
}

// TestKeyImportCmd_MissingKeyTypeIsRefused pins the requirement rather than the
// old behaviour. Omitting the algorithm used to produce a key stored under an
// "unknown" identifier that ListKeys then reported as RSA and no subsequent
// operation could find -- a silent corruption. It must now fail before anything
// is sent.
func TestKeyImportCmd_MissingKeyTypeIsRefused(t *testing.T) {
	mock := &mockKeyClient{importKeyResp: &client.ImportKeyResponse{}}
	withGlobalConfig(t, newKeyRunConfig("text", mock))

	wrapped := backend.WrappedKeyMaterial{WrappedKey: []byte("wrapped-bytes"), Algorithm: "RSAES_OAEP_SHA_256"}
	data, err := json.Marshal(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "wrapped.json")
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}

	code := captureExit(t, func() {
		keyImportCmd.Run(keyImportCmd, []string{"k1", p})
	})
	if code != 1 {
		t.Errorf("expected exit code 1 when --key-type is omitted, got %d", code)
	}
	if mock.importKeyReq != nil {
		t.Error("ImportKey must not be called when --key-type is missing; " +
			"refusing locally is what prevents an unresolvable key being stored")
	}
}

// ---------------------------------------------------------------------------
// keyExportCmd
// ---------------------------------------------------------------------------

func TestKeyExportCmd_Run(t *testing.T) {
	mock := &mockKeyClient{exportKeyResp: &client.ExportKeyResponse{WrappedKeyMaterial: []byte("wrapped")}}
	withGlobalConfig(t, newKeyRunConfig("text", mock))
	out := filepath.Join(t.TempDir(), "exported.json")
	out2 := captureStdout(t, func() {
		keyExportCmd.Run(keyExportCmd, []string{"k1", out})
	})
	_ = out2
}

// ---------------------------------------------------------------------------
// keyWrapCmd (reads key material + params files)
// ---------------------------------------------------------------------------

func TestKeyWrapCmd_KeyMaterialFileNotFound(t *testing.T) {
	withGlobalConfig(t, newKeyRunConfig("text", &mockKeyClient{}))
	code := captureExit(t, func() {
		keyWrapCmd.Run(keyWrapCmd, []string{"/nonexistent/keymat", "/nonexistent/params.json", "/tmp/out"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestKeyWrapCmd_ParamsFileNotFound(t *testing.T) {
	withGlobalConfig(t, newKeyRunConfig("text", &mockKeyClient{}))
	dir := t.TempDir()
	keyMat := filepath.Join(dir, "keymat.bin")
	if err := os.WriteFile(keyMat, []byte("raw-key-bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	code := captureExit(t, func() {
		keyWrapCmd.Run(keyWrapCmd, []string{keyMat, "/nonexistent/params.json", filepath.Join(dir, "out")})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestKeyWrapCmd_BadParamsJSON(t *testing.T) {
	withGlobalConfig(t, newKeyRunConfig("text", &mockKeyClient{}))
	dir := t.TempDir()
	keyMat := filepath.Join(dir, "keymat.bin")
	if err := os.WriteFile(keyMat, []byte("raw-key-bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	params := filepath.Join(dir, "params.json")
	if err := os.WriteFile(params, []byte("not-json"), 0600); err != nil {
		t.Fatal(err)
	}
	code := captureExit(t, func() {
		keyWrapCmd.Run(keyWrapCmd, []string{keyMat, params, filepath.Join(dir, "out")})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestKeyWrapCmd_UnexpectedWrappingKeyType(t *testing.T) {
	// A JSON-round-tripped interface{} field decodes to a string, not []byte,
	// so wrapKey's type assertion fails deterministically — this exercises
	// the closure's full file-parsing path plus that named-function branch.
	withGlobalConfig(t, newKeyRunConfig("text", &mockKeyClient{}))
	dir := t.TempDir()
	keyMat := filepath.Join(dir, "keymat.bin")
	if err := os.WriteFile(keyMat, []byte("raw-key-bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	params := filepath.Join(dir, "params.json")
	if err := os.WriteFile(params, []byte(`{"WrappingPublicKey":"cHVia2V5","Algorithm":"RSAES_OAEP_SHA_256"}`), 0600); err != nil {
		t.Fatal(err)
	}
	code := captureExit(t, func() {
		keyWrapCmd.Run(keyWrapCmd, []string{keyMat, params, filepath.Join(dir, "out")})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

// ---------------------------------------------------------------------------
// keyUnwrapCmd (reads wrapped-key + params files)
// ---------------------------------------------------------------------------

func TestKeyUnwrapCmd_WrappedFileNotFound(t *testing.T) {
	withGlobalConfig(t, newKeyRunConfig("text", &mockKeyClient{}))
	code := captureExit(t, func() {
		keyUnwrapCmd.Run(keyUnwrapCmd, []string{"/nonexistent/wrapped.json", "/nonexistent/params.json", "/tmp/out"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestKeyUnwrapCmd_BadWrappedJSON(t *testing.T) {
	withGlobalConfig(t, newKeyRunConfig("text", &mockKeyClient{}))
	dir := t.TempDir()
	wrappedFile := filepath.Join(dir, "wrapped.json")
	if err := os.WriteFile(wrappedFile, []byte("not-json"), 0600); err != nil {
		t.Fatal(err)
	}
	code := captureExit(t, func() {
		keyUnwrapCmd.Run(keyUnwrapCmd, []string{wrappedFile, "/nonexistent/params.json", filepath.Join(dir, "out")})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestKeyUnwrapCmd_ParamsFileNotFound(t *testing.T) {
	withGlobalConfig(t, newKeyRunConfig("text", &mockKeyClient{}))
	dir := t.TempDir()
	wrapped := backend.WrappedKeyMaterial{WrappedKey: []byte("wrapped-bytes"), Algorithm: "RSAES_OAEP_SHA_256"}
	data, err := json.Marshal(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	wrappedFile := filepath.Join(dir, "wrapped.json")
	if err := os.WriteFile(wrappedFile, data, 0600); err != nil {
		t.Fatal(err)
	}
	code := captureExit(t, func() {
		keyUnwrapCmd.Run(keyUnwrapCmd, []string{wrappedFile, "/nonexistent/params.json", filepath.Join(dir, "out")})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestKeyUnwrapCmd_BadParamsJSON(t *testing.T) {
	withGlobalConfig(t, newKeyRunConfig("text", &mockKeyClient{}))
	dir := t.TempDir()
	wrapped := backend.WrappedKeyMaterial{WrappedKey: []byte("wrapped-bytes"), Algorithm: "RSAES_OAEP_SHA_256"}
	data, err := json.Marshal(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	wrappedFile := filepath.Join(dir, "wrapped.json")
	if err := os.WriteFile(wrappedFile, data, 0600); err != nil {
		t.Fatal(err)
	}
	paramsFile := filepath.Join(dir, "params.json")
	if err := os.WriteFile(paramsFile, []byte("not-json"), 0600); err != nil {
		t.Fatal(err)
	}
	code := captureExit(t, func() {
		keyUnwrapCmd.Run(keyUnwrapCmd, []string{wrappedFile, paramsFile, filepath.Join(dir, "out")})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestKeyUnwrapCmd_Success(t *testing.T) {
	mock := &mockKeyClient{unwrapKeyResp: &client.UnwrapKeyResponse{KeyMaterial: []byte("raw-key")}}
	withGlobalConfig(t, newKeyRunConfig("text", mock))
	dir := t.TempDir()

	wrapped := backend.WrappedKeyMaterial{WrappedKey: []byte("wrapped-bytes"), Algorithm: "RSAES_OAEP_SHA_256"}
	wrappedData, err := json.Marshal(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	wrappedFile := filepath.Join(dir, "wrapped.json")
	if err := os.WriteFile(wrappedFile, wrappedData, 0600); err != nil {
		t.Fatal(err)
	}

	paramsFile := filepath.Join(dir, "params.json")
	if err := os.WriteFile(paramsFile, []byte(`{"Algorithm":"RSAES_OAEP_SHA_256"}`), 0600); err != nil {
		t.Fatal(err)
	}

	outFile := filepath.Join(dir, "unwrapped.bin")
	out := captureStdout(t, func() {
		keyUnwrapCmd.Run(keyUnwrapCmd, []string{wrappedFile, paramsFile, outFile})
	})
	if !strings.Contains(out, "Successfully unwrapped") {
		t.Errorf("expected success message, got: %q", out)
	}
	if _, err := os.Stat(outFile); err != nil {
		t.Errorf("expected unwrapped file to be written: %v", err)
	}
}

func TestKeyImportCmd_Success(t *testing.T) {
	mock := &mockKeyClient{importKeyResp: &client.ImportKeyResponse{}}
	withGlobalConfig(t, newKeyRunConfig("text", mock))

	wrapped := backend.WrappedKeyMaterial{WrappedKey: []byte("wrapped-bytes"), Algorithm: "RSAES_OAEP_SHA_256"}
	data, err := json.Marshal(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "wrapped.json")
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}

	// --key-type names the algorithm of the material inside the wrapper. The
	// server cannot infer it from ciphertext, so the command requires it.
	if err := keyImportCmd.Flags().Set("key-type", "rsa"); err != nil {
		t.Fatal(err)
	}
	if err := keyImportCmd.Flags().Set("key-size", "2048"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = keyImportCmd.Flags().Set("key-type", "")
		_ = keyImportCmd.Flags().Set("key-size", "0")
	})

	out := captureStdout(t, func() {
		keyImportCmd.Run(keyImportCmd, []string{"k1", p})
	})
	if !strings.Contains(out, "Successfully imported") {
		t.Errorf("expected success message, got: %q", out)
	}
	if mock.importKeyReq == nil {
		t.Fatal("ImportKey was never called")
	}
	if mock.importKeyReq.KeyType != "rsa" {
		t.Errorf("KeyType = %q, want %q -- the algorithm must reach the server, "+
			"or the imported key is stored with none and no later operation can resolve it",
			mock.importKeyReq.KeyType, "rsa")
	}
	if mock.importKeyReq.KeySize != 2048 {
		t.Errorf("KeySize = %d, want 2048", mock.importKeyReq.KeySize)
	}
}
