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

// key_ext_paths_test.go drives the hardware-capability key operations
// (attest, derive-ecdh, wrap-by-id, unwrap-by-id, export-material) directly,
// pinning every output mode and the sentinel each failure reports.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// keyExtOutputOp is one key_ext operation that prints a result or writes it
// to a file.
type keyExtOutputOp struct {
	name          string
	sdkSentinel   error
	writeSentinel error
	// textWant is a line the text output must carry.
	textWant string
	// jsonKey is a field the JSON output must carry.
	jsonKey string
	// fileWant is the exact output-file content; nil means the file holds
	// the response as JSON with jsonKey in it.
	fileWant []byte
	succeed  func(m *mockKeyExtClient)
	fail     func(m *mockKeyExtClient)
	run      func(cfg *Config, p *Printer, outputFile string)
}

var keyExtSecret = []byte("0123456789abcdef")

func keyExtOutputOps() []keyExtOutputOp {
	encoded := base64.StdEncoding.EncodeToString(keyExtSecret)
	return []keyExtOutputOp{
		{
			name:          "attest",
			sdkSentinel:   ErrAttestKeyFailed,
			writeSentinel: ErrWriteAttestationFileFailed,
			textWant:      "Sig Alg:      ES256",
			jsonKey:       "format",
			succeed: func(m *mockKeyExtClient) {
				m.attestResp = &transport.AttestKeyResponse{
					Backend: "tpm2", Format: "tpm2", SignatureAlgorithm: "ES256",
					AttestationData: []byte("quote"), Signature: []byte("sig"),
				}
			},
			fail: func(m *mockKeyExtClient) { m.attestErr = errKeyExtBoom },
			run: func(cfg *Config, p *Printer, out string) {
				attestKey(cfg, p, "k1", []byte("nonce"), out)
			},
		},
		{
			name:          "derive-ecdh",
			sdkSentinel:   ErrDeriveKeyECDHFailed,
			writeSentinel: ErrWriteDerivedKeyFileFailed,
			textWant:      "Derived Key (16 bytes):\n  " + encoded,
			jsonKey:       "derived_key",
			fileWant:      keyExtSecret,
			succeed: func(m *mockKeyExtClient) {
				m.deriveResp = &transport.DeriveKeyECDHResponse{DerivedKey: keyExtSecret}
			},
			fail: func(m *mockKeyExtClient) { m.deriveErr = errKeyExtBoom },
			run: func(cfg *Config, p *Printer, out string) {
				deriveKeyECDH(cfg, p, &client.DeriveKeyECDHRequest{KeyID: "k1"}, out)
			},
		},
		{
			name:          "wrap-by-id",
			sdkSentinel:   ErrWrapKeyByIDFailed,
			writeSentinel: ErrWriteWrappedKeyFileFailed,
			textWant:      "Wrapped Key (AES-KWP):\n  " + encoded,
			jsonKey:       "wrapped_key",
			fileWant:      keyExtSecret,
			succeed: func(m *mockKeyExtClient) {
				m.wrapResp = &transport.WrapKeyByIDResponse{WrappedKey: keyExtSecret, Algorithm: "AES-KWP"}
			},
			fail: func(m *mockKeyExtClient) { m.wrapErr = errKeyExtBoom },
			run: func(cfg *Config, p *Printer, out string) {
				wrapKeyByID(cfg, p, &client.WrapKeyByIDRequest{TargetKeyID: "k1"}, out)
			},
		},
		{
			name:          "export-material",
			sdkSentinel:   ErrExportKeyMaterialFailed,
			writeSentinel: ErrWriteKeyMaterialFileFailed,
			textWant:      "Key Material (aes, 128 bits):\n  " + encoded,
			jsonKey:       "key_material",
			fileWant:      keyExtSecret,
			succeed: func(m *mockKeyExtClient) {
				m.exportMatResp = &transport.ExportKeyMaterialResponse{KeyMaterial: keyExtSecret, KeyType: "aes", KeySize: 128}
			},
			fail: func(m *mockKeyExtClient) { m.exportMatErr = errKeyExtBoom },
			run: func(cfg *Config, p *Printer, out string) {
				exportKeyMaterial(cfg, p, "k1", out)
			},
		},
	}
}

// runKeyExt runs fn with a recorded exit code and captured stderr.
func runKeyExt(t *testing.T, fn func()) (int, string) {
	t.Helper()
	code := -1
	stderr := captureStderr(t, func() {
		code = captureExit(t, fn)
	})
	return code, stderr
}

func TestKeyExtOutputOps_PrintText(t *testing.T) {
	for _, op := range keyExtOutputOps() {
		t.Run(op.name, func(t *testing.T) {
			mock := &mockKeyExtClient{}
			op.succeed(mock)
			cfg := newKeyExtConfig(mock)
			withGlobalConfig(t, cfg)

			var buf bytes.Buffer
			code, _ := runKeyExt(t, func() { op.run(cfg, NewPrinter("text", &buf), "") })
			assert.Equal(t, -1, code)
			assert.Contains(t, buf.String(), op.textWant)
		})
	}
}

func TestKeyExtOutputOps_PrintJSON(t *testing.T) {
	for _, op := range keyExtOutputOps() {
		t.Run(op.name, func(t *testing.T) {
			mock := &mockKeyExtClient{}
			op.succeed(mock)
			cfg := newKeyExtConfig(mock)
			cfg.OutputFormat = "json"
			withGlobalConfig(t, cfg)

			var buf bytes.Buffer
			code, _ := runKeyExt(t, func() { op.run(cfg, NewPrinter("json", &buf), "") })
			assert.Equal(t, -1, code)
			var got map[string]any
			require.NoError(t, json.Unmarshal(buf.Bytes(), &got), buf.String())
			assert.Contains(t, got, op.jsonKey)
		})
	}
}

func TestKeyExtOutputOps_WriteOutputFile(t *testing.T) {
	for _, op := range keyExtOutputOps() {
		t.Run(op.name, func(t *testing.T) {
			mock := &mockKeyExtClient{}
			op.succeed(mock)
			cfg := newKeyExtConfig(mock)
			withGlobalConfig(t, cfg)
			out := filepath.Join(t.TempDir(), "out.bin")

			var buf bytes.Buffer
			code, _ := runKeyExt(t, func() { op.run(cfg, NewPrinter("text", &buf), out) })
			assert.Equal(t, -1, code)
			assert.Contains(t, buf.String(), "written to: "+out)

			info, err := os.Stat(out)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0600), info.Mode().Perm(), "key output must not be world-readable")
			data, err := os.ReadFile(out)
			require.NoError(t, err)
			if op.fileWant != nil {
				assert.Equal(t, op.fileWant, data)
				return
			}
			var got map[string]any
			require.NoError(t, json.Unmarshal(data, &got))
			assert.Contains(t, got, op.jsonKey)
		})
	}
}

func TestKeyExtOutputOps_Failures(t *testing.T) {
	for _, op := range keyExtOutputOps() {
		cases := []struct {
			name     string
			sentinel error
			output   func(t *testing.T) string
			setup    func(cfg *Config, m *mockKeyExtClient)
		}{
			{"client factory", ErrCreateClientFailed, nil, func(cfg *Config, _ *mockKeyExtClient) {
				cfg.ClientFactory = func(*Config) (client.Client, error) { return nil, errKeyExtBoom }
			}},
			{"connect", ErrConnectFailed, nil, func(_ *Config, m *mockKeyExtClient) { m.connectErr = errKeyExtBoom }},
			{"sdk call", op.sdkSentinel, nil, func(_ *Config, m *mockKeyExtClient) { op.fail(m) }},
			{"unwritable output", op.writeSentinel, func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "missing", "out.bin")
			}, func(_ *Config, m *mockKeyExtClient) { op.succeed(m) }},
		}
		for _, tc := range cases {
			t.Run(op.name+"/"+tc.name, func(t *testing.T) {
				mock := &mockKeyExtClient{}
				cfg := newKeyExtConfig(mock)
				tc.setup(cfg, mock)
				withGlobalConfig(t, cfg)
				out := ""
				if tc.output != nil {
					out = tc.output(t)
				}

				var buf bytes.Buffer
				code, stderr := runKeyExt(t, func() { op.run(cfg, NewPrinter("text", &buf), out) })
				assert.Equal(t, 1, code)
				assert.Contains(t, stderr, tc.sentinel.Error())
				assert.Empty(t, buf.String(), "a failed operation prints no result")
			})
		}
	}
}

func TestUnwrapKeyByID_ReportsTarget(t *testing.T) {
	mock := &mockKeyExtClient{unwrapResp: &transport.UnwrapKeyByIDResponse{Success: true, Backend: "pkcs11", KeyID: "imported"}}
	cfg := newKeyExtConfig(mock)
	withGlobalConfig(t, cfg)

	var buf bytes.Buffer
	code, _ := runKeyExt(t, func() {
		unwrapKeyByID(cfg, NewPrinter("text", &buf), &client.UnwrapKeyByIDRequest{TargetKeyID: "imported"})
	})
	assert.Equal(t, -1, code)
	assert.Contains(t, buf.String(), "pkcs11:imported")
}

func TestUnwrapKeyByID_Failures(t *testing.T) {
	cases := []struct {
		name     string
		mock     *mockKeyExtClient
		wantText string
	}{
		{"connect", &mockKeyExtClient{mockBackendsClient: mockBackendsClient{connectErr: errKeyExtBoom}}, ErrConnectFailed.Error()},
		{"sdk call", &mockKeyExtClient{unwrapErr: errKeyExtBoom}, ErrUnwrapKeyByIDFailed.Error()},
		{"server refused", &mockKeyExtClient{unwrapResp: &transport.UnwrapKeyByIDResponse{Message: "policy forbids import"}}, "policy forbids import"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newKeyExtConfig(tc.mock)
			withGlobalConfig(t, cfg)

			var buf bytes.Buffer
			code, stderr := runKeyExt(t, func() {
				unwrapKeyByID(cfg, NewPrinter("text", &buf), &client.UnwrapKeyByIDRequest{TargetKeyID: "imported"})
			})
			assert.Equal(t, 1, code)
			assert.Contains(t, stderr, tc.wantText)
			assert.Empty(t, buf.String())
		})
	}
}
