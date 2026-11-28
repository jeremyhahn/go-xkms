// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

package main

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/client/service"
	"github.com/spf13/viper"
)

// TestAccountAddCmd_RejectsHardwareKeyStore: `account add --key-store tpm2`
// (or pkcs11) must not register or sign with a software key. The client has
// no hardware backend for account keys, so it refuses with a typed error,
// sends nothing to the server and leaves no private key on disk.
func TestAccountAddCmd_RejectsHardwareKeyStore(t *testing.T) {
	for _, store := range []string{"tpm2", "pkcs11"} {
		t.Run(store, func(t *testing.T) {
			var hits atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				http.Error(w, "unexpected request", http.StatusTeapot)
			}))
			t.Cleanup(srv.Close)

			stateDir := t.TempDir()
			viper.Reset()
			t.Cleanup(viper.Reset)
			setDefaults()
			viper.Set("logging.level", "info")
			viper.Set("storage.options.path", stateDir)

			resetAccountAddFlags(t)
			f := accountAddCmd.Flags()
			_ = f.Set("directory", srv.URL+"/directory")
			_ = f.Set("email", "admin@example.com")
			_ = f.Set("key-store", store)

			cmd := accountAddCmd
			cmd.SetContext(context.Background())
			buf := &bytes.Buffer{}
			cmd.SetOut(buf)
			cmd.SetErr(buf)

			err := accountAddCmd.RunE(cmd, []string{"hw"})

			var want service.ErrUnsupportedAccountKeyStore
			if !errors.As(err, &want) {
				t.Fatalf("account add --key-store %s: err = %v (output %q), want ErrUnsupportedAccountKeyStore", store, err, buf.String())
			}
			if n := hits.Load(); n != 0 {
				t.Errorf("server contacted %d times", n)
			}
			walkErr := filepath.WalkDir(stateDir, func(path string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return err
				}
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				if bytes.Contains(data, []byte("PRIVATE KEY-----")) {
					t.Errorf("private key written to disk: %s", path)
				}
				return nil
			})
			if walkErr != nil {
				t.Fatalf("walk %s: %v", stateDir, walkErr)
			}
		})
	}
}
