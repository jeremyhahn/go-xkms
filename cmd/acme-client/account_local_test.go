// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

package main

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

// TestAccountAddCmd_LocalOnly pins docs/acme-issuance/cli.md:81-86: account
// add only stores the configuration locally and makes no newAccount request,
// so it succeeds against a directory URL that refuses connections.
func TestAccountAddCmd_LocalOnly(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refused := "https://" + ln.Addr().String() + "/directory"
	_ = ln.Close()

	viper.Reset()
	t.Cleanup(viper.Reset)
	setDefaults()
	viper.Set("logging.level", "info")
	viper.Set("storage.options.path", t.TempDir())

	resetAccountAddFlags(t)
	f := accountAddCmd.Flags()
	_ = f.Set("directory", refused)
	_ = f.Set("email", "admin@example.com")

	cmd := accountAddCmd
	cmd.SetContext(context.Background())
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := accountAddCmd.RunE(cmd, []string{"local"}); err != nil {
		t.Fatalf("account add contacted the server: %v (output %q)", err, buf.String())
	}
	if !strings.Contains(buf.String(), `Account "local" added`) {
		t.Errorf("account add output = %q, want the local add message", buf.String())
	}
}
