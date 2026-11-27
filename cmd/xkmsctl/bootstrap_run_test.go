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

// bootstrap_run_test.go exercises bootstrapAutoCmd's RunE closure directly
// (flag reads, config-file resolution, and the delegating call to
// runAutoBootstrap), which bootstrap_auto_test.go's table only reaches
// indirectly via runAutoBootstrap itself.
package main

import (
	"testing"

	"github.com/spf13/cobra"
)

func newBootstrapAutoCmdCopy() *cobra.Command {
	cmd := &cobra.Command{Use: "auto"}
	cmd.Flags().String("server-url", "", "")
	cmd.Flags().String("config", "", "")
	cmd.Flags().String("dane-hostname", "", "")
	cmd.Flags().String("dane-dns-server", "", "")
	cmd.Flags().String("noise-key", "", "")
	cmd.Flags().String("p256-key", "", "")
	cmd.Flags().String("noise-addr", "", "")
	cmd.Flags().String("spki-pin", "", "")
	cmd.Flags().Bool("direct", false, "")
	cmd.Flags().String("bundle-path", "", "")
	cmd.Flags().String("bundle-output", "", "")
	return cmd
}

func TestBootstrapAutoCmd_RunE_NoServerURL(t *testing.T) {
	withGlobalConfig(t, &Config{})
	cmd := newBootstrapAutoCmdCopy()

	err := bootstrapAutoCmd.RunE(cmd, nil)
	if err != ErrBootstrapServerURLRequired {
		t.Fatalf("want ErrBootstrapServerURLRequired, got %v", err)
	}
}

func TestBootstrapAutoCmd_RunE_GlobalConfigFileFallback(t *testing.T) {
	// configFile flag empty; globalConfig.ConfigFile provides the fallback path.
	withGlobalConfig(t, &Config{ConfigFile: "/nonexistent/xkmsd-config.yaml"})
	cmd := newBootstrapAutoCmdCopy()
	_ = cmd.Flags().Set("server-url", "https://kms.example.com:8443")

	err := bootstrapAutoCmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("expected error for missing fallback config file")
	}
}
