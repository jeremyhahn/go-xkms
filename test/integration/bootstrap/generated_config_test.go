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

package bootstrap

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// composeServerEnv is the XKMS_* environment the xkms-server service in
// docker-compose.yml sets on top of the generated config.
var composeServerEnv = map[string]string{
	"XKMS_LOGGING_LEVEL":           "debug",
	"XKMS_BOOTSTRAP_NOISE_ENABLED": "true",
	"XKMS_SERVER_NOISE_PORT":       "8445",
	"XKMS_STORAGE_BACKEND":         "qrdb",
	"XKMS_STORAGE_PATH":            "/data/storage",
}

// TestGeneratedConfigLoadsWithoutComplianceGaps runs the bootstrap suite's
// config generator and checks that xkmsd would accept its output: the
// daemon refuses to start when config.Load fails or ComplianceGaps reports
// anything, which is what kept the xkms-server container from turning healthy.
func TestGeneratedConfigLoadsWithoutComplianceGaps(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not available")
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not available")
	}

	dir := t.TempDir()
	configFile := filepath.Join(dir, "xkmsd.yaml")
	cmd := exec.Command("sh", filepath.Join("scripts", "generate-test-certs.sh"))
	cmd.Env = append(os.Environ(),
		"CERT_DIR="+filepath.Join(dir, "certs"),
		"TEST_DATA_DIR="+filepath.Join(dir, "data"),
		"CONFIG_FILE="+configFile,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generate-test-certs.sh: %v\n%s", err, out)
	}

	for k, v := range composeServerEnv {
		t.Setenv(k, v)
	}
	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("config.Load(generated xkmsd.yaml): %v", err)
	}
	if gaps := cfg.ComplianceGaps(); len(gaps) != 0 {
		t.Fatalf("generated config has compliance gaps: %q", gaps)
	}
}
