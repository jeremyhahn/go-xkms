// Package setup checks the files the bootstrap integration stack generates
// before its xkms-server container starts. It carries no integration build
// tag, so the normal unit gates catch a generated configuration that
// cmd/xkmsd would refuse before the Docker stack ever runs.
package setup

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// TestGeneratedConfigHasNoComplianceGaps runs
// test/integration/bootstrap/scripts/generate-test-certs.sh into a temporary
// directory, loads the xkmsd configuration it writes with config.Load (the
// loader cmd/xkmsd uses) and requires config.ComplianceGaps to report none:
// cmd/xkmsd refuses to start on any gap, which is what took the bootstrap
// stack's xkms-server down.
func TestGeneratedConfigHasNoComplianceGaps(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed: generate-test-certs.sh needs it")
	}
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	script := filepath.Join(filepath.Dir(thisFile), "..", "scripts", "generate-test-certs.sh")

	dir := t.TempDir()
	certDir := filepath.Join(dir, "certs")
	dataDir := filepath.Join(dir, "data")
	configFile := filepath.Join(dir, "xkmsd.yaml")

	cmd := exec.Command("sh", script)
	cmd.Env = append(os.Environ(),
		"CERT_DIR="+certDir,
		"TEST_DATA_DIR="+dataDir,
		"CONFIG_FILE="+configFile,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generate-test-certs.sh failed: %v\n%s", err, out)
	}

	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("config.Load(%s): %v", configFile, err)
	}
	if gaps := cfg.ComplianceGaps(); len(gaps) > 0 {
		t.Fatalf("generated xkmsd config has compliance gaps, cmd/xkmsd would refuse to start: %q", gaps)
	}
}
