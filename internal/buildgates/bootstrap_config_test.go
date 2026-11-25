package buildgates

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// bootstrapCertScript is the entrypoint script of the xkms-server service in
// test/integration/bootstrap/docker-compose.yml. It writes the daemon config
// the Integration [integration image] job boots xkmsd on.
const bootstrapCertScript = "../../test/integration/bootstrap/scripts/generate-test-certs.sh"

// TestBootstrapStackConfigStartsTheDaemon runs the bootstrap stack's
// generate-test-certs.sh into a temporary directory and asserts the config it
// writes passes the two checks cmd/xkmsd makes before it serves anything:
// config.Load (decode + Validate, with the compose environment applied) and
// ComplianceGaps (cmd/xkmsd/main.go refuses to start on any gap). A config that
// fails either makes the xkms-server container exit 1 a second after start, and
// every later service of the stack fails with "dependency failed to start"
// (issue #2232), which no Docker-less gate saw before.
func TestBootstrapStackConfigStartsTheDaemon(t *testing.T) {
	script, err := filepath.Abs(bootstrapCertScript)
	if err != nil {
		t.Fatalf("resolve %s: %v", bootstrapCertScript, err)
	}

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
		t.Fatalf("generate-test-certs.sh: %v\n%s", err, out)
	}
	if _, err := os.Stat(configFile); err != nil {
		t.Fatalf("generate-test-certs.sh did not write the config at CONFIG_FILE: %v", err)
	}

	// The xkms-server service environment of the compose file.
	t.Setenv("XKMS_CONFIG", configFile)
	t.Setenv("XKMS_LOGGING_LEVEL", "debug")
	t.Setenv("XKMS_BOOTSTRAP_NOISE_ENABLED", "true")
	t.Setenv("XKMS_SERVER_NOISE_PORT", "8445")
	t.Setenv("CERT_DIR", certDir)
	t.Setenv("XKMS_STORAGE_BACKEND", "qrdb")
	t.Setenv("XKMS_STORAGE_PATH", filepath.Join(dataDir, "storage"))

	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("config.Load of the generated bootstrap config: %v", err)
	}
	if gaps := cfg.ComplianceGaps(); len(gaps) > 0 {
		t.Fatalf("xkmsd refuses the generated bootstrap config: compliance gaps %q", gaps)
	}
	if !cfg.Bootstrap.Noise.Enabled || !cfg.Bootstrap.SPKI.Enabled || !cfg.Bootstrap.DANE.Enabled {
		t.Fatalf("bootstrap noise/spki/dane must stay enabled, got noise=%v spki=%v dane=%v",
			cfg.Bootstrap.Noise.Enabled, cfg.Bootstrap.SPKI.Enabled, cfg.Bootstrap.DANE.Enabled)
	}
}
