package buildgates

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

const bootstrapComposeFile = "../../test/integration/bootstrap/docker-compose.yml"

// TestBootstrapStackHealthcheckProbesWhatTheServerServes asserts the
// xkms-server healthcheck of the bootstrap compose stack sends a request the
// daemon answers with 200 on the config generate-test-certs.sh writes.
//
// /health on the unified mTLS listener answers GET with 200 and HEAD with 405
// (measured on xkmsd started from the generated config). GNU wget, which the
// golang:bookworm runtime image ships, sends HEAD under --spider, so a
// "wget --spider" probe exits non-zero on a healthy daemon: compose marks the
// container unhealthy and no dependent service starts (issue #2232, Integration
// on 3ba8cff03a65). The probe must be a GET of https://localhost:<rest_port>
// <health.path> that still verifies the server certificate against the
// stack's CA.
func TestBootstrapStackHealthcheckProbesWhatTheServerServes(t *testing.T) {
	raw, err := os.ReadFile(bootstrapComposeFile)
	if err != nil {
		t.Fatalf("read %s: %v", bootstrapComposeFile, err)
	}
	var compose struct {
		Services map[string]struct {
			Healthcheck struct {
				Test []string `yaml:"test"`
			} `yaml:"healthcheck"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(raw, &compose); err != nil {
		t.Fatalf("parse %s: %v", bootstrapComposeFile, err)
	}
	svc, ok := compose.Services["xkms-server"]
	if !ok {
		t.Fatalf("%s has no xkms-server service", bootstrapComposeFile)
	}
	probe := svc.Healthcheck.Test
	if len(probe) < 3 || probe[0] != "CMD" || probe[1] != "wget" {
		t.Fatalf("xkms-server healthcheck must be [CMD wget ...], got %q", probe)
	}
	args := probe[2:]

	if slices.Contains(args, "--spider") {
		t.Errorf("healthcheck uses wget --spider, which sends HEAD; /health answers HEAD with 405, so the probe never passes: %q", probe)
	}
	for _, a := range args {
		if a == "--no-check-certificate" || strings.HasPrefix(a, "http://") {
			t.Errorf("healthcheck must verify TLS against the stack CA, got %q", a)
		}
	}
	if !slices.Contains(args, "--ca-certificate=/etc/xkms/certs/ca.crt") {
		t.Errorf("healthcheck must verify the server against /etc/xkms/certs/ca.crt, got %q", probe)
	}

	cfg := generatedBootstrapConfig(t)
	want := fmt.Sprintf("https://localhost:%d%s", cfg.Server.RESTPort, cfg.Health.Path)
	if args[len(args)-1] != want {
		t.Errorf("healthcheck URL = %q, want %q (the generated config's rest_port and health.path)", args[len(args)-1], want)
	}
}

// generatedBootstrapConfig runs generate-test-certs.sh into a temporary
// directory and loads the config it writes with the compose environment.
func generatedBootstrapConfig(t *testing.T) *config.Config {
	t.Helper()
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
	t.Setenv("XKMS_CONFIG", configFile)
	t.Setenv("CERT_DIR", certDir)
	t.Setenv("XKMS_STORAGE_BACKEND", "qrdb")
	t.Setenv("XKMS_STORAGE_PATH", filepath.Join(dataDir, "storage"))
	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("config.Load of the generated bootstrap config: %v", err)
	}
	return cfg
}
