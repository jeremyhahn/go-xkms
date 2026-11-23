package buildgates

// The bootstrap integration stack (test/integration/bootstrap) generates its
// xkmsd config at container start with scripts/generate-test-certs.sh. These
// tests run that script into a temporary directory and check what cmd/xkmsd
// and the test runner need from it, so `make test-buildgates` catches a
// config the daemon would refuse before the Docker stack ever runs.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

const (
	bootstrapStackDir = repoRoot + "/test/integration/bootstrap"
	// bootstrapDataMount is where the compose file mounts the xkms-data
	// volume in the server container, and the script's TEST_DATA_DIR default.
	bootstrapDataMount = "/data"
)

// generateBootstrapConfig runs generate-test-certs.sh into t.TempDir() and
// loads the xkmsd config it writes with the loader cmd/xkmsd uses. It returns
// the config and the data directory the script was given.
func generateBootstrapConfig(t *testing.T) (*config.Config, string) {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed: generate-test-certs.sh needs it")
	}
	script, err := filepath.Abs(filepath.Join(bootstrapStackDir, "scripts", "generate-test-certs.sh"))
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	configFile := filepath.Join(dir, "xkmsd.yaml")
	cmd := exec.Command("sh", script)
	cmd.Env = append(os.Environ(),
		"CERT_DIR="+filepath.Join(dir, "certs"),
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
	return cfg, dataDir
}

func TestGeneratedConfigHasNoComplianceGaps(t *testing.T) {
	cfg, _ := generateBootstrapConfig(t)
	if gaps := cfg.ComplianceGaps(); len(gaps) > 0 {
		t.Fatalf("generated xkmsd config has compliance gaps, cmd/xkmsd would refuse to start: %q", gaps)
	}
}

// The default "passphrase" barrier boots sealed behind a sealed-window
// listener, and the stack has no unseal ceremony.
func TestGeneratedConfigBootsUnsealed(t *testing.T) {
	cfg, _ := generateBootstrapConfig(t)
	if !cfg.Barrier.Enabled {
		t.Fatal("generated config disables the barrier")
	}
	if got := cfg.Barrier.SealStrategy(); got != "none" {
		t.Fatalf("barrier seal strategy = %q, want \"none\": the stack has no unseal step, so the daemon would stay sealed", got)
	}
}

type bootstrapCompose struct {
	Services map[string]struct {
		Volumes     []string `yaml:"volumes"`
		Environment []string `yaml:"environment"`
	} `yaml:"services"`
}

// With authentication enabled every admin API call the suite makes needs a
// credential: the test runner must read the first-boot administrator's mTLS
// pair that xkmsd writes into datastore.path (pkg/server PersistAdminCredential).
func TestBootstrapTestRunnerGetsTheAdminCredential(t *testing.T) {
	cfg, dataDir := generateBootstrapConfig(t)
	rel, err := filepath.Rel(dataDir, cfg.Datastore.Path)
	if err != nil || strings.HasPrefix(rel, "..") {
		t.Fatalf("datastore.path %q is not under the data volume %q", cfg.Datastore.Path, dataDir)
	}
	credDir := filepath.ToSlash(filepath.Join(bootstrapDataMount, rel))

	raw, err := os.ReadFile(filepath.Join(bootstrapStackDir, "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var cf bootstrapCompose
	if err := yaml.Unmarshal(raw, &cf); err != nil {
		t.Fatalf("parse docker-compose.yml: %v", err)
	}

	server, ok := cf.Services["xkms-server"]
	if !ok {
		t.Fatal("docker-compose.yml has no xkms-server service")
	}
	if !hasVolume(server.Volumes, "xkms-data:"+bootstrapDataMount) {
		t.Fatalf("xkms-server does not mount xkms-data at %s: %q", bootstrapDataMount, server.Volumes)
	}

	runner, ok := cf.Services["test"]
	if !ok {
		t.Fatal("docker-compose.yml has no test service")
	}
	if !hasVolume(runner.Volumes, "xkms-data:"+bootstrapDataMount) {
		t.Fatalf("test service does not mount xkms-data at %s, so it cannot read the admin credential: %q", bootstrapDataMount, runner.Volumes)
	}
	for key, file := range map[string]string{
		"BOOTSTRAP_ADMIN_CERT": "admin-cert.pem",
		"BOOTSTRAP_ADMIN_KEY":  "admin-key.pem",
	} {
		want := key + "=" + credDir + "/" + file
		found := false
		for _, e := range runner.Environment {
			if e == want {
				found = true
			}
		}
		if !found {
			t.Errorf("test service environment lacks %s", want)
		}
	}
}

// hasVolume reports whether vols mounts spec, read-only or not.
func hasVolume(vols []string, spec string) bool {
	for _, v := range vols {
		if v == spec || v == spec+":ro" {
			return true
		}
	}
	return false
}
