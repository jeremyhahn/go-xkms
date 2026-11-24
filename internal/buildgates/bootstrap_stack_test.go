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

	assertServiceGetsAdminCredential(t, cf, "test", credDir)
	assertServiceGetsAdminCredential(t, cf, "xkey-truststrap-test", credDir)

	// Codex P1 #2 on #2377: the xkey runner discovers the server keys over
	// the admin API, so its show-keys call must present the admin pair.
	script, err := os.ReadFile(filepath.Join(bootstrapStackDir, "scripts", "run-xkey-truststrap-tests.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ReplaceAll(string(script), "\\\n", " ")
	start := strings.Index(text, "bootstrap show-keys")
	if start < 0 {
		t.Fatal("run-xkey-truststrap-tests.sh has no bootstrap show-keys call")
	}
	call := text[start:]
	if end := strings.Index(call, ")\""); end >= 0 {
		call = call[:end]
	}
	for _, flag := range []string{
		`--tls-cert "${BOOTSTRAP_ADMIN_CERT}"`,
		`--tls-key "${BOOTSTRAP_ADMIN_KEY}"`,
	} {
		if !strings.Contains(call, flag) {
			t.Errorf("run-xkey-truststrap-tests.sh show-keys call lacks %s: %q", flag, call)
		}
	}
}

// assertServiceGetsAdminCredential fails unless the compose service name
// mounts xkms-data and names the admin mTLS pair under credDir.
func assertServiceGetsAdminCredential(t *testing.T, cf bootstrapCompose, name, credDir string) {
	t.Helper()
	svc, ok := cf.Services[name]
	if !ok {
		t.Fatalf("docker-compose.yml has no %s service", name)
	}
	if !hasVolume(svc.Volumes, "xkms-data:"+bootstrapDataMount) {
		t.Errorf("%s service does not mount xkms-data at %s, so it cannot read the admin credential: %q", name, bootstrapDataMount, svc.Volumes)
	}
	for key, file := range map[string]string{
		"BOOTSTRAP_ADMIN_CERT": "admin-cert.pem",
		"BOOTSTRAP_ADMIN_KEY":  "admin-key.pem",
	} {
		want := key + "=" + credDir + "/" + file
		found := false
		for _, e := range svc.Environment {
			if e == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s service environment lacks %s", name, want)
		}
	}
}

// TestGeneratedConfigRequestsTheAdminClientCert guards Codex P1 #1 on #2377:
// with tls.client_auth empty the server never requests a client certificate,
// so the admin mTLS pair the suite sends is never seen and admin calls go out
// unauthenticated.
func TestGeneratedConfigRequestsTheAdminClientCert(t *testing.T) {
	cfg, _ := generateBootstrapConfig(t)
	switch mode := cfg.TLS.ClientAuth; mode {
	case "verify", "request":
	case "require", "require_and_verify":
		t.Fatalf("tls.client_auth %q demands a certificate, but the compose health check, the zone generator and the unauthenticated bootstrap/truststrap clients present none", mode)
	default:
		t.Fatalf("tls.client_auth %q never requests the admin client certificate; want \"verify\" or \"request\"", mode)
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
