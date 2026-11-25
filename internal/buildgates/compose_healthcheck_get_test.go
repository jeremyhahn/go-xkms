package buildgates

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestXKMSServerHealthcheckUsesGET pins the xkms-server compose healthchecks
// to a GET on /health. wget --spider sends HEAD, which the go-qrdb host
// answers with 405 because it registers /health for GET only, so the
// container never turns healthy (#2376).
func TestXKMSServerHealthcheckUsesGET(t *testing.T) {
	files := []string{
		"test/integration/bootstrap/docker-compose.yml",
		"test/integration/api/docker-compose.yml",
		"test/integration/sdk/docker-compose.yml",
		"test/integration/pkcs11/module/docker-compose.yml",
	}
	probe := regexp.MustCompile(`(?m)^\s*test:.*https://localhost:8443/health.*$`)
	for _, f := range files {
		t.Run(f, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(repoRoot, f))
			if err != nil {
				t.Fatalf("read %s: %v", f, err)
			}
			lines := probe.FindAllString(string(data), -1)
			if len(lines) == 0 {
				t.Fatalf("%s has no healthcheck test probing https://localhost:8443/health", f)
			}
			for _, l := range lines {
				if strings.Contains(l, "--spider") {
					t.Errorf("healthcheck uses --spider (HEAD, 405 from the qrdb host): %s", strings.TrimSpace(l))
				}
				if !strings.Contains(l, `"-O", "/dev/null"`) {
					t.Errorf(`healthcheck does not GET into "-O", "/dev/null": %s`, strings.TrimSpace(l))
				}
				if !strings.Contains(l, "--ca-certificate=/etc/xkms/certs/ca.crt") {
					t.Errorf("healthcheck does not verify against /etc/xkms/certs/ca.crt: %s", strings.TrimSpace(l))
				}
			}
		})
	}
}

// TestBootstrapTrapPrintsHealthState pins the integration-test-bootstrap
// failure trap to print the xkms-server container's health state after its
// log, so an "unhealthy" stop shows the failing probe output.
func TestBootstrapTrapPrintsHealthState(t *testing.T) {
	recipe := mustMakeRecipe(t, readMakefile(t), "integration-test-bootstrap")

	var trapLine string
	for _, l := range strings.Split(recipe, "\n") {
		if strings.Contains(l, "--- xkms-server log ---") {
			trapLine = l
			break
		}
	}
	if trapLine == "" {
		t.Fatalf("integration-test-bootstrap has no '--- xkms-server log ---' trap:\n%s", recipe)
	}
	inspect := regexp.MustCompile(`docker inspect --format "\{\{json \.State\.Health\}\}" [^;]*xkms-server`)
	loc := inspect.FindStringIndex(trapLine)
	if loc == nil {
		t.Fatalf("the trap does not print the xkms-server health state with docker inspect: %s", trapLine)
	}
	if hdr := strings.Index(trapLine, "--- xkms-server log ---"); hdr > loc[0] {
		t.Errorf("the health state prints before the log: %s", trapLine)
	}
}
