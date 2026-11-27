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
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// composeHealthcheck is the xkms-server healthcheck in docker-compose.yml.
type composeHealthcheck struct {
	Test        []string `yaml:"test"`
	Interval    string   `yaml:"interval"`
	Timeout     string   `yaml:"timeout"`
	Retries     int      `yaml:"retries"`
	StartPeriod string   `yaml:"start_period"`
}

func loadServerHealthcheck(t *testing.T) composeHealthcheck {
	t.Helper()
	raw, err := os.ReadFile("docker-compose.yml")
	if err != nil {
		t.Fatalf("read docker-compose.yml: %v", err)
	}
	var doc struct {
		Services map[string]struct {
			Healthcheck composeHealthcheck `yaml:"healthcheck"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse docker-compose.yml: %v", err)
	}
	svc, ok := doc.Services["xkms-server"]
	if !ok {
		t.Fatal("docker-compose.yml has no xkms-server service")
	}
	return svc.Healthcheck
}

func mustDuration(t *testing.T, field, v string) time.Duration {
	t.Helper()
	d, err := time.ParseDuration(v)
	if err != nil {
		t.Fatalf("healthcheck %s %q: %v", field, v, err)
	}
	return d
}

// TestHealthcheckWindowExceedsEnrolWait checks that compose waits for the
// server at least as long as enrol-admin-client.sh waits for the daemon:
// a shorter window marks the container unhealthy while enrolment can still
// succeed.
func TestHealthcheckWindowExceedsEnrolWait(t *testing.T) {
	hc := loadServerHealthcheck(t)
	window := mustDuration(t, "start_period", hc.StartPeriod) +
		time.Duration(hc.Retries)*mustDuration(t, "interval", hc.Interval)

	script, err := os.ReadFile(filepath.Join("scripts", "enrol-admin-client.sh"))
	if err != nil {
		t.Fatalf("read enrol-admin-client.sh: %v", err)
	}
	m := regexp.MustCompile(`ENROL_WAIT_SECONDS:-([0-9]+)`).FindSubmatch(script)
	if m == nil {
		t.Fatal("enrol-admin-client.sh sets no default ENROL_WAIT_SECONDS")
	}
	secs, _ := strconv.Atoi(string(m[1]))
	wait := time.Duration(secs) * time.Second
	if window <= wait {
		t.Fatalf("healthcheck window %s (start_period + retries x interval) does not exceed the enrol wait %s", window, wait)
	}
}

// TestHealthcheckProbeUsesGET checks that the healthcheck probes /health with
// GET: the endpoint answers HEAD with 405, so `wget --spider` (HEAD) or
// `curl -I` never passes and the container stays unhealthy (CI 2964e51e4).
func TestHealthcheckProbeUsesGET(t *testing.T) {
	probe := strings.Join(loadServerHealthcheck(t).Test, " ")
	for _, head := range []string{"--spider", "--head", "curl -I", " -I "} {
		if strings.Contains(probe, head) {
			t.Fatalf("healthcheck probes /health with HEAD (%q), which answers 405: %s", head, probe)
		}
	}
	for _, want := range []string{"admin-client.bound", "curl", "/health"} {
		if !strings.Contains(probe, want) {
			t.Fatalf("healthcheck lacks %q: %s", want, probe)
		}
	}
}

// TestMakefileBootstrapDumpsServerOnFailure checks that a failed
// integration-test-bootstrap run prints the stack state, the xkms-server
// logs (without key material) and its health record before `down -v`
// removes them.
func TestMakefileBootstrapDumpsServerOnFailure(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	text := string(raw)
	start := strings.Index(text, "\nintegration-test-bootstrap:")
	if start < 0 {
		t.Fatal("Makefile has no integration-test-bootstrap target")
	}
	recipe := text[start+1:]
	if end := strings.Index(recipe, "\n\n"); end >= 0 {
		recipe = recipe[:end]
	}
	for _, want := range []string{
		"run --build --rm test ||",
		"ps -a",
		"logs --no-color",
		"xkms-server",
		"grep -v 'PRIVATE KEY'",
		".State.Health",
		"exit $$rc",
		"down -v",
	} {
		if !strings.Contains(recipe, want) {
			t.Errorf("integration-test-bootstrap recipe lacks %q", want)
		}
	}
}
