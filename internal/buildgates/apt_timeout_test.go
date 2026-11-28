package buildgates

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Issue #2307 (ruling 978): an apt-get update in an image build hung on the
// in-network apt cache's 503 race, and BuildKit merged a second run's
// identical step into the hung one. apt's Acquire timeouts never fired
// because the step never returned. Every apt fetch in a Dockerfile therefore
// runs under timeout(1), and every Integration step carries its own
// timeout-minutes so a stalled step fails instead of holding a runner for
// the job's whole limit.

var (
	aptTimeoutCall       = regexp.MustCompile(`\bapt-get\s+(\$p\s+)?(update|install|upgrade|dist-upgrade)\b`)
	aptTimeoutBefore     = regexp.MustCompile(`\btimeout [1-9][0-9]* $`)
	aptNodesource        = regexp.MustCompile(`deb\.nodesource\.com/setup[^|]*\|`)
	aptNodesourceBash    = regexp.MustCompile(`\bbash\b`)
	aptPlaywright        = regexp.MustCompile(`\bplaywright install --with-deps\b`)
	aptPlaywrightTimeout = regexp.MustCompile(`\btimeout [1-9][0-9]* (npx\s+(--yes\s+|-y\s+)?)?$`)
)

// aptTimeoutProblems reports each apt fetch of a Dockerfile not bounded by
// timeout, and the number of RUN instructions that fetch through apt.
func aptTimeoutProblems(name, df string) ([]string, int) {
	var problems []string
	runs := 0
	for _, loc := range cacheRun.FindAllStringIndex(df, -1) {
		run := df[loc[0]:loc[1]]
		line := strings.Count(df[:loc[0]], "\n") + 1
		apt := false
		for _, m := range aptTimeoutCall.FindAllStringIndex(run, -1) {
			apt = true
			if !aptTimeoutBefore.MatchString(run[:m[0]]) {
				problems = append(problems, fmt.Sprintf("%s: RUN at l.%d: %q runs without timeout", name, line, run[m[0]:m[1]]))
			}
		}
		for _, m := range aptNodesource.FindAllStringIndex(run, -1) {
			apt = true
			rest := run[m[1]:]
			b := aptNodesourceBash.FindStringIndex(rest)
			if b == nil || !aptTimeoutBefore.MatchString(rest[:b[0]]) {
				problems = append(problems, fmt.Sprintf("%s: RUN at l.%d: the nodesource setup script runs without timeout bash", name, line))
			}
		}
		for _, m := range aptPlaywright.FindAllStringIndex(run, -1) {
			apt = true
			if !aptPlaywrightTimeout.MatchString(run[:m[0]]) {
				problems = append(problems, fmt.Sprintf("%s: RUN at l.%d: playwright install --with-deps runs without timeout", name, line))
			}
		}
		if apt {
			runs++
		}
	}
	return problems, runs
}

func TestDockerfileAptRunsUnderTimeout(t *testing.T) {
	runs := 0
	err := filepath.WalkDir(cachesRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasPrefix(d.Name(), "Dockerfile") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(cachesRoot, path)
		problems, n := aptTimeoutProblems(filepath.ToSlash(rel), string(body))
		runs += n
		for _, p := range problems {
			t.Error(p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if runs < 66 {
		t.Fatalf("found %d apt RUN instructions, want at least 66 (the tracked Dockerfiles' apt RUN count): the walk is broken", runs)
	}
}

type timeoutWorkflow struct {
	Jobs map[string]struct {
		TimeoutMinutes any `yaml:"timeout-minutes"`
		Steps          []struct {
			Name           string `yaml:"name"`
			Uses           string `yaml:"uses"`
			Run            string `yaml:"run"`
			TimeoutMinutes any    `yaml:"timeout-minutes"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

// integrationTimeoutProblems reports each step of jobs.integration without an
// integer timeout-minutes in [1, the job's timeout-minutes).
func integrationTimeoutProblems(body []byte) []string {
	var wf timeoutWorkflow
	if err := yaml.Unmarshal(body, &wf); err != nil {
		return []string{fmt.Sprintf("parse: %v", err)}
	}
	job, ok := wf.Jobs["integration"]
	if !ok {
		return []string{"integration: no such job"}
	}
	limit, ok := job.TimeoutMinutes.(int)
	if !ok {
		return []string{fmt.Sprintf("integration: job timeout-minutes %v is not an integer", job.TimeoutMinutes)}
	}
	if len(job.Steps) == 0 {
		return []string{"integration: no steps"}
	}
	var problems []string
	for i, s := range job.Steps {
		name := s.Name
		if name == "" {
			name = s.Uses
		}
		if name == "" {
			name = fmt.Sprintf("step %d", i+1)
		}
		v, ok := s.TimeoutMinutes.(int)
		switch {
		case s.TimeoutMinutes == nil:
			problems = append(problems, fmt.Sprintf("integration: step %q has no timeout-minutes", name))
		case !ok:
			problems = append(problems, fmt.Sprintf("integration: step %q timeout-minutes %v is not an integer", name, s.TimeoutMinutes))
		case v < 1 || v >= limit:
			problems = append(problems, fmt.Sprintf("integration: step %q timeout-minutes %d is outside [1, %d)", name, v, limit))
		}
	}
	return problems
}

func TestIntegrationStepsHaveTimeoutMinutes(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(cachesRoot, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range integrationTimeoutProblems(body) {
		t.Error(p)
	}
}

func TestAptTimeout_CanFail(t *testing.T) {
	for name, df := range map[string]string{
		"first apt call unbounded": "FROM x\nRUN apt-get update && timeout 300 apt-get install -y x\n",
		"proxy form unbounded":     "FROM x\nRUN p=\"\"; timeout 300 apt-get $p update && \\\n    apt-get $p install -y x\n",
		"nodesource unbounded":     "FROM x\nRUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && timeout 300 apt-get install -y nodejs\n",
		"playwright unbounded":     "FROM x\nRUN npx playwright install --with-deps chrome\n",
	} {
		if p, _ := aptTimeoutProblems("Dockerfile", df); len(p) == 0 {
			t.Errorf("%s: no problem", name)
		}
	}
	bounded := "FROM x\n" +
		"RUN timeout 300 apt-get update && timeout 300 apt-get install -y x\n" +
		"RUN p=\"\"; timeout 300 apt-get $p update && \\\n    timeout 300 apt-get $p install -y x\n" +
		"RUN curl -fsSL https://deb.nodesource.com/setup_22.x | timeout 300 bash - && timeout 300 apt-get install -y nodejs\n" +
		"RUN timeout 600 npx playwright install --with-deps chrome\n"
	p, n := aptTimeoutProblems("Dockerfile", bounded)
	if len(p) != 0 {
		t.Fatalf("bounded forms fail: %q", p)
	}
	if n != 4 {
		t.Fatalf("counted %d apt RUNs, want 4", n)
	}

	const job = "jobs:\n  integration:\n    timeout-minutes: 180\n    steps:\n"
	if p := integrationTimeoutProblems([]byte(job + "      - name: a\n        timeout-minutes: 10\n        run: true\n")); len(p) != 0 {
		t.Fatalf("a bounded step fails: %q", p)
	}
	for name, body := range map[string]string{
		"step without timeout-minutes": job + "      - name: a\n        timeout-minutes: 10\n        run: true\n      - name: b\n        run: true\n",
		"step at the job's limit":      job + "      - name: a\n        timeout-minutes: 180\n        run: true\n",
		"step with zero":               job + "      - name: a\n        timeout-minutes: 0\n        run: true\n",
		"step with an expression":      job + "      - name: a\n        timeout-minutes: ${{ env.T }}\n        run: true\n",
		"no integration job":           "jobs:\n  other:\n    steps:\n      - run: true\n",
	} {
		p := integrationTimeoutProblems([]byte(body))
		if len(p) == 0 {
			t.Errorf("%s: no problem", name)
		}
		if name == "step without timeout-minutes" && !slices.ContainsFunc(p, func(s string) bool { return strings.Contains(s, `"b"`) }) {
			t.Errorf("%s: step b not named: %q", name, p)
		}
	}
}
