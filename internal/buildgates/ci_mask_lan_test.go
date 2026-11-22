package buildgates

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Ruling 887: internal addresses stay out of public repositories, and their
// CI logs count. A pool runner's environment names LAN addresses (the
// DEVCACHE_* caches, the GOPROXY module proxy, the LAN CI registry); a
// BuildKit build echoes its build arguments and `go env` prints GOPROXY.
// Every pool job therefore runs scripts/ci-mask-lan.sh before any step that
// builds, and the runner masks each address in every later log line.

const (
	maskLANScript = "scripts/ci-mask-lan.sh"
	maskLANRoot   = "../.."
)

// maskLANBuildStep is a step that builds or runs anything that could print
// the environment: make, docker, go, or the image wrappers.
var maskLANBuildStep = regexp.MustCompile(`(^|[\s;&|(` + "`" + `])(make|docker|go|scripts/in-toolchain-image\.sh|scripts/ci-image\.sh|scripts/ci-registry\.sh)(\s|$)`)

// maskLANPoolLabel names a runs-on that can reach the pools; the release
// runners are pool hosts too.
var maskLANPoolLabel = regexp.MustCompile(`self-hosted|bigdisk|codex|qwen|release`)

// maskLANProblems lists each pool job that builds without the mask step
// before its first build step. A pool job that builds nothing (one that only
// reads the other jobs' results, like a gate) prints no environment and is
// left alone.
func maskLANProblems(body []byte) []string {
	var wf struct {
		Jobs map[string]struct {
			RunsOn yaml.Node `yaml:"runs-on"`
			Steps  []struct {
				Name string `yaml:"name"`
				Run  string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(body, &wf); err != nil {
		return []string{"ci.yml does not parse: " + err.Error()}
	}
	var problems []string
	for name, job := range wf.Jobs {
		var rb strings.Builder
		var walk func(*yaml.Node)
		walk = func(n *yaml.Node) {
			rb.WriteString(n.Value + " ")
			for _, c := range n.Content {
				walk(c)
			}
		}
		walk(&job.RunsOn)
		if !maskLANPoolLabel.MatchString(rb.String()) {
			continue
		}
		mask, build := -1, -1
		for i, s := range job.Steps {
			if mask < 0 && strings.TrimSpace(s.Run) == maskLANScript {
				mask = i
			}
			if build < 0 && maskLANBuildStep.MatchString(s.Run) {
				build = i
			}
		}
		switch {
		case build < 0:
		case mask < 0:
			problems = append(problems, "pool job "+name+" never runs "+maskLANScript+": its log could print a LAN address (ruling 887)")
		case build < mask:
			problems = append(problems, "pool job "+name+" runs "+strings.TrimSpace(job.Steps[build].Name)+" before "+maskLANScript)
		}
	}
	slices.Sort(problems)
	return problems
}

func TestCIPoolJobsMaskTheLANAddresses(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(maskLANRoot, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range maskLANProblems(body) {
		t.Error(p)
	}
	const pool = "jobs:\n  a:\n    runs-on: [self-hosted, bigdisk-docker]\n    steps:\n"
	if p := maskLANProblems([]byte(pool + "      - run: " + maskLANScript + "\n      - run: make build\n")); len(p) != 0 {
		t.Fatalf("a masked pool job fails: %v", p)
	}
	for name, body := range map[string]string{
		"no mask step":                        pool + "      - run: make build\n",
		"the mask after build":                pool + "      - name: Build\n        run: docker build .\n      - run: " + maskLANScript + "\n",
		"a registry publish without the mask": pool + "      - run: ref=$(scripts/ci-registry.sh publish toolchain)\n",
		"a release job without the mask":      "jobs:\n  a:\n    runs-on: ${{ github.event_name == 'push' && 'release' || 'ubuntu-latest' }}\n    steps:\n      - run: make build\n",
	} {
		if len(maskLANProblems([]byte(body))) == 0 {
			t.Errorf("%s passed", name)
		}
	}
	if p := maskLANProblems([]byte("jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make build\n")); len(p) != 0 {
		t.Fatalf("a hosted job was held to the pool rule: %v", p)
	}
	if p := maskLANProblems([]byte(pool + "      - run: echo \"$RESULTS\"\n")); len(p) != 0 {
		t.Fatalf("a pool job that builds nothing was held to the rule: %v", p)
	}
}

func TestCIMaskLANScript(t *testing.T) {
	script, err := filepath.Abs(filepath.Join(maskLANRoot, maskLANScript))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", script) // #nosec G204 -- the repository's own script
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"DEVCACHE_APT_PROXY=http://192.168.77.7:3142",
		"DEVCACHE_APK_MIRROR=http://192.168.77.7:3143/alpine",
		"GOPROXY=http://10.1.2.3:3300|https://proxy.golang.org,direct", // lab-string-ok: placeholder private address; the test proves ci-mask-lan.sh masks a private GOPROXY entry (ruling 910)
		"CI_REGISTRY=172.20.0.5:5005",
		// ci-registry.sh publishes to RELEASE_REGISTRY and resolves from the
		// forge's own host, GITHUB_SERVER_URL (Codex P1 on #2273).
		"RELEASE_REGISTRY=172.21.0.9:5443",
		"GITHUB_SERVER_URL=http://10.9.8.7:8443",
		"OTHER=http://192.168.9.9:1",
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", maskLANScript, err, out)
	}
	got := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, want := range []string{
		"::add-mask::http://192.168.77.7:3142", "::add-mask::192.168.77.7:3142", "::add-mask::192.168.77.7",
		"::add-mask::http://192.168.77.7:3143/alpine", "::add-mask::192.168.77.7:3143",
		"::add-mask::http://10.1.2.3:3300", "::add-mask::10.1.2.3",
		"::add-mask::172.20.0.5:5005", "::add-mask::172.20.0.5",
		"::add-mask::172.21.0.9:5443", "::add-mask::172.21.0.9",
		"::add-mask::http://10.9.8.7:8443", "::add-mask::10.9.8.7:8443", "::add-mask::10.9.8.7",
	} {
		if !slices.Contains(got, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
	for _, l := range got {
		if strings.Contains(l, "proxy.golang.org") || strings.Contains(l, "direct") || strings.Contains(l, "192.168.9.9") {
			t.Errorf("masked %q: a public host, a keyword or a variable outside the list", l)
		}
	}
	// Codex P1 on #2340: a host name is classified in any letter case and
	// with its terminal dot removed. Codex round 2 on #2346: each mask is
	// printed as written and, when that differs, lowercased, because
	// scripts/ci-registry.sh push_host lowercases RELEASE_REGISTRY and logs it.
	for _, tc := range []struct {
		name, env string
		want      []string
	}{
		{"an upper-case LAN suffix", "DEVCACHE_GO=http://cache.INTERNAL:3300/go",
			[]string{"http://cache.INTERNAL:3300/go", "cache.INTERNAL:3300", "cache.INTERNAL",
				"http://cache.internal:3300/go", "cache.internal:3300", "cache.internal"}},
		{"a fully qualified LAN name", "CI_IMAGE_REGISTRY=registry.lan.:5000",
			[]string{"registry.lan.:5000", "registry.lan."}},
		{"a fully qualified mixed-case name with no port", "RELEASE_REGISTRY=Pkgs.Home.Arpa.",
			[]string{"Pkgs.Home.Arpa.", "pkgs.home.arpa."}},
		// The registry helper's form: push_host prints ${RELEASE_REGISTRY,,},
		// and the login line logs it.
		{"a mixed-case release registry as the registry helper logs it", "RELEASE_REGISTRY=Pkgs.Home.Arpa:5000",
			[]string{"Pkgs.Home.Arpa:5000", "Pkgs.Home.Arpa", "pkgs.home.arpa:5000", "pkgs.home.arpa"}},
		{"a fully qualified single label", "GOPROXY=http://buildcache.:3000",
			[]string{"http://buildcache.:3000", "buildcache.:3000", "buildcache."}},
		{"a fully qualified public host and an upper-case keyword", "GOPROXY=https://Proxy.Golang.Org.,DIRECT",
			nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("bash", script) // #nosec G204 -- the repository's own script
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), tc.env}
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%s: %v\n%s", maskLANScript, err, out)
			}
			var got []string
			for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				if l != "" {
					got = append(got, strings.TrimPrefix(l, "::add-mask::"))
				}
			}
			slices.Sort(got)
			want := slices.Clone(tc.want)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Errorf("%s: masks %q, want %q", tc.env, got, want)
			}
		})
	}
	public := exec.Command("bash", script) // #nosec G204 -- the repository's own script
	public.Env = []string{"PATH=" + os.Getenv("PATH"), "GITHUB_SERVER_URL=https://github.com"}
	if out, err := public.CombinedOutput(); err != nil || strings.TrimSpace(string(out)) != "" {
		t.Errorf("on github.com the script masks %q (%v): want nothing", out, err)
	}
}
