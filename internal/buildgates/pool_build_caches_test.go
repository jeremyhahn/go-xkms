package buildgates

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Ruling 886: the images the pool jobs build fetch their packages through the
// LAN caches every pool names (DEVCACHE_APT_PROXY, DEVCACHE_APK_MIRROR,
// dept-infra hosts/ci-runners/build-package-caches.md); on a GitHub-hosted
// runner the variables are unset and the builds go to the public mirrors as
// before. Nothing of either cache is left in an image.

const (
	cachesRoot   = "../.."
	aptProxyDef  = `p=${APT_PROXY:+-o Acquire::http::Proxy=$APT_PROXY}`
	apkHelper    = "scripts/apk-mirror.sh"
	apkHelperDst = "target=/usr/local/bin/apk-mirror"
)

// aptBuilt are the apt-based Dockerfiles the pool jobs build.
var aptBuilt = []string{"build/docker/devcontainer/Dockerfile", "Dockerfile", "build/docker/devcontainer/Dockerfile.softfido"}

// apkBuilt are the apk-based ones, each with the build context that carries
// scripts/ (its compose services name it).
var apkBuilt = map[string]string{"test/docker/swtpm/Dockerfile": "scripts", "test/docker/softhsm/Dockerfile": "softhsm-pin"}

var (
	cacheStage   = regexp.MustCompile(`(?m)^FROM\s`)
	cacheRun     = regexp.MustCompile(`(?ms)^RUN .*?[^\\]$`)
	aptCall      = regexp.MustCompile(`apt-get\s+(\$p\s+)?(update|install|upgrade|dist-upgrade)\b`)
	aptBareCall  = regexp.MustCompile(`apt-get\s+(update|install|upgrade|dist-upgrade)\b`)
	apkBareCall  = regexp.MustCompile(`\bapk\s+(--no-cache\s+)?(add|upgrade|update)\b`)
	apkHelperUse = regexp.MustCompile(`\bapk-mirror\s`)
)

// aptCacheProblems: every apt-get that fetches goes through $p, defined in its
// RUN from APT_PROXY, which its stage declares.
func aptCacheProblems(name, df string) []string {
	var problems []string
	for _, stage := range cacheStage.Split(df, -1)[1:] {
		head := strings.SplitN(stage, "\n", 2)[0]
		uses := false
		for _, run := range cacheRun.FindAllString(stage, -1) {
			if !aptCall.MatchString(run) {
				continue
			}
			uses = true
			if aptBareCall.MatchString(run) {
				problems = append(problems, name+" stage "+head+" runs apt-get without $p: it would not take the pool's apt cache")
			}
			if !strings.Contains(run, aptProxyDef) {
				problems = append(problems, name+" stage "+head+" has an apt RUN that does not define "+aptProxyDef)
			}
		}
		if uses && !regexp.MustCompile(`(?m)^ARG APT_PROXY\b`).MatchString(stage) {
			problems = append(problems, name+" stage "+head+" uses $p without ARG APT_PROXY")
		}
	}
	return problems
}

// apkCacheProblems: every apk call goes through the bind-mounted helper, from
// the named context ctx, and its stage declares APK_MIRROR.
func apkCacheProblems(name, df, ctx string) []string {
	mount := "--mount=type=bind,from=" + ctx + ",source=apk-mirror.sh," + apkHelperDst
	var problems []string
	for _, stage := range cacheStage.Split(df, -1)[1:] {
		head := strings.SplitN(stage, "\n", 2)[0]
		if apkBareCall.MatchString(stage) {
			problems = append(problems, name+" stage "+head+" runs apk directly: want apk-mirror, so a pool build takes the LAN apk cache")
		}
		uses := false
		for _, run := range cacheRun.FindAllString(stage, -1) {
			if apkHelperUse.MatchString(run) {
				uses = true
				if !strings.Contains(run, mount) {
					problems = append(problems, name+" stage "+head+" runs apk-mirror without "+mount)
				}
			}
		}
		if uses && !regexp.MustCompile(`(?m)^ARG APK_MIRROR\b`).MatchString(stage) {
			problems = append(problems, name+" stage "+head+" uses apk-mirror without ARG APK_MIRROR")
		}
	}
	return problems
}

func readCacheFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(cachesRoot, rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestPoolBuiltImagesTakeTheLANCaches(t *testing.T) {
	for _, f := range aptBuilt {
		df := readCacheFile(t, f)
		if !aptCall.MatchString(df) {
			t.Errorf("%s runs no apt-get: the parse found nothing to check", f)
		}
		for _, p := range aptCacheProblems(f, df) {
			t.Error(p)
		}
	}
	for f, ctx := range apkBuilt {
		df := readCacheFile(t, f)
		if !apkHelperUse.MatchString(df) {
			t.Errorf("%s calls apk-mirror nowhere: the parse found nothing to check", f)
		}
		for _, p := range apkCacheProblems(f, df, ctx) {
			t.Error(p)
		}
	}
	if mk := readCacheFile(t, "Makefile"); !strings.Contains(mk, `$(if $(DEVCACHE_APT_PROXY),--build-arg APT_PROXY="$(DEVCACHE_APT_PROXY)")`) {
		t.Error("DEVCONTAINER_BUILD does not pass the pool's DEVCACHE_APT_PROXY as APT_PROXY")
	}
}

// TestPoolBuiltImagesComposeArgs: every compose service that builds one of
// those Dockerfiles passes the pool's variable, and an apk one the context
// its helper mount reads.
func TestPoolBuiltImagesComposeArgs(t *testing.T) {
	type build struct {
		Context            string            `yaml:"context"`
		Dockerfile         string            `yaml:"dockerfile"`
		Args               yaml.Node         `yaml:"args"`
		AdditionalContexts map[string]string `yaml:"additional_contexts"`
	}
	var checked int
	for _, f := range []string{"build/docker/devcontainer/compose.yaml", "test/integration/sdk/docker-compose.yml", "test/integration/api/docker-compose.yml"} {
		var doc struct {
			Services map[string]struct {
				Build *build `yaml:"build"`
			} `yaml:"services"`
		}
		if err := yaml.Unmarshal([]byte(readCacheFile(t, f)), &doc); err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for name, svc := range doc.Services {
			if svc.Build == nil {
				continue
			}
			b := svc.Build
			df := b.Dockerfile
			if df == "" {
				df = "Dockerfile"
			}
			path := filepath.ToSlash(filepath.Clean(filepath.Join(filepath.Dir(f), b.Context, df)))
			var arg, ctx string
			switch {
			case strings.HasSuffix(path, "test/docker/swtpm/Dockerfile"), strings.HasSuffix(path, "test/docker/softhsm/Dockerfile"):
				arg = "APK_MIRROR=${DEVCACHE_APK_MIRROR:-}"
				for k, v := range apkBuilt {
					if strings.HasSuffix(path, k) {
						ctx = v
					}
				}
			default:
				for _, a := range aptBuilt {
					if path == a {
						arg = "APT_PROXY=${DEVCACHE_APT_PROXY:-}"
					}
				}
			}
			if arg == "" {
				continue
			}
			checked++
			var args []string
			switch b.Args.Kind {
			case yaml.SequenceNode:
				_ = b.Args.Decode(&args)
			case yaml.MappingNode:
				for i := 0; i+1 < len(b.Args.Content); i += 2 {
					args = append(args, b.Args.Content[i].Value+"="+b.Args.Content[i+1].Value)
				}
			}
			found := false
			for _, a := range args {
				if a == arg {
					found = true
				}
			}
			if !found {
				t.Errorf("%s service %s builds %s without the build argument %s", f, name, path, arg)
			}
			if ctx != "" && !strings.HasSuffix(filepath.ToSlash(b.AdditionalContexts[ctx]), "/scripts") {
				t.Errorf("%s service %s builds %s without additional_contexts %s pointing at scripts/: its apk-mirror mount would find nothing", f, name, path, ctx)
			}
		}
	}
	if checked < 10 {
		t.Fatalf("checked %d compose builds; want at least 10: the parse found too little", checked)
	}
}

// TestCacheChecksCatchARegression: each check fails one broken form.
func TestCacheChecksCatchARegression(t *testing.T) {
	good := "FROM x AS a\nARG APT_PROXY=\nRUN " + aptProxyDef + "; \\\n    apt-get $p update && apt-get $p install -y curl\n"
	if p := aptCacheProblems("f", good); len(p) != 0 {
		t.Fatalf("a correct apt stage fails: %v", p)
	}
	for name, bad := range map[string]string{
		"apt-get without $p": "FROM x\nARG APT_PROXY=\nRUN " + aptProxyDef + "; apt-get update\n",
		"no p definition":    "FROM x\nARG APT_PROXY=\nRUN apt-get $p update\n",
		"no ARG":             "FROM x\nRUN " + aptProxyDef + "; apt-get $p update\n",
	} {
		if len(aptCacheProblems("f", bad)) == 0 {
			t.Errorf("%s passed", name)
		}
	}
	mount := "--mount=type=bind,from=scripts,source=apk-mirror.sh," + apkHelperDst
	if p := apkCacheProblems("f", "FROM alpine\nARG APK_MIRROR=\nRUN "+mount+" \\\n    apk-mirror add --no-cache git\n", "scripts"); len(p) != 0 {
		t.Fatalf("a correct apk stage fails: %v", p)
	}
	for name, bad := range map[string]string{
		"bare apk":          "FROM alpine\nARG APK_MIRROR=\nRUN apk --no-cache upgrade\n",
		"no mount":          "FROM alpine\nARG APK_MIRROR=\nRUN apk-mirror add git\n",
		"the wrong context": "FROM alpine\nARG APK_MIRROR=\nRUN --mount=type=bind,from=other,source=apk-mirror.sh," + apkHelperDst + " apk-mirror add git\n",
		"no ARG APK_MIRROR": "FROM alpine\nRUN " + mount + " apk-mirror add git\n",
	} {
		if len(apkCacheProblems("f", bad, "scripts")) == 0 {
			t.Errorf("%s passed", name)
		}
	}
}

// fakeApkXK records the repositories file as apk saw it and exits with
// FAKE_APK_STATUS.
const fakeApkXK = "#!/bin/sh\ncat \"$APK_REPOSITORIES\" > \"$FAKE_DIR/seen\"\nexit \"${FAKE_APK_STATUS:-0}\"\n"

func TestApkMirrorScript(t *testing.T) {
	script, err := filepath.Abs(filepath.Join(cachesRoot, apkHelper))
	if err != nil {
		t.Fatal(err)
	}
	const repos = "https://dl-cdn.alpinelinux.org/alpine/v3.24/main\n"
	for _, c := range []struct {
		name, mirror, status, wantSeen string
		wantCode                       int
	}{
		{"the pool's mirror", "http://cache.example:3143/alpine", "", "http://cache.example:3143/alpine/v3.24/main\n", 0},
		{"no mirror", "", "", repos, 0},
		{"a failed apk", "http://cache.example:3143/alpine/", "3", "http://cache.example:3143/alpine/v3.24/main\n", 3},
		{"a mirror that is no URL", "cache.example", "", "", 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "apk"), []byte(fakeApkXK), 0o755); err != nil { // #nosec G306 -- the stub must be executable
				t.Fatal(err)
			}
			rf := filepath.Join(dir, "repositories")
			if err := os.WriteFile(rf, []byte(repos), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("sh", script, "add", "git") // #nosec G204 -- the repository's own script
			cmd.Env = []string{"PATH=" + dir + string(os.PathListSeparator) + os.Getenv("PATH"), "APK_REPOSITORIES=" + rf,
				"APK_MIRROR=" + c.mirror, "FAKE_DIR=" + dir, "FAKE_APK_STATUS=" + c.status}
			out, err := cmd.CombinedOutput()
			code := 0
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if code != c.wantCode {
				t.Fatalf("exit %d; want %d\n%s", code, c.wantCode, out)
			}
			if seen, _ := os.ReadFile(filepath.Join(dir, "seen")); string(seen) != c.wantSeen {
				t.Fatalf("apk saw %q; want %q", seen, c.wantSeen)
			}
			if after, _ := os.ReadFile(rf); string(after) != repos {
				t.Fatalf("the repositories file was left as %q", after)
			}
		})
	}
}
