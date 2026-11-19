package buildgates

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Ruling 886: the images the pool jobs build fetch their packages through the
// LAN caches every pool names (DEVCACHE_APT_PROXY, DEVCACHE_APK_MIRROR,
// dept-infra hosts/ci-runners/build-package-caches.md); on a GitHub-hosted
// runner the variables are unset and the builds go to the public mirrors as
// before. Ruling 888: each cache reaches the build as a BuildKit secret
// (apt_proxy, apk_mirror), which the RUN mounts as APT_PROXY or APK_MIRROR,
// never as a build argument, whose value BuildKit records in the image
// history. Nothing of either cache is left in a layer or a history entry.

// aptProxyDef puts the proxy on apt-get's command line, which apt records in
// /var/log/apt/history.log, a file of the image (Codex P1 on #2273): with a
// proxy set it sends that log to /dev/null, so no layer keeps the address; a
// hosted build, with none, keeps its history log.
const (
	cachesRoot   = "../.."
	aptProxyDef  = `p=${APT_PROXY:+-o Acquire::http::Proxy=$APT_PROXY -o Dir::Log::History=/dev/null}`
	apkHelper    = "scripts/apk-mirror.sh"
	apkHelperDst = "target=/usr/local/bin/apk-mirror"
	aptSecret    = "--mount=type=secret,id=apt_proxy,env=APT_PROXY"
	apkSecret    = "--mount=type=secret,id=apk_mirror,env=APK_MIRROR"
)

// cacheArg finds a build argument that would carry a cache into the history.
var cacheArg = regexp.MustCompile(`(?m)^ARG (APT_PROXY|APK_MIRROR)\b`)

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
// RUN from APT_PROXY, which the RUN mounts from the secret apt_proxy; no
// stage declares the cache as a build argument.
func aptCacheProblems(name, df string) []string {
	var problems []string
	if m := cacheArg.FindString(df); m != "" {
		problems = append(problems, name+" declares "+m+": a build argument's value is recorded in the image history (ruling 888)")
	}
	for _, stage := range cacheStage.Split(df, -1)[1:] {
		head := strings.SplitN(stage, "\n", 2)[0]
		for _, run := range cacheRun.FindAllString(stage, -1) {
			if !aptCall.MatchString(run) {
				continue
			}
			if !strings.Contains(run, aptSecret) {
				problems = append(problems, name+" stage "+head+" has an apt RUN without "+aptSecret)
			}
			if aptBareCall.MatchString(run) {
				problems = append(problems, name+" stage "+head+" runs apt-get without $p: it would not take the pool's apt cache")
			}
			if !strings.Contains(run, aptProxyDef) {
				problems = append(problems, name+" stage "+head+" has an apt RUN that does not define "+aptProxyDef)
			}
		}
	}
	return problems
}

// apkCacheProblems: every apk call goes through the bind-mounted helper, from
// the named context ctx, with the secret apk_mirror mounted as APK_MIRROR; no
// stage declares the cache as a build argument.
func apkCacheProblems(name, df, ctx string) []string {
	mount := "--mount=type=bind,from=" + ctx + ",source=apk-mirror.sh," + apkHelperDst
	var problems []string
	if m := cacheArg.FindString(df); m != "" {
		problems = append(problems, name+" declares "+m+": a build argument's value is recorded in the image history (ruling 888)")
	}
	for _, stage := range cacheStage.Split(df, -1)[1:] {
		head := strings.SplitN(stage, "\n", 2)[0]
		if apkBareCall.MatchString(stage) {
			problems = append(problems, name+" stage "+head+" runs apk directly: want apk-mirror, so a pool build takes the LAN apk cache")
		}
		for _, run := range cacheRun.FindAllString(stage, -1) {
			if !apkHelperUse.MatchString(run) {
				continue
			}
			if !strings.Contains(run, mount) {
				problems = append(problems, name+" stage "+head+" runs apk-mirror without "+mount)
			}
			if !strings.Contains(run, apkSecret) {
				problems = append(problems, name+" stage "+head+" runs apk-mirror without "+apkSecret)
			}
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
}

// composeRE names a compose file: compose.yaml, docker-compose.yml and their
// overlays (compose.ci.yaml, docker-compose.test.yml).
var composeRE = regexp.MustCompile(`^(docker-)?compose(\.[a-z0-9-]+)*\.ya?ml$`)

// composeFiles lists every compose file of the repository, relative to its
// root: a service in any of them can build a pool image.
func composeFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(cachesRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules" || d.Name() == "vendor") {
			return filepath.SkipDir
		}
		if !d.IsDir() && composeRE.MatchString(d.Name()) {
			rel, err := filepath.Rel(cachesRoot, path)
			if err != nil {
				return err
			}
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk the repository: %v", err)
	}
	if len(files) < 20 {
		t.Fatalf("found %d compose files; want every one in the tree (at least 20): the walk found too little", len(files))
	}
	return files
}

// TestPoolBuiltImagesComposeArgs: every compose service, in any compose file
// of the tree, that builds one of those Dockerfiles passes the pool's cache
// as a build secret, and an apk one the context carrying scripts/; a caller
// without that context makes BuildKit look for an image named after it.
func TestPoolBuiltImagesComposeArgs(t *testing.T) {
	type build struct {
		Context            string            `yaml:"context"`
		Dockerfile         string            `yaml:"dockerfile"`
		Args               yaml.Node         `yaml:"args"`
		Secrets            []string          `yaml:"secrets"`
		AdditionalContexts map[string]string `yaml:"additional_contexts"`
	}
	var checked int
	for _, f := range composeFiles(t) {
		var doc struct {
			Services map[string]struct {
				Build yaml.Node `yaml:"build"`
			} `yaml:"services"`
			Secrets map[string]struct {
				Environment string `yaml:"environment"`
			} `yaml:"secrets"`
		}
		if err := yaml.Unmarshal([]byte(readCacheFile(t, f)), &doc); err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for name, svc := range doc.Services {
			b := &build{}
			switch svc.Build.Kind {
			case 0:
				continue
			case yaml.ScalarNode:
				b.Context = svc.Build.Value
			default:
				if err := svc.Build.Decode(b); err != nil {
					t.Errorf("%s service %s: its build does not parse: %v", f, name, err)
					continue
				}
			}
			df := b.Dockerfile
			if df == "" {
				df = "Dockerfile"
			}
			path := filepath.ToSlash(filepath.Clean(filepath.Join(filepath.Dir(f), b.Context, df)))
			var secret, ctx string
			switch {
			case strings.HasSuffix(path, "test/docker/swtpm/Dockerfile"), strings.HasSuffix(path, "test/docker/softhsm/Dockerfile"):
				secret = "apk_mirror"
				for k, v := range apkBuilt {
					if strings.HasSuffix(path, k) {
						ctx = v
					}
				}
			default:
				for _, a := range aptBuilt {
					if path == a {
						secret = "apt_proxy"
					}
				}
			}
			if secret == "" {
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
			for _, a := range args {
				if strings.HasPrefix(a, "APT_PROXY=") || strings.HasPrefix(a, "APK_MIRROR=") {
					t.Errorf("%s service %s passes %s as a build argument: its value is recorded in the image history (ruling 888)", f, name, a)
				}
			}
			if !slices.Contains(b.Secrets, secret) {
				t.Errorf("%s service %s builds %s without the build secret %s", f, name, path, secret)
			}
			want := "DEVCACHE_" + strings.ToUpper(secret)
			if got := doc.Secrets[secret].Environment; got != want {
				t.Errorf("%s defines the secret %s from environment %q; want %s", f, secret, got, want)
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

// aptMakeFlag is the secret a Makefile build of an apt-based pool image
// passes: the pool's cache, empty on a hosted runner where the variable is
// unset.
const aptMakeFlag = "--secret id=apt_proxy,env=DEVCACHE_APT_PROXY"

var (
	makeBuild = regexp.MustCompile(`docker (buildx )?build\s`)
	makeFile  = regexp.MustCompile(`\s-f\s+(\S+)`)
	makeDir   = regexp.MustCompile(`(?m)^DEVCONTAINER_DIR\s*:?=\s*(\S+)`)
)

// makefileCacheProblems: every Makefile docker build of an apt-based pool
// image passes aptMakeFlag. A build without -f builds the root Dockerfile; a
// comment that names a build is not one.
// It returns the problems and the number of such builds it checked.
func makefileCacheProblems(mk string) ([]string, int) {
	dir := ""
	if m := makeDir.FindStringSubmatch(mk); m != nil {
		dir = m[1]
	}
	logical := strings.ReplaceAll(mk, "\\\n", " ")
	var problems []string
	checked := 0
	for i, line := range strings.Split(logical, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") || !makeBuild.MatchString(line) {
			continue
		}
		df := "Dockerfile"
		if m := makeFile.FindStringSubmatch(line); m != nil {
			df = strings.ReplaceAll(m[1], "$(DEVCONTAINER_DIR)", dir)
		}
		for _, a := range aptBuilt {
			if df != a {
				continue
			}
			checked++
			if !strings.Contains(line, aptMakeFlag) {
				problems = append(problems, fmt.Sprintf("Makefile logical line %d builds %s without %s", i+1, df, aptMakeFlag))
			}
			if strings.Contains(line, "--build-arg APT_PROXY") {
				problems = append(problems, fmt.Sprintf("Makefile logical line %d passes APT_PROXY as a build argument: its value is recorded in the image history (ruling 888)", i+1))
			}
		}
	}
	return problems, checked
}

// TestPoolBuiltImagesMakefileArgs: the Makefile's builds of the apt-based pool
// images take the apt cache as a secret. docker-build-test-image, which
// `make docker-test` runs, builds the root Dockerfile directly, outside
// DEVCONTAINER_BUILD.
func TestPoolBuiltImagesMakefileArgs(t *testing.T) {
	problems, checked := makefileCacheProblems(readCacheFile(t, "Makefile"))
	for _, p := range problems {
		t.Error(p)
	}
	if checked < 2 {
		t.Fatalf("checked %d Makefile builds; want at least DEVCONTAINER_BUILD and docker-build-test-image", checked)
	}
	for _, proxy := range []string{"http://apt-cache.test:3142", ""} {
		cmd := exec.Command("make", "-n", "docker-build-test-image", "DEVCACHE_APT_PROXY="+proxy) // #nosec G204 -- a fixed target and a fixed value
		cmd.Dir = cachesRoot
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("make -n docker-build-test-image: %v\n%s", err, out)
		}
		if !strings.Contains(string(out), aptMakeFlag) {
			t.Errorf("make -n docker-build-test-image DEVCACHE_APT_PROXY=%q does not pass %s:\n%s", proxy, aptMakeFlag, out)
		}
		if strings.Contains(string(out), "--build-arg APT_PROXY") || strings.Contains(string(out), "apt-cache.test") {
			t.Errorf("make -n docker-build-test-image passes the cache as a build argument or on its command line:\n%s", out)
		}
	}
}

// TestCacheChecksCatchARegression: each check fails one broken form.
func TestCacheChecksCatchARegression(t *testing.T) {
	good := "FROM x AS a\nRUN " + aptSecret + " \\\n    " + aptProxyDef + "; \\\n    apt-get $p update && apt-get $p install -y curl\n"
	if p := aptCacheProblems("f", good); len(p) != 0 {
		t.Fatalf("a correct apt stage fails: %v", p)
	}
	for name, bad := range map[string]string{
		"apt-get without $p":                   "FROM x\nRUN " + aptSecret + " " + aptProxyDef + "; apt-get update\n",
		"no p definition":                      "FROM x\nRUN " + aptSecret + " apt-get $p update\n",
		"a proxy def that keeps apt's history": "FROM x\nRUN " + aptSecret + " p=${APT_PROXY:+-o Acquire::http::Proxy=$APT_PROXY}; apt-get $p update\n",
		"no secret mount":                      "FROM x\nRUN " + aptProxyDef + "; apt-get $p update\n",
		"the proxy as a build arg":             "FROM x\nARG APT_PROXY=\nRUN " + aptSecret + " " + aptProxyDef + "; apt-get $p update\n",
	} {
		if len(aptCacheProblems("f", bad)) == 0 {
			t.Errorf("%s passed", name)
		}
	}
	goodMk := "DEVCONTAINER_DIR := build/docker/devcontainer\nx:\n\tdocker buildx build --load \\\n\t\t" + aptMakeFlag + " \\\n\t\t-t i -f Dockerfile .\n"
	if p, n := makefileCacheProblems("# `docker build -t i` on one job retags that name\n" + goodMk); len(p) != 0 || n != 1 {
		t.Fatalf("a correct Makefile build fails: %v (checked %d)", p, n)
	}
	for name, bad := range map[string]string{
		"root image without the arg":         "x:\n\tdocker buildx build --load \\\n\t\t-t i -f Dockerfile .\n",
		"no -f builds the root image":        "x:\n\tdocker build -t i .\n",
		"devcontainer image without the arg": "DEVCONTAINER_DIR := build/docker/devcontainer\nB = docker buildx build \\\n\t-f $(DEVCONTAINER_DIR)/Dockerfile\n",
		"the proxy as a build arg":           "x:\n\tdocker buildx build " + aptMakeFlag + ` --build-arg APT_PROXY="$(DEVCACHE_APT_PROXY)" -f Dockerfile .` + "\n",
	} {
		if p, _ := makefileCacheProblems(bad); len(p) == 0 {
			t.Errorf("%s passed", name)
		}
	}
	mount := "--mount=type=bind,from=scripts,source=apk-mirror.sh," + apkHelperDst
	if p := apkCacheProblems("f", "FROM alpine\nRUN "+mount+" \\\n    "+apkSecret+" \\\n    apk-mirror add --no-cache git\n", "scripts"); len(p) != 0 {
		t.Fatalf("a correct apk stage fails: %v", p)
	}
	for name, bad := range map[string]string{
		"bare apk":                  "FROM alpine\nRUN apk --no-cache upgrade\n",
		"no mount":                  "FROM alpine\nRUN " + apkSecret + " apk-mirror add git\n",
		"the wrong context":         "FROM alpine\nRUN --mount=type=bind,from=other,source=apk-mirror.sh," + apkHelperDst + " " + apkSecret + " apk-mirror add git\n",
		"no secret mount":           "FROM alpine\nRUN " + mount + " apk-mirror add git\n",
		"the mirror as a build arg": "FROM alpine\nARG APK_MIRROR=\nRUN " + mount + " " + apkSecret + " apk-mirror add git\n",
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
