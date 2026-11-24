package buildgates

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// docsPathsRoot is the repository root seen from this package directory.
var docsPathsRoot = filepath.Join("..", "..")

func docsPathsRead(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(docsPathsRoot, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

var xkmsdExecStart = regexp.MustCompile(`(?m)^ExecStart=\S*/xkmsd(\s|$)`)

// xkmsdUnits returns every systemd unit under deploy/ and configs/ whose
// ExecStart runs xkmsd (go-xkms#2256: two such units named different
// config files).
func xkmsdUnits(t *testing.T) []string {
	t.Helper()
	var units []string
	for _, dir := range []string{"deploy", "configs"} {
		err := filepath.WalkDir(filepath.Join(docsPathsRoot, dir), func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || filepath.Ext(p) != ".service" {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if xkmsdExecStart.Match(b) {
				rel, _ := filepath.Rel(docsPathsRoot, p)
				units = append(units, filepath.ToSlash(rel))
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	return units
}

func TestOneXkmsdSystemdUnit(t *testing.T) {
	units := xkmsdUnits(t)
	if len(units) != 1 {
		t.Fatalf("want exactly one systemd unit running xkmsd under deploy/ and configs/, got %v", units)
	}
}

var (
	etcConfigRef  = regexp.MustCompile(`/etc/xkms/([\w.-]+\.ya?ml)`)
	repoConfigRef = regexp.MustCompile(`\bconfigs/([\w.-]+\.ya?ml)`)
)

// TestDeployConfigPathsExist asserts every config file the deploy README and
// the xkmsd unit name exists under configs/ by its base name.
func TestDeployConfigPathsExist(t *testing.T) {
	files := append([]string{"deploy/README.md", "deploy/openrc/xkms", "deploy/openrc/xkms.confd"}, xkmsdUnits(t)...)
	for _, f := range files {
		text := docsPathsRead(t, f)
		var names []string
		for _, m := range etcConfigRef.FindAllStringSubmatch(text, -1) {
			names = append(names, m[1])
		}
		for _, m := range repoConfigRef.FindAllStringSubmatch(text, -1) {
			names = append(names, m[1])
		}
		for _, n := range names {
			if _, err := os.Stat(filepath.Join(docsPathsRoot, "configs", n)); err != nil {
				t.Errorf("%s names config %s, but configs/%s does not exist", f, n, n)
			}
		}
	}
}

var (
	bundleJoin  = regexp.MustCompile(`filepath\.Join\(dataDir, "([^"]+)"\)`)
	initDataDir = regexp.MustCompile(`--data-dir\s+(\S+)`)
)

// docsPathsStep returns numbered step n of the "Bootstrap a new server"
// list in text, continuation lines included.
func docsPathsStep(t *testing.T, text string, n string) string {
	t.Helper()
	_, sec, ok := strings.Cut(text, "## Bootstrap a new server")
	if !ok {
		t.Fatal("user.md has no \"Bootstrap a new server\" section")
	}
	sec, _, _ = strings.Cut(sec, "\n## ")
	var b strings.Builder
	in := false
	for _, line := range strings.Split(sec, "\n") {
		if regexp.MustCompile(`^\d+\. `).MatchString(line) {
			in = strings.HasPrefix(line, n+". ")
		}
		if in {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	if b.Len() == 0 {
		t.Fatalf("user.md has no step %s", n)
	}
	return b.String()
}

// TestInitCeremonyStep3NamesWrittenBundle asserts user.md step 3 names the
// bundle file persistCABundle writes, at the --data-dir step 2 passes.
func TestInitCeremonyStep3NamesWrittenBundle(t *testing.T) {
	src := docsPathsRead(t, "cmd/xkmsd/init_ceremony.go")
	_, body, ok := strings.Cut(src, "func persistCABundle(")
	if !ok {
		t.Fatal("persistCABundle not found in cmd/xkmsd/init_ceremony.go")
	}
	body, _, _ = strings.Cut(body, "\n}\n")
	m := bundleJoin.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("persistCABundle has no filepath.Join(dataDir, \"<name>\")")
	}
	bundle := m[1]

	doc := docsPathsRead(t, "docs/init-ceremony/user.md")
	dd := initDataDir.FindStringSubmatch(docsPathsStep(t, doc, "2"))
	if dd == nil {
		t.Fatal("user.md step 2 passes no --data-dir")
	}
	want := "`" + filepath.ToSlash(filepath.Join(dd[1], bundle)) + "`"
	if step3 := docsPathsStep(t, doc, "3"); !strings.Contains(step3, want) {
		t.Errorf("user.md step 3 must name %s (persistCABundle under --data-dir), got:\n%s", want, step3)
	}
}

// TestInitCeremonyDistributesServerTrust pins the trust split of the init
// ceremony guide: the ceremony CA (ca-bundle.pem, spki-pin.txt) is the root
// the administrator's client certificate chains to, while first-contact
// clients pin the running server's TLS certificate and fetch its bundle from
// /v1/ca/bootstrap (docs/trust-bootstrap/user.md).
func TestInitCeremonyDistributesServerTrust(t *testing.T) {
	doc := docsPathsRead(t, "docs/init-ceremony/user.md")
	_, sec, ok := strings.Cut(doc, "## Bootstrap a new server")
	if !ok {
		t.Fatal("user.md has no \"Bootstrap a new server\" section")
	}
	sec, _, _ = strings.Cut(sec, "\n## ")
	n := len(regexp.MustCompile(`(?m)^\d+\. `).FindAllString(sec, -1))

	if step1 := docsPathsStep(t, doc, "1"); strings.Contains(step1, "advertises the CA bundle init wrote") {
		t.Errorf("user.md step 1 must not say xkmsd run serves the ceremony bundle as server trust, got:\n%s", step1)
	}
	if step3 := docsPathsStep(t, doc, "3"); !strings.Contains(step3, "ca-bundle.pem") ||
		!strings.Contains(step3, "client") || strings.Contains(step3, "first-contact") {
		t.Errorf("user.md step 3 must call ca-bundle.pem the client-authentication root, not first-contact trust, got:\n%s", step3)
	}

	start := 0
	for i := 1; i <= n; i++ {
		s := docsPathsStep(t, doc, strconv.Itoa(i))
		if start == 0 {
			if strings.Contains(s, "xkmsd --config") {
				start = i
			}
			continue
		}
		if strings.Contains(s, "xkmsctl bootstrap spki show-pin --cert-file") &&
			strings.Contains(s, "bootstrap auto") && strings.Contains(s, "--spki-pin") &&
			strings.Contains(s, "--bundle-path /v1/ca/bootstrap") {
			return
		}
	}
	if start == 0 {
		t.Fatal("user.md has no step that starts the daemon (xkmsd --config)")
	}
	t.Errorf("user.md has no step after the daemon start (step %d) that pins the server's TLS certificate "+
		"(xkmsctl bootstrap spki show-pin --cert-file) and fetches /v1/ca/bootstrap with bootstrap auto --spki-pin", start)
}

// TestInitCeremonyPinFromServerHost guards Codex round 5 on #2263: the pin the
// operator distributes must come from an authenticated source. A certificate
// fetched over the network from another machine lets an interceptor choose the
// pin, so the step takes it on the server host, from loopback or tls.cert_file.
func TestInitCeremonyPinFromServerHost(t *testing.T) {
	doc := docsPathsRead(t, "docs/init-ceremony/user.md")
	_, sec, ok := strings.Cut(doc, "## Bootstrap a new server")
	if !ok {
		t.Fatal("user.md has no \"Bootstrap a new server\" section")
	}
	sec, _, _ = strings.Cut(sec, "\n## ")
	n := len(regexp.MustCompile(`(?m)^\d+\. `).FindAllString(sec, -1))

	step := ""
	for i := 1; i <= n; i++ {
		if s := docsPathsStep(t, doc, strconv.Itoa(i)); strings.Contains(s, "xkmsctl bootstrap spki show-pin --cert-file") {
			step = s
			break
		}
	}
	if step == "" {
		t.Fatal("user.md has no step that computes the pin (xkmsctl bootstrap spki show-pin --cert-file)")
	}

	for _, m := range regexp.MustCompile(`openssl s_client[^\n]*-connect\s+(\S+)`).FindAllStringSubmatch(step, -1) {
		target := m[1]
		if !strings.HasPrefix(target, "127.0.0.1:") && !strings.HasPrefix(target, "localhost:") &&
			!strings.HasPrefix(target, "[::1]:") {
			t.Errorf("user.md pin step fetches the certificate it pins from %q over the network; "+
				"take it on the server host from a loopback address (127.0.0.1, localhost, [::1])", target)
		}
	}
	if !strings.Contains(step, "on the server host") {
		t.Errorf("user.md pin step must say it runs on the server host, got:\n%s", step)
	}
	if !strings.Contains(step, "tls.cert_file") {
		t.Errorf("user.md pin step must name tls.cert_file as the alternative certificate source, got:\n%s", step)
	}
}

var (
	relConfigPath = regexp.MustCompile(`(?m)^\s*(?:path|socket_path):\s*["']?([^"'\s#]+)`)
	unitKeyLine   = regexp.MustCompile(`(?m)^(WorkingDirectory|ReadWritePaths|StateDirectory)=(.*)$`)
)

// TestXkmsdUnitWorkingDirectoryWritable: configs/xkmsd.yaml uses relative
// paths (xkms-data/...) that config loading does not rebase, so the unit
// must start in a directory it may write, not in /.
func TestXkmsdUnitWorkingDirectoryWritable(t *testing.T) {
	cfg := docsPathsRead(t, "configs/xkmsd.yaml")
	var rel []string
	for _, m := range relConfigPath.FindAllStringSubmatch(cfg, -1) {
		if !strings.HasPrefix(m[1], "/") {
			rel = append(rel, m[1])
		}
	}
	if len(rel) == 0 {
		return
	}
	unit := docsPathsRead(t, "configs/xkmsd.service")
	var wd string
	writable := map[string]bool{}
	for _, m := range unitKeyLine.FindAllStringSubmatch(unit, -1) {
		val := strings.TrimSpace(m[2])
		switch m[1] {
		case "WorkingDirectory":
			wd = strings.TrimPrefix(val, "-")
		case "ReadWritePaths":
			for _, p := range strings.Fields(val) {
				writable[strings.TrimPrefix(p, "-")] = true
			}
		case "StateDirectory":
			for _, p := range strings.Fields(val) {
				writable["/var/lib/"+p] = true
			}
		}
	}
	if wd == "" {
		t.Fatalf("configs/xkmsd.service has no WorkingDirectory=, but configs/xkmsd.yaml uses relative paths %v (resolved against /)", rel)
	}
	if !writable[filepath.Clean(wd)] {
		t.Errorf("configs/xkmsd.service WorkingDirectory=%s is not a ReadWritePaths/StateDirectory entry %v", wd, writable)
	}
}

// docsPathsSteps splits the "Bootstrap a new server" numbered list into steps.
func docsPathsSteps(t *testing.T, text string) []string {
	t.Helper()
	_, sec, ok := strings.Cut(text, "## Bootstrap a new server")
	if !ok {
		t.Fatal("user.md has no \"Bootstrap a new server\" section")
	}
	sec, _, _ = strings.Cut(sec, "\n## ")
	num := regexp.MustCompile(`^\d+\. `)
	var steps []string
	for _, line := range strings.Split(sec, "\n") {
		if num.MatchString(line) {
			steps = append(steps, "")
		}
		if len(steps) > 0 {
			steps[len(steps)-1] += line + "\n"
		}
	}
	return steps
}

// TestInitCeremonySetsDatastorePathBeforeInit: init keeps a configured
// datastore.path (resolveInitNodeConfig), so changing it after init splits
// init and run across two datastores.
func TestInitCeremonySetsDatastorePathBeforeInit(t *testing.T) {
	steps := docsPathsSteps(t, docsPathsRead(t, "docs/init-ceremony/user.md"))
	runsInit := regexp.MustCompile(`(?m)^\s*xkmsd init\b`)
	initStep, dsStep := -1, -1
	for i, s := range steps {
		if initStep < 0 && runsInit.MatchString(s) {
			initStep = i
		}
		if dsStep < 0 && strings.Contains(s, "datastore.path") {
			dsStep = i
		}
	}
	if initStep < 0 {
		t.Fatal("user.md bootstrap list has no step running xkmsd init")
	}
	if dsStep < 0 || dsStep >= initStep {
		t.Errorf("user.md must set datastore.path before step %d (xkmsd init); first mention is step %d", initStep+1, dsStep+1)
	}
	change := regexp.MustCompile(`(?i)\b(set|change|update|edit)\b[^.]*datastore\.path`)
	for i := initStep + 1; i < len(steps); i++ {
		if change.MatchString(steps[i]) {
			t.Errorf("user.md step %d changes datastore.path after xkmsd init:\n%s", i+1, steps[i])
		}
	}
}

// unitFiles returns the base names of every systemd unit under deploy/ and
// configs/.
func unitFiles(t *testing.T) map[string]bool {
	t.Helper()
	names := map[string]bool{}
	for _, dir := range []string{"deploy", "configs"} {
		err := filepath.WalkDir(filepath.Join(docsPathsRoot, dir), func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && filepath.Ext(p) == ".service" {
				names[filepath.Base(p)] = true
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	return names
}

var (
	unitDepRef     = regexp.MustCompile(`(?m)^(?:After|Before|Wants|Requires|BindsTo|PartOf)=(.*)$`)
	xkmsUnitName   = regexp.MustCompile(`^xkms[\w-]*\.service$`)
	systemctlXkmsd = regexp.MustCompile(`(?:systemctl (?:enable|start|status|reload|stop|restart|disable)|journalctl -u) (xkms[\w-]*)\b`)
)

// TestUnitDependenciesNameExistingUnits asserts every xkms* unit a unit under
// deploy/ or configs/ orders against or depends on exists there (go-xkms#2256:
// xkey.service ordered after the removed xkms.service).
func TestUnitDependenciesNameExistingUnits(t *testing.T) {
	units := unitFiles(t)
	for u := range units {
		text := docsPathsRead(t, unitPath(t, u))
		for _, m := range unitDepRef.FindAllStringSubmatch(text, -1) {
			for _, dep := range strings.Fields(m[1]) {
				if xkmsUnitName.MatchString(dep) && !units[dep] {
					t.Errorf("%s names %s, which no unit under deploy/ or configs/ provides", u, dep)
				}
			}
		}
	}
}

// unitPath returns the repository path of the unit with base name u.
func unitPath(t *testing.T, u string) string {
	t.Helper()
	for _, dir := range []string{"configs", "deploy/systemd"} {
		p := filepath.Join(dir, u)
		if _, err := os.Stat(filepath.Join(docsPathsRoot, p)); err == nil {
			return p
		}
	}
	t.Fatalf("unit %s is neither in configs/ nor deploy/systemd/", u)
	return ""
}

// TestDocsSystemctlNameExistingUnits asserts the systemctl and journalctl
// commands in the READMEs name a unit that exists.
func TestDocsSystemctlNameExistingUnits(t *testing.T) {
	units := unitFiles(t)
	for _, f := range []string{"README.md", "deploy/README.md"} {
		for _, m := range systemctlXkmsd.FindAllStringSubmatch(docsPathsRead(t, f), -1) {
			if !units[m[1]+".service"] {
				t.Errorf("%s runs %q, but no unit %s.service exists under deploy/ or configs/", f, m[0], m[1])
			}
		}
	}
}

// TestXkmsdUnitReadsDocumentedEnvironmentFile asserts the xkmsd unit loads the
// environment file the deploy README tells operators to create.
func TestXkmsdUnitReadsDocumentedEnvironmentFile(t *testing.T) {
	const env = "/etc/xkms/environment"
	if !strings.Contains(docsPathsRead(t, "deploy/README.md"), env) {
		t.Skip("deploy/README.md documents no environment file")
	}
	for _, u := range xkmsdUnits(t) {
		if !regexp.MustCompile(`(?m)^EnvironmentFile=-?` + regexp.QuoteMeta(env) + `$`).MatchString(docsPathsRead(t, u)) {
			t.Errorf("%s does not load %s, which deploy/README.md tells operators to create", u, env)
		}
	}
}
