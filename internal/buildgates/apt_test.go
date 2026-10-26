package buildgates

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const (
	// dockerImagesDir holds the devcontainer and its sidecar images.
	dockerImagesDir = "../../build/docker"
	// aptConfigFile is the shared apt configuration (go-xkms#342): retries
	// with backoff and fetch timeouts, so an archive outage costs retries
	// rather than a red image build.
	aptConfigFile = "apt-retries.conf"
	aptConfigPath = dockerImagesDir + "/devcontainer/" + aptConfigFile
	// aptConfigTarget is where each stage installs it, before any apt-get.
	aptConfigTarget = "/etc/apt/apt.conf.d/80-retries"
)

// aptConfigKeys are the settings the shared file must carry, each with a
// value that enables it.
var aptConfigKeys = []string{
	"Acquire::Retries",
	"Acquire::Retries::Delay",
	"Acquire::Retries::Delay::Maximum",
	"Acquire::http::Timeout",
	"Acquire::https::Timeout",
}

// ciBuiltDockerfiles are the images .github/workflows/ci.yml builds outside
// dockerImagesDir: Dockerfile.cli in the image job on every pull request, and
// the root Dockerfile and the backend test images in the full-tier
// integration job's `make integration-test`. Each builds from the repository
// root, so each copies the shared file from dockerImagesDir.
var ciBuiltDockerfiles = []string{
	"../../Dockerfile",
	"../../Dockerfile.cli",
	"../../test/integration/awskms/Dockerfile",
	"../../test/integration/azurekv/Dockerfile",
	"../../test/integration/bootstrap/Dockerfile.test",
	"../../test/integration/frost/Dockerfile",
	"../../test/integration/gcpkms/Dockerfile",
	"../../test/integration/pkcs11/Dockerfile",
	"../../test/integration/pkcs11/module/Dockerfile",
	"../../test/integration/pkcs8/Dockerfile",
	"../../test/integration/quantum/Dockerfile",
	"../../test/integration/storage/Dockerfile",
	"../../test/integration/tpm2/Dockerfile",
	"../../test/integration/vault/Dockerfile",
}

var (
	aptCommand   = regexp.MustCompile(`\bapt(-get)?\s+(update|install|upgrade|dist-upgrade)\b`)
	aptUpdate    = regexp.MustCompile(`\bapt(-get)?\s+update\b`)
	aptInstall   = regexp.MustCompile(`\bapt(-get)?\s+install\b`)
	heredocStart = regexp.MustCompile(`<<-?\s*["']?([A-Za-z_][A-Za-z0-9_]*)["']?`)
)

// instruction is one Dockerfile instruction with its continuation lines
// joined.
type instruction struct {
	line int    // 1-based line of the instruction's first line
	op   string // the keyword, upper-cased
	args string
}

// skippable reports whether a Dockerfile line carries no instruction text:
// blank lines and comments, which Docker also drops inside continuations.
func skippable(text string) bool {
	return text == "" || strings.HasPrefix(text, "#")
}

// dockerInstructions splits a Dockerfile into its instructions. Comment
// lines are dropped, backslash continuations joined and heredoc bodies
// skipped, so text inside a here-document is never read as an instruction.
func dockerInstructions(body string) []instruction {
	lines := strings.Split(body, "\n")
	var out []instruction
	for i := 0; i < len(lines); i++ {
		text := strings.TrimSpace(lines[i])
		if skippable(text) {
			continue
		}
		start := i + 1
		var joined strings.Builder
		for strings.HasSuffix(text, "\\") && i+1 < len(lines) {
			joined.WriteString(strings.TrimSuffix(text, "\\"))
			joined.WriteByte(' ')
			i++
			text = strings.TrimSpace(lines[i])
			for skippable(text) && i+1 < len(lines) {
				i++
				text = strings.TrimSpace(lines[i])
			}
		}
		joined.WriteString(strings.TrimSuffix(text, "\\"))

		op, args, _ := strings.Cut(joined.String(), " ")
		in := instruction{line: start, op: strings.ToUpper(op), args: strings.TrimSpace(args)}
		out = append(out, in)
		if in.op == "RUN" || in.op == "COPY" {
			if m := heredocStart.FindStringSubmatch(in.args); m != nil {
				for i++; i < len(lines) && strings.TrimSpace(lines[i]) != m[1]; i++ {
				}
			}
		}
	}
	return out
}

// installsAptConfig reports whether a COPY instruction installs the shared
// apt configuration from the build context at aptConfigTarget.
func installsAptConfig(args string) bool {
	fields := strings.Fields(args)
	if len(fields) < 2 || fields[len(fields)-1] != aptConfigTarget {
		return false
	}
	for _, f := range fields[:len(fields)-1] {
		if strings.HasPrefix(f, "--from") {
			return false
		}
		if path.Base(f) == aptConfigFile {
			return true
		}
	}
	return false
}

// fromStage returns the base a FROM instruction builds on and the name it
// gives the new stage, both lower-cased as Docker matches them.
func fromStage(args string) (base, name string) {
	var fields []string
	for _, f := range strings.Fields(args) {
		if !strings.HasPrefix(f, "--") {
			fields = append(fields, strings.ToLower(f))
		}
	}
	if len(fields) == 0 {
		return "", ""
	}
	if len(fields) >= 3 && fields[len(fields)-2] == "as" {
		name = fields[len(fields)-1]
	}
	return fields[0], name
}

// aptLayerProblems lists every apt layer of one Dockerfile that is not
// outage-tolerant: one that runs before its stage (or a stage it is built
// FROM) installs the shared apt configuration, one that sets apt options
// inline instead, one that splits apt-get update from the install (a cached
// update layer goes stale), and, in a Dockerfile that already installs with
// --no-install-recommends, one that installs recommends.
func aptLayerProblems(name, body string) []string {
	instructions := dockerInstructions(body)
	var noRecommends bool
	for _, in := range instructions {
		if in.op == "RUN" && strings.Contains(in.args, "--no-install-recommends") {
			noRecommends = true
		}
	}
	configured := map[string]bool{}
	var problems []string
	var stage string
	var hasConfig bool
	report := func(in instruction, problem string) {
		problems = append(problems, fmt.Sprintf("%s:%d: %s", name, in.line, problem))
	}
	for _, in := range instructions {
		switch in.op {
		case "FROM":
			var base string
			base, stage = fromStage(in.args)
			hasConfig = configured[base]
		case "COPY":
			if installsAptConfig(in.args) {
				hasConfig = true
			}
		case "RUN":
			if strings.Contains(in.args, "Acquire::") {
				report(in, "sets apt options inline; COPY "+aptConfigFile+" to "+aptConfigTarget+" instead")
			}
			if !aptCommand.MatchString(in.args) {
				break
			}
			if !hasConfig {
				report(in, "runs apt before the stage installs "+aptConfigFile+" at "+aptConfigTarget)
			}
			update, install := aptUpdate.MatchString(in.args), aptInstall.MatchString(in.args)
			if install && !update {
				report(in, "installs without apt-get update in the same RUN")
			}
			if update && !install {
				report(in, "runs apt-get update without the install in the same RUN")
			}
			if noRecommends && install && !strings.Contains(in.args, "--no-install-recommends") {
				report(in, "installs recommends where the Dockerfile otherwise uses --no-install-recommends")
			}
		}
		if stage != "" {
			configured[stage] = hasConfig
		}
	}
	return problems
}

// dockerfiles lists every Dockerfile* under dir, sorted.
func dockerfiles(dir string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasPrefix(d.Name(), "Dockerfile") {
			files = append(files, p)
		}
		return nil
	})
	sort.Strings(files)
	return files, err
}

// aptConfigProblems lists every required setting the shared apt
// configuration lacks or disables.
func aptConfigProblems(body string) []string {
	var problems []string
	for _, key := range aptConfigKeys {
		setting := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(key) + `\s+"([^"]*)";`)
		m := setting.FindStringSubmatch(body)
		switch {
		case m == nil:
			problems = append(problems, key+" is not set")
		case m[1] == "" || m[1] == "0" || m[1] == "false":
			problems = append(problems, key+" is disabled ("+m[1]+")")
		}
	}
	return problems
}

func TestDockerfileAptLayersUseTheSharedRetryConfig(t *testing.T) {
	files, err := dockerfiles(dockerImagesDir)
	if err != nil {
		t.Fatalf("list %s: %v", dockerImagesDir, err)
	}
	if len(files) == 0 {
		t.Fatalf("no Dockerfile under %s", dockerImagesDir)
	}
	for _, f := range append(files, ciBuiltDockerfiles...) {
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, p := range aptLayerProblems(f, string(body)) {
			t.Error(p)
		}
	}
}

func TestSharedAptConfigCarriesRetriesAndTimeouts(t *testing.T) {
	body, err := os.ReadFile(aptConfigPath)
	if err != nil {
		t.Fatalf("read %s: %v", aptConfigPath, err)
	}
	for _, p := range aptConfigProblems(string(body)) {
		t.Errorf("%s: %s", aptConfigPath, p)
	}
}

// TestAptLayerProblemsCatchTheRevertedForm is the revert proof: the tools
// stage as it stood before go-xkms#342, with the retry setting written inline
// by printf, fails the gate.
func TestAptLayerProblemsCatchTheRevertedForm(t *testing.T) {
	const reverted = `FROM ${GO_IMAGE} AS tools
RUN printf 'Acquire::Retries "5";\nAcquire::http::Timeout "30";\n' > /etc/apt/apt.conf.d/80-retries
RUN apt-get update && apt-get install -y --no-install-recommends xz-utils && \
    rm -rf /var/lib/apt/lists/*
`
	problems := aptLayerProblems("Dockerfile", reverted)
	want := []string{
		"Dockerfile:2: sets apt options inline",
		"Dockerfile:3: runs apt before the stage installs",
	}
	if len(problems) != len(want) {
		t.Fatalf("want %d problems, got %q", len(want), problems)
	}
	for i, w := range want {
		if !strings.HasPrefix(problems[i], w) {
			t.Errorf("problem %d: want prefix %q, got %q", i, w, problems[i])
		}
	}
}

func TestAptLayerProblemsCatchEachViolation(t *testing.T) {
	const install = "COPY apt-retries.conf " + aptConfigTarget + "\n"
	tests := []struct {
		name string
		body string
		want string
	}{
		{"no config", "FROM debian\nRUN apt-get update && apt-get install -y --no-install-recommends curl\n", "runs apt before"},
		{"config copied from another stage", "FROM debian\nCOPY --from=x apt-retries.conf " + aptConfigTarget + "\nRUN apt-get update && apt-get install -y --no-install-recommends curl\n", "runs apt before"},
		{"config to another path", "FROM debian\nCOPY apt-retries.conf /etc/apt/apt.conf.d/99-other\nRUN apt-get update && apt-get install -y --no-install-recommends curl\n", "runs apt before"},
		{"config in an unrelated stage", "FROM debian AS a\n" + install + "FROM debian\nRUN apt-get update && apt-get install -y --no-install-recommends curl\n", "runs apt before"},
		{"install without update", "FROM debian\n" + install + "RUN apt-get install -y --no-install-recommends curl\n", "installs without apt-get update"},
		{"update in its own layer", "FROM debian\n" + install + "RUN apt-get update\n", "without the install"},
		{"recommends", "FROM debian\n" + install + "RUN apt-get update && apt-get install -y --no-install-recommends jq\nRUN apt update && apt install -y curl\n", "installs recommends"},
		{"inline option", "FROM debian\n" + install + "RUN echo 'Acquire::Retries \"3\";' > /etc/apt/apt.conf.d/90-x\n", "sets apt options inline"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			problems := aptLayerProblems("Dockerfile", tt.body)
			if len(problems) != 1 || !strings.Contains(problems[0], tt.want) {
				t.Fatalf("want one problem containing %q, got %q", tt.want, problems)
			}
		})
	}
}

func TestAptLayerProblemsAcceptTheSharedConfig(t *testing.T) {
	const body = `# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM debian:bookworm-slim AS Base
COPY build/docker/devcontainer/apt-retries.conf /etc/apt/apt.conf.d/80-retries
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    # a comment line inside the continuation
    curl \
    && rm -rf /var/lib/apt/lists/*
FROM base AS child
RUN apt-get update && apt-get install -y --no-install-recommends jq
RUN cat > /usr/local/bin/hint.sh << 'EOF'
apt-get install fido2-tools
RUN apt-get install -y curl
EOF
RUN echo done
`
	if problems := aptLayerProblems("Dockerfile", body); len(problems) != 0 {
		t.Fatalf("want no problems, got %q", problems)
	}
}

// TestAptLayerProblemsAcceptRecommendsWhereNotThePattern keeps the gate to
// outage tolerance in a Dockerfile that never uses --no-install-recommends:
// adding the flag there could drop a package the image relies on.
func TestAptLayerProblemsAcceptRecommendsWhereNotThePattern(t *testing.T) {
	const body = "FROM golang:1.27.3-bookworm\n" +
		"COPY build/docker/devcontainer/apt-retries.conf " + aptConfigTarget + "\n" +
		"RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*\n"
	if problems := aptLayerProblems("Dockerfile", body); len(problems) != 0 {
		t.Fatalf("want no problems, got %q", problems)
	}
}

func TestAptConfigProblemsCatchAMissingOrDisabledSetting(t *testing.T) {
	body, err := os.ReadFile(aptConfigPath)
	if err != nil {
		t.Fatalf("read %s: %v", aptConfigPath, err)
	}
	for _, key := range aptConfigKeys {
		setting := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(key) + `\s+"[^"]*";`)
		removed := setting.ReplaceAllString(string(body), "")
		if problems := aptConfigProblems(removed); len(problems) != 1 || !strings.HasPrefix(problems[0], key+" is not set") {
			t.Errorf("without %s: want one problem naming it, got %q", key, problems)
		}
		disabled := setting.ReplaceAllString(string(body), key+` "0";`)
		if problems := aptConfigProblems(disabled); len(problems) != 1 || !strings.HasPrefix(problems[0], key+" is disabled") {
			t.Errorf("with %s disabled: want one problem naming it, got %q", key, problems)
		}
	}
}

func TestDockerfilesReportAMissingDirectory(t *testing.T) {
	if _, err := dockerfiles(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("want an error for a directory that does not exist")
	}
}
