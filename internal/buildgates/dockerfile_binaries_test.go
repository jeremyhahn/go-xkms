package buildgates

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// serverDefaultCmd is the default command of every image that runs xkmsd:
// the protocol a server image serves comes from its config file, and xkmsd
// declares no other flag a default command could use (cmd/xkmsd/main.go).
var serverDefaultCmd = []string{"--config", "/etc/xkms/config.yaml"}

// minBinaryDockerfiles is the floor on Dockerfiles that build xkmsd or
// xkmsctl (Dockerfile, .rest, .grpc, .mcp, .quic, .server, .cli), so a parse
// that finds none fails instead of passing vacuously.
const minBinaryDockerfiles = 6

var cmdPackage = regexp.MustCompile(`^\./cmd/(xkmsd|xkmsctl)/?$`)

// dockerLine is one logical Dockerfile instruction: backslash-continued
// lines joined, numbered by the line it starts on.
type dockerLine struct {
	n    int
	text string
}

func logicalDockerLines(content string) []dockerLine {
	var out []dockerLine
	var cur strings.Builder
	start := 0
	for i, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if cur.Len() == 0 {
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			start = i + 1
		} else if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasSuffix(line, "\\") {
			cur.WriteString(strings.TrimSuffix(line, "\\"))
			cur.WriteString(" ")
			continue
		}
		cur.WriteString(line)
		out = append(out, dockerLine{n: start, text: cur.String()})
		cur.Reset()
	}
	if cur.Len() > 0 {
		out = append(out, dockerLine{n: start, text: cur.String()})
	}
	return out
}

func instruction(l dockerLine) (string, string) {
	keyword, rest, _ := strings.Cut(l.text, " ")
	return strings.ToUpper(keyword), strings.TrimSpace(rest)
}

// goBuildOutputs maps each `go build -o <out> ./cmd/<name>` output path in
// a RUN to the cmd directory name it builds.
func goBuildOutputs(run string) map[string]string {
	outs := map[string]string{}
	for _, cmd := range regexp.MustCompile(`&&|;|\|\|`).Split(run, -1) {
		fields := strings.Fields(cmd)
		isBuild := false
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "go" && fields[i+1] == "build" {
				isBuild = true
			}
		}
		if !isBuild {
			continue
		}
		out, name := "", ""
		for i, f := range fields {
			f = strings.Trim(f, `"'`)
			if f == "-o" && i+1 < len(fields) {
				out = strings.Trim(fields[i+1], `"'`)
			}
			if m := cmdPackage.FindStringSubmatch(f); m != nil {
				name = m[1]
			}
		}
		if out != "" && name != "" {
			outs[out] = name
		}
	}
	return outs
}

func execForm(arg string) ([]string, bool) {
	var v []string
	if err := json.Unmarshal([]byte(arg), &v); err != nil {
		return nil, false
	}
	return v, true
}

// dockerfileBinaryProblems checks one Dockerfile; matched reports whether it
// builds xkmsd or xkmsctl at all.
func dockerfileBinaryProblems(file, content string) (problems []string, matched bool) {
	lines := logicalDockerLines(content)
	outputs := map[string]string{} // build output path -> binary name
	built := map[string]bool{}
	for _, l := range lines {
		kw, rest := instruction(l)
		if kw != "RUN" {
			continue
		}
		for out, name := range goBuildOutputs(rest) {
			outputs[out] = name
			built[name] = true
			if path.Base(out) != name {
				problems = append(problems, fmt.Sprintf("%s:%d: go build -o %s ./cmd/%s: output must be named %s", file, l.n, out, name, name))
			}
		}
	}
	if len(outputs) == 0 {
		return nil, false
	}

	var entrypoint []string
	entrypointLine := 0
	var cmd []string
	cmdLine := 0
	cmdExec := false
	for _, l := range lines {
		kw, rest := instruction(l)
		switch kw {
		case "COPY":
			fields := strings.Fields(rest)
			fromStage := false
			var args []string
			for _, f := range fields {
				if strings.HasPrefix(f, "--from=") {
					fromStage = true
					continue
				}
				if strings.HasPrefix(f, "--") {
					continue
				}
				args = append(args, f)
			}
			if !fromStage || len(args) < 2 {
				continue
			}
			dest := args[len(args)-1]
			for _, src := range args[:len(args)-1] {
				name, ok := outputs[src]
				if !ok {
					continue
				}
				got := path.Base(dest)
				if strings.HasSuffix(dest, "/") {
					got = path.Base(src)
				}
				if got != name {
					problems = append(problems, fmt.Sprintf("%s:%d: COPY %s %s: %s must keep its name", file, l.n, src, dest, name))
				}
			}
		case "ENTRYPOINT":
			entrypointLine = l.n
			if v, ok := execForm(rest); ok {
				entrypoint = v
			} else {
				entrypoint = strings.Fields(rest)
			}
		case "CMD":
			cmdLine = l.n
			cmd, cmdExec = execForm(rest)
		}
	}

	if entrypointLine != 0 {
		got := ""
		if len(entrypoint) > 0 {
			got = path.Base(entrypoint[0])
		}
		if !built[got] {
			problems = append(problems, fmt.Sprintf("%s:%d: ENTRYPOINT %q must run the binary it builds (%s)", file, entrypointLine, entrypoint, strings.Join(sortedNames(built), " or ")))
		}
		if built["xkmsd"] {
			if !cmdExec || !equalStrings(cmd, serverDefaultCmd) {
				problems = append(problems, fmt.Sprintf("%s:%d: server image default CMD %q must be exec form %q", file, cmdLine, cmd, serverDefaultCmd))
			}
		}
	}
	return problems, true
}

func sortedNames(m map[string]bool) []string {
	var out []string
	for _, n := range []string{"xkmsd", "xkmsctl"} {
		if m[n] {
			out = append(out, n)
		}
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestDockerImagesShipBinariesUnderTheirOwnNames pins the binary names in
// every image (#2316): an image that builds ./cmd/xkmsd ships xkmsd and one
// that builds ./cmd/xkmsctl ships xkmsctl, and every server image starts
// xkmsd with the config-driven default command.
func TestDockerImagesShipBinariesUnderTheirOwnNames(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(repoRoot, "Dockerfile*"))
	if err != nil {
		t.Fatalf("glob Dockerfiles: %v", err)
	}
	var problems []string
	matched := 0
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		p, ok := dockerfileBinaryProblems(filepath.Base(f), string(data))
		if ok {
			matched++
		}
		problems = append(problems, p...)
	}
	if matched < minBinaryDockerfiles {
		problems = append(problems, fmt.Sprintf("only %d Dockerfiles build ./cmd/xkmsd or ./cmd/xkmsctl, want at least %d", matched, minBinaryDockerfiles))
	}
	if len(problems) > 0 {
		t.Errorf("Docker binary names:\n%s", strings.Join(problems, "\n"))
	}
}

func TestDockerfileBinaryProblemsCatchARenamedBinary(t *testing.T) {
	const df = `FROM golang AS builder
RUN go build \
    -o /build/xkms-grpc-server \
    ./cmd/xkmsd/
FROM debian
COPY --from=builder /build/xkms-grpc-server /app/xkms-grpc-server
ENTRYPOINT ["/app/xkms-grpc-server"]
CMD ["--port", "9443"]
`
	problems, matched := dockerfileBinaryProblems("Dockerfile.x", df)
	if !matched {
		t.Fatal("build of ./cmd/xkmsd not matched")
	}
	if len(problems) != 4 {
		t.Fatalf("want 4 problems (-o, COPY, ENTRYPOINT, CMD), got %d:\n%s", len(problems), strings.Join(problems, "\n"))
	}
	if !strings.HasPrefix(problems[0], "Dockerfile.x:2:") {
		t.Errorf("first problem not at the RUN line: %s", problems[0])
	}
}
