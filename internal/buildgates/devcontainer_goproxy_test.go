package buildgates

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestDevcontainerGOPROXYUsesImageCache pins the devcontainer stage to
// resolve modules from the image's prefetched module cache before the public
// proxy, so builds inside the devcontainer do not refetch their build list.
func TestDevcontainerGOPROXYUsesImageCache(t *testing.T) {
	const want = "file:///opt/go/mod/cache/download|https://proxy.golang.org|direct"

	data, err := os.ReadFile(filepath.Join(repoRoot, "build/docker/devcontainer/Dockerfile"))
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	full := string(data)

	stageStart := regexp.MustCompile(`(?m)^FROM toolchain AS devcontainer\s*$`).FindStringIndex(full)
	if stageStart == nil {
		t.Fatal("Dockerfile has no 'FROM toolchain AS devcontainer' stage")
	}
	stage := full[stageStart[0]:]

	if !strings.Contains(stage, "XKMS_DEVCONTAINER=1") {
		t.Fatal("devcontainer stage has no ENV block with XKMS_DEVCONTAINER=1")
	}

	matches := regexp.MustCompile(`(?m)^\s*GOPROXY=(\S+)`).FindAllStringSubmatch(stage, -1)
	if len(matches) != 1 {
		t.Fatalf("devcontainer stage sets GOPROXY %d times, want exactly 1", len(matches))
	}
	got := matches[0][1]
	if got != want {
		t.Errorf("devcontainer GOPROXY = %q, want %q", got, want)
	}
	if strings.Contains(got, ",") {
		t.Errorf("devcontainer GOPROXY %q uses a comma, which falls through only on 404/410", got)
	}
	if first := strings.Split(got, "|")[0]; first != "file:///opt/go/mod/cache/download" {
		t.Errorf("devcontainer GOPROXY first entry = %q, want the image module cache", first)
	}

	if !strings.Contains(full, "COPY --from=modules /opt/go/mod /opt/go/mod") {
		t.Error("Dockerfile no longer copies the module cache into /opt/go/mod")
	}
}
