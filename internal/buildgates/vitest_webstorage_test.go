package buildgates

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// webstorageVitestConfigs are the vitest configs that turn Node's Web Storage
// off in their workers (#2167).
var webstorageVitestConfigs = []string{
	"sdk/ts/svelte-auth/vitest.config.ts",
	"web/app/vite.config.ts",
	"xkey/frontend/vitest.config.ts",
}

// webstorageFlagGuard is the token a config must use to pass
// --no-experimental-webstorage only to a Node that knows the flag.
const webstorageFlagGuard = "allowedNodeEnvironmentFlags"

var (
	nodePinRE         = regexp.MustCompile(`(?m)^NODE_VERSION=v(\d+)\.(\d+)\.(\d+)`)
	literalWebstoreRE = regexp.MustCompile(`execArgv:\s*\[\s*["']--no-experimental-webstorage`)
)

// TestVitestWebstorageFlagGuardedForPinnedNode checks that no vitest config
// hands --no-experimental-webstorage to a Node that rejects it. The flag
// exists from Node 22.4; the CI image's Node (scripts/tool-pins.sh) is older,
// and an unknown execArgv makes every vitest worker exit.
func TestVitestWebstorageFlagGuardedForPinnedNode(t *testing.T) {
	pins, err := os.ReadFile(filepath.Join(repoRoot, "scripts", "tool-pins.sh"))
	if err != nil {
		t.Fatalf("read scripts/tool-pins.sh: %v", err)
	}
	m := nodePinRE.FindSubmatch(pins)
	if m == nil {
		t.Fatal("scripts/tool-pins.sh: no NODE_VERSION=vMAJOR.MINOR.PATCH line")
	}
	major, _ := strconv.Atoi(string(m[1]))
	minor, _ := strconv.Atoi(string(m[2]))
	pinned := "v" + string(m[1]) + "." + string(m[2]) + "." + string(m[3])
	knowsFlag := major > 22 || (major == 22 && minor >= 4)

	for _, cfg := range webstorageVitestConfigs {
		data, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(cfg)))
		if err != nil {
			t.Fatalf("read %s: %v", cfg, err)
		}
		src := string(data)
		if !strings.Contains(src, "--no-experimental-webstorage") || knowsFlag {
			continue
		}
		if literalWebstoreRE.MatchString(src) {
			t.Errorf("%s passes --no-experimental-webstorage as a literal execArgv; the pinned NODE_VERSION=%s rejects it (flag exists from Node 22.4)", cfg, pinned)
		}
		if !strings.Contains(src, webstorageFlagGuard) {
			t.Errorf("%s does not guard --no-experimental-webstorage with %s; the pinned NODE_VERSION=%s rejects it", cfg, webstorageFlagGuard, pinned)
		}
	}
}
