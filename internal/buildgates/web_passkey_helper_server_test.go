package buildgates

import (
	"os"
	"strings"
	"testing"
)

const (
	webPasskeyHelper     = "../../test/integration/web/tests/support/passkeyAccount.ts"
	webPlaywrightConfig  = "../../test/integration/web/playwright.config.ts"
	webPlaywrightNodeCfg = "../../test/integration/web/playwright.node.config.ts"
)

func readWebFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}

func requireContains(t *testing.T, path, body string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(body, w) {
			t.Errorf("%s: missing %q", path, w)
		}
	}
}

// TestWebPasskeyHelperFollowsTheRunningServer requires the web tier's
// passkey provisioning helper to address the server of the Playwright config
// that runs it: playwright.node.config.ts boots its daemon on 18464 with
// state under .runtime-node, so a helper pinned to 18463 and .runtime/storage
// sends every administrator call to a server that is not running.
func TestWebPasskeyHelperFollowsTheRunningServer(t *testing.T) {
	t.Run("helper derives origin and runtime", func(t *testing.T) {
		body := readWebFile(t, webPasskeyHelper)
		for _, forbidden := range []string{"localhost:18463", "/.runtime/storage"} {
			if strings.Contains(body, forbidden) {
				t.Errorf("%s: contains hard-coded %q; derive it from the running config", webPasskeyHelper, forbidden)
			}
		}
		requireContains(t, webPasskeyHelper, body, "project.use.baseURL", "config.metadata")
	})

	t.Run("node config declares its runtime", func(t *testing.T) {
		body := readWebFile(t, webPlaywrightNodeCfg)
		requireContains(t, webPlaywrightNodeCfg, body, "runtime: '.runtime-node'", "https://localhost:18464")
		const wantEnv = "XKMS_E2E_RUNTIME=.runtime-node"
		idx := strings.Index(body, "webServer:")
		if idx < 0 {
			t.Fatalf("%s: missing %q", webPlaywrightNodeCfg, "webServer:")
		}
		server := body[idx:]
		cmdIdx := strings.Index(server, "command:")
		if cmdIdx < 0 {
			t.Fatalf("%s: webServer missing %q", webPlaywrightNodeCfg, "command:")
		}
		line, _, _ := strings.Cut(server[cmdIdx:], "\n")
		if !strings.Contains(line, wantEnv) {
			t.Errorf("%s: webServer command %q missing %q (must match metadata runtime)", webPlaywrightNodeCfg, line, wantEnv)
		}
	})

	t.Run("default config declares its runtime", func(t *testing.T) {
		body := readWebFile(t, webPlaywrightConfig)
		requireContains(t, webPlaywrightConfig, body, "runtime: '.runtime'")
	})
}
