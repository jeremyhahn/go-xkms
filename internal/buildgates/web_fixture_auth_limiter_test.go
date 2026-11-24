package buildgates

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

// webFixtureMinLoginRate is the login limiter rate the webauthn-browser
// fixture (test/integration/webauthn-browser/config.yaml) runs its serial
// ceremonies under. The production default (10/min, burst 10) throttles a
// browser suite that signs in from one address several times a minute: the
// web tier's serial node tests then fail with 429.
const webFixtureMinLoginRate = 6000

// TestWebFixtureConfigsRaiseTheAuthLimiter requires every web-tier daemon
// config to raise auth.session.login_rate_per_min as the webauthn-browser
// fixture does. The limiter stays on; only its rate is raised.
func TestWebFixtureConfigsRaiseTheAuthLimiter(t *testing.T) {
	for _, path := range []string{
		"../../test/integration/web/config.yaml",
		"../../test/integration/web/config-node.yaml",
	} {
		t.Run(path, func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			var cfg struct {
				Auth struct {
					Session struct {
						LoginRatePerMin int `yaml:"login_rate_per_min"`
					} `yaml:"session"`
				} `yaml:"auth"`
			}
			if err := yaml.Unmarshal(raw, &cfg); err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			if got := cfg.Auth.Session.LoginRatePerMin; got < webFixtureMinLoginRate {
				t.Fatalf("%s: auth.session.login_rate_per_min = %d, want >= %d (as webauthn-browser/config.yaml)",
					path, got, webFixtureMinLoginRate)
			}
		})
	}
}
