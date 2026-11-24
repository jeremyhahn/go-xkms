package buildgates

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// TestWebNodeFixtureLoginLimiterCoversTheSuite guards the node browser
// fixture's login limiter. The passkey node suite runs serial
// provisionOperator ceremonies (registration refusal, invite begin/finish,
// login begin/finish, /auth/me, then logout/login) from one address in
// seconds; the auth limiter's 10/min production default would answer 429
// before the suite reaches the node-user behaviour it verifies.
func TestWebNodeFixtureLoginLimiterCoversTheSuite(t *testing.T) {
	load := func(path string) *config.Config {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var cfg config.Config
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		return &cfg
	}

	browser := load("../../test/integration/webauthn-browser/config.yaml")
	if browser.Auth.Session == nil || browser.Auth.Session.LoginRatePerMin <= 0 {
		t.Fatal("webauthn-browser fixture must set auth.session.login_rate_per_min > 0")
	}
	want := browser.Auth.Session.LoginRatePerMin

	node := load("../../test/integration/web/config-node.yaml")
	if node.Auth.Session == nil {
		t.Fatalf("config-node.yaml has no auth.session: the login limiter falls back to its 10/min default, "+
			"which the serial provisionOperator calls of the passkey node suite exceed; set login_rate_per_min >= %d", want)
	}
	if got := node.Auth.Session.LoginRatePerMin; got < want {
		t.Fatalf("config-node.yaml auth.session.login_rate_per_min = %d, want >= %d: the 10/min default "+
			"throttles the serial provisionOperator calls of the passkey node suite", got, want)
	}
}
