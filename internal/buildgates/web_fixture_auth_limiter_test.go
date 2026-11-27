package buildgates

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// loadWebFixtureConfig parses one integration fixture's config.yaml.
func loadWebFixtureConfig(t *testing.T, path string) *config.Config {
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

// browserFixtureLoginRate returns the webauthn-browser fixture's login rate,
// the floor every browser fixture's limiter must reach.
func browserFixtureLoginRate(t *testing.T) int {
	t.Helper()
	browser := loadWebFixtureConfig(t, "../../test/integration/webauthn-browser/config.yaml")
	if browser.Auth.Session == nil || browser.Auth.Session.LoginRatePerMin <= 0 {
		t.Fatal("webauthn-browser fixture must set auth.session.login_rate_per_min > 0")
	}
	return browser.Auth.Session.LoginRatePerMin
}

// TestWebNodeFixtureLoginLimiterCoversTheSuite guards the node browser
// fixture's login limiter. The passkey node suite runs serial
// provisionOperator ceremonies (registration refusal, invite begin/finish,
// login begin/finish, /auth/me, then logout/login) from one address in
// seconds; the auth limiter's 10/min production default would answer 429
// before the suite reaches the node-user behaviour it verifies.
func TestWebNodeFixtureLoginLimiterCoversTheSuite(t *testing.T) {
	want := browserFixtureLoginRate(t)

	node := loadWebFixtureConfig(t, "../../test/integration/web/config-node.yaml")
	if node.Auth.Session == nil {
		t.Fatalf("config-node.yaml has no auth.session: the login limiter falls back to its 10/min default, "+
			"which the serial provisionOperator calls of the passkey node suite exceed; set login_rate_per_min >= %d", want)
	}
	if got := node.Auth.Session.LoginRatePerMin; got < want {
		t.Fatalf("config-node.yaml auth.session.login_rate_per_min = %d, want >= %d: the 10/min default "+
			"throttles the serial provisionOperator calls of the passkey node suite", got, want)
	}
}

// TestWebMainFixtureLoginLimiterCoversTheSuite guards the main web fixture's
// login limiter. auth.spec.ts and key-lifecycle.spec.ts provision their
// operators through provisionOperator invitations, each several limited
// requests from one address; the 10/min default would answer 429.
func TestWebMainFixtureLoginLimiterCoversTheSuite(t *testing.T) {
	want := browserFixtureLoginRate(t)

	mainFixture := loadWebFixtureConfig(t, "../../test/integration/web/config.yaml")
	if mainFixture.Auth.Session == nil {
		t.Fatalf("web/config.yaml has no auth.session: the login limiter falls back to its 10/min default, "+
			"which the provisionOperator calls of auth.spec.ts and key-lifecycle.spec.ts exceed; "+
			"set login_rate_per_min >= %d", want)
	}
	if got := mainFixture.Auth.Session.LoginRatePerMin; got < want {
		t.Fatalf("web/config.yaml auth.session.login_rate_per_min = %d, want >= %d: the 10/min default "+
			"throttles the provisionOperator calls of auth.spec.ts and key-lifecycle.spec.ts", got, want)
	}
}
