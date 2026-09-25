// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package gui

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/serverregistry"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/tokenstore"
)

// relaxedPolicyYAML is an enterprise policy file that relaxes every secure
// default this change guards: the values a local user would write to loosen
// the authenticator and the extension gates. The Require* fields are turned
// off so this fixture exercises FIDO2/extension propagation only; the
// startup-precondition gate they feed has its own fixtures and tests in
// TestCheckStartupPreconditions* and
// TestApp_ApplyVerifiedEnterprisePolicy_PreconditionsUnmet_KeepsDefaults
// (#668).
const relaxedPolicyYAML = `policy:
  require_so_pin: false
  require_user_pin: false
  require_encrypted_storage: false
  fido2_require_user_presence: false
  fido2_user_intent_check: false
  extension_enabled: true
  extension_require_authentication: false
  extension_force_audit: false
  extension_allowed_domains: ["relaxed.example"]
  extension_max_fills_per_minute: 7
`

// useRelaxedConfigDir points config.Load at a temp directory holding the
// relaxed policy file and returns the directory.
func useRelaxedConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	config.SetConfigDir(dir)
	t.Cleanup(config.ResetConfigDir)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "xkey.yaml"), []byte(relaxedPolicyYAML), 0o600))
	return dir
}

// sealRelaxedPolicy writes the HMAC that makes dir an enterprise directory,
// computed over the policy config.Load returns, so the seal verifies under
// soPIN.
func sealRelaxedPolicy(t *testing.T, dir, soPIN string) {
	t.Helper()
	cfg, err := config.Load()
	require.NoError(t, err)
	require.False(t, cfg.Policy.FIDO2RequireUserPresence, "the fixture must relax the default")
	require.NoError(t, config.WritePolicyHMAC(&cfg.Policy, soPIN, config.PolicyHMACPath(dir)))
}

// newPolicyTestApp is newMinimalApp plus a real in-memory authenticator on
// the secure defaults, so both policy consumers can be observed.
func newPolicyTestApp(t *testing.T) *App {
	t.Helper()
	app := newMinimalApp(t)
	auth, err := authenticator.NewAuthenticator(&authenticator.Config{
		Storage:               authenticator.NewMemoryStorage(),
		AAGUID:                authenticator.DefaultAAGUID,
		EnableResidentKey:     true,
		RequireUserPresence:   true,
		EnableUserIntentCheck: true,
		UserPresenceHandler:   authenticator.NewAutoGrantHandler(),
	})
	require.NoError(t, err)
	app.authenticatorInstance = auth
	return app
}

func TestStartupEnterprisePolicy_PersonalModeAppliesNothing(t *testing.T) {
	dir := useRelaxedConfigDir(t)

	assert.Nil(t, startupEnterprisePolicy(dir, stateTestLogger()),
		"without an HMAC file there is no enterprise policy to apply")
}

func TestStartupEnterprisePolicy_SealedFallsBackToDefaults(t *testing.T) {
	dir := useRelaxedConfigDir(t)
	sealRelaxedPolicy(t, dir, "so-pin-12345")

	pol := startupEnterprisePolicy(dir, stateTestLogger())

	require.NotNil(t, pol)
	assert.Equal(t, *config.DefaultPolicy(), *pol)
	assert.True(t, pol.FIDO2RequireUserPresence, "the file's relaxation must not reach the consumer before SO login")
	assert.True(t, pol.ExtensionRequireAuthentication)
	assert.Empty(t, pol.ExtensionAllowedDomains)
}

func TestStartupEnterprisePolicy_UnreadableConfigFallsBackToDefaults(t *testing.T) {
	dir := useRelaxedConfigDir(t)
	sealRelaxedPolicy(t, dir, "so-pin-12345")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "xkey.yaml"), []byte("policy: [not a mapping"), 0o600))

	pol := startupEnterprisePolicy(dir, stateTestLogger())

	require.NotNil(t, pol)
	assert.Equal(t, *config.DefaultPolicy(), *pol)
}

func TestApp_VerifiedSOLoginAppliesTheSealedPolicy(t *testing.T) {
	const soPIN = "so-pin-12345"
	dir := useRelaxedConfigDir(t)
	sealRelaxedPolicy(t, dir, soPIN)

	app := newPolicyTestApp(t)

	// Startup: the sealed section is unverified, so both consumers run on
	// the defaults.
	pol := startupEnterprisePolicy(dir, app.log)
	require.NotNil(t, pol)
	applyFIDO2Policy(app.authenticatorInstance, pol, app.log)
	applyExtensionPolicy(app.autofillService, pol)
	require.True(t, app.authenticatorInstance.Config().RequireUserPresence)
	require.True(t, app.authenticatorInstance.Config().EnableUserIntentCheck)
	require.True(t, app.autofillService.GetEnterprisePolicy().RequireAuthentication)

	// SO login through the real software PIN backend, wired the way NewApp
	// wires it.
	pinSvc := newStatePINService(t)
	require.NoError(t, pinSvc.SetSOPIN("", soPIN))
	authSvc := services.NewAuthService(pinSvc, dir)
	authSvc.SetVerifiedPolicyHandler(app.applyVerifiedEnterprisePolicy)

	result := authSvc.LoginSO(soPIN)

	require.True(t, result.Success)
	require.True(t, result.PolicyVerified)
	assert.False(t, app.authenticatorInstance.Config().RequireUserPresence, "the verified section now applies")
	assert.False(t, app.authenticatorInstance.Config().EnableUserIntentCheck)
	ext := app.autofillService.GetEnterprisePolicy()
	require.NotNil(t, ext)
	assert.False(t, ext.RequireAuthentication)
	assert.False(t, ext.ForceAudit)
	assert.Equal(t, []string{"relaxed.example"}, ext.AllowedDomains)
	assert.Equal(t, 7, ext.MaxFillsPerMinute)
}

func TestApp_TamperedPolicyKeepsTheDefaultsAfterSOLogin(t *testing.T) {
	const soPIN = "so-pin-12345"
	dir := useRelaxedConfigDir(t)
	// The seal was computed over a different section than the file holds.
	other := config.DefaultPolicy()
	require.NoError(t, config.WritePolicyHMAC(other, soPIN, config.PolicyHMACPath(dir)))

	app := newPolicyTestApp(t)
	pol := startupEnterprisePolicy(dir, app.log)
	require.NotNil(t, pol)
	applyFIDO2Policy(app.authenticatorInstance, pol, app.log)
	applyExtensionPolicy(app.autofillService, pol)

	pinSvc := newStatePINService(t)
	require.NoError(t, pinSvc.SetSOPIN("", soPIN))
	authSvc := services.NewAuthService(pinSvc, dir)
	authSvc.SetVerifiedPolicyHandler(app.applyVerifiedEnterprisePolicy)

	result := authSvc.LoginSO(soPIN)

	require.True(t, result.Success)
	require.True(t, result.TamperDetected)
	assert.True(t, app.authenticatorInstance.Config().RequireUserPresence, "a tampered section never reaches the consumer")
	assert.True(t, app.authenticatorInstance.Config().EnableUserIntentCheck)
	assert.True(t, app.autofillService.GetEnterprisePolicy().RequireAuthentication)
	assert.Empty(t, app.autofillService.GetEnterprisePolicy().AllowedDomains)
}

func TestApp_ApplyVerifiedEnterprisePolicy_ToleratesAbsentConsumers(t *testing.T) {
	app := &App{log: stateTestLogger()}

	assert.NotPanics(t, func() {
		app.applyVerifiedEnterprisePolicy(config.DefaultPolicy())
	})
}

// ---------------------------------------------------------------------------
// Require* startup preconditions (#668).
// ---------------------------------------------------------------------------

func TestCheckStartupPreconditions_AllUnmet(t *testing.T) {
	app := newMinimalApp(t)
	// newMinimalApp's config has no StorageType set and its PIN/TPM services
	// are freshly constructed with nothing configured, so every Require*
	// precondition below is unmet by the host.

	pol := &config.PolicySection{
		RequireSOPIN:            true,
		RequireUserPIN:          true,
		RequireEncryptedStorage: true,
		RequireTPM:              true,
	}

	err := app.checkStartupPreconditions(pol)
	require.Error(t, err)
	var precondErr *PolicyPreconditionError
	require.ErrorAs(t, err, &precondErr)
	assert.ElementsMatch(t, []string{
		"require_so_pin", "require_user_pin", "require_encrypted_storage", "require_tpm",
	}, precondErr.Unmet)
}

func TestCheckStartupPreconditions_NoneRequiredIsAlwaysMet(t *testing.T) {
	app := newMinimalApp(t)

	err := app.checkStartupPreconditions(config.DefaultPolicy())
	// DefaultPolicy sets RequireSOPIN/RequireUserPIN/RequireEncryptedStorage
	// true but not RequireTPM; none of the PIN/storage state is met by
	// newMinimalApp's fresh services, so this is expected to report the
	// three that DefaultPolicy turns on.
	require.Error(t, err)
	var precondErr *PolicyPreconditionError
	require.ErrorAs(t, err, &precondErr)
	assert.ElementsMatch(t, []string{
		"require_so_pin", "require_user_pin", "require_encrypted_storage",
	}, precondErr.Unmet)

	// And when nothing is required, an unconfigured host always satisfies it.
	err = app.checkStartupPreconditions(&config.PolicySection{})
	assert.NoError(t, err)
}

func TestCheckStartupPreconditions_PartiallyMet(t *testing.T) {
	app := newMinimalApp(t)
	app.pinService = newStatePINService(t)
	require.NoError(t, app.pinService.SetSOPIN("", "so-pin-123456"))
	app.config.StorageType = "barrier"

	pol := &config.PolicySection{
		RequireSOPIN:            true,
		RequireUserPIN:          true,
		RequireEncryptedStorage: true,
		RequireTPM:              false,
	}

	err := app.checkStartupPreconditions(pol)
	require.Error(t, err)
	var precondErr *PolicyPreconditionError
	require.ErrorAs(t, err, &precondErr)
	assert.Equal(t, []string{"require_user_pin"}, precondErr.Unmet,
		"require_so_pin and require_encrypted_storage are now met; require_tpm was never required")
}

func TestApp_ApplyVerifiedEnterprisePolicy_PreconditionsUnmet_KeepsDefaults(t *testing.T) {
	app := newPolicyTestApp(t)
	// The secure defaults, applied the way startupEnterprisePolicy's caller
	// applies them before SO login.
	applyFIDO2Policy(app.authenticatorInstance, config.DefaultPolicy(), app.log)

	// A policy whose Require* preconditions the host cannot meet.
	strict := config.DefaultPolicy()
	strict.RequireTPM = true

	err := app.applyVerifiedEnterprisePolicy(strict)

	require.Error(t, err)
	var precondErr *PolicyPreconditionError
	require.ErrorAs(t, err, &precondErr)
	assert.Contains(t, precondErr.Unmet, "require_tpm")

	// The defaults already applied to the authenticator stay in effect;
	// the refused section never reaches it.
	assert.True(t, app.authenticatorInstance.Config().RequireUserPresence)
	assert.True(t, app.authenticatorInstance.Config().EnableUserIntentCheck)
}

// TestApplyCapabilityPolicy_PropagatesToEveryGatedService exercises the
// direct-installation branch (service != nil) for every capability-gated
// service applyCapabilityPolicy touches. Each assertion observes the
// installed policy through the service's own gated operation rather than
// reflection, so a service silently omitted from applyCapabilityPolicy
// shows up as an operation that unexpectedly still succeeds.
func TestApplyCapabilityPolicy_PropagatesToEveryGatedService(t *testing.T) {
	appSvc := services.NewAppService(nil)
	pinSvc := services.NewPINService()
	trustSvc := services.NewTrustService(nil)
	auditSvc := services.NewAuditService(nil)
	sealSvc := services.NewSealService(t.TempDir())
	explorerSvc, err := services.NewAPIExplorerService(&services.ExplorerConfig{
		TokenStore:   tokenstore.NewMemoryTokenStore(),
		Registry:     serverregistry.NewMemoryServerRegistry(),
		TrustStore:   xkmssdk.NewStorageMemory(),
		HistoryStore: xkmssdk.NewStorageMemory(),
	})
	require.NoError(t, err)

	locked := config.DefaultPolicy()
	locked.UserCanConfigureTheme = false
	locked.UserCanViewAuditLog = false
	locked.APIExplorerEnabled = false

	applyCapabilityPolicy(appSvc, pinSvc, trustSvc, auditSvc, sealSvc, explorerSvc, locked)

	// appSvc: SetTheme is gated by UserCanConfigureTheme.
	err = appSvc.SetTheme(ThemeDark)
	var policyErr *services.PolicyDeniedError
	require.ErrorAs(t, err, &policyErr, "AppService did not receive the installed policy")
	assert.Equal(t, "user_can_configure_theme", policyErr.Field)

	// auditSvc: GetEntries is gated by UserCanViewAuditLog.
	_, err = auditSvc.GetEntries(nil)
	require.ErrorAs(t, err, &policyErr, "AuditService did not receive the installed policy")
	assert.Equal(t, "user_can_view_audit_log", policyErr.Field)

	// explorerSvc: Execute is gated by APIExplorerEnabled.
	_, err = explorerSvc.Execute(&services.ExplorerRequest{Method: "GET", URL: "https://kms.example.com"})
	require.ErrorAs(t, err, &policyErr, "APIExplorerService did not receive the installed policy")
	assert.Equal(t, "api_explorer_enabled", policyErr.Field)
}

// TestApplyCapabilityPolicy_NilServicesDoNotPanic covers the nil-service
// guards: a caller may hold a nil service pointer in personal-mode wiring
// (e.g. no audit backend configured), and applyCapabilityPolicy must skip
// it rather than dereference a nil receiver.
func TestApplyCapabilityPolicy_NilServicesDoNotPanic(t *testing.T) {
	assert.NotPanics(t, func() {
		applyCapabilityPolicy(nil, nil, nil, nil, nil, nil, config.DefaultPolicy())
	})
}
