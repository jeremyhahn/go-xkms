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
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/fido2/authenticator"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
)

// startupEnterprisePolicy resolves the enterprise policy the GUI may apply
// before the SO has logged in.
//
// In personal mode there is no enterprise policy: the GUI's own settings
// stand and nil is returned. In enterprise mode the section is sealed and no
// SO PIN is available yet, so config.LoadVerifiedPolicy cannot authenticate
// it and config.DefaultPolicy applies. The file's own values, which may relax
// a secure default, reach the consumers only through
// applyVerifiedEnterprisePolicy once the SO PIN has verified them. A config
// that cannot be loaded is treated the same way: defaults, never the file.
func startupEnterprisePolicy(configDir string, log *slog.Logger) *config.PolicySection {
	if !config.IsEnterpriseMode(configDir) {
		return nil
	}

	cfg, err := config.Load()
	if err != nil {
		log.Warn("enterprise config unreadable at startup; applying the default policy",
			"error", err)
		return config.DefaultPolicy()
	}

	verified, err := config.LoadVerifiedPolicy(cfg, configDir, "")
	if err != nil {
		log.Info("sealed enterprise policy is not verified before SO login; applying the default policy",
			"error", err)
		return config.DefaultPolicy()
	}

	// Only reachable when the HMAC file disappeared between the two checks:
	// the loader then reports the section unsealed, which is the user's own
	// file and is honoured as such.
	return &verified.Policy
}

// applyFIDO2Policy applies pol's FIDO2 fields to the shared authenticator.
func applyFIDO2Policy(auth *authenticator.Authenticator, pol *config.PolicySection, log *slog.Logger) {
	auth.SetRequireUserPresence(pol.FIDO2RequireUserPresence)
	auth.SetEnableUserIntentCheck(pol.FIDO2UserIntentCheck)
	auth.SetAlwaysUV(pol.FIDO2AlwaysUV)
	log.Info("enterprise FIDO2 policy applied",
		"require_user_presence", pol.FIDO2RequireUserPresence,
		"user_intent_check", pol.FIDO2UserIntentCheck,
		"always_uv", pol.FIDO2AlwaysUV)
}

// applyExtensionPolicy applies pol's browser-extension fields to the autofill
// service.
func applyExtensionPolicy(autofill *services.AutoFillService, pol *config.PolicySection) {
	autofill.SetEnterprisePolicy(&services.EnterpriseExtensionPolicy{
		Enabled:               pol.ExtensionEnabled,
		RequireAuthentication: pol.ExtensionRequireAuthentication,
		ForceAudit:            pol.ExtensionForceAudit,
		AllowedDomains:        pol.ExtensionAllowedDomains,
		BlockedDomains:        pol.ExtensionBlockedDomains,
		MaxFillsPerMinute:     pol.ExtensionMaxFillsPerMinute,
		UserCanConfigure:      pol.UserCanConfigureExtension,
	})
}

// applyCapabilityPolicy installs pol on every service whose operations are
// gated directly by a PolicySection "UserCan*" deny switch or *Enabled kill
// switch: Settings (theme, developer tools, auto-unseal), own-PIN change,
// the trust store, the audit log viewer, sealed data management, and the API
// explorer. Each service's SetPolicy stores the pointer and checks it at the
// point of the gated operation; see PolicyDeniedError.
//
// PhoneService is deliberately NOT among them, even though it also has a
// SetPolicy. Every service here is safe to install pol at STARTUP as
// config.DefaultPolicy() -- a permissive placeholder -- and replace once SO
// login verifies the real section, because DefaultPolicy() is each one's own
// secure default. PhoneService's attested-application allow-list (#1305) has
// no such safe placeholder: installing DefaultPolicy() would read as
// "enterprise plane present but not locked" and silently fall back to
// devices.yaml before the SO has ever logged in. It is instead wired
// directly by applyVerifiedEnterprisePolicy below (SetPolicy, ONLY with a
// genuinely verified section) and by the GUI's startup path
// (PhoneService.SetEnterpriseSealed); see phone_service.go's policy field
// comment for the reasoning in full.
func applyCapabilityPolicy(
	appSvc *services.AppService,
	pinSvc *services.PINService,
	trustSvc *services.TrustService,
	auditSvc *services.AuditService,
	sealSvc *services.SealService,
	apiExplorerSvc *services.APIExplorerService,
	pol *config.PolicySection,
) {
	if appSvc != nil {
		appSvc.SetPolicy(pol)
	}
	if pinSvc != nil {
		pinSvc.SetPolicy(pol)
	}
	if trustSvc != nil {
		trustSvc.SetPolicy(pol)
	}
	if auditSvc != nil {
		auditSvc.SetPolicy(pol)
	}
	if sealSvc != nil {
		sealSvc.SetPolicy(pol)
	}
	if apiExplorerSvc != nil {
		apiExplorerSvc.SetPolicy(pol)
	}
}

// PolicyPreconditionError indicates the enterprise policy's Require* startup
// preconditions are not met by the current host state. Unmet names the
// PolicySection fields responsible (their yaml/json tags). The policy
// verified cryptographically -- this is a separate fact: the deployment
// does not meet the minimum bar it declares for itself.
type PolicyPreconditionError struct {
	Unmet []string
}

// Error implements the error interface.
func (e *PolicyPreconditionError) Error() string {
	return "policy: unmet startup preconditions: " + strings.Join(e.Unmet, ", ")
}

// checkStartupPreconditions evaluates pol's Require* fields against the
// current host state and returns a *PolicyPreconditionError listing every
// field whose requirement is not met, or nil if all are met. Mirrors
// EnsureSuiteAvailable in pkg/trust/bootstrap: preconditions are checked
// once, at the point the policy becomes authoritative, rather than
// re-checked on every operation.
func (a *App) checkStartupPreconditions(pol *config.PolicySection) error {
	var unmet []string

	soPINSet, userPINSet := false, false
	if a.pinService != nil {
		if status, err := a.pinService.GetPINStatus(); err == nil && status != nil {
			soPINSet, userPINSet = status.SOPINSet, status.UserPINSet
		}
	}
	if pol.RequireSOPIN && !soPINSet {
		unmet = append(unmet, "require_so_pin")
	}
	if pol.RequireUserPIN && !userPINSet {
		unmet = append(unmet, "require_user_pin")
	}

	if pol.RequireEncryptedStorage && (a.config == nil || a.config.StorageType != "barrier") {
		unmet = append(unmet, "require_encrypted_storage")
	}

	tpmAvailable := false
	if a.tpmService != nil {
		if status, err := a.tpmService.GetStatus(); err == nil && status != nil {
			tpmAvailable = status.Available
		}
	}
	if pol.RequireTPM && !tpmAvailable {
		unmet = append(unmet, "require_tpm")
	}

	if len(unmet) == 0 {
		return nil
	}
	return &PolicyPreconditionError{Unmet: unmet}
}

// applyVerifiedEnterprisePolicy is the AuthService's verified-policy hook. It
// runs once the SO PIN has authenticated the sealed section, and it decides
// whether the verified section replaces the startup defaults on every
// consumer.
//
// If pol's Require* preconditions are not met by the current host, the
// verified section is refused and the startup defaults (already applied,
// and already the secure choice -- see startupEnterprisePolicy) stay in
// effect; the caller (AuthService.LoginSO) surfaces the returned error to
// the SO without failing the login itself, since an SO who cannot log in
// cannot fix the deployment that is failing its own preconditions.
func (a *App) applyVerifiedEnterprisePolicy(pol *config.PolicySection) error {
	if err := a.checkStartupPreconditions(pol); err != nil {
		a.log.Warn("verified enterprise policy failed its own startup preconditions; keeping defaults",
			"error", err)
		if a.auditStore != nil {
			if auditErr := a.auditStore.Log(audit.Entry{
				Timestamp: time.Now(),
				Operation: audit.OpPolicyDenied,
				Success:   false,
				Error:     err.Error(),
				Details:   map[string]any{"operation": "apply_verified_policy"},
			}); auditErr != nil {
				return errors.Join(err, auditErr)
			}
		}
		return err
	}

	if a.authenticatorInstance != nil {
		applyFIDO2Policy(a.authenticatorInstance, pol, a.log)
	}
	if a.autofillService != nil {
		applyExtensionPolicy(a.autofillService, pol)
	}
	// The verified section may turn local app access off (or back on):
	// reconcile the IPC socket with it now rather than at the next lock,
	// seal or settings change.
	a.syncIPCServer()
	applyCapabilityPolicy(a.appService, a.pinService, a.trustService, a.auditService, a.sealService, a.apiExplorerService, pol)

	// PhoneService's attested-application allow-list is wired directly here,
	// not through applyCapabilityPolicy: this call site is reached ONLY once
	// pol has verified under the SO PIN, which is the one condition under
	// which SetPolicy may be called at all (#1305).
	if a.phoneService != nil {
		a.phoneService.SetPolicy(pol)
	}
	return nil
}
