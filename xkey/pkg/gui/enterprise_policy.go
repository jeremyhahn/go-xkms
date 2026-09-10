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
	"log/slog"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator"
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
	log.Info("enterprise FIDO2 policy applied",
		"require_user_presence", pol.FIDO2RequireUserPresence,
		"user_intent_check", pol.FIDO2UserIntentCheck)
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
	})
}

// applyVerifiedEnterprisePolicy is the AuthService's verified-policy hook. It
// runs once the SO PIN has authenticated the sealed section and replaces the
// startup defaults with the verified values on every consumer.
func (a *App) applyVerifiedEnterprisePolicy(pol *config.PolicySection) {
	if a.authenticatorInstance != nil {
		applyFIDO2Policy(a.authenticatorInstance, pol, a.log)
	}
	if a.autofillService != nil {
		applyExtensionPolicy(a.autofillService, pol)
	}
}
