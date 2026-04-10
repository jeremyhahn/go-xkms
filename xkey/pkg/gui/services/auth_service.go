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

package services

import (
	"context"
	"log/slog"
	"sync/atomic"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// AuthMode represents the current authentication state.
type AuthMode string

const (
	// AuthModeLocked indicates no user is authenticated.
	AuthModeLocked AuthMode = "locked"

	// AuthModeUser indicates a regular user is authenticated.
	AuthModeUser AuthMode = "user"

	// AuthModeSOAdmin indicates an SO administrator is authenticated.
	AuthModeSOAdmin AuthMode = "so_admin"
)

// LoginResult describes the outcome of a login attempt.
type LoginResult struct {
	Success        bool   `json:"success"`
	Mode           string `json:"mode"`
	PolicyVerified bool   `json:"policy_verified"`
	TamperDetected bool   `json:"tamper_detected"`
	Error          string `json:"error,omitempty"`
}

// AuthService manages authentication state for the GUI application.
// In personal mode, no auth gate is shown (barrier unseal is sufficient).
// In enterprise mode, users must authenticate with their User PIN or
// SO PIN to access the application.
type AuthService struct {
	ctx       context.Context
	log       *slog.Logger
	pinSvc    *PINService
	configDir string

	// policyVerified is a session-level cache. Once the SO verifies
	// policy integrity, it stays verified until the app restarts.
	policyVerified atomic.Bool

	// tamperDetected is set when HMAC verification fails.
	tamperDetected atomic.Bool

	// mode stores the current AuthMode.
	mode atomic.Value
}

// NewAuthService creates a new AuthService.
func NewAuthService(pinSvc *PINService, configDir string) *AuthService {
	svc := &AuthService{
		log:       slog.Default().With("component", "auth_service"),
		pinSvc:    pinSvc,
		configDir: configDir,
	}
	svc.mode.Store(AuthModeLocked)
	return svc
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *AuthService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// GetMode returns the current authentication mode.
func (s *AuthService) GetMode() string {
	return string(s.mode.Load().(AuthMode))
}

// IsEnterpriseMode returns whether enterprise mode is active.
func (s *AuthService) IsEnterpriseMode() bool {
	return config.IsEnterpriseMode(s.configDir)
}

// IsPolicyVerified returns whether the SO has verified policy integrity
// during this session.
func (s *AuthService) IsPolicyVerified() bool {
	return s.policyVerified.Load()
}

// IsTamperDetected returns whether policy tampering was detected.
func (s *AuthService) IsTamperDetected() bool {
	return s.tamperDetected.Load()
}

// LoginUser authenticates a regular user with their User PIN.
// In enterprise mode, the user must provide their User PIN.
// In personal mode, this is called after barrier unseal.
func (s *AuthService) LoginUser(userPIN string) *LoginResult {
	if s.mode.Load().(AuthMode) == AuthModeUser {
		return &LoginResult{
			Success: true,
			Mode:    string(AuthModeUser),
		}
	}

	if err := s.pinSvc.VerifyUserPIN(userPIN); err != nil {
		s.log.Warn("user login failed", "error", err)
		return &LoginResult{
			Success: false,
			Mode:    string(AuthModeLocked),
			Error:   "invalid user PIN",
		}
	}

	s.mode.Store(AuthModeUser)
	s.log.Info("user authenticated")

	return &LoginResult{
		Success:        true,
		Mode:           string(AuthModeUser),
		PolicyVerified: s.policyVerified.Load(),
	}
}

// LoginSO authenticates the Security Officer with the SO PIN.
// If enterprise mode is active, this also verifies policy integrity
// via HMAC and caches the result for the session.
func (s *AuthService) LoginSO(soPIN string) *LoginResult {
	if err := s.pinSvc.VerifySOPIN(soPIN); err != nil {
		s.log.Warn("SO login failed", "error", err)
		return &LoginResult{
			Success: false,
			Mode:    s.GetMode(),
			Error:   "invalid SO PIN",
		}
	}

	// In enterprise mode, verify policy integrity on SO login.
	if s.IsEnterpriseMode() {
		hmacPath := config.PolicyHMACPath(s.configDir)
		cfg, err := config.Load()
		if err != nil {
			s.log.Error("failed to load config for policy verification", "error", err)
			return &LoginResult{
				Success:        true,
				Mode:           string(AuthModeSOAdmin),
				PolicyVerified: false,
				Error:          "config load failed during policy verification",
			}
		}

		verified, verifyErr := config.VerifyPolicyHMAC(&cfg.Policy, hmacPath, soPIN)
		if verifyErr != nil {
			s.log.Error("policy HMAC verification error", "error", verifyErr)
			s.tamperDetected.Store(true)
			s.mode.Store(AuthModeSOAdmin)
			return &LoginResult{
				Success:        true,
				Mode:           string(AuthModeSOAdmin),
				PolicyVerified: false,
				TamperDetected: true,
				Error:          "policy verification error",
			}
		}

		s.policyVerified.Store(verified)
		if !verified {
			s.tamperDetected.Store(true)
			s.log.Warn("policy tamper detected")
		} else {
			s.tamperDetected.Store(false)
			s.log.Info("policy integrity verified")
		}
	}

	s.mode.Store(AuthModeSOAdmin)
	s.log.Info("SO authenticated", "enterprise", s.IsEnterpriseMode())

	return &LoginResult{
		Success:        true,
		Mode:           string(AuthModeSOAdmin),
		PolicyVerified: s.policyVerified.Load(),
		TamperDetected: s.tamperDetected.Load(),
	}
}

// Logout returns to locked state.
func (s *AuthService) Logout() {
	s.mode.Store(AuthModeLocked)
	s.log.Info("user logged out")
}

// SetModeUser sets the auth mode to user mode directly.
// This is used during startup for personal mode (non-enterprise)
// where barrier unseal is sufficient authentication.
func (s *AuthService) SetModeUser() {
	s.mode.Store(AuthModeUser)
}
