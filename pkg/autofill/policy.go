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

package autofill

import (
	"sync"
	"sync/atomic"
	"time"
)

// FillMode controls how credentials are injected into form fields.
type FillMode string

const (
	// FillModeClickToFill requires the user to click an icon to fill credentials.
	FillModeClickToFill FillMode = "click_to_fill"
	// FillModeAutoFill fills credentials automatically on page load.
	FillModeAutoFill FillMode = "auto_fill"
	// FillModePopupOnly requires the user to open the popup manually.
	FillModePopupOnly FillMode = "popup_only"
	// FillModeDisabled disables all autofill functionality.
	FillModeDisabled FillMode = "disabled"
)

// validFillModes provides O(1) validation for fill mode values.
var validFillModes = map[FillMode]struct{}{
	FillModeClickToFill: {},
	FillModeAutoFill:    {},
	FillModePopupOnly:   {},
	FillModeDisabled:    {},
}

// TOTPPolicy controls how TOTP codes are handled during autofill.
type TOTPPolicy string

const (
	// TOTPPolicyAuto fills TOTP codes automatically when a TOTP field is detected.
	TOTPPolicyAuto TOTPPolicy = "auto"
	// TOTPPolicyPrompt asks the user before filling TOTP codes.
	TOTPPolicyPrompt TOTPPolicy = "prompt"
	// TOTPPolicyDisabled never auto-fills TOTP codes.
	TOTPPolicyDisabled TOTPPolicy = "disabled"
)

// validTOTPPolicies provides O(1) validation for TOTP policy values.
var validTOTPPolicies = map[TOTPPolicy]struct{}{
	TOTPPolicyAuto:     {},
	TOTPPolicyPrompt:   {},
	TOTPPolicyDisabled: {},
}

// AutoFillPolicy defines the security and behavioral rules for credential autofill.
type AutoFillPolicy struct {
	FillMode              FillMode   `json:"fill_mode"`
	TOTPPolicy            TOTPPolicy `json:"totp_policy"`
	SessionTimeoutSec     int        `json:"session_timeout_sec"`
	RequireAuthentication bool       `json:"require_authentication"`
	AllowedDomains        []string   `json:"allowed_domains"`
	BlockedDomains        []string   `json:"blocked_domains"`
	MaxFillsPerMinute     int        `json:"max_fills_per_minute"`
	AuditEnabled          bool       `json:"audit_enabled"`
}

// DefaultPolicy returns an AutoFillPolicy with secure default values.
func DefaultPolicy() *AutoFillPolicy {
	return &AutoFillPolicy{
		FillMode:              FillModeClickToFill,
		TOTPPolicy:            TOTPPolicyPrompt,
		SessionTimeoutSec:     300,
		RequireAuthentication: true,
		MaxFillsPerMinute:     10,
		AuditEnabled:          true,
	}
}

// Validate checks all policy fields for correctness and returns a typed
// error if any field is invalid.
func (p *AutoFillPolicy) Validate() error {
	if _, ok := validFillModes[p.FillMode]; !ok {
		return ErrInvalidFillMode
	}
	if _, ok := validTOTPPolicies[p.TOTPPolicy]; !ok {
		return ErrInvalidTOTPPolicy
	}
	if p.SessionTimeoutSec < 0 {
		return ErrInvalidSessionTimeout
	}
	if p.MaxFillsPerMinute < 0 {
		return ErrInvalidMaxFills
	}
	return nil
}

// IsDomainAllowed checks whether a domain is permitted by the policy.
// Blocked domains are checked first and always take precedence.
// If AllowedDomains is non-empty, only domains in the list are permitted.
// An empty AllowedDomains list means all non-blocked domains are allowed.
func (p *AutoFillPolicy) IsDomainAllowed(domain string) bool {
	// Check blocked domains first (always takes precedence).
	for _, blocked := range p.BlockedDomains {
		if MatchesDomain(domain, blocked) {
			return false
		}
	}

	// If no allowed list is configured, all non-blocked domains pass.
	if len(p.AllowedDomains) == 0 {
		return true
	}

	// Check against the allowed list.
	for _, allowed := range p.AllowedDomains {
		if MatchesDomain(domain, allowed) {
			return true
		}
	}
	return false
}

// RateLimiter enforces a sliding-window rate limit on autofill operations.
// It tracks timestamps of recent fills and rejects new fills when the
// count within the last 60 seconds exceeds the configured maximum.
type RateLimiter struct {
	maxPerMinute atomic.Int64
	timestamps   []int64
	mu           sync.Mutex
}

// NewRateLimiter creates a RateLimiter with the given maximum fills per minute.
// A maxPerMinute of 0 disables rate limiting.
func NewRateLimiter(maxPerMinute int) *RateLimiter {
	r := &RateLimiter{
		timestamps: make([]int64, 0, maxPerMinute),
	}
	r.maxPerMinute.Store(int64(maxPerMinute))
	return r
}

// Allow checks whether a fill is permitted under the current rate limit.
// If allowed, it records the attempt and returns true. If the rate limit
// is exceeded, it returns false without recording. A maxPerMinute of 0
// disables the limiter and always returns true.
func (r *RateLimiter) Allow() bool {
	limit := r.maxPerMinute.Load()
	if limit == 0 {
		return true
	}

	now := time.Now().UnixNano()
	windowStart := now - int64(60*time.Second)

	r.mu.Lock()
	defer r.mu.Unlock()

	// Prune timestamps older than the 60-second sliding window.
	pruned := r.timestamps[:0]
	for _, ts := range r.timestamps {
		if ts >= windowStart {
			pruned = append(pruned, ts)
		}
	}
	r.timestamps = pruned

	if int64(len(r.timestamps)) >= limit {
		return false
	}

	r.timestamps = append(r.timestamps, now)
	return true
}

// Reset clears all recorded timestamps, resetting the rate limiter state.
func (r *RateLimiter) Reset() {
	r.mu.Lock()
	r.timestamps = r.timestamps[:0]
	r.mu.Unlock()
}

// SetLimit updates the maximum number of fills allowed per minute.
// A value of 0 disables rate limiting.
func (r *RateLimiter) SetLimit(maxPerMinute int) {
	r.maxPerMinute.Store(int64(maxPerMinute))
}
