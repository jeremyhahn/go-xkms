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
	"errors"
	"testing"
)

func TestDefaultPolicy(t *testing.T) {
	p := DefaultPolicy()

	if p.FillMode != FillModeClickToFill {
		t.Errorf("expected FillMode %q, got %q", FillModeClickToFill, p.FillMode)
	}
	if p.TOTPPolicy != TOTPPolicyPrompt {
		t.Errorf("expected TOTPPolicy %q, got %q", TOTPPolicyPrompt, p.TOTPPolicy)
	}
	if p.SessionTimeoutSec != 300 {
		t.Errorf("expected SessionTimeoutSec 300, got %d", p.SessionTimeoutSec)
	}
	if p.MaxFillsPerMinute != 10 {
		t.Errorf("expected MaxFillsPerMinute 10, got %d", p.MaxFillsPerMinute)
	}
	if !p.AuditEnabled {
		t.Error("expected AuditEnabled true, got false")
	}
	if !p.RequireAuthentication {
		t.Error("expected RequireAuthentication true, got false")
	}
	if len(p.AllowedDomains) != 0 {
		t.Errorf("expected empty AllowedDomains, got %v", p.AllowedDomains)
	}
	if len(p.BlockedDomains) != 0 {
		t.Errorf("expected empty BlockedDomains, got %v", p.BlockedDomains)
	}
}

func TestDefaultPolicyValidates(t *testing.T) {
	p := DefaultPolicy()
	if err := p.Validate(); err != nil {
		t.Fatalf("default policy should validate, got: %v", err)
	}
}

func TestValidate_AllFillModes(t *testing.T) {
	validModes := []FillMode{
		FillModeClickToFill,
		FillModeAutoFill,
		FillModePopupOnly,
		FillModeDisabled,
	}
	for _, mode := range validModes {
		t.Run(string(mode), func(t *testing.T) {
			p := DefaultPolicy()
			p.FillMode = mode
			if err := p.Validate(); err != nil {
				t.Errorf("fill mode %q should be valid, got: %v", mode, err)
			}
		})
	}
}

func TestValidate_InvalidFillMode(t *testing.T) {
	p := DefaultPolicy()
	p.FillMode = "bogus"
	err := p.Validate()
	if err == nil {
		t.Fatal("expected error for invalid fill mode, got nil")
	}
	if !errors.Is(err, ErrInvalidFillMode) {
		t.Errorf("expected ErrInvalidFillMode, got: %v", err)
	}
}

func TestValidate_EmptyFillMode(t *testing.T) {
	p := DefaultPolicy()
	p.FillMode = ""
	err := p.Validate()
	if !errors.Is(err, ErrInvalidFillMode) {
		t.Errorf("expected ErrInvalidFillMode for empty fill mode, got: %v", err)
	}
}

func TestValidate_AllTOTPPolicies(t *testing.T) {
	validPolicies := []TOTPPolicy{
		TOTPPolicyAuto,
		TOTPPolicyPrompt,
		TOTPPolicyDisabled,
	}
	for _, tp := range validPolicies {
		t.Run(string(tp), func(t *testing.T) {
			p := DefaultPolicy()
			p.TOTPPolicy = tp
			if err := p.Validate(); err != nil {
				t.Errorf("TOTP policy %q should be valid, got: %v", tp, err)
			}
		})
	}
}

func TestValidate_InvalidTOTPPolicy(t *testing.T) {
	p := DefaultPolicy()
	p.TOTPPolicy = "invalid"
	err := p.Validate()
	if err == nil {
		t.Fatal("expected error for invalid TOTP policy, got nil")
	}
	if !errors.Is(err, ErrInvalidTOTPPolicy) {
		t.Errorf("expected ErrInvalidTOTPPolicy, got: %v", err)
	}
}

func TestValidate_NegativeSessionTimeout(t *testing.T) {
	p := DefaultPolicy()
	p.SessionTimeoutSec = -1
	err := p.Validate()
	if err == nil {
		t.Fatal("expected error for negative session timeout, got nil")
	}
	if !errors.Is(err, ErrInvalidSessionTimeout) {
		t.Errorf("expected ErrInvalidSessionTimeout, got: %v", err)
	}
}

func TestValidate_ZeroSessionTimeout(t *testing.T) {
	p := DefaultPolicy()
	p.SessionTimeoutSec = 0
	if err := p.Validate(); err != nil {
		t.Errorf("zero session timeout should be valid (disabled), got: %v", err)
	}
}

func TestValidate_NegativeMaxFills(t *testing.T) {
	p := DefaultPolicy()
	p.MaxFillsPerMinute = -5
	err := p.Validate()
	if err == nil {
		t.Fatal("expected error for negative max fills, got nil")
	}
	if !errors.Is(err, ErrInvalidMaxFills) {
		t.Errorf("expected ErrInvalidMaxFills, got: %v", err)
	}
}

func TestValidate_ZeroMaxFills(t *testing.T) {
	p := DefaultPolicy()
	p.MaxFillsPerMinute = 0
	if err := p.Validate(); err != nil {
		t.Errorf("zero max fills should be valid (disabled), got: %v", err)
	}
}

func TestIsDomainAllowed_EmptyLists(t *testing.T) {
	p := DefaultPolicy()
	tests := []struct {
		domain string
		want   bool
	}{
		{"github.com", true},
		{"example.org", true},
		{"anything.test", true},
	}
	for _, tc := range tests {
		t.Run(tc.domain, func(t *testing.T) {
			if got := p.IsDomainAllowed(tc.domain); got != tc.want {
				t.Errorf("IsDomainAllowed(%q) = %v, want %v", tc.domain, got, tc.want)
			}
		})
	}
}

func TestIsDomainAllowed_AllowedListOnly(t *testing.T) {
	p := DefaultPolicy()
	p.AllowedDomains = []string{"github.com", "example.org"}

	tests := []struct {
		domain string
		want   bool
	}{
		{"github.com", true},
		{"www.github.com", true},
		{"api.github.com", true},
		{"example.org", true},
		{"evil.com", false},
		{"not-github.com", false},
	}
	for _, tc := range tests {
		t.Run(tc.domain, func(t *testing.T) {
			if got := p.IsDomainAllowed(tc.domain); got != tc.want {
				t.Errorf("IsDomainAllowed(%q) = %v, want %v", tc.domain, got, tc.want)
			}
		})
	}
}

func TestIsDomainAllowed_BlockedListOnly(t *testing.T) {
	p := DefaultPolicy()
	p.BlockedDomains = []string{"evil.com", "phishing.net"}

	tests := []struct {
		domain string
		want   bool
	}{
		{"github.com", true},
		{"example.org", true},
		{"evil.com", false},
		{"www.evil.com", false},
		{"sub.evil.com", false},
		{"phishing.net", false},
		{"safe.com", true},
	}
	for _, tc := range tests {
		t.Run(tc.domain, func(t *testing.T) {
			if got := p.IsDomainAllowed(tc.domain); got != tc.want {
				t.Errorf("IsDomainAllowed(%q) = %v, want %v", tc.domain, got, tc.want)
			}
		})
	}
}

func TestIsDomainAllowed_BlockedTakesPrecedence(t *testing.T) {
	p := DefaultPolicy()
	p.AllowedDomains = []string{"example.com"}
	p.BlockedDomains = []string{"example.com"}

	if p.IsDomainAllowed("example.com") {
		t.Error("blocked should take precedence over allowed")
	}
}

func TestIsDomainAllowed_SubdomainBlocked(t *testing.T) {
	p := DefaultPolicy()
	p.AllowedDomains = []string{"example.com"}
	p.BlockedDomains = []string{"evil.example.com"}

	// The parent domain is allowed.
	if !p.IsDomainAllowed("example.com") {
		t.Error("example.com should be allowed")
	}
	// But the blocked subdomain is not.
	if p.IsDomainAllowed("evil.example.com") {
		t.Error("evil.example.com should be blocked")
	}
	// Other subdomains remain allowed.
	if !p.IsDomainAllowed("safe.example.com") {
		t.Error("safe.example.com should be allowed")
	}
}

func TestIsDomainAllowed_SubdomainInAllowed(t *testing.T) {
	p := DefaultPolicy()
	p.AllowedDomains = []string{"corp.example.com"}

	// Exact subdomain match.
	if !p.IsDomainAllowed("corp.example.com") {
		t.Error("corp.example.com should be allowed")
	}
	// Sub-subdomain of allowed.
	if !p.IsDomainAllowed("app.corp.example.com") {
		t.Error("app.corp.example.com should be allowed")
	}
	// Parent domain is NOT in allowed list.
	if p.IsDomainAllowed("example.com") {
		t.Error("example.com should not be allowed when only corp.example.com is allowed")
	}
}

func TestRateLimiter_UnderLimit(t *testing.T) {
	r := NewRateLimiter(5)
	for i := 0; i < 5; i++ {
		if !r.Allow() {
			t.Fatalf("attempt %d should be allowed (limit 5)", i+1)
		}
	}
}

func TestRateLimiter_OverLimit(t *testing.T) {
	r := NewRateLimiter(3)
	for i := 0; i < 3; i++ {
		if !r.Allow() {
			t.Fatalf("attempt %d should be allowed (limit 3)", i+1)
		}
	}
	if r.Allow() {
		t.Error("4th attempt should be rejected (limit 3)")
	}
	if r.Allow() {
		t.Error("5th attempt should also be rejected")
	}
}

func TestRateLimiter_ZeroLimitDisables(t *testing.T) {
	r := NewRateLimiter(0)
	for i := 0; i < 100; i++ {
		if !r.Allow() {
			t.Fatalf("zero limit should disable rate limiting, attempt %d rejected", i+1)
		}
	}
}

func TestRateLimiter_Reset(t *testing.T) {
	r := NewRateLimiter(2)
	if !r.Allow() {
		t.Fatal("first attempt should be allowed")
	}
	if !r.Allow() {
		t.Fatal("second attempt should be allowed")
	}
	if r.Allow() {
		t.Fatal("third attempt should be rejected")
	}

	r.Reset()

	if !r.Allow() {
		t.Fatal("after reset, first attempt should be allowed")
	}
	if !r.Allow() {
		t.Fatal("after reset, second attempt should be allowed")
	}
}

func TestRateLimiter_SetLimit(t *testing.T) {
	r := NewRateLimiter(1)
	if !r.Allow() {
		t.Fatal("first attempt should be allowed")
	}
	if r.Allow() {
		t.Fatal("second attempt should be rejected (limit 1)")
	}

	// Increase limit.
	r.SetLimit(3)
	// The first entry is still in the window, so we should be able to do 2 more.
	if !r.Allow() {
		t.Fatal("after SetLimit(3), second attempt should be allowed")
	}
	if !r.Allow() {
		t.Fatal("after SetLimit(3), third attempt should be allowed")
	}
	if r.Allow() {
		t.Fatal("after SetLimit(3), fourth attempt should be rejected")
	}
}

func TestRateLimiter_SetLimitToZero(t *testing.T) {
	r := NewRateLimiter(2)
	if !r.Allow() {
		t.Fatal("first attempt should be allowed")
	}

	r.SetLimit(0)

	// Zero disables rate limiting.
	for i := 0; i < 50; i++ {
		if !r.Allow() {
			t.Fatalf("zero limit should disable, attempt %d rejected", i+1)
		}
	}
}

func TestRateLimiter_SlidingWindow(t *testing.T) {
	// We cannot easily wait 60 seconds in a unit test, so we verify
	// the pruning behavior by directly manipulating timestamps.
	r := NewRateLimiter(2)

	// Manually insert timestamps that are older than 60 seconds.
	r.mu.Lock()
	oldTimestamp := int64(1) // far in the past (1 nanosecond since epoch)
	r.timestamps = append(r.timestamps, oldTimestamp, oldTimestamp)
	r.mu.Unlock()

	// Even though there are 2 entries (at the limit), they are old
	// and should be pruned by Allow().
	if !r.Allow() {
		t.Error("old timestamps should be pruned, allowing new fill")
	}
	if !r.Allow() {
		t.Error("second fill should be allowed after pruning old entries")
	}
	if r.Allow() {
		t.Error("third fill should be rejected (2 recent entries)")
	}
}

func TestValidate_ValidationOrder(t *testing.T) {
	// When multiple fields are invalid, FillMode should be checked first.
	p := &AutoFillPolicy{
		FillMode:          "bad_mode",
		TOTPPolicy:        "bad_totp",
		SessionTimeoutSec: -1,
		MaxFillsPerMinute: -1,
	}
	err := p.Validate()
	if !errors.Is(err, ErrInvalidFillMode) {
		t.Errorf("expected ErrInvalidFillMode first, got: %v", err)
	}
}

func TestValidate_TOTPCheckedAfterFillMode(t *testing.T) {
	p := DefaultPolicy()
	p.TOTPPolicy = "bad_totp"
	p.SessionTimeoutSec = -1
	err := p.Validate()
	if !errors.Is(err, ErrInvalidTOTPPolicy) {
		t.Errorf("expected ErrInvalidTOTPPolicy, got: %v", err)
	}
}

func TestValidate_SessionTimeoutCheckedAfterTOTP(t *testing.T) {
	p := DefaultPolicy()
	p.SessionTimeoutSec = -1
	p.MaxFillsPerMinute = -1
	err := p.Validate()
	if !errors.Is(err, ErrInvalidSessionTimeout) {
		t.Errorf("expected ErrInvalidSessionTimeout, got: %v", err)
	}
}

func TestRateLimiter_SingleAllowance(t *testing.T) {
	r := NewRateLimiter(1)
	if !r.Allow() {
		t.Fatal("single attempt should be allowed")
	}
	if r.Allow() {
		t.Fatal("second attempt should be rejected with limit 1")
	}
}
