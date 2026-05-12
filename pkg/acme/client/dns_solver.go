// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package client

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
)

// DNS solver errors
var (
	ErrNilProvider           = errors.New("acme-client: nil DNS provider")
	ErrDNSRecordNotPresent   = errors.New("acme-client: DNS record not present")
	ErrDNSRecordCleanup      = errors.New("acme-client: failed to cleanup DNS record")
	ErrDNSPropagationTimeout = errors.New("acme-client: DNS propagation timeout")
	ErrDNSSolverClosed       = errors.New("acme-client: DNS solver has been closed")
)

// DNSSolverOption is a functional option for configuring a DNSSolver.
type DNSSolverOption func(*DNSSolver)

// WithPropagationWait sets the propagation wait duration.
// This is the time to wait for DNS changes to propagate before returning
// from Solve(). If zero, no propagation wait is performed.
func WithPropagationWait(d time.Duration) DNSSolverOption {
	return func(s *DNSSolver) {
		s.propagationWait = d
	}
}

// WithPropagationCheck enables propagation checking with the specified
// timeout and polling interval. When enabled, Solve() will verify that
// the DNS record is resolvable before returning.
func WithPropagationCheck(timeout, interval time.Duration) DNSSolverOption {
	return func(s *DNSSolver) {
		s.propagationTimeout = timeout
		s.propagationInterval = interval
		s.checkPropagation = true
	}
}

// WithNameservers sets custom nameservers for propagation checking.
func WithNameservers(nameservers []string) DNSSolverOption {
	return func(s *DNSSolver) {
		s.nameservers = nameservers
	}
}

// WithRecordTTL sets the TTL for DNS records created by this solver.
func WithRecordTTL(ttl int) DNSSolverOption {
	return func(s *DNSSolver) {
		s.recordTTL = ttl
	}
}

// DNSSolver implements ChallengeSolver for dns-01 challenges using a DNS provider.
// It provisions TXT records at _acme-challenge.<domain> with the challenge response.
type DNSSolver struct {
	provider            providers.Provider
	propagationWait     time.Duration
	propagationTimeout  time.Duration
	propagationInterval time.Duration
	checkPropagation    bool
	nameservers         []string
	recordTTL           int
	closed              atomic.Bool

	// Track active records for cleanup
	recordsMu     sync.RWMutex
	activeRecords map[string]recordInfo
}

// recordInfo stores information about a provisioned DNS record for cleanup.
type recordInfo struct {
	fqdn  string
	value string
}

// NewDNSSolver creates a new DNSSolver with the given provider.
// The provider is used to create and remove DNS TXT records.
func NewDNSSolver(provider providers.Provider, opts ...DNSSolverOption) (*DNSSolver, error) {
	if provider == nil {
		return nil, ErrNilProvider
	}

	s := &DNSSolver{
		provider:            provider,
		propagationWait:     0,
		propagationTimeout:  providers.PropagationTimeout,
		propagationInterval: providers.PropagationPoll,
		checkPropagation:    false,
		nameservers:         providers.DefaultNameservers,
		recordTTL:           providers.DefaultTTL,
		activeRecords:       make(map[string]recordInfo),
	}

	for _, opt := range opts {
		opt(s)
	}

	return s, nil
}

// Type returns the challenge type this solver handles.
func (s *DNSSolver) Type() string {
	return string(ChallengeTypeDNS01)
}

// Solve provisions a DNS TXT record for the dns-01 challenge.
// It computes the challenge response value from the key authorization,
// creates the TXT record, and optionally waits for propagation.
func (s *DNSSolver) Solve(ctx context.Context, domain string, challenge *acme.Challenge, keyAuth string) error {
	if s.closed.Load() {
		return ErrDNSSolverClosed
	}

	if domain == "" {
		return ErrEmptyDomain
	}

	if challenge == nil {
		return ErrNilChallenge
	}

	if keyAuth == "" {
		return ErrEmptyKeyAuth
	}

	// Compute the challenge value: base64url(SHA-256(keyAuth))
	challengeValue := ComputeDNS01ChallengeValue(keyAuth)

	// Build the FQDN for the TXT record
	fqdn := buildACMEChallengeFQDN(domain)

	// Present the DNS record
	if err := s.provider.Present(ctx, domain, fqdn, challengeValue); err != nil {
		return caerrors.DNSError("dns-01: failed to present record: %v", err)
	}

	// Store record info for cleanup
	recordKey := buildRecordKey(domain, challenge.Token)
	s.recordsMu.Lock()
	s.activeRecords[recordKey] = recordInfo{
		fqdn:  fqdn,
		value: challengeValue,
	}
	s.recordsMu.Unlock()

	// Wait for propagation if configured
	if s.propagationWait > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(s.propagationWait):
		}
	}

	// Check propagation if enabled
	if s.checkPropagation {
		if err := s.waitForPropagation(ctx, fqdn, challengeValue); err != nil {
			return err
		}
	}

	return nil
}

// Cleanup removes the DNS TXT record created by Solve.
func (s *DNSSolver) Cleanup(ctx context.Context, domain string, challenge *acme.Challenge) error {
	if s.closed.Load() {
		return ErrDNSSolverClosed
	}

	if domain == "" {
		return ErrEmptyDomain
	}

	if challenge == nil {
		return ErrNilChallenge
	}

	// Look up the record info
	recordKey := buildRecordKey(domain, challenge.Token)
	s.recordsMu.Lock()
	info, exists := s.activeRecords[recordKey]
	if !exists {
		s.recordsMu.Unlock()
		// Record was not created by this solver, try to clean up anyway
		fqdn := buildACMEChallengeFQDN(domain)
		// Use empty value for cleanup - provider should handle this
		if err := s.provider.CleanUp(ctx, domain, fqdn, ""); err != nil {
			return caerrors.DNSError("DNS record cleanup failed: %v", err)
		}
		return nil
	}

	// Remove from tracking
	delete(s.activeRecords, recordKey)
	s.recordsMu.Unlock()

	// Clean up the DNS record
	if err := s.provider.CleanUp(ctx, domain, info.fqdn, info.value); err != nil {
		return caerrors.DNSError("DNS record cleanup failed: %v", err)
	}

	return nil
}

// waitForPropagation waits until the DNS record is visible from external nameservers.
func (s *DNSSolver) waitForPropagation(ctx context.Context, fqdn, expectedValue string) error {
	return providers.WaitForCtx(ctx, s.propagationTimeout, s.propagationInterval, func() (bool, error) {
		return providers.CheckDNSPropagation(ctx, fqdn, expectedValue, s.nameservers)
	})
}

// Close marks the solver as closed and prevents further operations.
func (s *DNSSolver) Close() error {
	s.closed.Store(true)
	return nil
}

// IsClosed returns true if the solver has been closed.
func (s *DNSSolver) IsClosed() bool {
	return s.closed.Load()
}

// ActiveRecordCount returns the number of active records being tracked.
func (s *DNSSolver) ActiveRecordCount() int {
	s.recordsMu.RLock()
	defer s.recordsMu.RUnlock()
	return len(s.activeRecords)
}

// ComputeDNS01ChallengeValue computes the value for a DNS TXT record.
// Per RFC 8555 Section 8.4, the value is: base64url(SHA-256(keyAuthorization))
func ComputeDNS01ChallengeValue(keyAuth string) string {
	hash := sha256.Sum256([]byte(keyAuth))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// buildACMEChallengeFQDN builds the FQDN for an ACME challenge TXT record.
func buildACMEChallengeFQDN(domain string) string {
	// Ensure domain doesn't have trailing dot
	domain = strings.TrimSuffix(domain, ".")
	fqdn := fmt.Sprintf("_acme-challenge.%s.", domain)
	return fqdn
}

// buildRecordKey creates a unique key for tracking active records.
func buildRecordKey(domain, token string) string {
	return fmt.Sprintf("%s:%s", domain, token)
}

// PreCheckFunc is a function that runs before the ACME server is notified
// that the challenge is ready. It can be used to verify DNS propagation
// from specific nameservers or perform custom validation.
type PreCheckFunc func(ctx context.Context, fqdn, value string) error

// PreCheckOption configures the pre-check behavior
type PreCheckOption struct {
	// CheckFunc is the pre-check function to run
	CheckFunc PreCheckFunc

	// Timeout is the maximum time to wait for pre-check to succeed
	// Default: 120s
	Timeout time.Duration

	// Interval is the polling interval for pre-check retries
	// Default: 4s
	Interval time.Duration

	// AllowFailure allows the challenge to proceed even if pre-check fails
	// Default: false
	AllowFailure bool
}

// DefaultPreCheckOption returns default pre-check options
func DefaultPreCheckOption() *PreCheckOption {
	return &PreCheckOption{
		Timeout:      providers.PropagationTimeout,
		Interval:     providers.PropagationPoll,
		AllowFailure: false,
	}
}

// WrapPreCheck wraps a DNS solver with a pre-check function.
// The pre-check runs after the DNS record is provisioned but before
// returning from Solve(), allowing verification that the record is
// visible from specific nameservers or satisfies custom conditions.
//
// Example usage:
//
//	// Create solver with pre-check that verifies from Google DNS
//	solver := WrapPreCheck(baseSolver, &PreCheckOption{
//	    CheckFunc: func(ctx context.Context, fqdn, value string) error {
//	        return providers.CheckDNSPropagationWithNameservers(ctx, fqdn, value, []string{"8.8.8.8:53"})
//	    },
//	    Timeout:  2 * time.Minute,
//	    Interval: 5 * time.Second,
//	})
func WrapPreCheck(solver *DNSSolver, option *PreCheckOption) *PreCheckDNSSolver {
	if option == nil {
		option = DefaultPreCheckOption()
	}
	if option.Timeout <= 0 {
		option.Timeout = providers.PropagationTimeout
	}
	if option.Interval <= 0 {
		option.Interval = providers.PropagationPoll
	}

	return &PreCheckDNSSolver{
		solver: solver,
		option: option,
	}
}

// PreCheckDNSSolver wraps a DNSSolver with pre-check functionality
type PreCheckDNSSolver struct {
	solver *DNSSolver
	option *PreCheckOption
}

// Type returns the challenge type this solver handles.
func (s *PreCheckDNSSolver) Type() string {
	return s.solver.Type()
}

// Solve provisions a DNS TXT record and runs the pre-check function.
func (s *PreCheckDNSSolver) Solve(ctx context.Context, domain string, challenge *acme.Challenge, keyAuth string) error {
	// First, run the underlying solver to provision the record
	if err := s.solver.Solve(ctx, domain, challenge, keyAuth); err != nil {
		return err
	}

	// Run pre-check if configured
	if s.option.CheckFunc != nil {
		fqdn := buildACMEChallengeFQDN(domain)
		challengeValue := ComputeDNS01ChallengeValue(keyAuth)

		err := s.runPreCheck(ctx, fqdn, challengeValue)
		if err != nil {
			if !s.option.AllowFailure {
				// Clean up on pre-check failure
				_ = s.solver.Cleanup(ctx, domain, challenge)
				return caerrors.DNSError("dns-01: pre-check failed: %v", err)
			}
			// Log but continue if AllowFailure is true
		}
	}

	return nil
}

// runPreCheck runs the pre-check function with retry logic
func (s *PreCheckDNSSolver) runPreCheck(ctx context.Context, fqdn, value string) error {
	return providers.WaitForCtx(ctx, s.option.Timeout, s.option.Interval, func() (bool, error) {
		err := s.option.CheckFunc(ctx, fqdn, value)
		if err != nil {
			return false, nil // Keep retrying
		}
		return true, nil // Success
	})
}

// Cleanup removes the DNS TXT record created by Solve.
func (s *PreCheckDNSSolver) Cleanup(ctx context.Context, domain string, challenge *acme.Challenge) error {
	return s.solver.Cleanup(ctx, domain, challenge)
}

// Close marks the solver as closed.
func (s *PreCheckDNSSolver) Close() error {
	return s.solver.Close()
}

// IsClosed returns true if the solver has been closed.
func (s *PreCheckDNSSolver) IsClosed() bool {
	return s.solver.IsClosed()
}

// ActiveRecordCount returns the number of active records being tracked.
func (s *PreCheckDNSSolver) ActiveRecordCount() int {
	return s.solver.ActiveRecordCount()
}

// CheckDNSFromAuthoritative creates a pre-check function that verifies
// DNS propagation by querying the authoritative nameservers for the domain.
func CheckDNSFromAuthoritative() PreCheckFunc {
	return func(ctx context.Context, fqdn, value string) error {
		// Get authoritative nameservers for the domain
		ns, err := getAuthoritativeNameservers(fqdn)
		if err != nil {
			return caerrors.DNSError("failed to get authoritative nameservers: %v", err)
		}

		// Check propagation from authoritative servers
		ok, err := providers.CheckDNSPropagation(ctx, fqdn, value, ns)
		if err != nil {
			return err
		}
		if !ok {
			return ErrDNSRecordNotPresent
		}
		return nil
	}
}

// CheckDNSFromPublic creates a pre-check function that verifies
// DNS propagation by querying public DNS resolvers (Google, Cloudflare).
func CheckDNSFromPublic() PreCheckFunc {
	publicDNS := []string{
		"8.8.8.8:53",        // Google
		"8.8.4.4:53",        // Google
		"1.1.1.1:53",        // Cloudflare
		"1.0.0.1:53",        // Cloudflare
		"208.67.222.222:53", // OpenDNS
	}

	return func(ctx context.Context, fqdn, value string) error {
		ok, err := providers.CheckDNSPropagation(ctx, fqdn, value, publicDNS)
		if err != nil {
			return err
		}
		if !ok {
			return ErrDNSRecordNotPresent
		}
		return nil
	}
}

// CheckDNSFromNameservers creates a pre-check function that verifies
// DNS propagation from the specified nameservers.
func CheckDNSFromNameservers(nameservers []string) PreCheckFunc {
	return func(ctx context.Context, fqdn, value string) error {
		ok, err := providers.CheckDNSPropagation(ctx, fqdn, value, nameservers)
		if err != nil {
			return err
		}
		if !ok {
			return ErrDNSRecordNotPresent
		}
		return nil
	}
}

// getAuthoritativeNameservers queries for the authoritative nameservers
// for a domain. This is a simplified implementation.
func getAuthoritativeNameservers(fqdn string) ([]string, error) {
	// Extract the base domain from the FQDN
	// _acme-challenge.example.com. -> example.com.
	domain := strings.TrimPrefix(fqdn, "_acme-challenge.")

	// Use default resolver to find NS records
	// In a production implementation, you might want to walk up
	// the DNS hierarchy to find the actual zone
	ns, err := net.LookupNS(strings.TrimSuffix(domain, "."))
	if err != nil {
		return nil, err
	}

	servers := make([]string, 0, len(ns))
	for _, n := range ns {
		servers = append(servers, n.Host+":53")
	}

	if len(servers) == 0 {
		return nil, caerrors.DNSError("no nameservers found for domain")
	}

	return servers, nil
}
