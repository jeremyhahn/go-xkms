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

package server

import (
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/circuitbreaker"
	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// noopVerifier is a common.ChallengeVerifierFunc that always succeeds,
// standing in for the real http-01/dns-01/attestation verifiers so these
// tests exercise WrapChallengeVerifiers' wrapping decision rather than any
// network behavior.
func noopVerifier(*net.Resolver, common.CertificateAuthority, string, string, string, string) error {
	return nil
}

// errFailingTarget is returned by a verifier standing in for a validation
// target that is always unreachable, so tests can trip a target's breaker
// deterministically without a real network call.
var errFailingTarget = errors.New("target unreachable")

// failingVerifier is a common.ChallengeVerifierFunc that always fails with
// errFailingTarget, regardless of which target (authzValue) it is asked to
// verify.
func failingVerifier(*net.Resolver, common.CertificateAuthority, string, string, string, string) error {
	return errFailingTarget
}

// oneFailureTripsConfig configures a breaker group that opens a target's
// breaker on its first failure and never resets it for the duration of a
// test (ResetTimeoutSeconds well beyond any test's runtime).
func oneFailureTripsConfig() config.ACMECircuitBreakerConfig {
	return config.ACMECircuitBreakerConfig{MaxFailures: 1, ResetTimeoutSeconds: 3600}
}

// TestWrapChallengeVerifiers_WrapsHTTP01AndDNS01PerTarget verifies that
// WrapChallengeVerifiers wraps the "http-01" and "dns-01" entries of the
// input map with per-target breaker groups on breakers (named "http01" and
// "dns01"), and leaves every other entry (e.g. enroll-01) untouched. This is
// the regression test for go-xkms#1189/#1190: an account whose target always
// fails trips only that target's own breaker, so a different target under
// the same challenge type still reaches the verifier instead of failing
// fast on someone else's open breaker.
func TestWrapChallengeVerifiers_WrapsHTTP01AndDNS01PerTarget(t *testing.T) {
	breakers := circuitbreaker.NewManager()

	in := map[string]common.ChallengeVerifierFunc{
		common.ChallengeTypeHTTP01:   failingVerifier,
		common.ChallengeTypeDNS01:    failingVerifier,
		common.ChallengeTypeEnroll01: noopVerifier,
	}

	resilience := config.ACMEResilienceConfig{
		HTTP01: oneFailureTripsConfig(),
		DNS01:  oneFailureTripsConfig(),
	}
	out := WrapChallengeVerifiers(in, resilience, breakers)
	require.Len(t, out, 3)

	// A failing call against "bad.example.com" trips that target's http01
	// breaker (MaxFailures 1).
	err := out[common.ChallengeTypeHTTP01](nil, nil, "bad.example.com", "80", "tok", "ka")
	assert.ErrorIs(t, err, errFailingTarget)
	err = out[common.ChallengeTypeHTTP01](nil, nil, "bad.example.com", "80", "tok", "ka")
	assert.ErrorIs(t, err, circuitbreaker.ErrCircuitOpen, "bad.example.com's own breaker must now be open")

	// A different http-01 target must be unaffected: it has its own breaker
	// and still reaches the verifier.
	err = out[common.ChallengeTypeHTTP01](nil, nil, "good.example.com", "80", "tok", "ka")
	assert.ErrorIs(t, err, errFailingTarget, "a healthy target must not fail fast on another target's open breaker")

	// dns-01 exhibits the same per-target isolation.
	err = out[common.ChallengeTypeDNS01](nil, nil, "bad.example.com", "80", "tok", "ka")
	assert.ErrorIs(t, err, errFailingTarget)
	err = out[common.ChallengeTypeDNS01](nil, nil, "bad.example.com", "80", "tok", "ka")
	assert.ErrorIs(t, err, circuitbreaker.ErrCircuitOpen)
	err = out[common.ChallengeTypeDNS01](nil, nil, "good.example.com", "80", "tok", "ka")
	assert.ErrorIs(t, err, errFailingTarget)

	err = out[common.ChallengeTypeEnroll01](nil, nil, "example.com", "80", "tok", "ka")
	assert.NoError(t, err, "enroll-01 has no breaker and must be returned unwrapped")

	// The input map itself must not be mutated: its http-01 entry is still
	// the original, unwrapped verifier.
	err = in[common.ChallengeTypeHTTP01](nil, nil, "bad.example.com", "80", "tok", "ka")
	assert.ErrorIs(t, err, errFailingTarget, "input map must not be mutated by WrapChallengeVerifiers")
}

// TestWrapChallengeVerifiers_RegistersTargetGroupsForHealth verifies that
// wrapping registers the "http01"/"dns01" per-target breaker groups on
// breakers immediately -- so /acme/health can report them (via
// circuitbreaker.Manager.TargetGroupStatuses) before any challenge has ever
// been validated -- configured with the resolved capacity from resilience.
func TestWrapChallengeVerifiers_RegistersTargetGroupsForHealth(t *testing.T) {
	breakers := circuitbreaker.NewManager()
	in := map[string]common.ChallengeVerifierFunc{
		common.ChallengeTypeHTTP01: noopVerifier,
		common.ChallengeTypeDNS01:  noopVerifier,
	}
	resilience := config.ACMEResilienceConfig{
		HTTP01: config.ACMECircuitBreakerConfig{TargetCapacity: 7},
		DNS01:  config.ACMECircuitBreakerConfig{TargetCapacity: 9},
	}

	WrapChallengeVerifiers(in, resilience, breakers)

	statuses := breakers.TargetGroupStatuses()
	require.Contains(t, statuses, "http01")
	assert.Equal(t, 7, statuses["http01"].Capacity)
	assert.Zero(t, statuses["http01"].Tracked, "no target has been validated yet")
	require.Contains(t, statuses, "dns01")
	assert.Equal(t, 9, statuses["dns01"].Capacity)
}

// TestWrapChallengeVerifiers_NilBreakersReturnsInputUnchanged verifies the
// error/edge path: a nil Manager is the documented "resilience not wired"
// case and must return m unchanged (same entries, unwrapped), not panic or
// silently drop challenge types.
func TestWrapChallengeVerifiers_NilBreakersReturnsInputUnchanged(t *testing.T) {
	in := map[string]common.ChallengeVerifierFunc{
		common.ChallengeTypeHTTP01: noopVerifier,
	}

	out := WrapChallengeVerifiers(in, config.ACMEResilienceConfig{}, nil)

	require.Len(t, out, 1)
	err := out[common.ChallengeTypeHTTP01](nil, nil, "example.com", "80", "tok", "ka")
	assert.NoError(t, err)
}
