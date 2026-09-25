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
	"net"
	"testing"
	"time"

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

// TestWrapChallengeVerifiers_WrapsHTTP01AndDNS01 verifies that
// WrapChallengeVerifiers wraps the "http-01" and "dns-01" entries of the
// input map with breakers registered on the given Manager under "http01"
// and "dns01" respectively, and leaves every other entry (e.g. enroll-01)
// untouched. It pre-trips both breakers rather than driving a real network
// failure through the verifier, so the assertion is that the wrapped
// verifiers fail fast on an already-open breaker while the untouched entry
// still succeeds.
func TestWrapChallengeVerifiers_WrapsHTTP01AndDNS01(t *testing.T) {
	breakers := circuitbreaker.NewManager()
	httpCB := breakers.GetOrCreate(&circuitbreaker.Config{Name: "http01", MaxFailures: 1, ResetTimeout: time.Hour})
	dnsCB := breakers.GetOrCreate(&circuitbreaker.Config{Name: "dns01", MaxFailures: 1, ResetTimeout: time.Hour})
	httpCB.Trip()
	dnsCB.Trip()

	in := map[string]common.ChallengeVerifierFunc{
		common.ChallengeTypeHTTP01:   noopVerifier,
		common.ChallengeTypeDNS01:    noopVerifier,
		common.ChallengeTypeEnroll01: noopVerifier,
	}

	out := WrapChallengeVerifiers(in, config.ACMEResilienceConfig{}, breakers)
	require.Len(t, out, 3)

	err := out[common.ChallengeTypeHTTP01](nil, nil, "example.com", "80", "tok", "ka")
	assert.ErrorIs(t, err, circuitbreaker.ErrCircuitOpen, "http-01 verifier should be wrapped with the open http01 breaker")

	err = out[common.ChallengeTypeDNS01](nil, nil, "example.com", "80", "tok", "ka")
	assert.ErrorIs(t, err, circuitbreaker.ErrCircuitOpen, "dns-01 verifier should be wrapped with the open dns01 breaker")

	err = out[common.ChallengeTypeEnroll01](nil, nil, "example.com", "80", "tok", "ka")
	assert.NoError(t, err, "enroll-01 has no breaker and must be returned unwrapped")

	// The input map itself must not be mutated: its http-01 entry is still
	// the original, unwrapped verifier, so it succeeds even though the
	// breaker the returned copy wraps it with is open.
	err = in[common.ChallengeTypeHTTP01](nil, nil, "example.com", "80", "tok", "ka")
	assert.NoError(t, err, "input map must not be mutated by WrapChallengeVerifiers")
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
