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
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/circuitbreaker"
	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// WrapChallengeVerifiers returns a copy of m with its "http-01" and
// "dns-01" entries -- when present -- wrapped with a per-target circuit
// breaker group on breakers, configured from resilience.HTTP01 /
// resilience.DNS01 (circuitbreaker.DefaultConfig substitutes for any field
// left at its zero value; see ACMECircuitBreakerConfig.CircuitBreakerConfig).
// Every other challenge type, such as the TPM attestation verifiers
// sdk/go/acme.ACMEAttestationVerifiers builds, has no outbound network call
// for a breaker to protect and is returned unchanged.
//
// Each group gives every validation target (the domain http-01 dials, or
// the zone dns-01 queries) its own breaker, bounded by
// resilience.HTTP01.ResolveTargetCapacity/ResolveTargetIdleTimeout (and the
// DNS01 equivalents): a target that never responds trips only its own
// breaker instead of the one breaker every account's validation used to
// share (go-xkms#1189/#1190). circuitbreaker.WrapChallengeVerifierPerTarget
// does the wrapping itself; this function is the one place that decides
// WHICH entries get wrapped and under WHICH group names, so a group
// reported as "http01" or "dns01" on a /health endpoint always means the
// same thing. xkmsd's embedded ACME listener (cmd/xkmsd/acme.go's
// buildChallengeMap) and the standalone TrustedCA
// (pkg/acme/client/trustedca.go) both call it instead of hand-rolling their
// own wrapping.
//
// A nil breakers or nil m returns m unchanged.
func WrapChallengeVerifiers(
	m map[string]common.ChallengeVerifierFunc,
	resilience config.ACMEResilienceConfig,
	breakers *circuitbreaker.Manager,
) map[string]common.ChallengeVerifierFunc {
	if breakers == nil || m == nil {
		return m
	}

	out := make(map[string]common.ChallengeVerifierFunc, len(m))
	for challengeType, verifier := range m {
		out[challengeType] = verifier
	}

	if verifier, ok := out[common.ChallengeTypeHTTP01]; ok {
		cfg := circuitbreaker.TargetConfig{
			Group:     "http01",
			NewConfig: resilience.HTTP01.CircuitBreakerConfig,
			Capacity:  resilience.HTTP01.ResolveTargetCapacity(),
			IdleTTL:   resilience.HTTP01.ResolveTargetIdleTimeout(),
		}
		breakers.RegisterTargetGroup(cfg)
		out[common.ChallengeTypeHTTP01] = circuitbreaker.WrapChallengeVerifierPerTarget(breakers, cfg, verifier)
	}
	if verifier, ok := out[common.ChallengeTypeDNS01]; ok {
		cfg := circuitbreaker.TargetConfig{
			Group:     "dns01",
			NewConfig: resilience.DNS01.CircuitBreakerConfig,
			Capacity:  resilience.DNS01.ResolveTargetCapacity(),
			IdleTTL:   resilience.DNS01.ResolveTargetIdleTimeout(),
		}
		breakers.RegisterTargetGroup(cfg)
		out[common.ChallengeTypeDNS01] = circuitbreaker.WrapChallengeVerifierPerTarget(breakers, cfg, verifier)
	}
	return out
}
