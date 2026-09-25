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
// "dns-01" entries -- when present -- wrapped with a circuit breaker from
// breakers, configured from resilience.HTTP01 / resilience.DNS01
// (circuitbreaker.DefaultConfig substitutes for any field left at its zero
// value; see ACMECircuitBreakerConfig.CircuitBreakerConfig). Every other
// challenge type, such as the TPM attestation verifiers
// sdk/go/acme.ACMEAttestationVerifiers builds, has no outbound network call
// for a breaker to protect and is returned unchanged.
//
// circuitbreaker.WrapChallengeVerifier does the wrapping itself; this
// function is the one place that decides WHICH entries get wrapped and
// under WHICH breaker names, so a breaker reported as "http01" or "dns01"
// on a /health endpoint always means the same thing. xkmsd's embedded ACME
// listener (cmd/xkmsd/acme.go's buildChallengeMap) and the standalone
// TrustedCA (pkg/acme/client/trustedca.go) both call it instead of
// hand-rolling their own wrapping.
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
		cb := breakers.GetOrCreate(resilience.HTTP01.CircuitBreakerConfig("http01"))
		out[common.ChallengeTypeHTTP01] = circuitbreaker.WrapChallengeVerifier(cb, verifier)
	}
	if verifier, ok := out[common.ChallengeTypeDNS01]; ok {
		cb := breakers.GetOrCreate(resilience.DNS01.CircuitBreakerConfig("dns01"))
		out[common.ChallengeTypeDNS01] = circuitbreaker.WrapChallengeVerifier(cb, verifier)
	}
	return out
}
