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

package peer

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"testing"
)

// TestEvidenceFromTLS_BindsTheQuoteToThisConnection is the end-to-end pair:
// the quoting side computes its qualifying data from its own end of the
// connection, the verifying side builds evidence and a policy from the other
// end, and the verdict passes. Both ends export the same keying material, so
// neither has to transmit the binding.
func TestEvidenceFromTLS_BindsTheQuoteToThisConnection(t *testing.T) {
	f := newFixture(t)
	client, server := tlsPair(t, tls.VersionTLS13)

	// Quoting side, on the client end of the connection.
	qualifying, err := QualifyingDataFromTLS(&client, f.nonce)
	if err != nil {
		t.Fatalf("QualifyingDataFromTLS: %v", err)
	}
	reported := f.evidenceFor(t, buildQuote(t, f.nonce, f.pcrs, quoteOptions{extraData: qualifying}))

	// Verifying side, on the server end.
	bound, err := EvidenceFromTLS(&server, reported)
	if err != nil {
		t.Fatalf("EvidenceFromTLS: %v", err)
	}
	if len(bound.ChannelBinding) != ChannelBindingLength {
		t.Fatalf("binding is %d bytes, want %d", len(bound.ChannelBinding), ChannelBindingLength)
	}

	verdict, err := f.verifier().Verify(context.Background(), bound.Evidence, bound.BindPolicy(f.policy()))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !verdict.Passed || verdict.Checks != allChecks {
		t.Fatalf("verdict = %+v", verdict)
	}
}

// TestEvidenceFromTLS_RejectsAQuoteRelayedFromAnotherConnection is the attack
// the binding exists to stop: a genuine, correctly signed quote over the right
// PCRs, replayed onto a connection the attacker holds.
func TestEvidenceFromTLS_RejectsAQuoteRelayedFromAnotherConnection(t *testing.T) {
	f := newFixture(t)
	genuineClient, _ := tlsPair(t, tls.VersionTLS13)
	_, attackerServer := tlsPair(t, tls.VersionTLS13)

	qualifying, err := QualifyingDataFromTLS(&genuineClient, f.nonce)
	if err != nil {
		t.Fatalf("QualifyingDataFromTLS: %v", err)
	}
	relayed := f.evidenceFor(t, buildQuote(t, f.nonce, f.pcrs, quoteOptions{extraData: qualifying}))

	bound, err := EvidenceFromTLS(&attackerServer, relayed)
	if err != nil {
		t.Fatalf("EvidenceFromTLS: %v", err)
	}
	verdict, err := f.verifier().Verify(context.Background(), bound.Evidence, bound.BindPolicy(f.policy()))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verdict.Passed {
		t.Fatal("a quote bound to another connection passed")
	}
	if verdict.Checks.ChannelBinding {
		t.Fatal("the channel binding check held for a relayed quote")
	}
	// Evidence was present and wrong, which is the class that may justify
	// quarantine — not an absence.
	if verdict.Failure != FailureCryptographic {
		t.Fatalf("failure = %v, want cryptographic", verdict.Failure)
	}
}

// TestEvidenceFromTLS_RejectsAnUnboundQuoteUnderABindingPolicy: a peer that
// quoted the bare nonce satisfies the nonce check and fails the binding one,
// so the verdict says which of the two it was.
func TestEvidenceFromTLS_RejectsAnUnboundQuoteUnderABindingPolicy(t *testing.T) {
	f := newFixture(t)
	_, server := tlsPair(t, tls.VersionTLS13)

	unbound := f.evidenceFor(t, buildQuote(t, f.nonce, f.pcrs, quoteOptions{}))
	bound, err := EvidenceFromTLS(&server, unbound)
	if err != nil {
		t.Fatalf("EvidenceFromTLS: %v", err)
	}
	verdict, err := f.verifier().Verify(context.Background(), bound.Evidence, bound.BindPolicy(f.policy()))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verdict.Passed || verdict.Checks.ChannelBinding || !verdict.Checks.Nonce {
		t.Fatalf("verdict = %+v; want the nonce check to hold and the binding check to fail", verdict)
	}
	if verdict.Failure != FailureCryptographic {
		t.Fatalf("failure = %v, want cryptographic", verdict.Failure)
	}
}

// TestEvidenceFromTLS_RefusesAnUnusableConnection: there is no unbound
// fall-back. A connection that yields no binding yields no evidence, so a
// caller cannot accidentally verify the relayable form.
func TestEvidenceFromTLS_RefusesAnUnusableConnection(t *testing.T) {
	f := newFixture(t)
	reported := f.evidence(t)

	cases := map[string]*tls.ConnectionState{
		"nil state":            nil,
		"incomplete handshake": {Version: tls.VersionTLS13},
	}
	for name, state := range cases {
		t.Run(name, func(t *testing.T) {
			bound, err := EvidenceFromTLS(state, reported)
			var cbe *ChannelBindingError
			if !errors.As(err, &cbe) {
				t.Fatalf("err = %v, want *ChannelBindingError", err)
			}
			if bound.ChannelBinding != nil || bound.Evidence.Quote != nil {
				t.Fatalf("a refused connection produced evidence: %+v", bound)
			}

			if _, err := QualifyingDataFromTLS(state, f.nonce); !errors.As(err, &cbe) {
				t.Fatalf("QualifyingDataFromTLS err = %v, want *ChannelBindingError", err)
			}
		})
	}
}

// TestEvidenceFromTLS_DoesNotAliasTheCaller: the returned evidence is the
// verifier's copy. A collector that reuses its receive buffers, or a cache
// that hands the same evidence to two verifications, cannot have its values
// changed underneath it.
func TestEvidenceFromTLS_DoesNotAliasTheCaller(t *testing.T) {
	f := newFixture(t)
	_, server := tlsPair(t, tls.VersionTLS13)
	reported := f.evidence(t)

	bound, err := EvidenceFromTLS(&server, reported)
	if err != nil {
		t.Fatalf("EvidenceFromTLS: %v", err)
	}

	bound.Evidence.Quote[0] ^= 0xff
	bound.Evidence.Signature[0] ^= 0xff
	bound.Evidence.Nonce[0] ^= 0xff
	bound.Evidence.AKCertificatePEM[0] ^= 0xff
	for idx := range bound.Evidence.PCRs {
		bound.Evidence.PCRs[idx][0] ^= 0xff
	}

	if reported.Quote[0] == bound.Evidence.Quote[0] ||
		reported.Signature[0] == bound.Evidence.Signature[0] ||
		reported.Nonce[0] == bound.Evidence.Nonce[0] ||
		reported.AKCertificatePEM[0] == bound.Evidence.AKCertificatePEM[0] {
		t.Fatal("EvidenceFromTLS returned the caller's buffers")
	}
	for idx, value := range reported.PCRs {
		if value[0] == bound.Evidence.PCRs[idx][0] {
			t.Fatalf("PCR %d aliases the caller's map", idx)
		}
	}
}

// TestBindPolicy_LeavesTheProvisionedPolicyAlone: one provisioned policy value
// binds many connections, so binding must not write into it.
func TestBindPolicy_LeavesTheProvisionedPolicyAlone(t *testing.T) {
	f := newFixture(t)
	first, _ := tlsPair(t, tls.VersionTLS13)
	second, _ := tlsPair(t, tls.VersionTLS13)

	provisioned := f.policy()
	boundFirst, err := EvidenceFromTLS(&first, f.evidence(t))
	if err != nil {
		t.Fatalf("EvidenceFromTLS: %v", err)
	}
	boundSecond, err := EvidenceFromTLS(&second, f.evidence(t))
	if err != nil {
		t.Fatalf("EvidenceFromTLS: %v", err)
	}

	policyFirst := boundFirst.BindPolicy(provisioned)
	policySecond := boundSecond.BindPolicy(provisioned)

	if provisioned.ChannelBinding != nil {
		t.Fatal("BindPolicy wrote into the caller's policy")
	}
	if bytes.Equal(policyFirst.ChannelBinding, policySecond.ChannelBinding) {
		t.Fatal("two connections produced the same bound policy")
	}
	if !bytes.Equal(policyFirst.ChannelBinding, boundFirst.ChannelBinding) {
		t.Fatal("BindPolicy did not install this connection's binding")
	}
	// Everything else the caller provisioned survives.
	if policyFirst.MaxEvidenceAge != provisioned.MaxEvidenceAge || len(policyFirst.Baseline) != len(provisioned.Baseline) {
		t.Fatalf("BindPolicy altered the policy: %+v", policyFirst)
	}

	policyFirst.ChannelBinding[0] ^= 0xff
	if policyFirst.ChannelBinding[0] == boundFirst.ChannelBinding[0] {
		t.Fatal("the bound policy aliases the evidence's binding")
	}
}

// TestQualifyingDataFromTLS_AgreesWithBothEndsAndWithQualifyingData: the
// convenience form must compute exactly what the two-step form does, or a
// quoter using one and a verifier using the other would never agree.
func TestQualifyingDataFromTLS_AgreesWithBothEndsAndWithQualifyingData(t *testing.T) {
	client, server := tlsPair(t, tls.VersionTLS13)
	nonce := []byte("nonce-0123456789abcdef0123456789")

	fromClient, err := QualifyingDataFromTLS(&client, nonce)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	fromServer, err := QualifyingDataFromTLS(&server, nonce)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	if !bytes.Equal(fromClient, fromServer) {
		t.Fatal("the two ends of one connection computed different qualifying data")
	}

	binding, err := ChannelBinding(&server)
	if err != nil {
		t.Fatalf("ChannelBinding: %v", err)
	}
	if !bytes.Equal(fromServer, QualifyingData(nonce, binding)) {
		t.Fatal("QualifyingDataFromTLS disagrees with QualifyingData over the same binding")
	}
	if bytes.Equal(fromServer, QualifyingData(nonce, nil)) {
		t.Fatal("QualifyingDataFromTLS produced the unbound form")
	}
}
