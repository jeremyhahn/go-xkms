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
	"context"
	"crypto"
	"crypto/subtle"
	"strconv"
	"strings"
	"time"
)

// Verifier renders a Verdict on a peer's attestation evidence under a
// policy. Implementations are safe for concurrent use.
type Verifier interface {
	// Verify evaluates the evidence against the policy. It returns an error
	// only when the policy is unusable (*PolicyError) or the context is done
	// (*ContextError); every question about the evidence itself is answered
	// in the Verdict, fail-closed.
	Verify(ctx context.Context, evidence Evidence, policy Policy) (Verdict, error)
}

// Option configures a Verifier.
type Option func(*verifier)

// WithClock replaces the clock used for certificate validity, VerifiedAt and
// the freshness check. Tests pin it; production leaves it alone.
func WithClock(now func() time.Time) Option {
	return func(v *verifier) {
		if now != nil {
			v.now = now
		}
	}
}

// NewVerifier constructs a Verifier.
func NewVerifier(opts ...Option) Verifier {
	v := &verifier{now: func() time.Time { return time.Now().UTC() }}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

type verifier struct {
	now func() time.Time
}

// failure is one check's negative outcome: which class it falls in and why.
type failure struct {
	class  FailureClass
	reason string
}

// absent records a check that could not run.
func absent(reason string) *failure {
	return &failure{class: FailureAbsence, reason: reason}
}

// wrong records a check that ran and found the evidence wrong.
func wrong(reason string) *failure {
	return &failure{class: FailureCryptographic, reason: reason}
}

// outcome accumulates the checks into a Verdict. The failure class is
// derived in exactly one place, finish, so no check can promote or demote
// another's classification.
type outcome struct {
	verdict       Verdict
	reasons       []string
	cryptographic bool
}

func (o *outcome) fail(f *failure) {
	o.reasons = append(o.reasons, f.reason)
	if f.class == FailureCryptographic {
		o.cryptographic = true
	}
}

func (o *outcome) finish() Verdict {
	c := o.verdict.Checks
	o.verdict.Passed = c.AKCertificate && c.Signature && c.Nonce && c.ChannelBinding &&
		c.PCRDigest && c.RequiredPCRs && c.Baseline && c.Freshness
	switch {
	case o.verdict.Passed:
		o.verdict.Failure = FailureNone
	case o.cryptographic:
		o.verdict.Failure = FailureCryptographic
	default:
		o.verdict.Failure = FailureAbsence
	}
	o.verdict.Reason = strings.Join(o.reasons, "; ")
	return o.verdict
}

// Verify implements Verifier.
func (v *verifier) Verify(ctx context.Context, evidence Evidence, policy Policy) (Verdict, error) {
	if err := ctx.Err(); err != nil {
		return Verdict{}, &ContextError{Cause: err}
	}
	if err := policy.validate(); err != nil {
		return Verdict{}, err
	}

	now := v.now()
	o := &outcome{verdict: Verdict{VerifiedAt: now}}

	akKey := o.checkAKCertificate(&evidence, &policy, now)
	q := o.checkQuote(&evidence)
	o.checkSignature(&evidence, q, akKey)
	o.checkQualifyingData(&evidence, q, &policy)
	o.checkPCRDigest(&evidence, q)
	o.checkRequiredPCRs(q, &policy)
	o.checkBaseline(&evidence, &policy)
	o.checkFreshness(&evidence, &policy, now)

	return o.finish(), nil
}

// validate rejects a policy that cannot be evaluated as written.
func (p *Policy) validate() error {
	if p.MaxEvidenceAge < 0 {
		return &PolicyError{Field: "MaxEvidenceAge", Reason: "must not be negative"}
	}
	for idx, value := range p.Baseline {
		if idx < 0 {
			return &PolicyError{Field: "Baseline", Reason: "PCR index " + strconv.Itoa(idx) + " is negative"}
		}
		if len(value) == 0 {
			return &PolicyError{Field: "Baseline", Reason: "PCR " + strconv.Itoa(idx) + " has an empty value"}
		}
	}
	for _, idx := range p.RequiredPCRs {
		if idx < 0 {
			return &PolicyError{Field: "RequiredPCRs", Reason: "PCR index " + strconv.Itoa(idx) + " is negative"}
		}
		if len(p.Baseline) > 0 {
			if _, ok := p.Baseline[idx]; !ok {
				return &PolicyError{Field: "RequiredPCRs", Reason: "PCR " + strconv.Itoa(idx) + " is required but has no baseline value"}
			}
		}
	}
	return nil
}

// checkAKCertificate resolves the trust anchor for the quote signature and
// returns the certified public key, or nil when no key can be trusted.
func (o *outcome) checkAKCertificate(evidence *Evidence, policy *Policy, now time.Time) crypto.PublicKey {
	if len(evidence.AKCertificatePEM) == 0 {
		o.fail(absent("no attestation key certificate in evidence; tcg-cap-verifiedTPMRestricted cannot be checked (TCG DevID v1 r12 §8.2)"))
		return nil
	}
	leaf, extra, f := parseAKCertificates(evidence.AKCertificatePEM)
	if f != nil {
		o.fail(f)
		return nil
	}
	key, f := verifyAKCertificate(leaf, extra, policy, now)
	if f != nil {
		o.fail(f)
		return nil
	}
	o.verdict.Checks.AKCertificate = true
	return key
}

// checkQuote parses the TPMS_ATTEST. It is not itself one of the eight
// checks, but every check that reads the quote depends on it, and it stamps
// the TPM clock information onto the verdict.
func (o *outcome) checkQuote(evidence *Evidence) *quote {
	if len(evidence.Quote) == 0 {
		o.fail(absent("no quote in evidence"))
		return nil
	}
	q, f := parseQuote(evidence.Quote)
	if f != nil {
		o.fail(f)
		return nil
	}
	o.verdict.Clock = ClockInfo{
		Clock:        q.attest.ClockInfo.Clock,
		ResetCount:   q.attest.ClockInfo.ResetCount,
		RestartCount: q.attest.ClockInfo.RestartCount,
		Safe:         bool(q.attest.ClockInfo.Safe),
	}
	o.verdict.FirmwareVersion = q.attest.FirmwareVersion
	return q
}

// checkSignature verifies the attestation key's signature over the quote.
func (o *outcome) checkSignature(evidence *Evidence, q *quote, key crypto.PublicKey) {
	if len(evidence.Signature) == 0 {
		o.fail(absent("no quote signature in evidence"))
		return
	}
	if key == nil {
		o.fail(absent("signature not evaluated: no verified attestation key"))
		return
	}
	if q == nil {
		o.fail(absent("signature not evaluated: quote did not parse"))
		return
	}
	if f := verifySignature(key, q.hash, evidence.Quote, evidence.Signature); f != nil {
		o.fail(f)
		return
	}
	o.verdict.Checks.Signature = true
}

// checkQualifyingData checks the nonce and, when the policy binds to a
// channel, the channel binding. The two are one value in the quote, so a
// quote that carries the bare nonce under a binding policy passes the nonce
// check and fails the binding check; anything else fails both.
func (o *outcome) checkQualifyingData(evidence *Evidence, q *quote, policy *Policy) {
	bound := len(policy.ChannelBinding) > 0
	if !bound {
		o.verdict.Checks.ChannelBinding = true
	}
	if len(evidence.Nonce) == 0 {
		o.verdict.Checks.ChannelBinding = false
		o.fail(absent("no nonce in evidence"))
		return
	}
	if q == nil {
		o.verdict.Checks.ChannelBinding = false
		o.fail(absent("nonce not evaluated: quote did not parse"))
		return
	}

	extra := q.attest.ExtraData.Buffer
	expected := QualifyingData(evidence.Nonce, policy.ChannelBinding)
	if subtle.ConstantTimeCompare(extra, expected) == 1 {
		o.verdict.Checks.Nonce = true
		o.verdict.Checks.ChannelBinding = true
		return
	}
	if bound && subtle.ConstantTimeCompare(extra, evidence.Nonce) == 1 {
		o.verdict.Checks.Nonce = true
		o.fail(wrong("quote carries the bare nonce and is not bound to this TLS channel"))
		return
	}
	if bound {
		o.fail(wrong("quote qualifying data carries neither the verifier's nonce nor its binding to this channel"))
		return
	}
	o.fail(wrong("quote qualifying data does not carry the verifier's nonce"))
}

// checkPCRDigest proves the reported values against the signed digest.
func (o *outcome) checkPCRDigest(evidence *Evidence, q *quote) {
	if len(evidence.PCRs) == 0 {
		o.fail(absent("no PCR values in evidence; the peer must report the values it quoted"))
		return
	}
	if q == nil {
		o.fail(absent("PCR digest not evaluated: quote did not parse"))
		return
	}
	if f := q.verifyPCRDigest(evidence.PCRs); f != nil {
		o.fail(f)
		return
	}
	o.verdict.Checks.PCRDigest = true
}

// checkRequiredPCRs confirms the quote covers every register the policy
// insists on. A register the peer did not quote is an absence: the evidence
// does not cover what the policy needs, and nothing about it was wrong.
func (o *outcome) checkRequiredPCRs(q *quote, policy *Policy) {
	if len(policy.RequiredPCRs) == 0 {
		o.verdict.Checks.RequiredPCRs = true
		return
	}
	if q == nil {
		o.fail(absent("required PCRs not evaluated: quote did not parse"))
		return
	}
	var missing []int
	for _, idx := range policy.RequiredPCRs {
		if !q.covers(idx) {
			missing = append(missing, idx)
		}
	}
	if len(missing) > 0 {
		o.fail(absent("required PCR " + formatIndices(missing) + " was not quoted"))
		return
	}
	o.verdict.Checks.RequiredPCRs = true
}

// checkBaseline compares the proven values against the policy baseline.
// Values are proven only when the certificate, signature, nonce and digest
// checks all hold: until then they are numbers the peer typed.
func (o *outcome) checkBaseline(evidence *Evidence, policy *Policy) {
	c := o.verdict.Checks
	if !c.AKCertificate || !c.Signature || !c.Nonce || !c.PCRDigest {
		o.fail(absent("baseline not evaluated: the quoted PCR values were not proven"))
		return
	}
	o.verdict.PCRs = copyPCRs(evidence.PCRs)

	if len(policy.Baseline) == 0 {
		o.fail(absent("no PCR baseline in policy; nothing to compare the quoted state against"))
		return
	}
	if f := compareBaseline(o.verdict.PCRs, policy.Baseline); f != nil {
		o.fail(f)
		return
	}
	o.verdict.Checks.Baseline = true
}

// checkFreshness bounds the evidence age when the policy asks for it. Age is
// judged against the collector's timestamp, never the TPM clock, which
// counts TPM up-time and has no wall-clock meaning on its own. Stale or
// undated evidence is an absence: it proves nothing about the peer now.
func (o *outcome) checkFreshness(evidence *Evidence, policy *Policy, now time.Time) {
	if !evidence.CollectedAt.IsZero() {
		o.verdict.EvidenceAge = now.Sub(evidence.CollectedAt)
	}
	if policy.MaxEvidenceAge == 0 {
		o.verdict.Checks.Freshness = true
		return
	}
	if evidence.CollectedAt.IsZero() {
		o.fail(absent("evidence carries no collection time; freshness cannot be judged"))
		return
	}
	if o.verdict.EvidenceAge < 0 {
		o.fail(absent("evidence collection time is in the verifier's future"))
		return
	}
	if o.verdict.EvidenceAge > policy.MaxEvidenceAge {
		o.fail(absent("evidence is " + o.verdict.EvidenceAge.String() + " old; the policy allows " + policy.MaxEvidenceAge.String()))
		return
	}
	o.verdict.Checks.Freshness = true
}
