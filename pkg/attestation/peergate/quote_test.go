// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package peergate_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/peer"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/peergate"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
)

// softQuoter stands in for the TPM on the quoting side: it signs with a
// software attestation key and reports PCR values the way tpm2.TPM2.Quote
// does, gob-encoded across banks. reads, when set, supplies the values read
// back after each quote, to model a register extended in between.
type softQuoter struct {
	t      *testing.T
	ak     attestationKey
	quoted map[int][]byte
	reads  []map[int][]byte
	bank   string
	calls  int
	err    error
}

func (q *softQuoter) Quote(pcrs []uint, qualifying []byte) (tpm2.Quote, error) {
	if q.err != nil {
		return tpm2.Quote{}, q.err
	}
	q.calls++
	selected := make(map[int][]byte, len(pcrs))
	for _, idx := range pcrs {
		selected[int(idx)] = q.quoted[int(idx)]
	}
	attest, signature := q.ak.quote(q.t, qualifying, selected)

	read := selected
	if len(q.reads) > 0 {
		read, q.reads = q.reads[0], q.reads[1:]
	}
	bank := tpm2.PCRBank{Algorithm: q.bank}
	for idx, value := range read {
		bank.PCRs = append(bank.PCRs, tpm2.PCR{ID: int32(idx), Value: value})
	}
	encoded, err := tpm2.EncodePCRs([]tpm2.PCRBank{{Algorithm: "SHA1"}, bank})
	require.NoError(q.t, err)
	return tpm2.Quote{Quoted: attest, Signature: signature, Nonce: qualifying, PCRs: encoded}, nil
}

func newSoftQuoter(t *testing.T, ak attestationKey) *softQuoter {
	return &softQuoter{t: t, ak: ak, quoted: goldenPCRs(), bank: "SHA256"}
}

// The evidence QuoteEvidence assembles is what the collector accepts and the
// verifier passes: the round trip a peer agent performs.
func TestQuoteEvidence_ProducesEvidenceTheVerifierAccepts(t *testing.T) {
	h := newHarness(t, device{}, device{})
	quoter := newSoftQuoter(t, h.ak)

	h.submit(t, func(nonce []byte) peer.Evidence {
		evidence, err := peergate.QuoteEvidence(h.conn.client, nonce, quoter, []uint{0, 7, 10}, h.ak.pem)
		require.NoError(t, err)
		assert.Equal(t, nonce, evidence.Nonce, "the evidence carries the challenge nonce, not the qualifying data")
		assert.Equal(t, goldenPCRs(), evidence.PCRs)
		return evidence
	})

	verdict := h.verify(t, h.verifier(t, peergate.VerifierConfig{}))
	assert.True(t, verdict.Passed, "reason: %s", verdict.Reason)
}

func TestQuoteEvidence_RequotesWhenAPCRChangesUnderIt(t *testing.T) {
	h := newHarness(t, device{}, device{})
	extended := goldenPCRs()
	extended[10] = fill(0x55)

	t.Run("a lost race is retried", func(t *testing.T) {
		quoter := newSoftQuoter(t, h.ak)
		quoter.reads = []map[int][]byte{extended}
		evidence, err := peergate.QuoteEvidence(h.conn.client, []byte("nonce"), quoter, []uint{0, 7, 10}, h.ak.pem)
		require.NoError(t, err)
		assert.Equal(t, 2, quoter.calls)
		assert.Equal(t, goldenPCRs(), evidence.PCRs)
	})
	t.Run("a register that never settles", func(t *testing.T) {
		quoter := newSoftQuoter(t, h.ak)
		quoter.reads = []map[int][]byte{extended, extended, extended}
		_, err := peergate.QuoteEvidence(h.conn.client, []byte("nonce"), quoter, []uint{0, 7, 10}, h.ak.pem)
		var quoteErr *peergate.QuoteError
		require.True(t, errors.As(err, &quoteErr), "QuoteEvidence = %v", err)
		assert.Equal(t, 3, quoter.calls)
	})
}

func TestQuoteEvidence_RefusesWhatItCannotQuote(t *testing.T) {
	h := newHarness(t, device{}, device{})
	tpmDown := newSoftQuoter(t, h.ak)
	tpmDown.err = errors.New("tpm unavailable")
	wrongBank := newSoftQuoter(t, h.ak)
	wrongBank.bank = "SHA384"
	missingPCR := newSoftQuoter(t, h.ak)
	missingPCR.reads = []map[int][]byte{{0: fill(0x10)}}

	cases := map[string]struct {
		quoter peergate.Quoter
		nonce  []byte
		pcrs   []uint
	}{
		"no quoter":                 {nil, []byte("n"), []uint{0}},
		"no nonce":                  {newSoftQuoter(t, h.ak), nil, []uint{0}},
		"no PCRs":                   {newSoftQuoter(t, h.ak), []byte("n"), nil},
		"TPM error":                 {tpmDown, []byte("n"), []uint{0}},
		"no values for the bank":    {wrongBank, []byte("n"), []uint{0}},
		"no value for a quoted PCR": {missingPCR, []byte("n"), []uint{0, 7}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := peergate.QuoteEvidence(h.conn.client, tc.nonce, tc.quoter, tc.pcrs, h.ak.pem)
			var quoteErr *peergate.QuoteError
			require.True(t, errors.As(err, &quoteErr), "QuoteEvidence = %v", err)
		})
	}
}

// A connection that yields no binding yields no evidence: there is no unbound
// fall-back on the quoting side either.
func TestQuoteEvidence_RefusesAConnectionThatCannotBind(t *testing.T) {
	h := newHarness(t, device{}, device{})
	quoter := newSoftQuoter(t, h.ak)
	_, err := peergate.QuoteEvidence(nil, []byte("nonce"), quoter, []uint{0}, h.ak.pem)
	var bindingErr *peer.ChannelBindingError
	require.True(t, errors.As(err, &bindingErr), "QuoteEvidence = %v", err)
	assert.Zero(t, quoter.calls, "nothing is quoted without a binding")
}
