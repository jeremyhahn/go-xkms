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

package peergate

import (
	"bytes"
	"crypto/tls"

	gotpm "github.com/google/go-tpm/tpm2"

	evid "github.com/jeremyhahn/go-xkms/pkg/attestation/evidence"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/peer"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
)

// Quoter produces a TPM 2.0 quote over the listed PCRs with the given
// qualifying data. *tpm2.TPM2 is one: it quotes with the TPM's IAK.
type Quoter interface {
	Quote(pcrs []uint, qualifyingData []byte) (tpm2.Quote, error)
}

// quoteAttempts bounds how often QuoteEvidence re-quotes when a PCR is
// extended between the quote and the read of its value. Measured userspace
// (PCR 10) extends whenever a new file is measured, so a single attempt can
// lose that race on a busy host; a race lost this many times running is not a
// race.
const quoteAttempts = 3

// bankNames maps a PCR bank to the name tpm2.ReadPCRs reports it under.
var bankNames = map[gotpm.TPMAlgID]string{
	gotpm.TPMAlgSHA1:   "SHA1",
	gotpm.TPMAlgSHA256: "SHA256",
	gotpm.TPMAlgSHA384: "SHA384",
	gotpm.TPMAlgSHA512: "SHA512",
}

// QuoteEvidence is the quoting side of a Collector challenge: it binds the
// challenge nonce to the TLS connection the evidence will be submitted on
// (peer.QualifyingDataFromTLS), quotes the listed PCRs with that qualifying
// data, and assembles the peer.Evidence to submit, carrying the attestation
// key certificate chain akCertificatePEM.
//
// The values reported are checked against the digest the TPM signed before
// they are returned; if a register was extended between the quote and the
// read, the quote is taken again, so a busy host does not submit evidence the
// verifier would have to call wrong.
//
// It returns *peer.ChannelBindingError when the connection cannot export
// keying material (there is no unbound fall-back), and *QuoteError when the
// TPM cannot quote or the quote cannot be assembled into evidence.
func QuoteEvidence(state *tls.ConnectionState, nonce []byte, quoter Quoter, pcrs []uint, akCertificatePEM []byte) (peer.Evidence, error) {
	if quoter == nil {
		return peer.Evidence{}, &QuoteError{Reason: "no quoter"}
	}
	if len(nonce) == 0 {
		return peer.Evidence{}, &QuoteError{Reason: "no challenge nonce"}
	}
	if len(pcrs) == 0 {
		return peer.Evidence{}, &QuoteError{Reason: "no PCRs to quote"}
	}
	qualifying, err := peer.QualifyingDataFromTLS(state, nonce)
	if err != nil {
		return peer.Evidence{}, err
	}

	var lastErr error
	for range quoteAttempts {
		evidence, raced, err := quoteOnce(quoter, pcrs, qualifying)
		if err != nil {
			return peer.Evidence{}, err
		}
		if raced == nil {
			evidence.Nonce = bytes.Clone(nonce)
			evidence.AKCertificatePEM = bytes.Clone(akCertificatePEM)
			return evidence, nil
		}
		lastErr = raced
	}
	return peer.Evidence{}, &QuoteError{Reason: "the PCRs kept changing between the quote and the read", Cause: lastErr}
}

// quoteOnce takes one quote. A failure to quote or to decode is returned as
// err; reported values that do not hash to the signed digest -- a lost race
// with a PCR extend -- are returned as raced, so the caller can retry.
func quoteOnce(quoter Quoter, pcrs []uint, qualifying []byte) (evidence peer.Evidence, raced, err error) {
	quoted, err := quoter.Quote(pcrs, qualifying)
	if err != nil {
		return peer.Evidence{}, nil, &QuoteError{Reason: "the TPM did not quote", Cause: err}
	}
	parsed, err := evid.ParseQuote(quoted.Quoted)
	if err != nil {
		return peer.Evidence{}, nil, &QuoteError{Reason: "the quote does not parse", Cause: err}
	}
	name, ok := bankNames[parsed.Bank]
	if !ok {
		return peer.Evidence{}, nil, &QuoteError{Reason: "the quote selects an unsupported PCR bank"}
	}
	banks, err := tpm2.DecodePCRs(quoted.PCRs)
	if err != nil {
		return peer.Evidence{}, nil, &QuoteError{Reason: "the PCR values do not decode", Cause: err}
	}
	values, err := selectBank(banks, name, parsed.Selected)
	if err != nil {
		return peer.Evidence{}, nil, err
	}
	if err := parsed.VerifyPCRValues(values); err != nil {
		return peer.Evidence{}, err, nil
	}
	return peer.Evidence{
		Quote:     bytes.Clone(quoted.Quoted),
		Signature: bytes.Clone(quoted.Signature),
		PCRs:      values,
	}, nil, nil
}

// selectBank returns the values of the quoted registers from the bank the
// quote selected.
func selectBank(banks []tpm2.PCRBank, name string, selected []int) (map[int][]byte, error) {
	for _, bank := range banks {
		if bank.Algorithm != name {
			continue
		}
		read := make(map[int][]byte, len(bank.PCRs))
		for _, pcr := range bank.PCRs {
			read[int(pcr.ID)] = pcr.Value
		}
		values := make(map[int][]byte, len(selected))
		for _, idx := range selected {
			value, ok := read[idx]
			if !ok {
				return nil, &QuoteError{Reason: "the TPM reported no value for a quoted PCR"}
			}
			values[idx] = bytes.Clone(value)
		}
		return values, nil
	}
	return nil, &QuoteError{Reason: "the TPM reported no values for the quoted bank " + name}
}
