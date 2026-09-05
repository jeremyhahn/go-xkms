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
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	_ "crypto/sha256" // registers SHA-256 for crypto.Hash.New
	_ "crypto/sha512" // registers SHA-384 and SHA-512 for crypto.Hash.New
	"crypto/subtle"
	"math/big"
	"sort"
	"strconv"

	"github.com/google/go-tpm/tpm2"
)

// quote is a parsed TPMS_ATTEST of type TPM_ST_ATTEST_QUOTE together with
// the facts the checks need from it.
type quote struct {
	attest *tpm2.TPMSAttest
	info   *tpm2.TPMSQuoteInfo
	// hash is the signing scheme's hash, identified by the PCR digest length:
	// the TPM computes the PCR digest and signs with the same algorithm.
	hash crypto.Hash
	// bank is the PCR bank the quote selected.
	bank tpm2.TPMAlgID
	// selected lists the quoted PCR indices in ascending order.
	selected []int
}

// hashByDigestLength maps a digest length to the hash that produced it. A
// TPM computes the PCR digest with the signing key's scheme hash, so the
// digest length names the hash used for both the digest and the signature.
var hashByDigestLength = map[int]crypto.Hash{
	32: crypto.SHA256,
	48: crypto.SHA384,
	64: crypto.SHA512,
}

// bankDigestLength maps an accepted PCR bank to its digest size. SHA-1 is
// deliberately not here: a SHA-1 bank is not acceptable evidence of state.
var bankDigestLength = map[tpm2.TPMAlgID]int{
	tpm2.TPMAlgSHA256: 32,
	tpm2.TPMAlgSHA384: 48,
	tpm2.TPMAlgSHA512: 64,
}

// parseQuote unmarshals the TPMS_ATTEST and checks that it is a quote a TPM
// produced. A failure here is cryptographic: the bytes were present and are
// not what a TPM emits.
func parseQuote(raw []byte) (*quote, *failure) {
	// go-tpm checks TPM_GENERATED_VALUE itself for the `gotpm:"check"` field;
	// it is re-checked below so the failure names the reason.
	attest, err := tpm2.Unmarshal[tpm2.TPMSAttest](raw)
	if err != nil {
		return nil, wrong("quote is not a TPMS_ATTEST: " + err.Error())
	}
	if attest.Magic != tpm2.TPMGeneratedValue {
		return nil, wrong("quote does not carry TPM_GENERATED_VALUE")
	}
	if attest.Type != tpm2.TPMSTAttestQuote {
		return nil, wrong("attestation is not a TPM2_Quote (type 0x" + strconv.FormatUint(uint64(attest.Type), 16) + ")")
	}
	info, err := attest.Attested.Quote()
	if err != nil {
		return nil, wrong("quote carries no TPMS_QUOTE_INFO: " + err.Error())
	}
	hash, ok := hashByDigestLength[len(info.PCRDigest.Buffer)]
	if !ok {
		return nil, wrong("quote PCR digest is " + strconv.Itoa(len(info.PCRDigest.Buffer)) + " bytes, which names no supported hash")
	}

	q := &quote{attest: attest, info: info, hash: hash}
	if f := q.readSelection(); f != nil {
		return nil, f
	}
	return q, nil
}

// readSelection decodes the PCR selection into a bank and an ascending index
// list. Exactly one non-empty bank is accepted: a multi-bank quote cannot be
// compared against a single-bank baseline, and an empty selection proves
// nothing about state. Both are absences, not forgeries.
func (q *quote) readSelection() *failure {
	banks := 0
	var indices []int
	for _, sel := range q.info.PCRSelect.PCRSelections {
		empty := true
		for _, b := range sel.PCRSelect {
			if b != 0 {
				empty = false
				break
			}
		}
		if empty {
			continue
		}
		banks++
		q.bank = sel.Hash
		for byteIdx, b := range sel.PCRSelect {
			for bit := 0; bit < 8; bit++ {
				if b&(1<<uint(bit)) != 0 {
					indices = append(indices, byteIdx*8+bit)
				}
			}
		}
	}
	if banks == 0 {
		return absent("quote selects no PCRs")
	}
	if banks > 1 {
		return absent("quote selects " + strconv.Itoa(banks) + " PCR banks; only a single bank can be compared to a baseline")
	}
	if _, ok := bankDigestLength[q.bank]; !ok {
		return absent("quote selects PCR bank 0x" + strconv.FormatUint(uint64(q.bank), 16) + ", which is not accepted")
	}
	sort.Ints(indices)
	q.selected = indices
	return nil
}

// verifySignature checks the attestation key's signature over the marshaled
// TPMS_ATTEST using the hash the quote itself names.
//
// RSA signatures are accepted as RSASSA (PKCS #1 v1.5) or RSA-PSS, because a
// raw TPM signature does not say which scheme the key used and the
// certificate does not either. ECDSA signatures are accepted as ASN.1 DER
// (the form TPM2.Quote returns) or raw r||s (the form a TPM emits).
func verifySignature(key crypto.PublicKey, hash crypto.Hash, quoted, signature []byte) *failure {
	h := hash.New()
	h.Write(quoted)
	digest := h.Sum(nil)

	switch k := key.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(k, hash, digest, signature); err == nil {
			return nil
		}
		if err := rsa.VerifyPSS(k, hash, digest, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: hash}); err == nil {
			return nil
		}
		return wrong("quote signature does not verify under the attestation key (RSA)")
	case *ecdsa.PublicKey:
		if ecdsa.VerifyASN1(k, digest, signature) {
			return nil
		}
		coordLen := (k.Curve.Params().BitSize + 7) / 8
		if len(signature) == 2*coordLen {
			r := new(big.Int).SetBytes(signature[:coordLen])
			s := new(big.Int).SetBytes(signature[coordLen:])
			if ecdsa.Verify(k, digest, r, s) {
				return nil
			}
		}
		return wrong("quote signature does not verify under the attestation key (ECDSA)")
	default:
		return wrong("attestation key type is not supported for quote signatures")
	}
}

// verifyPCRDigest proves the reported values: the reported index set must
// equal the quote's selection, every value must be the bank's digest size,
// and the values hashed in ascending index order with the signing hash must
// equal the digest the TPM signed.
func (q *quote) verifyPCRDigest(reported map[int][]byte) *failure {
	if len(reported) != len(q.selected) {
		return wrong("reported PCR set " + formatIndices(sortedKeys(reported)) + " does not equal the quoted selection " + formatIndices(q.selected))
	}
	want := bankDigestLength[q.bank]
	for _, idx := range q.selected {
		value, ok := reported[idx]
		if !ok {
			return wrong("reported PCR set " + formatIndices(sortedKeys(reported)) + " does not equal the quoted selection " + formatIndices(q.selected))
		}
		if len(value) != want {
			return wrong("reported PCR " + strconv.Itoa(idx) + " is " + strconv.Itoa(len(value)) + " bytes; the quoted bank has " + strconv.Itoa(want) + "-byte registers")
		}
	}

	h := q.hash.New()
	for _, idx := range q.selected {
		h.Write(reported[idx])
	}
	if subtle.ConstantTimeCompare(h.Sum(nil), q.info.PCRDigest.Buffer) != 1 {
		return wrong("reported PCR values do not hash to the signed PCR digest")
	}
	return nil
}

// covers reports whether the quote selected the PCR.
func (q *quote) covers(idx int) bool {
	for _, sel := range q.selected {
		if sel == idx {
			return true
		}
	}
	return false
}

// compareBaseline compares proven values against the baseline. The two index
// sets must be equal, an absence when they are not: nothing was proven wrong,
// the quote simply does not cover what the policy accepts. A value that
// differs is cryptographic: the TPM signed a state the policy rejects.
func compareBaseline(proven, baseline map[int][]byte) *failure {
	provenKeys := sortedKeys(proven)
	baselineKeys := sortedKeys(baseline)
	if len(provenKeys) != len(baselineKeys) {
		return absent("quoted PCR set " + formatIndices(provenKeys) + " does not equal the baseline set " + formatIndices(baselineKeys))
	}
	for i := range provenKeys {
		if provenKeys[i] != baselineKeys[i] {
			return absent("quoted PCR set " + formatIndices(provenKeys) + " does not equal the baseline set " + formatIndices(baselineKeys))
		}
	}

	var diverged []int
	for _, idx := range baselineKeys {
		got := proven[idx]
		want := baseline[idx]
		if len(got) != len(want) || subtle.ConstantTimeCompare(got, want) != 1 {
			diverged = append(diverged, idx)
		}
	}
	if len(diverged) > 0 {
		return wrong("PCR " + formatIndices(diverged) + " diverges from the baseline")
	}
	return nil
}

func sortedKeys(m map[int][]byte) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}

func formatIndices(indices []int) string {
	out := "["
	for i, idx := range indices {
		if i > 0 {
			out += ","
		}
		out += strconv.Itoa(idx)
	}
	return out + "]"
}

// copyPCRs deep-copies a PCR map so a verdict never aliases the evidence's
// buffers.
func copyPCRs(in map[int][]byte) map[int][]byte {
	out := make(map[int][]byte, len(in))
	for idx, value := range in {
		cp := make([]byte, len(value))
		copy(cp, value)
		out[idx] = cp
	}
	return out
}
