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

package evidence

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

// ClockInfo is the TPMS_CLOCK_INFO a TPM stamps into an attestation. Clock is
// milliseconds of TPM up-time, not wall-clock time.
type ClockInfo struct {
	Clock        uint64
	ResetCount   uint32
	RestartCount uint32
	Safe         bool
}

// Quote is a parsed TPMS_ATTEST of type TPM_ST_ATTEST_QUOTE. ParseQuote has
// already checked that it carries TPM_GENERATED_VALUE, is a quote, selects
// exactly one accepted PCR bank and carries a PCR digest of a supported
// length. Nothing about it is trusted until VerifySignature succeeds.
type Quote struct {
	// Hash is the signing scheme's hash, identified by the PCR digest
	// length: a TPM computes the PCR digest with the same algorithm it
	// signs with.
	Hash crypto.Hash
	// Bank is the PCR bank the quote selected.
	Bank tpm2.TPMAlgID
	// Selected lists the quoted PCR indices in ascending order.
	Selected []int
	// PCRDigest is the digest of the selected PCR values the TPM signed.
	PCRDigest []byte
	// ExtraData is the qualifying data the caller supplied to TPM2_Quote.
	ExtraData []byte
	// QualifiedSigner is the qualified name of the signing key.
	QualifiedSigner []byte
	// Clock is the TPM clock information.
	Clock ClockInfo
	// FirmwareVersion is the TPM vendor's firmware version.
	FirmwareVersion uint64

	// raw is the marshaled TPMS_ATTEST the signature covers.
	raw []byte
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

// BankDigestSize returns the register size of an accepted PCR bank, and
// false for a bank this package does not accept (SHA-1 among them).
func BankDigestSize(bank tpm2.TPMAlgID) (int, bool) {
	size, ok := bankDigestLength[bank]
	return size, ok
}

// QuoteInput is everything VerifyQuote needs.
type QuoteInput struct {
	// Attest is the marshaled TPMS_ATTEST.
	Attest []byte
	// Signature is the attestation key's signature over Attest.
	Signature []byte
	// Key is the attestation key's public key, already trusted by the
	// caller (see VerifyAKCertificate).
	Key crypto.PublicKey
	// QualifyingData is the value the quote must carry as extraData: the
	// verifier's nonce, or a binding derived from it.
	QualifyingData []byte
	// PCRs are the reported values of the quoted registers.
	PCRs map[int][]byte
}

// VerifyQuote runs every quote check in order -- parse, signature,
// qualifying data, PCR digest -- and returns the parsed quote when all of
// them hold. The first failure is returned.
func VerifyQuote(in QuoteInput) (*Quote, error) {
	if len(in.Attest) == 0 {
		return nil, absent(CheckQuote, "no quote in evidence")
	}
	if len(in.Signature) == 0 {
		return nil, absent(CheckSignature, "no quote signature in evidence")
	}
	if in.Key == nil {
		return nil, absent(CheckSignature, "no attestation key to verify the quote signature with")
	}
	if len(in.QualifyingData) == 0 {
		return nil, absent(CheckQualifyingData, "no qualifying data to compare the quote against")
	}
	if len(in.PCRs) == 0 {
		return nil, absent(CheckPCRDigest, "no PCR values in evidence; the attester must report the values it quoted")
	}
	q, err := ParseQuote(in.Attest)
	if err != nil {
		return nil, err
	}
	if err := q.VerifySignature(in.Key, in.Signature); err != nil {
		return nil, err
	}
	if err := q.VerifyQualifyingData(in.QualifyingData); err != nil {
		return nil, err
	}
	if err := q.VerifyPCRValues(in.PCRs); err != nil {
		return nil, err
	}
	return q, nil
}

// ParseQuote unmarshals the TPMS_ATTEST and checks that it is a quote a TPM
// produced. A malformed structure is ClassForged: the bytes were present and
// are not what a TPM emits. A selection that cannot be compared (no PCRs,
// several banks, an unaccepted bank) is ClassAbsent.
func ParseQuote(attest []byte) (*Quote, error) {
	if len(attest) == 0 {
		return nil, absent(CheckQuote, "no quote in evidence")
	}
	// go-tpm checks TPM_GENERATED_VALUE itself for the `gotpm:"check"` field;
	// it is re-checked below so the failure names the reason.
	parsed, err := tpm2.Unmarshal[tpm2.TPMSAttest](attest)
	if err != nil {
		return nil, forged(CheckQuote, "quote is not a TPMS_ATTEST: "+err.Error())
	}
	if parsed.Magic != tpm2.TPMGeneratedValue {
		return nil, forged(CheckQuote, "quote does not carry TPM_GENERATED_VALUE")
	}
	if parsed.Type != tpm2.TPMSTAttestQuote {
		return nil, forged(CheckQuote, "attestation is not a TPM2_Quote (type 0x"+strconv.FormatUint(uint64(parsed.Type), 16)+")")
	}
	info, err := parsed.Attested.Quote()
	if err != nil {
		return nil, forged(CheckQuote, "quote carries no TPMS_QUOTE_INFO: "+err.Error())
	}
	hash, ok := hashByDigestLength[len(info.PCRDigest.Buffer)]
	if !ok {
		return nil, forged(CheckQuote, "quote PCR digest is "+strconv.Itoa(len(info.PCRDigest.Buffer))+" bytes, which names no supported hash")
	}

	q := &Quote{
		Hash:            hash,
		PCRDigest:       info.PCRDigest.Buffer,
		ExtraData:       parsed.ExtraData.Buffer,
		QualifiedSigner: parsed.QualifiedSigner.Buffer,
		Clock: ClockInfo{
			Clock:        parsed.ClockInfo.Clock,
			ResetCount:   parsed.ClockInfo.ResetCount,
			RestartCount: parsed.ClockInfo.RestartCount,
			Safe:         bool(parsed.ClockInfo.Safe),
		},
		FirmwareVersion: parsed.FirmwareVersion,
		raw:             attest,
	}
	if err := q.readSelection(info.PCRSelect.PCRSelections); err != nil {
		return nil, err
	}
	return q, nil
}

// readSelection decodes the PCR selection into a bank and an ascending index
// list. Exactly one non-empty bank is accepted: a multi-bank quote cannot be
// compared against a single-bank reference, and an empty selection proves
// nothing about state. Both are absences, not forgeries.
func (q *Quote) readSelection(selections []tpm2.TPMSPCRSelection) error {
	banks := 0
	var indices []int
	for _, sel := range selections {
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
		q.Bank = sel.Hash
		for byteIdx, b := range sel.PCRSelect {
			for bit := 0; bit < 8; bit++ {
				if b&(1<<uint(bit)) != 0 {
					indices = append(indices, byteIdx*8+bit)
				}
			}
		}
	}
	if banks == 0 {
		return absent(CheckQuote, "quote selects no PCRs")
	}
	if banks > 1 {
		return absent(CheckQuote, "quote selects "+strconv.Itoa(banks)+" PCR banks; only a single bank can be compared to a reference")
	}
	if _, ok := bankDigestLength[q.Bank]; !ok {
		return absent(CheckQuote, "quote selects PCR bank 0x"+strconv.FormatUint(uint64(q.Bank), 16)+", which is not accepted")
	}
	sort.Ints(indices)
	q.Selected = indices
	return nil
}

// VerifySignature checks the attestation key's signature over the marshaled
// TPMS_ATTEST using the hash the quote itself names.
//
// RSA signatures are accepted as RSASSA (PKCS #1 v1.5) or RSA-PSS, because a
// raw TPM signature does not say which scheme the key used and the
// certificate does not either. ECDSA signatures are accepted as ASN.1 DER
// (the form TPM2.Quote returns) or raw r||s (the form a TPM emits).
func (q *Quote) VerifySignature(key crypto.PublicKey, signature []byte) error {
	if len(signature) == 0 {
		return absent(CheckSignature, "no quote signature in evidence")
	}
	h := q.Hash.New()
	h.Write(q.raw)
	digest := h.Sum(nil)

	switch k := key.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(k, q.Hash, digest, signature); err == nil {
			return nil
		}
		if err := rsa.VerifyPSS(k, q.Hash, digest, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: q.Hash}); err == nil {
			return nil
		}
		return forged(CheckSignature, "quote signature does not verify under the attestation key (RSA)")
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
		return forged(CheckSignature, "quote signature does not verify under the attestation key (ECDSA)")
	default:
		return forged(CheckSignature, "attestation key type is not supported for quote signatures")
	}
}

// VerifyQualifyingData compares the quote's extraData with the expected
// value in constant time.
func (q *Quote) VerifyQualifyingData(expected []byte) error {
	if len(expected) == 0 {
		return absent(CheckQualifyingData, "no qualifying data to compare the quote against")
	}
	if subtle.ConstantTimeCompare(q.ExtraData, expected) != 1 {
		return forged(CheckQualifyingData, "quote qualifying data does not carry the expected value")
	}
	return nil
}

// VerifyPCRValues proves the reported values: the reported index set must
// equal the quote's selection, every value must be the bank's digest size,
// and the values hashed in ascending index order with the signing hash must
// equal the digest the TPM signed.
func (q *Quote) VerifyPCRValues(reported map[int][]byte) error {
	if len(reported) == 0 {
		return absent(CheckPCRDigest, "no PCR values in evidence; the attester must report the values it quoted")
	}
	if len(reported) != len(q.Selected) {
		return forged(CheckPCRDigest, "reported PCR set "+FormatIndices(sortedKeys(reported))+" does not equal the quoted selection "+FormatIndices(q.Selected))
	}
	want := bankDigestLength[q.Bank]
	for _, idx := range q.Selected {
		value, ok := reported[idx]
		if !ok {
			return forged(CheckPCRDigest, "reported PCR set "+FormatIndices(sortedKeys(reported))+" does not equal the quoted selection "+FormatIndices(q.Selected))
		}
		if len(value) != want {
			return forged(CheckPCRDigest, "reported PCR "+strconv.Itoa(idx)+" is "+strconv.Itoa(len(value))+" bytes; the quoted bank has "+strconv.Itoa(want)+"-byte registers")
		}
	}

	h := q.Hash.New()
	for _, idx := range q.Selected {
		h.Write(reported[idx])
	}
	if subtle.ConstantTimeCompare(h.Sum(nil), q.PCRDigest) != 1 {
		return forged(CheckPCRDigest, "reported PCR values do not hash to the signed PCR digest")
	}
	return nil
}

// Covers reports whether the quote selected the PCR.
func (q *Quote) Covers(idx int) bool {
	i := sort.SearchInts(q.Selected, idx)
	return i < len(q.Selected) && q.Selected[i] == idx
}

// ComparePCRs compares proven values against reference values. The two index
// sets must be equal, an absence when they are not: nothing was proven
// wrong, the evidence simply does not cover what the reference describes. A
// value that differs is ClassForged: the TPM signed a state the reference
// rejects.
func ComparePCRs(proven, reference map[int][]byte) error {
	if len(reference) == 0 {
		return absent(CheckBaseline, "no reference PCR values to compare against")
	}
	provenKeys := sortedKeys(proven)
	referenceKeys := sortedKeys(reference)
	if len(provenKeys) != len(referenceKeys) {
		return absent(CheckBaseline, "quoted PCR set "+FormatIndices(provenKeys)+" does not equal the baseline set "+FormatIndices(referenceKeys))
	}
	for i := range provenKeys {
		if provenKeys[i] != referenceKeys[i] {
			return absent(CheckBaseline, "quoted PCR set "+FormatIndices(provenKeys)+" does not equal the baseline set "+FormatIndices(referenceKeys))
		}
	}

	var diverged []int
	for _, idx := range referenceKeys {
		got := proven[idx]
		want := reference[idx]
		if len(got) != len(want) || subtle.ConstantTimeCompare(got, want) != 1 {
			diverged = append(diverged, idx)
		}
	}
	if len(diverged) > 0 {
		return forged(CheckBaseline, "PCR "+FormatIndices(diverged)+" diverges from the baseline")
	}
	return nil
}

// FormatIndices renders PCR indices as "[0,1,7]".
func FormatIndices(indices []int) string {
	out := "["
	for i, idx := range indices {
		if i > 0 {
			out += ","
		}
		out += strconv.Itoa(idx)
	}
	return out + "]"
}

// sortedKeys returns m's keys in ascending order.
func sortedKeys(m map[int][]byte) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}
