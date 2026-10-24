// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-quicbaas.
//
// go-quicbaas is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package orchestration

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"reflect"
	"sort"
	"sync"
	"testing"

	"github.com/google/go-tpm/tpm2"
	xkmsevidence "github.com/jeremyhahn/go-xkms/pkg/attestation/evidence"
	xkmstpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"

	"github.com/jeremyhahn/go-quicbaas/pkg/service/attestationtest"
)

// =============================================================================
// Fake host TPM
// =============================================================================
//
// The Tier 1 / Tier 2 tests run against an in-memory TPM that implements the
// same three primitives go-xkms *tpm2.TPM2 exposes. This keeps them fast and
// host-clean: no swtpm process, no /dev/tpm0, no state written anywhere. The
// PCR arithmetic below is the real TPM extend rule — newPCR = H(oldPCR ||
// digest) — so a measured-launch measurement is verified against a value a
// real TPM would have produced.

type fakeHostTPM struct {
	mu sync.Mutex

	// bank is the algorithm name ReadPCRs reports. Real go-xkms reports
	// "SHA256"; the default here is the lowercase spelling a ContainerSpec
	// uses, and TestTPMAttestingRuntime_Attest_BankMatching drives both.
	bank string

	// quoteBank is the bank named inside the signed PCR selection. It
	// defaults to bank; setting it differently models a TPM whose quote
	// covers a bank the read did not supply.
	quoteBank string

	// iakBank is the bank the attestation key's hash algorithm names. It
	// defaults to bank.
	iakBank string

	pcrs map[uint32][]byte

	// ak signs every quote. Its certificate chains to the ak-root the
	// test's Verifier endorses, so the appraisal judges a genuine signature.
	ak *attestationtest.AttestationKey

	quoteErr  error
	extendErr error
	readErr   error
	iakErr    error

	iakAttrsErr error

	// tamperPCRDigest corrupts the pcrDigest inside the signed body, so the
	// signed evidence and the PCR read disagree — the exact condition the
	// quote binding exists to catch.
	tamperPCRDigest bool

	// tamperNonce replaces the quote's qualifying data with a stale value,
	// modelling a replayed quote.
	tamperNonce bool

	// corruptQuoteBody replaces the signed body with bytes that are not a
	// TPMS_ATTEST structure at all.
	corruptQuoteBody bool

	// eventLog is the boot event log every quote carries; nil means none.
	eventLog []byte

	quoteCalls  int
	extendCalls int
	lastQuoted  []uint
	lastNonce   []byte
}

// =============================================================================
// TPMS_ATTEST synthesis
// =============================================================================
//
// The runtime now verifies the PCR read against the pcrDigest inside the
// signed quote body, so the fake TPM has to produce a real TPMS_ATTEST /
// TPMS_QUOTE_INFO structure rather than a placeholder string. The encoder
// below is the TPM 2.0 wire layout go-xkms ParseTPMSAttest consumes; keeping
// it in the test means the production path is exercised against bytes a TPM
// would actually emit.

const (
	// tpmGeneratedMagic is TPM_GENERATED_VALUE (0xFF || "TCG").
	tpmGeneratedMagic = 0xff544347

	// tpmSTAttestQuoteType is TPM_ST_ATTEST_QUOTE.
	tpmSTAttestQuoteType = 0x8018

	// pcrBitmapBytes covers PCR 0-23, the TCG PC Client register range.
	pcrBitmapBytes = 3
)

// testSelection is one bank's worth of a quote's TPML_PCR_SELECTION.
type testSelection struct {
	bank    string
	indices []uint32
}

// encodeTPMSAttest builds the signed body of a TPM2_Quote over indices in
// bank, committing to pcrDigest and carrying nonce as qualifying data.
func encodeTPMSAttest(t *testing.T, nonce []byte, bank string, indices []uint32, pcrDigest []byte) []byte {
	t.Helper()
	return encodeTPMSAttestSelections(t, nonce, []testSelection{{bank: bank, indices: indices}}, pcrDigest)
}

// encodeTPMSAttestSelections is the general form: a quote may select registers
// across several banks, and the pcrDigest then covers them in selection order.
func encodeTPMSAttestSelections(t *testing.T, nonce []byte, selections []testSelection, pcrDigest []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	writeUint32 := func(v uint32) {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], v)
		buf.Write(b[:])
	}
	writeUint16 := func(v uint16) {
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], v)
		buf.Write(b[:])
	}
	writeSized := func(b []byte) {
		writeUint16(uint16(len(b)))
		buf.Write(b)
	}

	writeUint32(tpmGeneratedMagic)
	writeUint16(tpmSTAttestQuoteType)
	writeSized([]byte("qualified-signer"))
	writeSized(nonce)

	// TPMS_CLOCK_INFO: clock, resetCount, restartCount, safe.
	var clock [8]byte
	binary.BigEndian.PutUint64(clock[:], 1234)
	buf.Write(clock[:])
	writeUint32(1) // resetCount
	writeUint32(0) // restartCount
	buf.WriteByte(1)

	// firmwareVersion
	var firmware [8]byte
	binary.BigEndian.PutUint64(firmware[:], 0xdeadbeef)
	buf.Write(firmware[:])

	writeUint32(uint32(len(selections)))
	for _, selection := range selections {
		algID, err := xkmstpm2.ParsePCRBankAlgID(selection.bank)
		if err != nil {
			t.Fatalf("ParsePCRBankAlgID(%q): %v", selection.bank, err)
		}
		writeUint16(uint16(algID))
		buf.WriteByte(pcrBitmapBytes)
		bitmap := make([]byte, pcrBitmapBytes)
		for _, index := range selection.indices {
			bitmap[index/8] |= 1 << (index % 8)
		}
		buf.Write(bitmap)
	}

	writeSized(pcrDigest)

	return buf.Bytes()
}

// quotePCRDigest reproduces the TPM's pcrDigest: the bank hash over the
// selected PCR values concatenated in ascending index order.
func quotePCRDigest(t *testing.T, bank string, values [][]byte) []byte {
	t.Helper()

	hash, err := xkmstpm2.ParsePCRBankCryptoHash(bank)
	if err != nil {
		t.Fatalf("ParsePCRBankCryptoHash(%q): %v", bank, err)
	}
	h := hash.New()
	for _, value := range values {
		h.Write(value)
	}
	return h.Sum(nil)
}

func newFakeHostTPM() *fakeHostTPM {
	return &fakeHostTPM{bank: DefaultMeasurementBank, pcrs: map[uint32][]byte{}}
}

// setPCR seeds a PCR with an exact value, standing in for a host that booted
// into a particular firmware and kernel state.
func (f *fakeHostTPM) setPCR(index uint32, value []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pcrs[index] = append([]byte(nil), value...)
}

// pcr returns the current value of a PCR, zero-initialised on first read the
// way a real PCR is at reset.
func (f *fakeHostTPM) pcr(index uint32) []byte {
	if v, ok := f.pcrs[index]; ok {
		return v
	}
	zero := make([]byte, sha256.Size)
	f.pcrs[index] = zero
	return zero
}

// quote is the fake TPM's quote path. It takes a *testing.T because a
// synthesized TPMS_ATTEST is only meaningful when the encoding succeeds, and a
// silent encoding failure would weaken every test that depends on it.
func (f *fakeHostTPM) quote(t *testing.T, pcrs []uint, nonce []byte) (xkmstpm2.Quote, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.quoteCalls++
	f.lastQuoted = append([]uint(nil), pcrs...)
	f.lastNonce = append([]byte(nil), nonce...)
	if f.quoteErr != nil {
		return xkmstpm2.Quote{}, f.quoteErr
	}

	indices := make([]uint32, 0, len(pcrs))
	for _, index := range pcrs {
		indices = append(indices, uint32(index))
	}
	sort.Slice(indices, func(i, j int) bool { return indices[i] < indices[j] })

	values := make([][]byte, 0, len(indices))
	for _, index := range indices {
		values = append(values, f.pcr(index))
	}

	bank := f.signedBank()
	digest := quotePCRDigest(t, bank, values)
	if f.tamperPCRDigest {
		digest[0] ^= 0xFF
	}

	quotedNonce := nonce
	if f.tamperNonce {
		quotedNonce = []byte("a-stale-nonce-from-an-earlier-quote")
	}

	quoted := encodeTPMSAttest(t, quotedNonce, bank, indices, digest)
	if f.corruptQuoteBody {
		quoted = []byte("tpms-attest")
	}

	if f.ak == nil {
		t.Fatal("fakeHostTPM has no attestation key: build the runtime with newAttestingTestRuntime")
	}
	signature, err := attestationtest.SignAttest(f.ak, quoted)
	if err != nil {
		t.Fatalf("SignAttest: %v", err)
	}

	// No event log unless a test sets one: the Verifier skips an absent
	// log, and a placeholder would be appraised as forged.
	return xkmstpm2.Quote{
		Quoted:    quoted,
		Signature: signature,
		Nonce:     nonce,
		EventLog:  f.eventLog,
	}, nil
}

// IAKCertificate returns the certificate of the key that signs the quotes.
func (f *fakeHostTPM) IAKCertificate() (*x509.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.iakErr != nil {
		return nil, f.iakErr
	}
	if f.ak == nil {
		return nil, errors.New("fakeHostTPM has no attestation key")
	}
	return f.ak.Certificate, nil
}

// signedBank is the bank named inside the signed selection.
// IAKAttributes reports the attestation key's hash algorithm. It names the
// TPM's bank, as go-xkms does, unless iakBank overrides it.
func (f *fakeHostTPM) IAKAttributes() (*types.KeyAttributes, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.iakAttrsErr != nil {
		return nil, f.iakAttrsErr
	}
	bank := f.iakBank
	if bank == "" {
		bank = f.bank
	}
	alg, err := xkmstpm2.ParsePCRBankAlgID(bank)
	if err != nil {
		return nil, err
	}
	return &types.KeyAttributes{TPMAttributes: &types.TPMAttributes{HashAlg: tpm2.TPMIAlgHash(alg)}}, nil
}

func (f *fakeHostTPM) signedBank() string {
	if f.quoteBank != "" {
		return f.quoteBank
	}
	return f.bank
}

// Quote satisfies HostTPM. It is only reachable through boundHostTPM, which
// supplies the *testing.T the encoder needs; calling it directly is a test
// wiring mistake and says so rather than producing an unverifiable quote.
func (f *fakeHostTPM) Quote(pcrs []uint, nonce []byte) (xkmstpm2.Quote, error) {
	return xkmstpm2.Quote{}, errors.New("fakeHostTPM must be wrapped with newBoundHostTPM to produce a signed quote")
}

// boundHostTPM binds a fakeHostTPM to a test so quotes can be synthesized.
type boundHostTPM struct {
	t     *testing.T
	inner *fakeHostTPM
}

// newBoundHostTPM returns the fake TPM as a HostTPM able to produce a real
// TPMS_ATTEST body.
func newBoundHostTPM(t *testing.T, inner *fakeHostTPM) *boundHostTPM {
	t.Helper()
	return &boundHostTPM{t: t, inner: inner}
}

func (b *boundHostTPM) Quote(pcrs []uint, nonce []byte) (xkmstpm2.Quote, error) {
	return b.inner.quote(b.t, pcrs, nonce)
}

func (b *boundHostTPM) ReadPCRs(pcrList []uint) ([]xkmstpm2.PCRBank, error) {
	return b.inner.ReadPCRs(pcrList)
}

func (b *boundHostTPM) ExtendPCR(pcrIndex int, hashAlg string, data []byte) error {
	return b.inner.ExtendPCR(pcrIndex, hashAlg, data)
}

func (b *boundHostTPM) IAKCertificate() (*x509.Certificate, error) {
	return b.inner.IAKCertificate()
}

func (b *boundHostTPM) IAKAttributes() (*types.KeyAttributes, error) {
	return b.inner.IAKAttributes()
}

func (f *fakeHostTPM) ReadPCRs(pcrList []uint) ([]xkmstpm2.PCRBank, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.readErr != nil {
		return nil, f.readErr
	}
	bank := xkmstpm2.PCRBank{Algorithm: f.bank}
	for _, index := range pcrList {
		bank.PCRs = append(bank.PCRs, xkmstpm2.PCR{
			ID:    int32(index),
			Value: append([]byte(nil), f.pcr(uint32(index))...),
		})
	}
	return []xkmstpm2.PCRBank{bank}, nil
}

func (f *fakeHostTPM) ExtendPCR(pcrIndex int, hashAlg string, data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.extendCalls++
	if f.extendErr != nil {
		return f.extendErr
	}
	digest := sha256.Sum256(data)
	current := f.pcr(uint32(pcrIndex))
	next := sha256.Sum256(append(append([]byte(nil), current...), digest[:]...))
	f.pcrs[uint32(pcrIndex)] = next[:]
	return nil
}

// expectedExtend replays the TPM extend rule so a test can assert the PCR the
// runtime produced matches what the measurement implies.
func expectedExtend(current, data []byte) []byte {
	digest := sha256.Sum256(data)
	next := sha256.Sum256(append(append([]byte(nil), current...), digest[:]...))
	return next[:]
}

// =============================================================================
// Recording base runtime
// =============================================================================

// recordingRuntime is a ContainerRuntime that records what it was asked to
// launch without touching the host.
type recordingRuntime struct {
	mu       sync.Mutex
	runSpecs []*ContainerSpec
	runErr   error
}

func (r *recordingRuntime) Run(_ context.Context, spec *ContainerSpec) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.runSpecs = append(r.runSpecs, spec)
	if r.runErr != nil {
		return "", r.runErr
	}
	return "container-1", nil
}

func (r *recordingRuntime) RunInteractive(_ context.Context, spec *ContainerSpec) (*InteractiveProcess, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.runSpecs = append(r.runSpecs, spec)
	if r.runErr != nil {
		return nil, r.runErr
	}
	return &InteractiveProcess{ContainerID: "container-1"}, nil
}

func (r *recordingRuntime) Stop(context.Context, string) error { return nil }

// Exec satisfies the runtime seam. Nothing in this test runs a command
// inside a container; a call would be a test asserting behaviour it never
// arranged, so it refuses rather than answering.
func (r *recordingRuntime) Exec(context.Context, string, *ExecSpec) (*ExecResult, error) {
	return nil, &ContainerExecError{ContainerID: "fake", Cause: errNoExecInThisTest}
}
func (r *recordingRuntime) Remove(context.Context, string) error { return nil }
func (r *recordingRuntime) Logs(context.Context, string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(nil)), nil
}
func (r *recordingRuntime) IsRunning(context.Context, string) (bool, error) { return true, nil }
func (r *recordingRuntime) IsAvailable() bool                               { return true }
func (r *recordingRuntime) Pull(context.Context, string) error              { return nil }

func (r *recordingRuntime) launchCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.runSpecs)
}

// newAttestingTestRuntime wires the recording base runtime to a fake TPM and
// the real Verifier. A bare *fakeHostTPM is given an AK under the Verifier's
// ak-root and bound to the test so it can synthesize signed quotes. reference
// is stored as the reference values "golden"; nil stores none.
func newAttestingTestRuntime(t *testing.T, tpm HostTPM, reference map[uint32][]byte) (*TPMAttestingRuntime, *recordingRuntime) {
	t.Helper()
	return newAttestingTestRuntimeDigests(t, tpm, attestationtest.SHA256Digests(reference))
}

// newAttestingTestRuntimeDigests is newAttestingTestRuntime with reference
// digests in any mix of PCR banks.
func newAttestingTestRuntimeDigests(t *testing.T, tpm HostTPM, reference []attestationtest.PCRDigest) (*TPMAttestingRuntime, *recordingRuntime) {
	t.Helper()
	if NewTestHostAppraiser == nil {
		t.Fatal("NewTestHostAppraiser is not installed; host_appraisal_verifier_test.go installs it")
	}
	akRoot, err := attestationtest.NewAuthority("AK CA")
	if err != nil {
		t.Fatal(err)
	}
	ak, err := attestationtest.IssueAttestationKey(akRoot, true)
	if err != nil {
		t.Fatal(err)
	}
	if fake, ok := tpm.(*fakeHostTPM); ok {
		fake.ak = ak
		tpm = newBoundHostTPM(t, fake)
	}
	base := &recordingRuntime{}
	appraiser := NewTestHostAppraiser(t, akRoot, reference)
	rt, err := NewTPMAttestingRuntime(base, tpm, appraiser, newContainerTestLogger(t))
	if err != nil {
		t.Fatalf("NewTPMAttestingRuntime: %v", err)
	}
	return rt, base
}

// NewTestHostAppraiser builds the Verifier a runtime test appraises against:
// its tenant endorses akRoot as the ak-root and, when reference is non-nil,
// stores reference as the signed reference values "golden". The service
// package owns the Verifier and imports this one, so the external test
// package installs this from host_appraisal_verifier_test.go.
var NewTestHostAppraiser func(t testing.TB, akRoot *attestationtest.Authority, reference []attestationtest.PCRDigest) HostAppraiser

// =============================================================================
// Construction
// =============================================================================

func TestNewTPMAttestingRuntime_Validation(t *testing.T) {
	logger := newContainerTestLogger(t)
	akRoot, err := attestationtest.NewAuthority("AK CA")
	if err != nil {
		t.Fatal(err)
	}
	appraiser := NewTestHostAppraiser(t, akRoot, nil)

	t.Run("Complete", func(t *testing.T) {
		rt, err := NewTPMAttestingRuntime(&recordingRuntime{}, newFakeHostTPM(), appraiser, logger)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		caps := rt.TrustCapabilities()
		if !caps.DigestPinning || !caps.HostTPM || !caps.MeasuredLaunch {
			t.Fatalf("attesting runtime must advertise every tier, got %+v", caps)
		}
	})

	t.Run("MissingDependencies", func(t *testing.T) {
		if _, err := NewTPMAttestingRuntime(nil, newFakeHostTPM(), appraiser, logger); err == nil {
			t.Fatal("expected an error for a nil base runtime")
		}
		if _, err := NewTPMAttestingRuntime(&recordingRuntime{}, nil, appraiser, logger); err == nil {
			t.Fatal("expected an error for a nil TPM")
		}
		if _, err := NewTPMAttestingRuntime(&recordingRuntime{}, newFakeHostTPM(), appraiser, nil); err == nil {
			t.Fatal("expected an error for a nil logger")
		}
	})

	// Tier 1 fails closed: without a Verifier there is nothing to appraise
	// the quote against, so the runtime is never built.
	t.Run("MissingAppraiser", func(t *testing.T) {
		rt, err := NewTPMAttestingRuntime(&recordingRuntime{}, newFakeHostTPM(), nil, logger)
		if rt != nil {
			t.Fatal("no runtime may be built without an appraiser")
		}
		var invalid *InputValidationError
		if !errors.As(err, &invalid) {
			t.Fatalf("expected *InputValidationError, got %T (%v)", err, err)
		}
		if invalid.Field != "appraiser" {
			t.Fatalf("Field = %q, want appraiser", invalid.Field)
		}
	})
}

// =============================================================================
// Tier 1 — host quote appraised by the Verifier against named reference values
// =============================================================================

func TestTPMAttestingRuntime_Attest_Tier1(t *testing.T) {
	golden := bytes.Repeat([]byte{0xAB}, sha256.Size)
	reference := map[uint32][]byte{7: golden}

	t.Run("MatchingPCRsProduceEvidence", func(t *testing.T) {
		tpm := newFakeHostTPM()
		tpm.setPCR(7, golden)
		rt, _ := newAttestingTestRuntime(t, tpm, reference)

		spec := &ContainerSpec{
			Image:           "alpine@" + testDigest,
			TrustLevel:      TrustLevelAttested,
			TrustLabel:      "prod-agent",
			ReferenceValues: "golden",
		}

		evidence, err := rt.Attest(t.Context(), spec, "container-1")
		if err != nil {
			t.Fatalf("Attest: %v", err)
		}
		if evidence.ContainerID != "container-1" {
			t.Errorf("ContainerID = %q", evidence.ContainerID)
		}
		if evidence.ImageDigest != testDigest {
			t.Errorf("ImageDigest = %q, want %q", evidence.ImageDigest, testDigest)
		}
		if evidence.TrustLevel != TrustLevelAttested {
			t.Errorf("TrustLevel = %v, want attested", evidence.TrustLevel)
		}
		if evidence.Measured {
			t.Error("Tier 1 evidence must not claim a measured launch")
		}
		if len(evidence.Nonce) != attestationNonceBytes {
			t.Errorf("nonce length = %d, want %d", len(evidence.Nonce), attestationNonceBytes)
		}
		if !bytes.Equal(evidence.Nonce, tpm.lastNonce) {
			t.Error("evidence nonce must be the qualifying data the quote was bound to")
		}
		if !bytes.Equal(evidence.PCRs[7], golden) {
			t.Errorf("quoted PCR 7 = %x, want %x", evidence.PCRs[7], golden)
		}
		if evidence.ConfigDigest == "" {
			t.Error("evidence must carry the configuration digest")
		}
		if evidence.AttestedAt.IsZero() {
			t.Error("evidence must carry a timestamp")
		}
		if tpm.extendCalls != 0 {
			t.Errorf("Tier 1 must not extend a PCR, got %d extends", tpm.extendCalls)
		}
	})

	t.Run("DriftedPCRIsRejected", func(t *testing.T) {
		tpm := newFakeHostTPM()
		tpm.setPCR(7, bytes.Repeat([]byte{0xCD}, sha256.Size))
		rt, _ := newAttestingTestRuntime(t, tpm, reference)

		spec := &ContainerSpec{
			Image:           "alpine@" + testDigest,
			TrustLevel:      TrustLevelAttested,
			ReferenceValues: "golden",
		}

		_, err := rt.Attest(t.Context(), spec, "container-1")
		if err == nil {
			t.Fatal("expected a drifted PCR to be rejected")
		}
		if !errors.Is(err, ErrPCRMismatch) {
			t.Fatalf("error %v does not wrap ErrPCRMismatch", err)
		}
		if !errors.Is(err, ErrHostNotVerified) {
			t.Fatalf("error %v does not wrap ErrHostNotVerified", err)
		}
		var appraisal *HostAppraisalError
		if !errors.As(err, &appraisal) {
			t.Fatalf("expected *HostAppraisalError, got %T", err)
		}
		if !appraisal.CryptographicFailure {
			t.Error("a drifted PCR is a cryptographic failure of the baseline")
		}
		if appraisal.ReferenceValues != "golden" {
			t.Errorf("ReferenceValues = %q, want golden", appraisal.ReferenceValues)
		}
		var divergence *PCRDivergence
		for _, failure := range appraisal.Failures {
			for i := range failure.PCRs {
				divergence = &failure.PCRs[i]
			}
		}
		if divergence == nil {
			t.Fatalf("the appraisal must name the diverging PCR, got %+v", appraisal.Failures)
		}
		if divergence.Index != 7 {
			t.Errorf("divergence index = %d, want 7", divergence.Index)
		}
		if !bytes.Equal(divergence.Quoted, bytes.Repeat([]byte{0xCD}, sha256.Size)) {
			t.Errorf("quoted digest = %x, want the drifted value", divergence.Quoted)
		}
		if len(divergence.Expected) != 1 || !bytes.Equal(divergence.Expected[0], golden) {
			t.Errorf("expected digests = %x, want [%x]", divergence.Expected, golden)
		}
	})

	t.Run("PCRSelectedByTheQuoteButAbsentFromTheReadIsRejected", func(t *testing.T) {
		// The signed selection names PCR 7 but the read supplies no
		// registers at all. There is nothing to bind the signature to, so
		// the attestation is refused before any golden value is consulted:
		// absence of evidence is not evidence of a match.
		tpm := newFakeHostTPM()
		rt, _ := newAttestingTestRuntime(t, tpm, reference)
		rt.tpm = &pcrOmittingTPM{t: t, inner: tpm}

		spec := &ContainerSpec{
			Image:           "alpine@" + testDigest,
			TrustLevel:      TrustLevelAttested,
			ReferenceValues: "golden",
		}

		_, err := rt.Attest(t.Context(), spec, "container-1")
		if !errors.Is(err, ErrQuoteNotBound) {
			t.Fatalf("error %v does not wrap ErrQuoteNotBound", err)
		}
	})

	t.Run("QuoteFailurePropagates", func(t *testing.T) {
		tpm := newFakeHostTPM()
		tpm.setPCR(7, golden)
		tpm.quoteErr = errors.New("tpm busy")
		rt, _ := newAttestingTestRuntime(t, tpm, reference)

		spec := &ContainerSpec{
			Image:           "alpine@" + testDigest,
			TrustLevel:      TrustLevelAttested,
			ReferenceValues: "golden",
		}

		_, err := rt.Attest(t.Context(), spec, "container-1")
		if !errors.Is(err, ErrQuoteFailed) {
			t.Fatalf("error %v does not wrap ErrQuoteFailed", err)
		}
	})

	t.Run("PCRReadFailurePropagates", func(t *testing.T) {
		tpm := newFakeHostTPM()
		tpm.setPCR(7, golden)
		tpm.readErr = errors.New("pcr read denied")
		rt, _ := newAttestingTestRuntime(t, tpm, reference)

		spec := &ContainerSpec{
			Image:           "alpine@" + testDigest,
			TrustLevel:      TrustLevelAttested,
			ReferenceValues: "golden",
		}

		_, err := rt.Attest(t.Context(), spec, "container-1")
		if !errors.Is(err, ErrQuoteFailed) {
			t.Fatalf("error %v does not wrap ErrQuoteFailed", err)
		}
	})

	t.Run("AKCertificateFailurePropagates", func(t *testing.T) {
		// Without the AK certificate the Verifier cannot judge the
		// signature, so the quote is refused before any appraisal.
		tpm := newFakeHostTPM()
		tpm.setPCR(7, golden)
		tpm.iakErr = errors.New("no IAK certificate provisioned")
		rt, _ := newAttestingTestRuntime(t, tpm, reference)

		spec := &ContainerSpec{
			Image:           "alpine@" + testDigest,
			TrustLevel:      TrustLevelAttested,
			ReferenceValues: "golden",
		}

		_, err := rt.Attest(t.Context(), spec, "container-1")
		if !errors.Is(err, ErrQuoteFailed) {
			t.Fatalf("error %v does not wrap ErrQuoteFailed", err)
		}
	})

	t.Run("BelowAttestedLevelIsRefused", func(t *testing.T) {
		rt, _ := newAttestingTestRuntime(t, newFakeHostTPM(), nil)
		spec := &ContainerSpec{Image: "alpine@" + testDigest, TrustLevel: TrustLevelPinned}

		_, err := rt.Attest(t.Context(), spec, "container-1")
		if !errors.Is(err, ErrAttestationUnavailable) {
			t.Fatalf("error %v does not wrap ErrAttestationUnavailable", err)
		}
	})

	t.Run("InvalidSpecIsRefused", func(t *testing.T) {
		rt, _ := newAttestingTestRuntime(t, newFakeHostTPM(), nil)

		if _, err := rt.Attest(t.Context(), nil, ""); err == nil {
			t.Fatal("expected an error for a nil spec")
		}

		// Attested level with only a tag: the tier gate fires in Validate.
		spec := &ContainerSpec{
			Image:           "alpine:3.20",
			TrustLevel:      TrustLevelAttested,
			ReferenceValues: "golden",
		}
		if _, err := rt.Attest(t.Context(), spec, ""); !errors.Is(err, ErrImageNotPinned) {
			t.Fatalf("error %v does not wrap ErrImageNotPinned", err)
		}
	})

	t.Run("CanceledContextIsRefused", func(t *testing.T) {
		tpm := newFakeHostTPM()
		tpm.setPCR(7, golden)
		rt, _ := newAttestingTestRuntime(t, tpm, reference)

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		spec := &ContainerSpec{
			Image:           "alpine@" + testDigest,
			TrustLevel:      TrustLevelAttested,
			ReferenceValues: "golden",
		}
		if _, err := rt.Attest(ctx, spec, ""); !errors.Is(err, context.Canceled) {
			t.Fatalf("error %v is not a context cancellation", err)
		}
	})
}

// pcrOmittingTPM wraps a fake TPM and drops every PCR from the read, modelling
// a host that quotes fewer registers than were requested.
type pcrOmittingTPM struct {
	t     *testing.T
	inner *fakeHostTPM
}

func (p *pcrOmittingTPM) Quote(pcrs []uint, nonce []byte) (xkmstpm2.Quote, error) {
	return p.inner.quote(p.t, pcrs, nonce)
}

func (p *pcrOmittingTPM) ReadPCRs([]uint) ([]xkmstpm2.PCRBank, error) {
	return []xkmstpm2.PCRBank{{Algorithm: DefaultMeasurementBank}}, nil
}

func (p *pcrOmittingTPM) ExtendPCR(index int, alg string, data []byte) error {
	return p.inner.ExtendPCR(index, alg, data)
}

func (p *pcrOmittingTPM) IAKCertificate() (*x509.Certificate, error) {
	return p.inner.IAKCertificate()
}

func (p *pcrOmittingTPM) IAKAttributes() (*types.KeyAttributes, error) {
	return p.inner.IAKAttributes()
}

// =============================================================================
// Tier 2 — measured launch
// =============================================================================

func TestTPMAttestingRuntime_MeasuredLaunch(t *testing.T) {
	reference := map[uint32][]byte{7: make([]byte, sha256.Size)}

	t.Run("ExtendsMeasurementPCRBeforeLaunch", func(t *testing.T) {
		tpm := newFakeHostTPM()
		rt, base := newAttestingTestRuntime(t, tpm, reference)

		spec := &ContainerSpec{
			Image:           "alpine@" + testDigest,
			TrustLevel:      TrustLevelMeasured,
			TrustLabel:      "prod-agent",
			ReferenceValues: "golden",
		}

		zero := make([]byte, sha256.Size)
		measurement, err := LaunchMeasurement(spec)
		if err != nil {
			t.Fatalf("LaunchMeasurement: %v", err)
		}
		want := expectedExtend(zero, measurement)

		id, err := rt.Run(t.Context(), spec)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if id != "container-1" {
			t.Fatalf("container id = %q", id)
		}
		if base.launchCount() != 1 {
			t.Fatalf("base runtime launch count = %d, want 1", base.launchCount())
		}
		if tpm.extendCalls != 1 {
			t.Fatalf("extend count = %d, want exactly one measured launch", tpm.extendCalls)
		}
		if got := tpm.pcr(uint32(MeasurementPCRDefault)); !bytes.Equal(got, want) {
			t.Fatalf("measurement PCR = %x, want %x", got, want)
		}
	})

	t.Run("MeasurementPrecedesLaunch", func(t *testing.T) {
		// A failing extend must abort the launch: a container that started
		// before it was measured is not a measured launch.
		tpm := newFakeHostTPM()
		tpm.extendErr = errors.New("pcr locked")
		rt, base := newAttestingTestRuntime(t, tpm, reference)

		spec := &ContainerSpec{
			Image:           "alpine@" + testDigest,
			TrustLevel:      TrustLevelMeasured,
			ReferenceValues: "golden",
		}

		_, err := rt.Run(t.Context(), spec)
		if !errors.Is(err, ErrMeasurementFailed) {
			t.Fatalf("error %v does not wrap ErrMeasurementFailed", err)
		}
		if base.launchCount() != 0 {
			t.Fatal("the container must not be launched when the measurement fails")
		}
	})

	t.Run("InteractiveIsMeasuredToo", func(t *testing.T) {
		tpm := newFakeHostTPM()
		rt, base := newAttestingTestRuntime(t, tpm, reference)

		spec := &ContainerSpec{
			Image:           "alpine@" + testDigest,
			TrustLevel:      TrustLevelMeasured,
			ReferenceValues: "golden",
		}

		if _, err := rt.RunInteractive(t.Context(), spec); err != nil {
			t.Fatalf("RunInteractive: %v", err)
		}
		if tpm.extendCalls != 1 {
			t.Fatalf("extend count = %d, want 1", tpm.extendCalls)
		}
		if base.launchCount() != 1 {
			t.Fatalf("base runtime launch count = %d, want 1", base.launchCount())
		}
	})

	t.Run("LowerTiersDoNotTouchTheTPM", func(t *testing.T) {
		tpm := newFakeHostTPM()
		rt, base := newAttestingTestRuntime(t, tpm, reference)

		for _, level := range []TrustLevel{TrustLevelDefault, TrustLevelNone, TrustLevelPinned, TrustLevelAttested} {
			spec := &ContainerSpec{
				Image:           "alpine@" + testDigest,
				TrustLevel:      level,
				ReferenceValues: "golden",
			}
			if _, err := rt.Run(t.Context(), spec); err != nil {
				t.Fatalf("Run at level %v: %v", level, err)
			}
		}
		if tpm.extendCalls != 0 {
			t.Fatalf("extend count = %d, want 0 below the measured tier", tpm.extendCalls)
		}
		if base.launchCount() != 4 {
			t.Fatalf("base runtime launch count = %d, want 4", base.launchCount())
		}
	})

	t.Run("AttestIncludesMeasurementPCRAndLaunchMeasurement", func(t *testing.T) {
		spec := &ContainerSpec{
			Image:           "alpine@" + testDigest,
			TrustLevel:      TrustLevelMeasured,
			TrustLabel:      "prod-agent",
			ReferenceValues: "golden",
		}

		// The Verifier compares equal sets, so the reference values for a
		// measured launch carry the measurement PCR the launch produces.
		measurement, err := LaunchMeasurement(spec)
		if err != nil {
			t.Fatalf("LaunchMeasurement: %v", err)
		}
		tpm := newFakeHostTPM()
		rt, _ := newAttestingTestRuntime(t, tpm, map[uint32][]byte{
			7:                             make([]byte, sha256.Size),
			uint32(MeasurementPCRDefault): expectedExtend(make([]byte, sha256.Size), measurement),
		})

		if _, err := rt.Run(t.Context(), spec); err != nil {
			t.Fatalf("Run: %v", err)
		}

		evidence, err := rt.Attest(t.Context(), spec, "container-1")
		if err != nil {
			t.Fatalf("Attest: %v", err)
		}
		if !evidence.Measured {
			t.Error("Tier 2 evidence must report a measured launch")
		}
		if evidence.MeasurementPCR != MeasurementPCRDefault {
			t.Errorf("MeasurementPCR = %d, want %d", evidence.MeasurementPCR, MeasurementPCRDefault)
		}
		if len(evidence.LaunchMeasurement) == 0 {
			t.Error("Tier 2 evidence must carry the launch measurement for replay")
		}

		// The measurement PCR must be part of the quote so the launch is
		// covered by the signature, not merely reported alongside it.
		var quoted bool
		for _, index := range tpm.lastQuoted {
			if index == uint(MeasurementPCRDefault) {
				quoted = true
			}
		}
		if !quoted {
			t.Fatalf("measurement PCR %d was not quoted (quoted %v)", MeasurementPCRDefault, tpm.lastQuoted)
		}

		// A verifier replays the measurement against the zero PCR.
		want := expectedExtend(make([]byte, sha256.Size), evidence.LaunchMeasurement)
		if got := evidence.PCRs[uint32(MeasurementPCRDefault)]; !bytes.Equal(got, want) {
			t.Fatalf("quoted measurement PCR = %x, replay yields %x", got, want)
		}
	})

	t.Run("CustomMeasurementPCR", func(t *testing.T) {
		tpm := newFakeHostTPM()
		rt, _ := newAttestingTestRuntime(t, tpm, reference)

		spec := &ContainerSpec{
			Image:           "alpine@" + testDigest,
			TrustLevel:      TrustLevelMeasured,
			MeasurementPCR:  12,
			ReferenceValues: "golden",
		}

		if _, err := rt.Run(t.Context(), spec); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if bytes.Equal(tpm.pcr(12), make([]byte, sha256.Size)) {
			t.Fatal("PCR 12 was not extended")
		}
		if !bytes.Equal(tpm.pcr(uint32(MeasurementPCRDefault)), make([]byte, sha256.Size)) {
			t.Fatal("the default measurement PCR must be left untouched")
		}
	})
}

// TestTPMAttestingRuntime_MeasuredLaunchWithBootLog is the regression guard
// for a measured launch on a host that supplies its firmware event log. The
// log explains the boot registers; the runtime extended the measurement PCR
// after boot, so the log cannot explain that one. Replaying every quoted
// register refused every such host; the replay now leaves the measurement
// PCR to the reference values.
func TestTPMAttestingRuntime_MeasuredLaunchWithBootLog(t *testing.T) {
	spec := &ContainerSpec{
		Image:           "alpine@" + testDigest,
		TrustLevel:      TrustLevelMeasured,
		ReferenceValues: "golden",
	}
	measurement, err := LaunchMeasurement(spec)
	if err != nil {
		t.Fatalf("LaunchMeasurement: %v", err)
	}
	digest := func(b byte) []byte { return bytes.Repeat([]byte{b}, sha256.Size) }
	bootLog, boot := attestationtest.BootEventLog([]attestationtest.LogEvent{
		{PCR: 0, Digest: digest(0x01)},
		{PCR: 7, Digest: digest(0x07)},
	})

	// measuredHost boots the fake TPM through the log, with pcr7 standing in
	// for whatever PCR 7 holds, and launches the container.
	measuredHost := func(t *testing.T, pcr7 []byte) (*TPMAttestingRuntime, *fakeHostTPM) {
		t.Helper()
		tpm := newFakeHostTPM()
		tpm.eventLog = bootLog
		tpm.setPCR(0, boot[0])
		tpm.setPCR(7, pcr7)
		rt, _ := newAttestingTestRuntime(t, tpm, map[uint32][]byte{
			0:                             boot[0],
			7:                             pcr7,
			uint32(MeasurementPCRDefault): expectedExtend(make([]byte, sha256.Size), measurement),
		})
		if _, err := rt.Run(t.Context(), spec); err != nil {
			t.Fatalf("Run: %v", err)
		}
		return rt, tpm
	}

	t.Run("BootLogAndExtendedMeasurementPCRPass", func(t *testing.T) {
		rt, _ := measuredHost(t, boot[7])
		evidence, err := rt.Attest(t.Context(), spec, "container-1")
		if err != nil {
			t.Fatalf("Attest: %v", err)
		}
		if !bytes.Equal(evidence.EventLog, bootLog) {
			t.Fatal("the evidence must carry the boot event log the quote supplied")
		}
	})

	t.Run("TamperedBootPCRIsRefused", func(t *testing.T) {
		// The reference values were signed over the tampered value, so only
		// the log replay can catch it.
		rt, _ := measuredHost(t, digest(0xEE))
		_, err := rt.Attest(t.Context(), spec, "container-1")
		var appraisal *HostAppraisalError
		if !errors.As(err, &appraisal) || !errors.Is(err, ErrHostNotVerified) {
			t.Fatalf("Attest = %v, want a *HostAppraisalError", err)
		}
		if !appraisal.CryptographicFailure || len(appraisal.Failures) != 1 || appraisal.Failures[0].Check != "event-log" {
			t.Fatalf("failures = %+v, want only a forged event log", appraisal.Failures)
		}
	})
}

func TestLaunchMeasurement(t *testing.T) {
	t.Run("Deterministic", func(t *testing.T) {
		spec := &ContainerSpec{
			Image:       "alpine",
			ImageDigest: testDigest,
			TrustLabel:  "prod",
			Env:         map[string]string{"A": "1", "B": "2"},
		}
		first, err := LaunchMeasurement(spec)
		if err != nil {
			t.Fatalf("LaunchMeasurement: %v", err)
		}
		for i := 0; i < 50; i++ {
			next, err := LaunchMeasurement(spec)
			if err != nil {
				t.Fatalf("LaunchMeasurement: %v", err)
			}
			if !bytes.Equal(first, next) {
				t.Fatal("launch measurement is not deterministic")
			}
		}
	})

	t.Run("BindsImageConfigAndLabel", func(t *testing.T) {
		base := &ContainerSpec{Image: "alpine", ImageDigest: testDigest, TrustLabel: "prod"}
		baseMeasurement, err := LaunchMeasurement(base)
		if err != nil {
			t.Fatalf("LaunchMeasurement: %v", err)
		}

		variants := map[string]*ContainerSpec{
			"DifferentDigest": {Image: "alpine", ImageDigest: otherDigest, TrustLabel: "prod"},
			"DifferentLabel":  {Image: "alpine", ImageDigest: testDigest, TrustLabel: "staging"},
			"DifferentConfig": {Image: "alpine", ImageDigest: testDigest, TrustLabel: "prod", User: "0:0"},
		}
		for name, spec := range variants {
			t.Run(name, func(t *testing.T) {
				got, err := LaunchMeasurement(spec)
				if err != nil {
					t.Fatalf("LaunchMeasurement: %v", err)
				}
				if bytes.Equal(got, baseMeasurement) {
					t.Fatalf("%s must change the launch measurement", name)
				}
			})
		}
	})

	t.Run("NilSpecRejected", func(t *testing.T) {
		if _, err := LaunchMeasurement(nil); err == nil {
			t.Fatal("expected an error for a nil spec")
		}
	})
}

func TestQuotePCRIndices(t *testing.T) {
	t.Run("SortedAndDeduplicated", func(t *testing.T) {
		reference := []uint32{14, 0, 7, 16}
		spec := &ContainerSpec{MeasurementPCR: 16}
		want := []uint{0, 7, 14, 16}

		// Repeat: the indices pass through a set, so an unsorted
		// implementation would pass intermittently.
		for i := 0; i < 100; i++ {
			got := quotePCRIndices(reference, spec, true)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("quotePCRIndices = %v, want %v", got, want)
			}
		}
	})

	t.Run("MeasurementPCRAddedOnlyWhenMeasured", func(t *testing.T) {
		reference := []uint32{7}
		spec := &ContainerSpec{}
		if got := quotePCRIndices(reference, spec, false); !reflect.DeepEqual(got, []uint{7}) {
			t.Fatalf("quotePCRIndices = %v, want [7]", got)
		}
		want := []uint{7, uint(MeasurementPCRDefault)}
		if got := quotePCRIndices(reference, spec, true); !reflect.DeepEqual(got, want) {
			t.Fatalf("quotePCRIndices = %v, want %v", got, want)
		}
	})
}

func TestFlattenPCRBanks(t *testing.T) {
	t.Run("SelectsRequestedBank", func(t *testing.T) {
		banks := []xkmstpm2.PCRBank{
			{Algorithm: "sha1", PCRs: []xkmstpm2.PCR{{ID: 7, Value: []byte{0x01}}}},
			{Algorithm: "sha256", PCRs: []xkmstpm2.PCR{{ID: 7, Value: []byte{0x02}}}},
		}
		got, err := flattenPCRBanks(banks, "sha256")
		if err != nil {
			t.Fatalf("flattenPCRBanks: %v", err)
		}
		if !bytes.Equal(got[7], []byte{0x02}) {
			t.Fatalf("PCR 7 = %x, want the sha256 bank value", got[7])
		}
	})

	// go-xkms ReadPCRs reports "SHA1"/"SHA256"/"SHA384"/"SHA512" while every
	// bank name in this package is lowercase. An exact comparison missed on
	// every multi-bank host and silently read a different bank.
	t.Run("MatchesBankNameCaseInsensitively", func(t *testing.T) {
		cases := []struct {
			name      string
			reported  string
			requested string
		}{
			{name: "XKMSUppercaseReport", reported: "SHA256", requested: "sha256"},
			{name: "LowercaseReport", reported: "sha256", requested: "SHA256"},
			{name: "MixedCase", reported: "Sha384", requested: "sHa384"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				banks := []xkmstpm2.PCRBank{
					{Algorithm: "SHA1", PCRs: []xkmstpm2.PCR{{ID: 7, Value: []byte{0x01}}}},
					{Algorithm: tc.reported, PCRs: []xkmstpm2.PCR{{ID: 7, Value: []byte{0x02}}}},
				}
				got, err := flattenPCRBanks(banks, tc.requested)
				if err != nil {
					t.Fatalf("flattenPCRBanks: %v", err)
				}
				if !bytes.Equal(got[7], []byte{0x02}) {
					t.Fatalf("PCR 7 = %x, want the %s bank value (never the first bank)", got[7], tc.reported)
				}
			})
		}
	})

	// The old behaviour fell back to banks[0], so a host without the
	// requested bank produced measurements from an unintended one with no
	// error at all.
	t.Run("AbsentBankIsAnErrorNotAFallback", func(t *testing.T) {
		banks := []xkmstpm2.PCRBank{
			{Algorithm: "SHA1", PCRs: []xkmstpm2.PCR{{ID: 7, Value: []byte{0x01}}}},
		}
		got, err := flattenPCRBanks(banks, "sha384")
		if got != nil {
			t.Fatalf("no PCR values may be returned for an absent bank, got %v", got)
		}
		if !errors.Is(err, ErrPCRBankUnavailable) {
			t.Fatalf("error %v does not wrap ErrPCRBankUnavailable", err)
		}
		var unavailable *PCRBankUnavailableError
		if !errors.As(err, &unavailable) {
			t.Fatalf("expected *PCRBankUnavailableError, got %T", err)
		}
		if unavailable.Requested != "sha384" {
			t.Errorf("Requested = %q, want sha384", unavailable.Requested)
		}
		if !reflect.DeepEqual(unavailable.Available, []string{"SHA1"}) {
			t.Errorf("Available = %v, want [SHA1]", unavailable.Available)
		}
		if unavailable.Error() == "" {
			t.Error("error message must not be empty")
		}
	})

	t.Run("EmptyInputIsAnError", func(t *testing.T) {
		got, err := flattenPCRBanks(nil, "sha256")
		if got != nil {
			t.Fatalf("expected no values, got %v", got)
		}
		if !errors.Is(err, ErrPCRBankUnavailable) {
			t.Fatalf("error %v does not wrap ErrPCRBankUnavailable", err)
		}
		if err.Error() == "" {
			t.Fatal("error message must not be empty")
		}
	})

	t.Run("SkipsNegativeIndices", func(t *testing.T) {
		banks := []xkmstpm2.PCRBank{
			{Algorithm: "sha256", PCRs: []xkmstpm2.PCR{{ID: -1, Value: []byte{0x01}}}},
		}
		got, err := flattenPCRBanks(banks, "sha256")
		if err != nil {
			t.Fatalf("flattenPCRBanks: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("negative PCR ids must be skipped, got %v", got)
		}
	})
}

// =============================================================================
// Binding the PCR read to the signed quote
// =============================================================================

// TestTPMAttestingRuntime_Attest_BindsPCRsToSignedQuote is the regression guard
// for the security defect this binding fixes: attestation used to compare the
// golden PCR set against an unsigned TPM2_PCR_Read, so a read that disagreed
// with the signed quote — through a tampered read path or a TOCTOU extend
// between the quote and the read — passed while the signed evidence said
// otherwise.
func TestTPMAttestingRuntime_Attest_BindsPCRsToSignedQuote(t *testing.T) {
	golden := bytes.Repeat([]byte{0xAB}, sha256.Size)
	reference := map[uint32][]byte{7: golden}

	attestedSpec := func() *ContainerSpec {
		return &ContainerSpec{
			Image:           "alpine@" + testDigest,
			TrustLevel:      TrustLevelAttested,
			ReferenceValues: "golden",
		}
	}

	t.Run("SignedDigestDisagreeingWithTheReadIsRejected", func(t *testing.T) {
		// The read reports exactly the golden value, so the old
		// unsigned comparison would pass. The signed quote commits to a
		// different digest, so this host must be refused.
		tpm := newFakeHostTPM()
		tpm.setPCR(7, golden)
		tpm.tamperPCRDigest = true
		rt, _ := newAttestingTestRuntime(t, tpm, reference)

		evidence, err := rt.Attest(t.Context(), attestedSpec(), "container-1")
		if evidence != nil {
			t.Fatal("no evidence may be produced when the read contradicts the signed quote")
		}
		if !errors.Is(err, ErrQuotedPCRDigestMismatch) {
			t.Fatalf("error %v does not wrap ErrQuotedPCRDigestMismatch", err)
		}
		if !errors.Is(err, ErrQuoteNotBound) {
			t.Fatalf("error %v does not wrap ErrQuoteNotBound", err)
		}
		var mismatch *QuotedPCRDigestMismatchError
		if !errors.As(err, &mismatch) {
			t.Fatalf("expected *QuotedPCRDigestMismatchError, got %T", err)
		}
		if len(mismatch.Signed) == 0 {
			t.Fatal("the signed digest must be reported")
		}
		if !errors.Is(err, xkmsevidence.ErrForged) {
			t.Fatalf("error %v must carry go-xkms's forged-evidence cause", err)
		}
		if mismatch.Bank != DefaultMeasurementBank {
			t.Errorf("Bank = %q, want %q", mismatch.Bank, DefaultMeasurementBank)
		}
		if mismatch.Error() == "" {
			t.Error("error message must not be empty")
		}
	})

	// A PCR extended between the quote and the read is the TOCTOU the
	// binding closes: the values are self-consistent, but they are not the
	// values the TPM signed.
	t.Run("PCRChangedBetweenQuoteAndReadIsRejected", func(t *testing.T) {
		tpm := newFakeHostTPM()
		tpm.setPCR(7, golden)
		rt, _ := newAttestingTestRuntime(t, tpm, reference)
		rt.tpm = &extendBetweenQuoteAndReadTPM{t: t, inner: tpm, index: 7, value: golden}

		_, err := rt.Attest(t.Context(), attestedSpec(), "container-1")
		if !errors.Is(err, ErrQuotedPCRDigestMismatch) {
			t.Fatalf("error %v does not wrap ErrQuotedPCRDigestMismatch", err)
		}
	})

	t.Run("QuoteWithoutThisNonceIsRejected", func(t *testing.T) {
		tpm := newFakeHostTPM()
		tpm.setPCR(7, golden)
		tpm.tamperNonce = true
		rt, _ := newAttestingTestRuntime(t, tpm, reference)

		_, err := rt.Attest(t.Context(), attestedSpec(), "container-1")
		if !errors.Is(err, ErrQuoteNotBound) {
			t.Fatalf("error %v does not wrap ErrQuoteNotBound", err)
		}
	})

	t.Run("UnparseableQuoteBodyIsRejected", func(t *testing.T) {
		tpm := newFakeHostTPM()
		tpm.setPCR(7, golden)
		tpm.corruptQuoteBody = true
		rt, _ := newAttestingTestRuntime(t, tpm, reference)

		_, err := rt.Attest(t.Context(), attestedSpec(), "container-1")
		if !errors.Is(err, ErrQuoteNotBound) {
			t.Fatalf("error %v does not wrap ErrQuoteNotBound", err)
		}
		var binding *QuoteBindingError
		if !errors.As(err, &binding) {
			t.Fatalf("expected *QuoteBindingError, got %T", err)
		}
		if binding.Cause == nil {
			t.Error("a parse failure must carry the go-xkms cause")
		}
		if binding.Error() == "" {
			t.Error("error message must not be empty")
		}
	})

	t.Run("QuoteOverABankTheReadLacksIsRejected", func(t *testing.T) {
		tpm := newFakeHostTPM()
		tpm.setPCR(7, golden)
		tpm.quoteBank = "sha384" // signed selection names a bank ReadPCRs does not report
		rt, _ := newAttestingTestRuntime(t, tpm, reference)

		_, err := rt.Attest(t.Context(), attestedSpec(), "container-1")
		if !errors.Is(err, ErrPCRBankUnavailable) {
			t.Fatalf("error %v does not wrap ErrPCRBankUnavailable", err)
		}
	})

	// go-xkms ReadPCRs reports uppercase bank names. Attestation must work
	// on such a host and must report the bank the signed selection named.
	t.Run("UppercaseBankFromXKMSVerifiesAndIsReported", func(t *testing.T) {
		tpm := newFakeHostTPM()
		tpm.bank = "SHA256"
		tpm.setPCR(7, golden)
		rt, _ := newAttestingTestRuntime(t, tpm, reference)

		evidence, err := rt.Attest(t.Context(), attestedSpec(), "container-1")
		if err != nil {
			t.Fatalf("Attest: %v", err)
		}
		if evidence.PCRBank != DefaultMeasurementBank {
			t.Errorf("PCRBank = %q, want %q", evidence.PCRBank, DefaultMeasurementBank)
		}
		if !bytes.Equal(evidence.PCRs[7], golden) {
			t.Errorf("quoted PCR 7 = %x, want %x", evidence.PCRs[7], golden)
		}
	})

	t.Run("HonestQuoteOverMultiplePCRsVerifies", func(t *testing.T) {
		tpm := newFakeHostTPM()
		tpm.setPCR(0, bytes.Repeat([]byte{0x01}, sha256.Size))
		tpm.setPCR(7, golden)
		tpm.setPCR(14, bytes.Repeat([]byte{0x0E}, sha256.Size))
		rt, _ := newAttestingTestRuntime(t, tpm, map[uint32][]byte{
			0:  bytes.Repeat([]byte{0x01}, sha256.Size),
			7:  golden,
			14: bytes.Repeat([]byte{0x0E}, sha256.Size),
		})

		evidence, err := rt.Attest(t.Context(), attestedSpec(), "container-1")
		if err != nil {
			t.Fatalf("Attest: %v", err)
		}
		if len(evidence.PCRs) != 3 {
			t.Fatalf("evidence carries %d PCRs, want 3", len(evidence.PCRs))
		}
	})
}

// The reference PCRs are chosen in the bank the attestation key quotes:
// digests in another bank are neither quoted nor appraised, and reference
// values with none in that bank are refused before any quote.
func TestTPMAttestingRuntime_Attest_QuotesTheAttestationKeyBank(t *testing.T) {
	pcr0 := bytes.Repeat([]byte{0x01}, sha256.Size)
	pcr7 := bytes.Repeat([]byte{0x07}, sha512.Size384)
	mixed := []attestationtest.PCRDigest{
		{Index: 0, Hash: crypto.SHA256, Value: pcr0},
		{Index: 7, Hash: crypto.SHA384, Value: pcr7},
	}
	spec := func() *ContainerSpec {
		return &ContainerSpec{Image: "alpine@" + testDigest, TrustLevel: TrustLevelAttested, ReferenceValues: "golden"}
	}

	t.Run("MixedReferencesQuoteOnlyTheHostBank", func(t *testing.T) {
		tpm := newFakeHostTPM()
		tpm.setPCR(0, pcr0)
		rt, _ := newAttestingTestRuntimeDigests(t, tpm, mixed)

		evidence, err := rt.Attest(t.Context(), spec(), "container-1")
		if err != nil {
			t.Fatalf("Attest: %v", err)
		}
		if want := []uint{0}; !reflect.DeepEqual(tpm.lastQuoted, want) {
			t.Fatalf("quoted PCRs %v, want %v", tpm.lastQuoted, want)
		}
		if len(evidence.PCRs) != 1 || !bytes.Equal(evidence.PCRs[0], pcr0) {
			t.Fatalf("evidence PCRs = %x, want only PCR 0", evidence.PCRs)
		}
	})

	t.Run("ReferencesOnlyInAnotherBankAreRefused", func(t *testing.T) {
		tpm := newFakeHostTPM()
		rt, _ := newAttestingTestRuntimeDigests(t, tpm, []attestationtest.PCRDigest{
			{Index: 0, Hash: crypto.SHA384, Value: bytes.Repeat([]byte{0x10}, sha512.Size384)},
			{Index: 7, Hash: crypto.SHA384, Value: pcr7},
		})

		_, err := rt.Attest(t.Context(), spec(), "container-1")
		var uncovered *ReferenceBankUncoveredError
		if !errors.As(err, &uncovered) || !errors.Is(err, ErrReferenceBankUncovered) {
			t.Fatalf("error %v, want *ReferenceBankUncoveredError", err)
		}
		if uncovered.Bank != crypto.SHA256 {
			t.Errorf("Bank = %s, want SHA-256", uncovered.Bank)
		}
		if tpm.quoteCalls != 0 {
			t.Fatalf("quoted %d times; nothing may be quoted without reference values in the bank", tpm.quoteCalls)
		}
	})

	t.Run("SHA1AttestationKeyIsRefused", func(t *testing.T) {
		tpm := newFakeHostTPM()
		tpm.iakBank = "sha1"
		rt, _ := newAttestingTestRuntimeDigests(t, tpm, mixed)

		_, err := rt.Attest(t.Context(), spec(), "container-1")
		if !errors.Is(err, ErrPCRBankUnavailable) {
			t.Fatalf("error %v does not wrap ErrPCRBankUnavailable", err)
		}
		if tpm.quoteCalls != 0 {
			t.Fatal("a SHA-1 bank must be refused before quoting")
		}
	})

	t.Run("UnreadableAttestationKeyIsAQuoteFailure", func(t *testing.T) {
		tpm := newFakeHostTPM()
		tpm.iakAttrsErr = errors.New("IAK attributes unavailable")
		rt, _ := newAttestingTestRuntimeDigests(t, tpm, mixed)

		_, err := rt.Attest(t.Context(), spec(), "container-1")
		if !errors.Is(err, ErrQuoteFailed) || !errors.Is(err, tpm.iakAttrsErr) {
			t.Fatalf("error %v, want ErrQuoteFailed carrying the cause", err)
		}
	})
}

// TestBindQuotedPCRs_RefusesQuotesNoSingleBankReferenceCanJudge covers the
// selections go-xkms's evidence primitive refuses: a quote over two banks
// (whose index->value map a golden comparison cannot use) and a quote over
// the SHA-1 bank (not acceptable evidence of state). Both are absences, not
// forgeries, and both leave the quote unbound.
func TestBindQuotedPCRs_RefusesQuotesNoSingleBankReferenceCanJudge(t *testing.T) {
	sha1Value := bytes.Repeat([]byte{0x11}, 20)
	sha256Value := bytes.Repeat([]byte{0x22}, sha256.Size)
	nonce := []byte("nonce-for-a-refused-quote")
	banks := []xkmstpm2.PCRBank{
		{Algorithm: "SHA1", PCRs: []xkmstpm2.PCR{{ID: 7, Value: sha1Value}}},
		{Algorithm: "SHA256", PCRs: []xkmstpm2.PCR{{ID: 7, Value: sha256Value}}},
	}

	cases := map[string]struct {
		selections []testSelection
		digest     []byte
	}{
		"TwoBanks": {
			selections: []testSelection{{bank: "sha1", indices: []uint32{7}}, {bank: "sha256", indices: []uint32{7}}},
			digest:     quotePCRDigest(t, "sha256", [][]byte{sha1Value, sha256Value}),
		},
		"SHA1Bank": {
			// The digest is the signing scheme's SHA-256 over the SHA-1
			// register, as a TPM produces it; the bank is what is refused.
			selections: []testSelection{{bank: "sha1", indices: []uint32{7}}},
			digest:     quotePCRDigest(t, "sha256", [][]byte{sha1Value}),
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			quoted := encodeTPMSAttestSelections(t, nonce, tc.selections, tc.digest)
			_, err := bindQuotedPCRs("alpine", quoted, nonce, banks)
			if !errors.Is(err, ErrQuoteNotBound) {
				t.Fatalf("error %v does not wrap ErrQuoteNotBound", err)
			}
			if !errors.Is(err, xkmsevidence.ErrAbsent) {
				t.Fatalf("error %v must carry go-xkms's absent-evidence cause", err)
			}
		})
	}
}

// TestBindQuotedPCRs_ShortRegisterIsRejected proves a read whose register is
// not the bank's digest size cannot bind, even when its bytes happen to hash
// to the signed digest: go-xkms checks the register size before the digest.
func TestBindQuotedPCRs_ShortRegisterIsRejected(t *testing.T) {
	short := bytes.Repeat([]byte{0x44}, 16)
	nonce := []byte("nonce-for-a-short-register")
	quoted := encodeTPMSAttestSelections(t, nonce,
		[]testSelection{{bank: "sha256", indices: []uint32{7}}},
		quotePCRDigest(t, "sha256", [][]byte{short}))
	banks := []xkmstpm2.PCRBank{{Algorithm: "SHA256", PCRs: []xkmstpm2.PCR{{ID: 7, Value: short}}}}

	_, err := bindQuotedPCRs("alpine", quoted, nonce, banks)
	if !errors.Is(err, ErrQuotedPCRDigestMismatch) {
		t.Fatalf("error %v does not wrap ErrQuotedPCRDigestMismatch", err)
	}
}

// extendBetweenQuoteAndReadTPM extends a PCR after the quote is taken and
// before the read, modelling the time-of-check/time-of-use window the signed
// pcrDigest closes.
type extendBetweenQuoteAndReadTPM struct {
	t     *testing.T
	inner *fakeHostTPM
	index uint32
	value []byte
}

func (p *extendBetweenQuoteAndReadTPM) Quote(pcrs []uint, nonce []byte) (xkmstpm2.Quote, error) {
	quote, err := p.inner.quote(p.t, pcrs, nonce)
	if err != nil {
		return quote, err
	}
	// The quote is signed over the pre-extend value; the register moves on.
	p.inner.setPCR(p.index, expectedExtend(p.value, []byte("late measurement")))
	return quote, nil
}

func (p *extendBetweenQuoteAndReadTPM) ReadPCRs(pcrList []uint) ([]xkmstpm2.PCRBank, error) {
	return p.inner.ReadPCRs(pcrList)
}

func (p *extendBetweenQuoteAndReadTPM) ExtendPCR(index int, alg string, data []byte) error {
	return p.inner.ExtendPCR(index, alg, data)
}

func (p *extendBetweenQuoteAndReadTPM) IAKCertificate() (*x509.Certificate, error) {
	return p.inner.IAKCertificate()
}

func (p *extendBetweenQuoteAndReadTPM) IAKAttributes() (*types.KeyAttributes, error) {
	return p.inner.IAKAttributes()
}

// TestPCRBankName proves the TPM algorithm ID in a signed selection maps back
// to the bank name go-xkms reports, using go-xkms's own mapping in both
// directions.
func TestPCRBankName(t *testing.T) {
	t.Run("EverySupportedBankRoundTrips", func(t *testing.T) {
		for _, bank := range supportedPCRBankNames {
			algID, err := xkmstpm2.ParsePCRBankAlgID(bank)
			if err != nil {
				t.Fatalf("ParsePCRBankAlgID(%q): %v", bank, err)
			}
			got, err := pcrBankName(uint16(algID))
			if err != nil {
				t.Fatalf("pcrBankName(0x%04x): %v", uint16(algID), err)
			}
			if got != bank {
				t.Fatalf("pcrBankName(0x%04x) = %q, want %q", uint16(algID), got, bank)
			}
		}
	})

	t.Run("UnknownAlgorithmIsRejected", func(t *testing.T) {
		if _, err := pcrBankName(0x0099); !errors.Is(err, ErrPCRBankUnavailable) {
			t.Fatalf("error %v does not wrap ErrPCRBankUnavailable", err)
		}
	})
}

func TestAttestationErrorsUnwrap(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		target error
	}{
		{
			name:   "AttestationUnavailable",
			err:    &AttestationUnavailableError{TrustLevel: TrustLevelAttested, Reason: "no tpm"},
			target: ErrAttestationUnavailable,
		},
		{
			name: "PCRMismatch",
			err: &HostAppraisalError{Image: "alpine", ReferenceValues: "golden", CryptographicFailure: true, Failures: []HostAppraisalFailure{{
				Check: "baseline", Outcome: "forged",
				PCRs: []PCRDivergence{{Index: 7, Expected: [][]byte{{0x01}}, Quoted: []byte{0x02}}},
			}}},
			target: ErrPCRMismatch,
		},
		{
			name: "PCRMismatchAbsent",
			err: &HostAppraisalError{Image: "alpine", ReferenceValues: "golden", Failures: []HostAppraisalFailure{{
				Check: "baseline", Outcome: "absent",
				PCRs: []PCRDivergence{{Index: 7, Expected: [][]byte{{0x01}}}},
			}}},
			target: ErrPCRMismatch,
		},
		{
			name:   "HostNotVerified",
			err:    &HostAppraisalError{Image: "alpine", ReferenceValues: "golden", Failures: []HostAppraisalFailure{{Check: "ak-certificate", Outcome: "absent"}}},
			target: ErrHostNotVerified,
		},
		{
			name:   "MeasurementNoCause",
			err:    &ContainerMeasurementError{Image: "alpine", PCR: 16, Bank: "sha256"},
			target: ErrMeasurementFailed,
		},
		{
			name:   "MeasurementWithCause",
			err:    &ContainerMeasurementError{Image: "alpine", PCR: 16, Bank: "sha256", Cause: errors.New("locked")},
			target: ErrMeasurementFailed,
		},
		{
			name:   "QuoteNoCause",
			err:    &ContainerQuoteError{Image: "alpine"},
			target: ErrQuoteFailed,
		},
		{
			name:   "QuoteWithCause",
			err:    &ContainerQuoteError{Image: "alpine", Cause: errors.New("busy")},
			target: ErrQuoteFailed,
		},
		{
			name:   "QuoteBindingNoCause",
			err:    &QuoteBindingError{Image: "alpine", Reason: "not a quote"},
			target: ErrQuoteNotBound,
		},
		{
			name:   "QuoteBindingWithCause",
			err:    &QuoteBindingError{Image: "alpine", Reason: "unparseable", Cause: errors.New("short buffer")},
			target: ErrQuoteNotBound,
		},
		{
			name:   "QuotedPCRDigestMismatch",
			err:    &QuotedPCRDigestMismatchError{Image: "alpine", Bank: "sha256", Signed: []byte{0x01}, Cause: errors.New("digest differs")},
			target: ErrQuotedPCRDigestMismatch,
		},
		{
			name:   "QuotedPCRDigestMismatchIsAlsoUnbound",
			err:    &QuotedPCRDigestMismatchError{Image: "alpine", Bank: "sha256", Signed: []byte{0x01}, Cause: errors.New("digest differs")},
			target: ErrQuoteNotBound,
		},
		{
			name:   "PCRBankUnavailable",
			err:    &PCRBankUnavailableError{Requested: "sha384", Available: []string{"SHA1", "SHA256"}},
			target: ErrPCRBankUnavailable,
		},
		{
			name:   "PCRBankUnavailableNoBanks",
			err:    &PCRBankUnavailableError{Requested: "sha256"},
			target: ErrPCRBankUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !errors.Is(tt.err, tt.target) {
				t.Fatalf("%v does not wrap %v", tt.err, tt.target)
			}
			if tt.err.Error() == "" {
				t.Fatal("error message must not be empty")
			}
		})
	}
}

// TestAttestingRuntimeSatisfiesContainerRuntime pins the seam shape: the
// attesting runtime is a drop-in ContainerRuntime, so an orchestrator holds
// one interface and type-asserts only when it needs evidence.
func TestAttestingRuntimeSatisfiesContainerRuntime(t *testing.T) {
	rt, _ := newAttestingTestRuntime(t, newFakeHostTPM(), nil)

	var runtime ContainerRuntime = rt
	if !runtime.IsAvailable() {
		t.Fatal("promoted IsAvailable must reach the base runtime")
	}

	attester, ok := runtime.(AttestingContainerRuntime)
	if !ok {
		t.Fatal("TPMAttestingRuntime must satisfy AttestingContainerRuntime")
	}
	if !attester.TrustCapabilities().HostTPM {
		t.Fatal("attesting runtime must advertise host TPM support")
	}
}
