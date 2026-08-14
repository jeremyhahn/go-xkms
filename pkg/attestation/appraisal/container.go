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
	"crypto/rand"
	"sort"
	"strings"
	"time"

	// The PCR-digest recomputation resolves its hash from the digest length
	// reported by the TPM, so every bank a TPM 2.0 PC Client platform can
	// expose must be linked into the binary for crypto.Hash.New to work.
	_ "crypto/sha1" //nolint:gosec // G505: TPM 2.0 PC Client platforms expose a SHA-1 PCR bank; the hash is only used to recompute quoted PCR digests, never for signing.
	_ "crypto/sha256"
	_ "crypto/sha512"

	deviceattest01 "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/device-attest-01"
	xkmstpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"

	"github.com/jeremyhahn/go-quicbaas/pkg/interfaces"
)

// =============================================================================
// Tier 1 / Tier 2 — Host TPM Attestation and Measured Launch
// =============================================================================
//
// Tier 1 asks the host TPM for a quote over a chosen PCR set and checks the
// quoted values against the golden set on the spec. A host whose firmware,
// bootloader or kernel changed produces different PCRs and is refused before
// an agent is scheduled onto it.
//
// Tier 2 adds measured launch: immediately before the container starts, the
// image and configuration digest are extended into an application PCR, and
// that PCR is included in the quote. The quote then proves not just that the
// host booted correctly, but that THIS configuration was the thing launched
// on it — a property no post-hoc inspection of the running container can
// establish.
//
// Both tiers compose go-xkms pkg/tpm2 (Quote / ReadPCRs / ExtendPCR). Nothing
// here reimplements a TPM primitive.

// MeasurementPCRDefault is the PCR index used for measured launch when a spec
// does not name one. PCR 16 is the TCG PC Client "debug" register: it is
// resettable, is not consumed by firmware or the bootloader, and is the
// conventional home for application-supplied measurements, so extending it
// cannot disturb a platform's boot-integrity PCRs.
const MeasurementPCRDefault = 16

// attestationNonceBytes is the size of the qualifying-data nonce sent with a
// quote. Twenty bytes matches the smallest TPM digest size and is ample to
// make quote replay infeasible.
const attestationNonceBytes = 20

// HostTPM is the narrow TPM capability the attesting container runtime needs.
//
// It is satisfied as-is by go-xkms *tpm2.TPM2 and by anything else that
// implements xkms's TrustedPlatformModule (including its software simulator),
// so no adapter type exists between quicbaas and xkms. Declaring the narrow
// interface rather than depending on the full TrustedPlatformModule keeps the
// runtime mockable and states exactly which three primitives the trust tiers
// rest on.
type HostTPM interface {
	// Quote produces a TPM 2.0 quote over the supplied PCR indices, bound
	// to nonce as qualifying data.
	Quote(pcrs []uint, nonce []byte) (xkmstpm2.Quote, error)

	// ReadPCRs reads the current value of the supplied PCR indices across
	// the TPM's active banks.
	ReadPCRs(pcrList []uint) ([]xkmstpm2.PCRBank, error)

	// ExtendPCR hashes data with hashAlg and extends the result into the
	// PCR at pcrIndex.
	ExtendPCR(pcrIndex int, hashAlg string, data []byte) error
}

// AttestingContainerRuntime is the trusted-computing seam: a ContainerRuntime
// that can additionally prove, to a remote verifier, what it launched and
// where.
//
// The interface is deliberately an EMBEDDING of ContainerRuntime rather than
// three extra methods bolted onto it. A runtime either can attest or cannot,
// and callers should be able to tell which by a type assertion:
//
//	if attester, ok := runtime.(AttestingContainerRuntime); ok {
//	        evidence, err := attester.Attest(ctx, spec, containerID)
//	}
//
// go-trusted-platform supplies a fleet-grade implementation of this interface
// (device registry, scheduled re-attestation, quarantine); TPMAttestingRuntime
// below is the standalone one, and it is complete on its own — quicbaas has no
// dependency on go-trusted-platform.
type AttestingContainerRuntime interface {
	ContainerRuntime

	// TrustCapabilities reports which trust tiers this runtime can
	// actually satisfy on this host, so a scheduler can resolve a
	// TrustLevel before it commits to a target.
	TrustCapabilities() TrustCapabilities

	// Attest produces attestation evidence for a container launched from
	// spec. It verifies the host quote against spec.ExpectedPCRs and, for
	// a measured launch, that the measurement PCR carries the expected
	// launch measurement. containerID may be empty when attesting a host
	// before scheduling anything onto it.
	Attest(ctx context.Context, spec *ContainerSpec, containerID string) (*ContainerAttestation, error)
}

// ContainerAttestation is the evidence produced by Attest. It is a
// self-contained record: a remote verifier needs the quote, the nonce it was
// bound to, the PCR values, and the identity of what was launched, and all
// four are here.
type ContainerAttestation struct {
	// ContainerID identifies the attested container. Empty when a host was
	// attested without a container.
	ContainerID string `json:"container_id,omitempty"`

	// Image is the pinned image reference the container was launched from.
	Image string `json:"image"`

	// ImageDigest is the immutable content digest of that image.
	ImageDigest string `json:"image_digest"`

	// ConfigDigest is the deterministic digest of the launch configuration
	// (see ContainerConfigDigest).
	ConfigDigest string `json:"config_digest"`

	// TrustLabel echoes the operator-assigned workload identity.
	TrustLabel string `json:"trust_label,omitempty"`

	// TrustLevel is the tier this evidence satisfies.
	TrustLevel TrustLevel `json:"trust_level"`

	// Nonce is the qualifying data the quote is bound to. A verifier that
	// supplied the nonce checks it here to establish freshness.
	Nonce []byte `json:"nonce"`

	// Quoted is the raw TPMS_ATTEST structure produced by the TPM.
	Quoted []byte `json:"quoted"`

	// Signature is the attestation key's signature over Quoted.
	Signature []byte `json:"signature"`

	// PCRs holds the quoted PCR values keyed by index. Every value here has
	// been bound to Quoted: the digest of these values, recomputed in the
	// order the signed PCR selection names them, equals the pcrDigest inside
	// the signed body. Values that fail that check never reach a caller.
	PCRs map[uint32][]byte `json:"pcrs"`

	// PCRBank names the bank the quoted PCR values were read from. The bank
	// is dictated by the signed quote's PCR selection, not by the spec, so a
	// verifier does not have to guess which bank PCRs refers to. It may
	// differ from MeasurementBank when the host's attestation key uses a
	// different hash algorithm than the measured launch does.
	PCRBank string `json:"pcr_bank,omitempty"`

	// EventLog is the raw TCG measurement log, when the host exposes one.
	EventLog []byte `json:"event_log,omitempty"`

	// Measured reports whether the launch measurement was extended into
	// MeasurementPCR before the container started (Tier 2).
	Measured bool `json:"measured"`

	// MeasurementPCR is the PCR index carrying the launch measurement.
	MeasurementPCR int `json:"measurement_pcr,omitempty"`

	// MeasurementBank is the PCR bank the measurement was extended into.
	MeasurementBank string `json:"measurement_bank,omitempty"`

	// LaunchMeasurement is the exact byte string extended into
	// MeasurementPCR. A verifier replays it against the pre-launch PCR
	// value to confirm the measurement corresponds to this configuration.
	LaunchMeasurement []byte `json:"launch_measurement,omitempty"`

	// AttestedAt is when the quote was taken.
	AttestedAt time.Time `json:"attested_at"`
}

// LaunchMeasurement returns the byte string extended into the measurement PCR
// for a spec. It binds the pinned image digest, the deterministic
// configuration digest and the operator trust label into one newline-free,
// field-separated record so a verifier can reconstruct it from the spec alone.
func LaunchMeasurement(spec *ContainerSpec) ([]byte, error) {
	configDigest, err := ContainerConfigDigest(spec)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString("quicbaas-container-launch/v1")
	buf.WriteByte(0)
	buf.WriteString(spec.ResolvedImageDigest())
	buf.WriteByte(0)
	buf.WriteString(configDigest)
	buf.WriteByte(0)
	buf.WriteString(spec.TrustLabel)
	return buf.Bytes(), nil
}

// TPMAttestingRuntime is the standalone Tier 1 / Tier 2 container runtime. It
// delegates every container operation to a base runtime (normally
// ExecContainerRuntime, which supplies Tier 0) and adds host attestation and
// measured launch on top by composing go-xkms pkg/tpm2.
//
// It is the reference implementation of AttestingContainerRuntime and requires
// nothing from go-trusted-platform.
type TPMAttestingRuntime struct {
	// ContainerRuntime is the embedded base runtime. Every verb except Run
	// and RunInteractive is promoted from it unchanged.
	ContainerRuntime

	tpm    HostTPM
	logger interfaces.Logger
}

// Compile-time interface check.
var _ AttestingContainerRuntime = (*TPMAttestingRuntime)(nil)

// NewTPMAttestingRuntime wraps base with TPM-backed attestation.
//
// base supplies Tier 0 (digest pinning); tpm supplies Tiers 1 and 2. Both are
// required — an attesting runtime with no TPM would silently degrade to Tier 0
// while advertising more, which is exactly the failure mode deny-by-default
// exists to prevent.
func NewTPMAttestingRuntime(base ContainerRuntime, tpm HostTPM, logger interfaces.Logger) (*TPMAttestingRuntime, error) {
	if base == nil {
		return nil, &InputValidationError{Field: "base", Message: "cannot be nil"}
	}
	if tpm == nil {
		return nil, &InputValidationError{Field: "tpm", Message: "cannot be nil"}
	}
	if logger == nil {
		return nil, &InputValidationError{Field: "logger", Message: "cannot be nil"}
	}
	return &TPMAttestingRuntime{ContainerRuntime: base, tpm: tpm, logger: logger}, nil
}

// TrustCapabilities reports the tiers this runtime can satisfy. Digest
// pinning comes from the base runtime and is always available; the TPM tiers
// are available because a TPM is required at construction.
func (r *TPMAttestingRuntime) TrustCapabilities() TrustCapabilities {
	return TrustCapabilities{
		DigestPinning:  true,
		HostTPM:        true,
		MeasuredLaunch: true,
	}
}

// Run performs a measured launch when the spec asks for one, then delegates
// to the base runtime. The measurement is extended BEFORE the container
// starts: a measurement taken afterwards would not be a measured launch, it
// would be an assertion that something already running was approved.
func (r *TPMAttestingRuntime) Run(ctx context.Context, spec *ContainerSpec) (string, error) {
	if err := r.measureLaunch(spec); err != nil {
		return "", err
	}
	return r.ContainerRuntime.Run(ctx, spec)
}

// RunInteractive performs a measured launch when the spec asks for one, then
// delegates to the base runtime.
func (r *TPMAttestingRuntime) RunInteractive(ctx context.Context, spec *ContainerSpec) (*InteractiveProcess, error) {
	if err := r.measureLaunch(spec); err != nil {
		return nil, err
	}
	return r.ContainerRuntime.RunInteractive(ctx, spec)
}

// measureLaunch extends the launch measurement into the spec's measurement
// PCR. It is a no-op below TrustLevelMeasured, so Tier 0 and Tier 1 launches
// leave the TPM untouched.
func (r *TPMAttestingRuntime) measureLaunch(spec *ContainerSpec) error {
	if spec == nil {
		return &InputValidationError{Field: "spec", Message: "cannot be nil"}
	}
	if err := spec.Validate(); err != nil {
		return err
	}
	if !spec.TrustLevel.RequiresMeasuredLaunch() {
		return nil
	}

	measurement, err := LaunchMeasurement(spec)
	if err != nil {
		return err
	}

	pcr := spec.EffectiveMeasurementPCR()
	bank := spec.EffectiveMeasurementBank()
	if err := r.tpm.ExtendPCR(pcr, bank, measurement); err != nil {
		return &ContainerMeasurementError{
			Image: spec.Image,
			PCR:   pcr,
			Bank:  bank,
			Cause: err,
		}
	}

	r.logger.Infof("measured launch: extended PCR %d (%s) for %s",
		pcr, bank, spec.PinnedImageReference())
	return nil
}

// EffectiveMeasurementPCR returns the PCR index the spec's launch measurement
// is extended into, defaulting to MeasurementPCRDefault.
func (s *ContainerSpec) EffectiveMeasurementPCR() int {
	if s == nil || s.MeasurementPCR == 0 {
		return MeasurementPCRDefault
	}
	return s.MeasurementPCR
}

// Attest produces attestation evidence for a container launched from spec.
//
// It quotes the union of the spec's expected PCR indices and — for a measured
// launch — the measurement PCR, binds the PCR read to the signed quote body
// (see bindQuotedPCRs), and only then verifies every expected value against
// the bound one. Any mismatch is a PCRMismatchError: the host is not in the
// state the operator approved and the agent must not be trusted on it.
//
// The golden-value comparison is deliberately downstream of the binding. A
// comparison against a bare TPM2_PCR_Read proves nothing — the read is
// unauthenticated and a PCR can be extended between the quote and the read —
// so a read that does not reproduce the signed pcrDigest is rejected as
// QuotedPCRDigestMismatchError before any golden value is looked at.
func (r *TPMAttestingRuntime) Attest(ctx context.Context, spec *ContainerSpec, containerID string) (*ContainerAttestation, error) {
	if spec == nil {
		return nil, &InputValidationError{Field: "spec", Message: "cannot be nil"}
	}
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if !spec.TrustLevel.RequiresHostTPM() {
		return nil, &AttestationUnavailableError{
			TrustLevel: spec.TrustLevel,
			Reason:     "trust level does not request host attestation",
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	configDigest, err := ContainerConfigDigest(spec)
	if err != nil {
		return nil, err
	}

	measured := spec.TrustLevel.RequiresMeasuredLaunch()
	pcrIndices := quotePCRIndices(spec, measured)

	nonce := make([]byte, attestationNonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return nil, &ContainerQuoteError{Image: spec.Image, Cause: err}
	}

	quote, err := r.tpm.Quote(pcrIndices, nonce)
	if err != nil {
		return nil, &ContainerQuoteError{Image: spec.Image, Cause: err}
	}

	banks, err := r.tpm.ReadPCRs(pcrIndices)
	if err != nil {
		return nil, &ContainerQuoteError{Image: spec.Image, Cause: err}
	}

	// The PCR values come from an unsigned read; the quote signs only a
	// digest over them. Bind the two before either is believed.
	bound, err := bindQuotedPCRs(spec.Image, quote.Quoted, nonce, banks)
	if err != nil {
		return nil, err
	}

	if err := verifyExpectedPCRs(spec.ExpectedPCRs, bound.values); err != nil {
		return nil, err
	}

	attestation := &ContainerAttestation{
		ContainerID:     containerID,
		Image:           spec.PinnedImageReference(),
		ImageDigest:     spec.ResolvedImageDigest(),
		ConfigDigest:    configDigest,
		TrustLabel:      spec.TrustLabel,
		TrustLevel:      spec.TrustLevel,
		Nonce:           nonce,
		Quoted:          quote.Quoted,
		Signature:       quote.Signature,
		PCRs:            bound.values,
		PCRBank:         bound.bank,
		EventLog:        quote.EventLog,
		Measured:        measured,
		MeasurementBank: spec.EffectiveMeasurementBank(),
		AttestedAt:      time.Now().UTC(),
	}

	if measured {
		measurement, err := LaunchMeasurement(spec)
		if err != nil {
			return nil, err
		}
		attestation.MeasurementPCR = spec.EffectiveMeasurementPCR()
		attestation.LaunchMeasurement = measurement
	}

	return attestation, nil
}

// quotePCRIndices returns the sorted, de-duplicated set of PCR indices to
// quote: every index with an expected value, plus the measurement PCR for a
// measured launch.
func quotePCRIndices(spec *ContainerSpec, measured bool) []uint {
	seen := make(map[uint]struct{}, len(spec.ExpectedPCRs)+1)
	for index := range spec.ExpectedPCRs {
		seen[uint(index)] = struct{}{}
	}
	if measured {
		seen[uint(spec.EffectiveMeasurementPCR())] = struct{}{}
	}

	indices := make([]uint, 0, len(seen))
	for index := range seen {
		indices = append(indices, index)
	}
	// Sorting keeps the quote's PCR selection deterministic, which matters
	// because the selection is part of the signed TPMS_ATTEST structure.
	sort.Slice(indices, func(i, j int) bool { return indices[i] < indices[j] })
	return indices
}

// =============================================================================
// Binding the PCR read to the signed quote
// =============================================================================
//
// A TPM2_Quote signs a TPMS_ATTEST structure whose TPMS_QUOTE_INFO carries the
// PCR selection and one pcrDigest — H(PCR[i1] || PCR[i2] || …) over the
// selected registers in selection order. It does NOT carry the individual PCR
// values, so those must come from a separate, unsigned TPM2_PCR_Read.
//
// Comparing golden values against that read alone establishes nothing: the
// read carries no signature, and a PCR can be extended in the window between
// the quote and the read. bindQuotedPCRs closes the gap by recomputing
// pcrDigest over the values that were read and requiring it to equal the
// digest inside the signed body, and by requiring the body's extraData to be
// the nonce this process just generated.
//
// Every TPM structure here is parsed by go-xkms (deviceattest01.ParseTPMSAttest
// and VerifyQualifyingData) and every algorithm mapping comes from go-xkms
// (tpm2.ParsePCRBankAlgID, ParsePCRBankCryptoHash, PCRDigestSize). Nothing in
// this file hand-rolls a TPM structure.

// boundPCRs is a PCR read that has been proven to agree with a signed quote.
// Its values are the only ones Attest will compare against a golden set.
type boundPCRs struct {
	// bank is the PCR bank the signed selection named.
	bank string

	// values are the read PCR values, keyed by index, that reproduce the
	// signed pcrDigest.
	values map[uint32][]byte
}

// bindQuotedPCRs proves that the PCR values read back from the TPM are the
// values the TPM committed to when it signed quoted, and that the quote is
// fresh.
//
// What this establishes: the returned values are exactly the ones covered by
// the signed pcrDigest, and the signed body carries this attestation's nonce.
// A TOCTOU change between the quote and the read, or a tampered read path,
// makes the recomputed digest differ and is rejected.
//
// What this does NOT establish: that the signature over quoted verifies under
// a trusted attestation key. That check needs the AK public key and its
// certificate chain, neither of which the narrow HostTPM seam exposes, and it
// belongs to the remote verifier that consumes ContainerAttestation.Quoted and
// .Signature. Locally, the quote body is trusted because it came from the
// host's own TPM handle; what is being defended against here is a divergence
// between that body and the separate PCR read.
func bindQuotedPCRs(image string, quoted, nonce []byte, banks []xkmstpm2.PCRBank) (*boundPCRs, error) {
	attest, err := deviceattest01.ParseTPMSAttest(quoted)
	if err != nil {
		return nil, &QuoteBindingError{
			Image:  image,
			Reason: "signed quote body could not be parsed",
			Cause:  err,
		}
	}

	// ParseTPMSAttest fills Attested only for TPM_ST_ATTEST_QUOTE, so an
	// empty selection or digest means the signed body attests to something
	// other than a PCR quote and cannot be bound to a PCR read. Testing the
	// parsed result rather than the raw type code keeps the TPM structure
	// codes in go-xkms, where they belong.
	if len(attest.Attested.PCRSelect) == 0 || len(attest.Attested.PCRDigest) == 0 {
		return nil, &QuoteBindingError{
			Image:  image,
			Reason: "signed body carries no TPMS_QUOTE_INFO; it does not attest to a PCR quote",
		}
	}

	// Freshness: the nonce must be inside the signed body, not merely
	// alongside it. The parse above already succeeded, so VerifyQualifyingData
	// compares extraData exactly and never reaches its containment fallback.
	if !deviceattest01.VerifyQualifyingData(quoted, nonce) {
		return nil, &QuoteBindingError{
			Image:  image,
			Reason: "signed quote does not carry the nonce this attestation generated",
		}
	}

	hash, err := pcrDigestHash(len(attest.Attested.PCRDigest))
	if err != nil {
		return nil, &QuoteBindingError{
			Image:  image,
			Reason: "signed pcrDigest length matches no supported PCR bank",
			Cause:  err,
		}
	}

	composite := hash.New()
	values := make(map[uint32][]byte)
	primaryBank := ""

	for _, selection := range attest.Attested.PCRSelect {
		bankName, err := pcrBankName(selection.Hash)
		if err != nil {
			return nil, &QuoteBindingError{
				Image:  image,
				Reason: "signed quote selects a PCR bank this build does not support",
				Cause:  err,
			}
		}
		read, err := flattenPCRBanks(banks, bankName)
		if err != nil {
			return nil, err
		}
		if primaryBank == "" {
			primaryBank = bankName
		}

		for _, index := range selectedPCRIndices(selection) {
			value, ok := read[index]
			if !ok {
				return nil, &QuoteBindingError{
					Image: image,
					Reason: "PCR " + intToStr(int(index)) + " is in the signed selection but absent from the " +
						bankName + " read",
				}
			}
			if previous, duplicated := values[index]; duplicated && !bytes.Equal(previous, value) {
				// The same index selected in two banks would make the
				// index->value map ambiguous, and a golden comparison
				// against an ambiguous value is not a comparison.
				return nil, &QuoteBindingError{
					Image:  image,
					Reason: "PCR " + intToStr(int(index)) + " is selected in more than one bank with differing values",
				}
			}
			values[index] = value
			// hash.Hash never returns a write error (documented in the
			// hash package), so the result is discarded deliberately.
			_, _ = composite.Write(value)
		}
	}

	if recomputed := composite.Sum(nil); !bytes.Equal(recomputed, attest.Attested.PCRDigest) {
		return nil, &QuotedPCRDigestMismatchError{
			Image:      image,
			Bank:       primaryBank,
			Signed:     append([]byte(nil), attest.Attested.PCRDigest...),
			Recomputed: recomputed,
		}
	}

	return &boundPCRs{bank: primaryBank, values: values}, nil
}

// selectedPCRIndices expands a TPMS_PCR_SELECTION bitmap into ascending PCR
// indices. The TPM numbers bits little-endian within each byte, and the
// pcrDigest concatenates the selected registers in exactly this order, so the
// expansion order is part of the verification and not a presentation choice.
func selectedPCRIndices(selection deviceattest01.TPMSPCRSelection) []uint32 {
	indices := make([]uint32, 0, len(selection.PCRBitmap)*8)
	for byteIndex, bitmap := range selection.PCRBitmap {
		for bit := 0; bit < 8; bit++ {
			if bitmap&(1<<uint(bit)) != 0 {
				indices = append(indices, uint32(byteIndex*8+bit))
			}
		}
	}
	return indices
}

// pcrBankName maps the TPM algorithm ID carried in a signed PCR selection back
// to the bank name go-xkms reports from ReadPCRs. The mapping is derived from
// go-xkms rather than restated, so a bank added upstream needs no constant
// here.
func pcrBankName(algID uint16) (string, error) {
	for _, name := range supportedPCRBankNames {
		id, err := xkmstpm2.ParsePCRBankAlgID(name)
		if err != nil {
			return "", err
		}
		if uint16(id) == algID {
			return name, nil
		}
	}
	return "", &PCRBankUnavailableError{Requested: "TPM algorithm 0x" + hexOrAbsent([]byte{byte(algID >> 8), byte(algID)})}
}

// pcrDigestHash resolves the hash a quote's pcrDigest was computed with from
// its length. The TPM does not name that algorithm inside TPMS_QUOTE_INFO —
// it is the signing scheme's hash — but the four banks a PC Client TPM can
// expose have four distinct digest sizes, so the length determines it
// uniquely.
func pcrDigestHash(digestLength int) (crypto.Hash, error) {
	for _, name := range supportedPCRBankNames {
		if xkmstpm2.PCRDigestSize(name) != digestLength {
			continue
		}
		hash, err := xkmstpm2.ParsePCRBankCryptoHash(name)
		if err != nil {
			return 0, err
		}
		if !hash.Available() {
			return 0, &PCRBankUnavailableError{Requested: name}
		}
		return hash, nil
	}
	return 0, &PCRBankUnavailableError{
		Requested: intToStr(digestLength) + "-byte digest",
		Available: supportedPCRBankNames,
	}
}

// flattenPCRBanks reduces the multi-bank PCR read to a single index->digest
// map for the named bank.
//
// The match is case-insensitive: go-xkms ReadPCRs reports "SHA256" while every
// bank name in this package (and in a ContainerSpec) is lowercase, and an
// exact comparison silently missed on every multi-bank host. A bank that is
// genuinely absent is an error, never a fallback to whichever bank happened to
// be first — reading PCRs from an unintended bank produces measurements that
// look valid and mean nothing.
func flattenPCRBanks(banks []xkmstpm2.PCRBank, name string) (map[uint32][]byte, error) {
	for _, bank := range banks {
		if !strings.EqualFold(bank.Algorithm, name) {
			continue
		}
		out := make(map[uint32][]byte, len(bank.PCRs))
		for _, pcr := range bank.PCRs {
			if pcr.ID < 0 {
				continue
			}
			value := make([]byte, len(pcr.Value))
			copy(value, pcr.Value)
			out[uint32(pcr.ID)] = value
		}
		return out, nil
	}

	available := make([]string, 0, len(banks))
	for _, bank := range banks {
		available = append(available, bank.Algorithm)
	}
	return nil, &PCRBankUnavailableError{Requested: name, Available: available}
}

// verifyExpectedPCRs compares every expected PCR against the quoted value.
// A missing quoted PCR is a mismatch, not a pass: absence of evidence is not
// evidence of a match.
func verifyExpectedPCRs(expected, quoted map[uint32][]byte) error {
	indices := make([]uint32, 0, len(expected))
	for index := range expected {
		indices = append(indices, index)
	}
	// Sorted so the reported mismatch is the lowest-numbered failing PCR
	// rather than whichever one map iteration happened to reach first.
	sort.Slice(indices, func(i, j int) bool { return indices[i] < indices[j] })

	for _, index := range indices {
		want := expected[index]
		got, ok := quoted[index]
		if !ok {
			return &PCRMismatchError{Index: index, Expected: want, Actual: nil}
		}
		if !bytes.Equal(want, got) {
			return &PCRMismatchError{Index: index, Expected: want, Actual: got}
		}
	}
	return nil
}

// =============================================================================
// Typed Attestation Errors
// =============================================================================

// AttestationUnavailableError indicates the attestation capability a trust
// tier requires is not present.
type AttestationUnavailableError struct {
	TrustLevel TrustLevel
	Reason     string
}

// Error implements the error interface.
func (e *AttestationUnavailableError) Error() string {
	return ErrAttestationUnavailable.Error() + " for trust level " +
		e.TrustLevel.String() + ": " + e.Reason
}

// Unwrap returns the sentinel error for errors.Is support.
func (e *AttestationUnavailableError) Unwrap() error {
	return ErrAttestationUnavailable
}

// PCRMismatchError indicates a quoted PCR does not match the expected golden
// value, meaning the host is not in the state the operator approved.
type PCRMismatchError struct {
	Index    uint32
	Expected []byte
	Actual   []byte
}

// Error implements the error interface.
func (e *PCRMismatchError) Error() string {
	return ErrPCRMismatch.Error() + ": PCR " + intToStr(int(e.Index)) +
		" expected " + hexOrAbsent(e.Expected) + " but quoted " + hexOrAbsent(e.Actual)
}

// Unwrap returns the sentinel error for errors.Is support.
func (e *PCRMismatchError) Unwrap() error {
	return ErrPCRMismatch
}

// QuoteBindingError indicates the PCR values read from the TPM could not be
// tied to the signed quote body, so they are not evidence of anything. It
// covers an unparseable or non-quote TPMS_ATTEST, a quote that does not carry
// this attestation's nonce, and a selection that names a bank or a register
// the read did not supply.
type QuoteBindingError struct {
	Image  string
	Reason string
	Cause  error
}

// Error implements the error interface.
func (e *QuoteBindingError) Error() string {
	msg := ErrQuoteNotBound.Error() + ": " + e.Image + ": " + e.Reason
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

// Unwrap returns the sentinel and the cause for errors.Is support.
func (e *QuoteBindingError) Unwrap() []error {
	if e.Cause == nil {
		return []error{ErrQuoteNotBound}
	}
	return []error{ErrQuoteNotBound, e.Cause}
}

// QuotedPCRDigestMismatchError indicates the pcrDigest inside the signed quote
// does not match a recomputation over the PCR values the TPM reported. The
// signed evidence and the PCR read disagree about the state of the host, so
// neither may be trusted.
//
// It reports both ErrQuotedPCRDigestMismatch and ErrQuoteNotBound, so a caller
// can catch the specific failure or the whole class of unbound quotes.
type QuotedPCRDigestMismatchError struct {
	Image      string
	Bank       string
	Signed     []byte
	Recomputed []byte
}

// Error implements the error interface.
func (e *QuotedPCRDigestMismatchError) Error() string {
	return ErrQuotedPCRDigestMismatch.Error() + ": " + e.Image + ": the " + e.Bank +
		" PCR read hashes to " + hexOrAbsent(e.Recomputed) +
		" but the signed quote commits to " + hexOrAbsent(e.Signed)
}

// Unwrap returns both sentinels for errors.Is support.
func (e *QuotedPCRDigestMismatchError) Unwrap() []error {
	return []error{ErrQuotedPCRDigestMismatch, ErrQuoteNotBound}
}

// PCRBankUnavailableError indicates the PCR bank a verification step requires
// is not one the TPM reported. It is returned instead of silently reading a
// different bank, which would yield measurements that are well-formed and
// meaningless.
type PCRBankUnavailableError struct {
	Requested string
	Available []string
}

// Error implements the error interface.
func (e *PCRBankUnavailableError) Error() string {
	msg := ErrPCRBankUnavailable.Error() + ": " + e.Requested
	if len(e.Available) > 0 {
		msg += " (the TPM reported: " + strings.Join(e.Available, ", ") + ")"
	} else {
		msg += " (the TPM reported no banks)"
	}
	return msg
}

// Unwrap returns the sentinel error for errors.Is support.
func (e *PCRBankUnavailableError) Unwrap() error {
	return ErrPCRBankUnavailable
}

// ContainerMeasurementError indicates the measured-launch PCR extension
// failed, so the container was not started.
type ContainerMeasurementError struct {
	Image string
	PCR   int
	Bank  string
	Cause error
}

// Error implements the error interface.
func (e *ContainerMeasurementError) Error() string {
	msg := ErrMeasurementFailed.Error() + ": " + e.Image +
		" PCR " + intToStr(e.PCR) + " (" + e.Bank + ")"
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

// Unwrap returns the sentinel and the cause for errors.Is support.
func (e *ContainerMeasurementError) Unwrap() []error {
	if e.Cause == nil {
		return []error{ErrMeasurementFailed}
	}
	return []error{ErrMeasurementFailed, e.Cause}
}

// ContainerQuoteError indicates the host TPM refused or failed to produce a
// quote.
type ContainerQuoteError struct {
	Image string
	Cause error
}

// Error implements the error interface.
func (e *ContainerQuoteError) Error() string {
	msg := ErrQuoteFailed.Error() + ": " + e.Image
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

// Unwrap returns the sentinel and the cause for errors.Is support.
func (e *ContainerQuoteError) Unwrap() []error {
	if e.Cause == nil {
		return []error{ErrQuoteFailed}
	}
	return []error{ErrQuoteFailed, e.Cause}
}

// hexOrAbsent renders a PCR digest for an error message, distinguishing an
// empty digest from an absent one.
func hexOrAbsent(b []byte) string {
	if len(b) == 0 {
		return "<absent>"
	}
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hexDigits[c>>4], hexDigits[c&0x0f])
	}
	return string(out)
}
