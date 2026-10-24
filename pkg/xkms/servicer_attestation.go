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

package service

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	stderrors "errors"
	"time"

	xkmsattestation "github.com/jeremyhahn/go-xkms/pkg/attestation"

	"github.com/jeremyhahn/go-quicbaas/pkg/errors"
	"github.com/jeremyhahn/go-quicbaas/pkg/orchestration"
)

// AttestationService is the verify-and-compose surface QuicBaaS exposes under
// Security().Attestation(). It has two distinct halves:
//
//   - A pure VERIFIER over the go-xkms attestation package. Verify and
//     VerifyChain hand a reconstructed xkms AttestationStatement to
//     xkmsattestation.Verifier; QuicBaaS reimplements no signature check,
//     no chain walk, and no PCR comparison. All this layer does is turn
//     wire-portable material (PEM chains, DER public keys) into the xkms
//     types the verifier expects, because crypto.PublicKey does not cross a
//     transport.
//
//   - An ORCHESTRATION SEAM. AttestContainer forwards to an application-
//     supplied ContainerAttestor. QuicBaaS ships the standalone tiers
//     (digest pinning, host quote, measured launch) in pkg/orchestration and
//     can fill this seam with them via NewRuntimeContainerAttestor; a fleet
//     operator such as go-trusted-platform supplies its own implementation
//     with a device registry, scheduled re-attestation and quarantine. When
//     nothing is registered the seam returns ErrAttestationNoAttestor, the
//     same "not configured" contract Trust().PublishDANE uses for its DANE
//     publisher hook.
type AttestationService interface {
	// Verify validates a complete attestation statement: certificate
	// chain, signature over the attestation data, and — when the request
	// asks for them — nonce freshness and PCR values.
	Verify(ctx context.Context, req *VerifyAttestationRequest) (*VerifyAttestationResponse, error)

	// VerifyChain validates only the certificate chain carried by an
	// attestation statement, without checking the attestation signature.
	// Callers use it to decide whether an attesting key is genuine before
	// paying for a full verification.
	VerifyChain(ctx context.Context, req *VerifyAttestationChainRequest) (*VerifyAttestationChainResponse, error)

	// AttestContainer requests attestation evidence for a container from
	// the registered ContainerAttestor. Returns ErrAttestationNoAttestor
	// when no attestor has been registered.
	AttestContainer(ctx context.Context, req *AttestContainerRequest) (*AttestContainerResponse, error)

	// PutEndorsement stores (or replaces) a trust anchor of the Verifier:
	// a reference-value signer or an attestation-key root.
	PutEndorsement(ctx context.Context, req *PutEndorsementRequest) (*Endorsement, error)

	// ListEndorsements lists the tenant's endorsements, optionally of one
	// kind.
	ListEndorsements(ctx context.Context, req *ListEndorsementsRequest) (*ListEndorsementsResponse, error)

	// DeleteEndorsement removes an endorsement. Reference values it signed
	// stop appraising until another endorsement verifies them.
	DeleteEndorsement(ctx context.Context, req *DeleteEndorsementRequest) error

	// PutReferenceValues verifies a signed CoRIM against the stored
	// reference-signer endorsements and stores it under a name. Unsigned or
	// unendorsed reference values are refused: there is no trust on first
	// use.
	PutReferenceValues(ctx context.Context, req *PutReferenceValuesRequest) (*ReferenceValues, error)

	// GetReferenceValues returns stored reference values.
	GetReferenceValues(ctx context.Context, req *GetReferenceValuesRequest) (*ReferenceValues, error)

	// ListReferenceValues lists stored reference values.
	ListReferenceValues(ctx context.Context) (*ListReferenceValuesResponse, error)

	// DeleteReferenceValues removes stored reference values.
	DeleteReferenceValues(ctx context.Context, req *DeleteReferenceValuesRequest) error

	// AppraiseQuote appraises TPM quote evidence — attestation-key
	// certificate, quote, optional event log — against stored, signed
	// reference values and returns the attestation result.
	AppraiseQuote(ctx context.Context, req *AppraiseQuoteRequest) (*AttestationResult, error)
}

// ContainerAttestor is the application-supplied orchestration hook the
// attestation service calls to obtain container attestation evidence.
//
// It mirrors the DANEPublisher seam exactly: QuicBaaS declares the interface,
// ships a nil default, and returns a typed not-configured error until an
// embedder registers one through the server's WithContainerAttestor option.
//
// Two implementations are expected:
//
//   - The standalone one, built from an orchestration.AttestingContainerRuntime
//     by NewRuntimeContainerAttestor. It attests the local host, which is all
//     a single-node deployment needs.
//   - A fleet one, supplied by go-trusted-platform, which resolves DeviceID
//     against a device registry, applies golden-PCR policy, records the
//     result for scheduled re-attestation, and quarantines hosts that drift.
//     None of that belongs in QuicBaaS.
type ContainerAttestor interface {
	// AttestContainer produces attestation evidence for the container
	// described by req. Implementations MUST fail closed: a host that
	// cannot prove its state returns an error rather than an unattested
	// success.
	AttestContainer(ctx context.Context, req *AttestContainerRequest) (*AttestContainerResponse, error)
}

// =============================================================================
// Request / Response Types
// =============================================================================

// VerifyAttestationRequest carries a wire-portable attestation statement plus
// the options to verify it under.
type VerifyAttestationRequest struct {
	// Format identifies the attestation format, e.g. "tpm2" or "pkcs11".
	Format string `json:"format"`

	// Backend names the backend that produced the attestation, e.g.
	// "tpm2". Optional; carried through to the result for auditing.
	Backend string `json:"backend,omitempty"`

	// ChainPEM is the attesting key's certificate chain, leaf first. The
	// leaf's public key is the attesting key that signed the statement.
	ChainPEM [][]byte `json:"chain_pem"`

	// AttestedKeyDER is the PKIX DER encoding of the public key that was
	// attested.
	AttestedKeyDER []byte `json:"attested_key_der"`

	// AttestationData is the format-specific evidence the signature covers
	// (for TPM 2.0, the TPMS_ATTEST structure).
	AttestationData []byte `json:"attestation_data"`

	// Signature is the attesting key's signature over AttestationData.
	Signature []byte `json:"signature"`

	// SignatureAlgorithm names the x509 signature algorithm, e.g.
	// "ECDSA-SHA256". Empty means infer it from the leaf certificate.
	SignatureAlgorithm string `json:"signature_algorithm,omitempty"`

	// Nonce is the challenge the attestation was bound to.
	Nonce []byte `json:"nonce,omitempty"`

	// CreatedAt is the RFC 3339 timestamp the attestation was produced at.
	// Required when Options.CheckFreshness is set.
	CreatedAt string `json:"created_at,omitempty"`

	// PCRs holds the attested PCR values keyed by index.
	PCRs map[uint32][]byte `json:"pcrs,omitempty"`

	// Options configures the verification. Nil selects secure defaults
	// (freshness checked, self-signed chains rejected).
	Options *VerifyAttestationOptions `json:"options,omitempty"`
}

// VerifyAttestationOptions is the wire-portable form of the xkms
// attestation VerifyOptions.
type VerifyAttestationOptions struct {
	// TrustedRootsPEM are additional PEM-encoded trust anchors to accept
	// for this call, on top of any configured on the service.
	TrustedRootsPEM [][]byte `json:"trusted_roots_pem,omitempty"`

	// CheckFreshness enables the nonce and timestamp freshness check.
	CheckFreshness bool `json:"check_freshness,omitempty"`

	// ExpectedNonce is the nonce the verifier requires the attestation to
	// carry. Only consulted when CheckFreshness is set.
	ExpectedNonce []byte `json:"expected_nonce,omitempty"`

	// FreshnessWindowSeconds is the maximum acceptable age of the
	// attestation. Zero selects the xkms default of 300 seconds.
	FreshnessWindowSeconds int64 `json:"freshness_window_seconds,omitempty"`

	// VerifyPCRs enables PCR comparison against ExpectedPCRs.
	VerifyPCRs bool `json:"verify_pcrs,omitempty"`

	// ExpectedPCRs are the golden PCR values, keyed by index.
	ExpectedPCRs map[uint32][]byte `json:"expected_pcrs,omitempty"`

	// AllowSelfSigned permits a self-signed attesting certificate. Lab and
	// simulator use only — a self-signed attestation proves nothing about
	// hardware provenance.
	AllowSelfSigned bool `json:"allow_self_signed,omitempty"`
}

// VerifyAttestationResponse reports the outcome of a verification. Valid is
// authoritative; the component flags exist so a caller can report WHY a
// verification failed without parsing an error string.
type VerifyAttestationResponse struct {
	Valid          bool   `json:"valid"`
	Format         string `json:"format,omitempty"`
	Backend        string `json:"backend,omitempty"`
	ChainValid     bool   `json:"chain_valid"`
	SignatureValid bool   `json:"signature_valid"`
	FreshnessValid bool   `json:"freshness_valid"`
	PCRsValid      bool   `json:"pcrs_valid"`

	// Reason is a human-readable explanation when Valid is false. It is
	// empty on success.
	Reason string `json:"reason,omitempty"`
}

// VerifyAttestationChainRequest carries the certificate chain to validate.
type VerifyAttestationChainRequest struct {
	// Format identifies the attestation format the chain belongs to.
	Format string `json:"format"`

	// ChainPEM is the certificate chain, leaf first.
	ChainPEM [][]byte `json:"chain_pem"`

	// Options configures anchoring and self-signed acceptance.
	Options *VerifyAttestationOptions `json:"options,omitempty"`
}

// VerifyAttestationChainResponse reports whether the chain validated.
type VerifyAttestationChainResponse struct {
	Valid  bool   `json:"valid"`
	Reason string `json:"reason,omitempty"`
}

// AttestContainerRequest describes the container whose execution environment
// is to be attested.
type AttestContainerRequest struct {
	// DeviceID identifies the host the container runs on. Standalone
	// attestors ignore it; a fleet attestor resolves it against a device
	// registry.
	DeviceID string `json:"device_id,omitempty"`

	// ContainerID identifies the running container. Empty attests the host
	// alone, which is what a scheduler does before placing an agent.
	ContainerID string `json:"container_id,omitempty"`

	// Image is the pinned image reference, "repository@sha256:<hex>".
	Image string `json:"image"`

	// ImageDigest is the immutable content digest of the image.
	ImageDigest string `json:"image_digest,omitempty"`

	// TrustLabel is the operator-assigned workload identity.
	TrustLabel string `json:"trust_label,omitempty"`

	// TrustLevel names the required tier: "pinned", "attested" or
	// "measured". Empty defers to the attestor's own policy.
	TrustLevel string `json:"trust_level,omitempty"`

	// ReferenceValues names the stored reference values (PutReferenceValues)
	// the Verifier appraises the host quote against. Required at the
	// "attested" tier and above.
	ReferenceValues string `json:"reference_values,omitempty"`

	// MeasurementPCR is the PCR index carrying the launch measurement for
	// a measured launch. Zero selects the attestor's default.
	MeasurementPCR int `json:"measurement_pcr,omitempty"`

	// MeasurementBank names the PCR bank for the launch measurement.
	MeasurementBank string `json:"measurement_bank,omitempty"`

	// Nonce is caller-supplied qualifying data. Attestors that generate
	// their own nonce echo theirs back in the response.
	Nonce []byte `json:"nonce,omitempty"`
}

// AttestContainerResponse is the attestation evidence produced for a
// container.
type AttestContainerResponse struct {
	Attested          bool              `json:"attested"`
	DeviceID          string            `json:"device_id,omitempty"`
	ContainerID       string            `json:"container_id,omitempty"`
	Image             string            `json:"image,omitempty"`
	ImageDigest       string            `json:"image_digest,omitempty"`
	ConfigDigest      string            `json:"config_digest,omitempty"`
	TrustLabel        string            `json:"trust_label,omitempty"`
	TrustLevel        string            `json:"trust_level,omitempty"`
	Nonce             []byte            `json:"nonce,omitempty"`
	Quoted            []byte            `json:"quoted,omitempty"`
	Signature         []byte            `json:"signature,omitempty"`
	PCRs              map[uint32][]byte `json:"pcrs,omitempty"`
	EventLog          []byte            `json:"event_log,omitempty"`
	Measured          bool              `json:"measured"`
	MeasurementPCR    int               `json:"measurement_pcr,omitempty"`
	MeasurementBank   string            `json:"measurement_bank,omitempty"`
	LaunchMeasurement []byte            `json:"launch_measurement,omitempty"`
	AttestedAt        time.Time         `json:"attested_at"`
}

// =============================================================================
// Typed Errors
// =============================================================================

// Typed sentinel errors for the attestation service.
var (
	ErrAttestationNilRequest    = &errors.QBError{Code: errors.ErrInvalidInput, Op: "AttestationService", Err: errAttestationNilRequest}
	ErrAttestationEmptyChain    = &errors.QBError{Code: errors.ErrInvalidInput, Op: "AttestationService", Err: errAttestationEmptyChain}
	ErrAttestationEmptyFormat   = &errors.QBError{Code: errors.ErrInvalidInput, Op: "AttestationService", Err: errAttestationEmptyFormat}
	ErrAttestationNoSignature   = &errors.QBError{Code: errors.ErrInvalidInput, Op: "AttestationService.Verify", Err: errAttestationNoSignature}
	ErrAttestationNoAttestedKey = &errors.QBError{Code: errors.ErrInvalidInput, Op: "AttestationService.Verify", Err: errAttestationNoAttestedKey}
	ErrAttestationEmptyImage    = &errors.QBError{Code: errors.ErrInvalidInput, Op: "AttestationService.AttestContainer", Err: errAttestationEmptyImage}
	ErrAttestationNoAttestor    = &errors.QBError{Code: errors.ErrUnavailable, Op: "AttestationService.AttestContainer", Err: errAttestationNoAttestor}
)

var (
	errAttestationNilRequest    = stderrors.New("request must not be nil")
	errAttestationEmptyChain    = stderrors.New("certificate chain is required")
	errAttestationEmptyFormat   = stderrors.New("attestation format is required")
	errAttestationNoSignature   = stderrors.New("signature is required")
	errAttestationNoAttestedKey = stderrors.New("attested key is required")
	errAttestationEmptyImage    = stderrors.New("image is required")
	errAttestationNoAttestor    = stderrors.New("no container attestor is registered on this server")
)

// =============================================================================
// Implementation
// =============================================================================

// attestationService is the production AttestationService. It owns an xkms
// verifier configured with the deployment's trust anchors plus an optional
// container attestor.
type attestationService struct {
	verifier *xkmsattestation.Verifier
	attestor ContainerAttestor

	// store holds the Verifier's endorsements and reference values; nil
	// leaves those verbs reporting AttestationStoreUnavailableError.
	store AttestationStore

	// now is the appraisal clock.
	now func() time.Time
}

// AttestationOption configures NewAttestationService.
type AttestationOption func(*attestationService)

// WithAttestationStore gives the service the store its Verifier keeps
// endorsements and reference values in. The server passes the platform
// shard's qrdb KV; an embedder may pass any AttestationStore.
func WithAttestationStore(store AttestationStore) AttestationOption {
	return func(s *attestationService) { s.store = store }
}

// WithAttestationClock sets the clock appraisals and validity windows are
// evaluated at. The default is time.Now.
func WithAttestationClock(now func() time.Time) AttestationOption {
	return func(s *attestationService) { s.now = now }
}

// NewAttestationService creates an AttestationService.
//
// trustAnchors are the roots every verification is anchored against; callers
// may supply additional per-call anchors through the request options. A nil
// attestor is valid — AttestContainer then returns ErrAttestationNoAttestor
// until an application registers one, matching the DANEPublisher contract.
func NewAttestationService(trustAnchors []*x509.Certificate, attestor ContainerAttestor, opts ...AttestationOption) AttestationService {
	s := &attestationService{
		verifier: xkmsattestation.NewVerifier(trustAnchors),
		attestor: attestor,
		now:      time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// NewRuntimeContainerAttestor adapts a standalone attesting container runtime
// into a ContainerAttestor, so a single-node deployment can fill the
// orchestration seam with QuicBaaS's own Tier 1 / Tier 2 implementation and
// needs no fleet manager at all.
//
// Returns nil when rt is nil, so callers can pass an optional runtime through
// without a nil check and get the "not configured" contract for free.
func NewRuntimeContainerAttestor(rt orchestration.AttestingContainerRuntime) ContainerAttestor {
	if rt == nil {
		return nil
	}
	return &runtimeContainerAttestor{rt: rt}
}

// runtimeContainerAttestor bridges the AttestingContainerRuntime seam in
// pkg/orchestration to the ContainerAttestor seam in the service layer.
type runtimeContainerAttestor struct {
	rt orchestration.AttestingContainerRuntime
}

// AttestContainer reconstructs a ContainerSpec from the request and delegates
// to the runtime's Attest.
func (a *runtimeContainerAttestor) AttestContainer(ctx context.Context, req *AttestContainerRequest) (*AttestContainerResponse, error) {
	level, err := orchestration.ParseTrustLevel(req.TrustLevel)
	if err != nil {
		return nil, &errors.QBError{Code: errors.ErrInvalidInput, Op: "AttestationService.AttestContainer", Err: err}
	}
	if level == orchestration.TrustLevelDefault {
		level = orchestration.TrustLevelAttested
	}

	spec := &orchestration.ContainerSpec{
		Image:           req.Image,
		ImageDigest:     req.ImageDigest,
		ReferenceValues: req.ReferenceValues,
		TrustLevel:      level,
		TrustLabel:      req.TrustLabel,
		MeasurementPCR:  req.MeasurementPCR,
		MeasurementBank: req.MeasurementBank,
	}

	evidence, err := a.rt.Attest(ctx, spec, req.ContainerID)
	if err != nil {
		return nil, &errors.QBError{Code: errors.ErrInternal, Op: "AttestationService.AttestContainer", Err: err}
	}

	return &AttestContainerResponse{
		Attested:          true,
		DeviceID:          req.DeviceID,
		ContainerID:       evidence.ContainerID,
		Image:             evidence.Image,
		ImageDigest:       evidence.ImageDigest,
		ConfigDigest:      evidence.ConfigDigest,
		TrustLabel:        evidence.TrustLabel,
		TrustLevel:        evidence.TrustLevel.String(),
		Nonce:             evidence.Nonce,
		Quoted:            evidence.Quoted,
		Signature:         evidence.Signature,
		PCRs:              evidence.PCRs,
		EventLog:          evidence.EventLog,
		Measured:          evidence.Measured,
		MeasurementPCR:    evidence.MeasurementPCR,
		MeasurementBank:   evidence.MeasurementBank,
		LaunchMeasurement: evidence.LaunchMeasurement,
		AttestedAt:        evidence.AttestedAt,
	}, nil
}

// Verify validates a full attestation statement through the xkms verifier.
func (s *attestationService) Verify(ctx context.Context, req *VerifyAttestationRequest) (*VerifyAttestationResponse, error) {
	if req == nil {
		return nil, ErrAttestationNilRequest
	}
	if req.Format == "" {
		return nil, ErrAttestationEmptyFormat
	}
	if len(req.Signature) == 0 {
		return nil, ErrAttestationNoSignature
	}
	if len(req.AttestedKeyDER) == 0 {
		return nil, ErrAttestationNoAttestedKey
	}
	if err := ctx.Err(); err != nil {
		return nil, &errors.QBError{Code: errors.ErrInternal, Op: "AttestationService.Verify", Err: err}
	}

	stmt, err := s.statement(req)
	if err != nil {
		return nil, err
	}

	opts, err := verifyOptions(req.Options)
	if err != nil {
		return nil, err
	}

	// Run the component checks individually so the response can report
	// which stage failed. The xkms Verify performs the same sequence, but
	// short-circuits with a single error and no per-stage detail.
	resp := &VerifyAttestationResponse{Format: req.Format, Backend: req.Backend}

	if err := s.verifyChain(stmt, opts); err != nil {
		resp.Reason = err.Error()
		return resp, nil
	}
	resp.ChainValid = true

	if err := s.verifier.VerifySignature(stmt, opts); err != nil {
		resp.Reason = err.Error()
		return resp, nil
	}
	resp.SignatureValid = true

	// Freshness and PCR checks have no exported single-stage entry point,
	// so the full Verify is used for them. Chain and signature are
	// revalidated inside it; that is cheap relative to a transport hop and
	// keeps QuicBaaS from reimplementing either check.
	if opts.CheckFreshness || opts.VerifyPCRs {
		if err := s.verifier.Verify(stmt, opts); err != nil {
			resp.Reason = err.Error()
			return resp, nil
		}
		resp.FreshnessValid = opts.CheckFreshness
		resp.PCRsValid = opts.VerifyPCRs
	}

	resp.Valid = true
	return resp, nil
}

// VerifyChain validates only the certificate chain of an attestation.
func (s *attestationService) VerifyChain(ctx context.Context, req *VerifyAttestationChainRequest) (*VerifyAttestationChainResponse, error) {
	if req == nil {
		return nil, ErrAttestationNilRequest
	}
	if len(req.ChainPEM) == 0 {
		return nil, ErrAttestationEmptyChain
	}
	if err := ctx.Err(); err != nil {
		return nil, &errors.QBError{Code: errors.ErrInternal, Op: "AttestationService.VerifyChain", Err: err}
	}

	chain, err := parseCertChainPEM(req.ChainPEM, "AttestationService.VerifyChain")
	if err != nil {
		return nil, err
	}

	opts, err := verifyOptions(req.Options)
	if err != nil {
		return nil, err
	}

	format := req.Format
	if format == "" {
		format = "unknown"
	}

	// VerifyChain reads only Format and CertificateChain from the
	// statement, so a minimal one is sufficient and avoids demanding
	// signature material a chain check does not use.
	stmt := &xkmsattestation.AttestationStatement{
		Format:           format,
		CertificateChain: chain,
	}

	if err := s.verifyChain(stmt, opts); err != nil {
		return &VerifyAttestationChainResponse{Valid: false, Reason: err.Error()}, nil
	}
	return &VerifyAttestationChainResponse{Valid: true}, nil
}

// verifyChain runs the chain check at the strength the options ask for.
//
// go-xkms offers two entry points and the difference is the whole security
// property: VerifyChain performs structural validation only when no trust
// anchor is configured, which proves nothing — the entire chain is
// caller-supplied. VerifyChainAnchored fails closed with ErrNoTrustAnchors
// instead.
//
// QuicBaaS therefore defaults to the anchored form and only drops to the
// structural one when the caller explicitly sets AllowSelfSigned, which is
// documented as lab and simulator use. A deployment that has configured no
// anchors and asked for no exception gets a refusal rather than a
// meaningless pass.
func (s *attestationService) verifyChain(stmt *xkmsattestation.AttestationStatement, opts *xkmsattestation.VerifyOptions) error {
	if opts != nil && opts.AllowSelfSigned {
		return s.verifier.VerifyChain(stmt, opts)
	}
	return s.verifier.VerifyChainAnchored(stmt, opts)
}

// AttestContainer forwards to the registered ContainerAttestor.
func (s *attestationService) AttestContainer(ctx context.Context, req *AttestContainerRequest) (*AttestContainerResponse, error) {
	if req == nil {
		return nil, ErrAttestationNilRequest
	}
	if req.Image == "" {
		return nil, ErrAttestationEmptyImage
	}
	if err := ctx.Err(); err != nil {
		return nil, &errors.QBError{Code: errors.ErrInternal, Op: "AttestationService.AttestContainer", Err: err}
	}

	// A nil attestor means no application registered an orchestration
	// hook: the typed "not configured" contract, distinct from an
	// attestation failure.
	if s.attestor == nil {
		return nil, ErrAttestationNoAttestor
	}

	resp, err := s.attestor.AttestContainer(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, &errors.QBError{
			Code: errors.ErrInternal,
			Op:   "AttestationService.AttestContainer",
			Err:  stderrors.New("attestor returned no evidence"),
		}
	}
	return resp, nil
}

// statement reconstructs the xkms AttestationStatement from wire-portable
// request material.
func (s *attestationService) statement(req *VerifyAttestationRequest) (*xkmsattestation.AttestationStatement, error) {
	chain, err := parseCertChainPEM(req.ChainPEM, "AttestationService.Verify")
	if err != nil {
		return nil, err
	}

	attestedKey, err := x509.ParsePKIXPublicKey(req.AttestedKeyDER)
	if err != nil {
		return nil, &errors.QBError{Code: errors.ErrInvalidInput, Op: "AttestationService.Verify", Err: err}
	}

	leaf := chain[0]
	sigAlg := leaf.SignatureAlgorithm
	if req.SignatureAlgorithm != "" {
		parsed, ok := signatureAlgorithmByName[req.SignatureAlgorithm]
		if !ok {
			return nil, &errors.QBError{
				Code: errors.ErrInvalidInput,
				Op:   "AttestationService.Verify",
				Err:  stderrors.New("unsupported signature algorithm: " + req.SignatureAlgorithm),
			}
		}
		sigAlg = parsed
	}

	return &xkmsattestation.AttestationStatement{
		Format:                req.Format,
		Backend:               req.Backend,
		AttestingKeyAlgorithm: leaf.PublicKeyAlgorithm,
		AttestingKeyPublic:    leaf.PublicKey,
		Signature:             req.Signature,
		SignatureAlgorithm:    sigAlg,
		CertificateChain:      chain,
		AttestedKeyPublic:     attestedKey,
		AttestationData:       req.AttestationData,
		CreatedAt:             req.CreatedAt,
		Nonce:                 req.Nonce,
		PCRValues:             req.PCRs,
	}, nil
}

// signatureAlgorithmByName maps the canonical x509.SignatureAlgorithm string
// form back to its enum value, giving O(1) lookup instead of a linear scan
// over every algorithm.
var signatureAlgorithmByName = buildSignatureAlgorithmIndex()

// buildSignatureAlgorithmIndex derives the name index from x509's own String
// method, so the mapping cannot drift from the standard library's naming.
func buildSignatureAlgorithmIndex() map[string]x509.SignatureAlgorithm {
	algorithms := []x509.SignatureAlgorithm{
		x509.MD2WithRSA, x509.MD5WithRSA,
		x509.SHA1WithRSA, x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.DSAWithSHA1, x509.DSAWithSHA256,
		x509.ECDSAWithSHA1, x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512,
		x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS,
		x509.PureEd25519,
	}
	index := make(map[string]x509.SignatureAlgorithm, len(algorithms))
	for _, alg := range algorithms {
		index[alg.String()] = alg
	}
	return index
}

// verifyOptions converts the wire options into xkms VerifyOptions, applying
// the secure defaults when none were supplied.
func verifyOptions(opts *VerifyAttestationOptions) (*xkmsattestation.VerifyOptions, error) {
	if opts == nil {
		return xkmsattestation.DefaultVerifyOptions(), nil
	}

	var roots []*x509.Certificate
	if len(opts.TrustedRootsPEM) > 0 {
		parsed, err := parseCertChainPEM(opts.TrustedRootsPEM, "AttestationService.verifyOptions")
		if err != nil {
			return nil, err
		}
		roots = parsed
	}

	return &xkmsattestation.VerifyOptions{
		TrustedRoots:    roots,
		CheckFreshness:  opts.CheckFreshness,
		ExpectedNonce:   opts.ExpectedNonce,
		FreshnessWindow: opts.FreshnessWindowSeconds,
		VerifyPCRs:      opts.VerifyPCRs,
		ExpectedPCRs:    opts.ExpectedPCRs,
		AllowSelfSigned: opts.AllowSelfSigned,
	}, nil
}

// parseCertChainPEM decodes a slice of PEM (or bare DER) certificate blobs
// into x509 certificates, preserving order.
func parseCertChainPEM(chainPEM [][]byte, op string) ([]*x509.Certificate, error) {
	if len(chainPEM) == 0 {
		return nil, ErrAttestationEmptyChain
	}

	chain := make([]*x509.Certificate, 0, len(chainPEM))
	for _, blob := range chainPEM {
		if len(blob) == 0 {
			return nil, &errors.QBError{
				Code: errors.ErrInvalidInput,
				Op:   op,
				Err:  stderrors.New("certificate chain entry is empty"),
			}
		}
		der := blob
		if block, _ := pem.Decode(blob); block != nil {
			der = block.Bytes
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, &errors.QBError{Code: errors.ErrInvalidInput, Op: op, Err: err}
		}
		chain = append(chain, cert)
	}
	return chain, nil
}
