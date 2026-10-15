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
	"crypto"
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	stderrors "errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-tpm/tpm2"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/evidence"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/refvalue"

	"github.com/jeremyhahn/go-quicbaas/pkg/errors"
	"github.com/jeremyhahn/go-quicbaas/pkg/tenantctx"
)

// This file is the attestation Verifier of RFC 9334 (handbook doc 00 §R:
// "appraisal, the reference-value and endorsement store, attestation
// results"). go-xkms owns the evidence-level primitives — quote, AK
// certificate, event log and signed-CoRIM checks — and this layer composes
// them into an appraisal against stored, signed reference values.
//
// Reference values are accepted ONLY as a signed CoRIM that verifies against
// an endorsement the tenant stored beforehand. There is no trust on first use:
// a device's own report never becomes its baseline. The signature is checked
// again at every appraisal, so deleting a signer's endorsement withdraws every
// baseline it signed.

// EndorsementKind names what an endorsement anchors.
type EndorsementKind string

const (
	// EndorsementReferenceSigner anchors reference values: a CA certificate
	// under which signed CoRIM signers chain (via the COSE x5chain header),
	// or a pinned public key the COSE signature must verify under.
	EndorsementReferenceSigner EndorsementKind = "reference-signer"

	// EndorsementAKRoot anchors attestation-key certificates: a CA
	// certificate the AK certificate must chain to.
	EndorsementAKRoot EndorsementKind = "ak-root"
)

// endorsementKinds is the closed set of kinds.
var endorsementKinds = map[EndorsementKind]bool{
	EndorsementReferenceSigner: true,
	EndorsementAKRoot:          true,
}

// Appraisal check names.
const (
	AppraisalCheckAKCertificate = "ak-certificate"
	AppraisalCheckQuote         = "quote"
	AppraisalCheckEventLog      = "event-log"
	AppraisalCheckBaseline      = "baseline"
)

// AppraisalOutcome is one check's result.
type AppraisalOutcome string

const (
	// AppraisalPass reports evidence that was present and verified.
	AppraisalPass AppraisalOutcome = "pass"

	// AppraisalForged reports evidence that was present and is wrong: the
	// grounds for treating the attester as compromised.
	AppraisalForged AppraisalOutcome = "forged"

	// AppraisalAbsent reports a check that could not run: evidence or a
	// trust anchor or a reference is missing. Nothing was proven wrong.
	AppraisalAbsent AppraisalOutcome = "absent"

	// AppraisalSkipped reports optional evidence the attester did not send.
	AppraisalSkipped AppraisalOutcome = "skipped"
)

// BaselineSourceSigned is the only baseline source the Verifier has: signed
// reference values.
const BaselineSourceSigned = "signed"

// Endorsement is a stored trust anchor.
type Endorsement struct {
	Name           string          `json:"name"`
	Kind           EndorsementKind `json:"kind"`
	CertificatePEM []byte          `json:"certificate_pem,omitempty"`
	PublicKeyPEM   []byte          `json:"public_key_pem,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
}

// PutEndorsementRequest stores (or replaces) an endorsement. Exactly one of
// CertificatePEM and PublicKeyPEM is set; an ak-root needs a certificate.
type PutEndorsementRequest struct {
	Name           string          `json:"name"`
	Kind           EndorsementKind `json:"kind"`
	CertificatePEM []byte          `json:"certificate_pem,omitempty"`
	PublicKeyPEM   []byte          `json:"public_key_pem,omitempty"`
}

// ListEndorsementsRequest filters endorsements by kind; empty lists all.
type ListEndorsementsRequest struct {
	Kind EndorsementKind `json:"kind,omitempty"`
}

// ListEndorsementsResponse lists endorsements, ordered by name.
type ListEndorsementsResponse struct {
	Endorsements []*Endorsement `json:"endorsements"`
}

// DeleteEndorsementRequest removes an endorsement.
type DeleteEndorsementRequest struct {
	Name string `json:"name"`
}

// ReferenceValues describes a stored, verified signed CoRIM.
type ReferenceValues struct {
	Name       string    `json:"name"`
	ManifestID string    `json:"manifest_id"`
	Profile    string    `json:"profile,omitempty"`
	Signer     string    `json:"signer,omitempty"`
	NotBefore  time.Time `json:"not_before,omitzero"`
	NotAfter   time.Time `json:"not_after,omitzero"`
	// PCRIndices are the PCR indices the reference values cover, ascending.
	PCRIndices []uint32  `json:"pcr_indices"`
	StoredAt   time.Time `json:"stored_at"`
	// SignedCoRIM is the COSE_Sign1 signed CoRIM as stored.
	SignedCoRIM []byte `json:"signed_corim,omitempty"`
}

// PutReferenceValuesRequest stores (or replaces) reference values. The
// signed CoRIM must verify against a stored reference-signer endorsement.
type PutReferenceValuesRequest struct {
	Name        string `json:"name"`
	SignedCoRIM []byte `json:"signed_corim"`
}

// GetReferenceValuesRequest names stored reference values.
type GetReferenceValuesRequest struct {
	Name string `json:"name"`
}

// ListReferenceValuesResponse lists stored reference values (without the
// signed CoRIM bodies), ordered by name.
type ListReferenceValuesResponse struct {
	ReferenceValues []*ReferenceValues `json:"reference_values"`
}

// DeleteReferenceValuesRequest removes stored reference values.
type DeleteReferenceValuesRequest struct {
	Name string `json:"name"`
}

// AppraiseQuoteRequest is TPM quote evidence plus the reference values to
// appraise it against.
type AppraiseQuoteRequest struct {
	// AKCertificatePEM is the attestation-key certificate, leaf first, with
	// any intermediates after it.
	AKCertificatePEM []byte `json:"ak_certificate_pem"`

	// Quote is the marshaled TPMS_ATTEST.
	Quote []byte `json:"quote"`

	// Signature is the attestation key's signature over Quote.
	Signature []byte `json:"signature"`

	// Nonce is the verifier-issued qualifying data the quote must carry.
	Nonce []byte `json:"nonce"`

	// PCRs are the values the attester read for the quoted selection.
	PCRs map[uint32][]byte `json:"pcrs"`

	// EventLog is the TCG crypto-agile event log. Optional.
	EventLog []byte `json:"event_log,omitempty"`

	// ReferenceValues names the stored reference values to compare against.
	ReferenceValues string `json:"reference_values"`
}

// AppraisalCheck is one check of an appraisal.
type AppraisalCheck struct {
	Name    string           `json:"name"`
	Outcome AppraisalOutcome `json:"outcome"`
	Reason  string           `json:"reason,omitempty"`
}

// AttestationResult is the Verifier's attestation result for one appraisal.
type AttestationResult struct {
	// Verified is true only when every check that ran passed and none was
	// absent.
	Verified bool `json:"verified"`

	// CryptographicFailure is true when a check found evidence that was
	// present and wrong — the grounds for quarantine, as opposed to missing
	// evidence, which is grounds only for denying service.
	CryptographicFailure bool `json:"cryptographic_failure"`

	// Checks report each check's outcome, in evaluation order.
	Checks []AppraisalCheck `json:"checks"`

	// ReferenceValues, ManifestID and Signer identify the baseline used.
	ReferenceValues string `json:"reference_values,omitempty"`
	ManifestID      string `json:"manifest_id,omitempty"`
	Signer          string `json:"signer,omitempty"`

	// BaselineSource is always BaselineSourceSigned when a baseline was
	// evaluated.
	BaselineSource string `json:"baseline_source,omitempty"`

	// AppraisedAt is when the appraisal ran.
	AppraisedAt time.Time `json:"appraised_at"`
}

// =============================================================================
// Typed errors
// =============================================================================

// AttestationNameError reports an invalid endorsement or reference-value name.
type AttestationNameError struct {
	Name string
}

// Error returns a human-readable description.
func (e *AttestationNameError) Error() string {
	return "attestation: name " + strconv.Quote(e.Name) + " must be 1-253 bytes without '/'"
}

// EndorsementInvalidError reports an endorsement that cannot be stored.
type EndorsementInvalidError struct {
	Reason string
}

// Error returns a human-readable description.
func (e *EndorsementInvalidError) Error() string {
	return "attestation: invalid endorsement: " + e.Reason
}

// AttestationRecordNotFoundError reports a missing endorsement or reference
// values.
type AttestationRecordNotFoundError struct {
	Kind string
	Name string
}

// Error returns a human-readable description.
func (e *AttestationRecordNotFoundError) Error() string {
	return "attestation: " + e.Kind + " " + strconv.Quote(e.Name) + " not found"
}

// ReferenceValuesRejectedError reports a signed CoRIM that no stored
// reference-signer endorsement verifies.
type ReferenceValuesRejectedError struct {
	Reason string
	Cause  error
}

// Error returns a human-readable description.
func (e *ReferenceValuesRejectedError) Error() string {
	return "attestation: reference values rejected: " + e.Reason
}

// Unwrap returns the verification failure.
func (e *ReferenceValuesRejectedError) Unwrap() error { return e.Cause }

// AttestationStoreUnavailableError reports a Verifier with no store.
type AttestationStoreUnavailableError struct{}

// Error returns a human-readable description.
func (e *AttestationStoreUnavailableError) Error() string {
	return "attestation: the reference-value and endorsement store is not available"
}

// =============================================================================
// Store
// =============================================================================

// AttestationStore is the persistence seam of the Verifier: opaque records
// under string keys. The production store is the platform shard's qrdb KV;
// tests supply an in-memory map.
type AttestationStore interface {
	// Put writes a record.
	Put(ctx context.Context, key string, value []byte) error

	// Get reads a record; found is false when the key does not exist.
	Get(ctx context.Context, key string) (value []byte, found bool, err error)

	// Scan returns every record under a prefix.
	Scan(ctx context.Context, prefix string) (map[string][]byte, error)

	// Delete removes a record.
	Delete(ctx context.Context, key string) error
}

// qrdbAttestationStore stores Verifier records in qrdb KV.
//
// Raw KV is the sanctioned form here (handbook conventions/data-access.md §3
// case 3): every record is an opaque blob — a certificate, a public key or a
// signed CoRIM — with no fields to index and an externally chosen name.
type qrdbAttestationStore struct {
	client func() (*qrdbsdk.Client, error)
}

// NewQRDBAttestationStore returns an AttestationStore over a qrdb client
// resolver.
func NewQRDBAttestationStore(client func() (*qrdbsdk.Client, error)) AttestationStore {
	return &qrdbAttestationStore{client: client}
}

func (s *qrdbAttestationStore) Put(ctx context.Context, key string, value []byte) error {
	c, err := s.client()
	if err != nil {
		return err
	}
	return c.KV().Put(ctx, key, value)
}

func (s *qrdbAttestationStore) Get(ctx context.Context, key string) ([]byte, bool, error) {
	c, err := s.client()
	if err != nil {
		return nil, false, err
	}
	value, err := c.KV().Get(ctx, key)
	if err != nil {
		var missing *qrdbtransport.KeyNotFoundError
		if stderrors.As(err, &missing) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return value, true, nil
}

func (s *qrdbAttestationStore) Scan(ctx context.Context, prefix string) (map[string][]byte, error) {
	c, err := s.client()
	if err != nil {
		return nil, err
	}
	return c.KV().Scan(ctx, prefix)
}

func (s *qrdbAttestationStore) Delete(ctx context.Context, key string) error {
	c, err := s.client()
	if err != nil {
		return err
	}
	return c.KV().Delete(ctx, key)
}

// attestationShardID is the qrdb shard the Verifier's records live on: the
// platform shard every other system-namespace record uses.
const attestationShardID = 1

const (
	attestationKeyPrefix       = "__sys:attest/"
	attestationTenantKeyPrefix = "__sys:attest-t/"
	endorsementSegment         = "endorsement/"
	referenceValuesSegment     = "refval/"
	maxAttestationNameLen      = 253
)

// attestationPrefix returns the request tenant's record prefix for a segment.
// The tenant is the authenticated one (prepareTenantContext, which refuses a
// request with none); the system tenant, bound explicitly, owns the unscoped
// prefix.
func attestationPrefix(ctx context.Context, segment string) (string, error) {
	tenant, err := prepareTenantContext(ctx)
	if err != nil {
		return "", err
	}
	if tenant == "" {
		return attestationKeyPrefix + segment, nil
	}
	return attestationTenantKeyPrefix + tenant + "/" + segment, nil
}

// validateAttestationName rejects names that could escape their prefix.
func validateAttestationName(name string) error {
	if name == "" || len(name) > maxAttestationNameLen || strings.ContainsRune(name, '/') {
		return &AttestationNameError{Name: name}
	}
	return nil
}

// =============================================================================
// Verifier
// =============================================================================

// verifierError wraps a Verifier failure with its transport status code.
//
// A tenant refusal (pkg/tenantctx) keeps its own ErrForbidden code: a caller
// with no tenant, or naming another, is refused, not told the store failed.
func verifierError(op string, code errors.ErrorCode, err error) error {
	var missing *tenantctx.MissingTenantError
	var cross *tenantctx.CrossTenantError
	if stderrors.As(err, &missing) || stderrors.As(err, &cross) {
		return err
	}
	return &errors.QBError{Code: code, Op: op, Err: err}
}

// store returns the Verifier store or the typed unavailable error.
func (s *attestationService) verifierStore(op string) (AttestationStore, error) {
	if s.store == nil {
		return nil, verifierError(op, errors.ErrUnavailable, &AttestationStoreUnavailableError{})
	}
	return s.store, nil
}

// PutEndorsement stores (or replaces) an endorsement.
func (s *attestationService) PutEndorsement(ctx context.Context, req *PutEndorsementRequest) (*Endorsement, error) {
	const op = "AttestationService.PutEndorsement"
	if req == nil {
		return nil, ErrAttestationNilRequest
	}
	if err := validateAttestationName(req.Name); err != nil {
		return nil, verifierError(op, errors.ErrInvalidInput, err)
	}
	if err := validateEndorsement(req); err != nil {
		return nil, verifierError(op, errors.ErrInvalidInput, err)
	}
	store, err := s.verifierStore(op)
	if err != nil {
		return nil, err
	}
	endorsement := &Endorsement{
		Name:           req.Name,
		Kind:           req.Kind,
		CertificatePEM: req.CertificatePEM,
		PublicKeyPEM:   req.PublicKeyPEM,
		CreatedAt:      s.now().UTC(),
	}
	data, err := json.Marshal(endorsement)
	if err != nil {
		return nil, verifierError(op, errors.ErrInternal, err)
	}
	prefix, err := attestationPrefix(ctx, endorsementSegment)
	if err != nil {
		return nil, err
	}
	if err := store.Put(ctx, prefix+req.Name, data); err != nil {
		return nil, verifierError(op, errors.ErrUnavailable, err)
	}
	return endorsement, nil
}

// validateEndorsement checks the kind and that the anchor material parses.
func validateEndorsement(req *PutEndorsementRequest) error {
	if !endorsementKinds[req.Kind] {
		return &EndorsementInvalidError{Reason: "kind must be reference-signer or ak-root"}
	}
	hasCert, hasKey := len(req.CertificatePEM) > 0, len(req.PublicKeyPEM) > 0
	if hasCert == hasKey {
		return &EndorsementInvalidError{Reason: "exactly one of certificate_pem and public_key_pem is required"}
	}
	if req.Kind == EndorsementAKRoot && !hasCert {
		return &EndorsementInvalidError{Reason: "an ak-root endorsement is a CA certificate"}
	}
	if hasCert {
		cert, err := parseCertificatePEM(req.CertificatePEM)
		if err != nil {
			return &EndorsementInvalidError{Reason: "certificate: " + err.Error()}
		}
		if !cert.IsCA {
			return &EndorsementInvalidError{Reason: "certificate is not a CA certificate"}
		}
		return nil
	}
	if _, err := parsePublicKeyPEM(req.PublicKeyPEM); err != nil {
		return &EndorsementInvalidError{Reason: "public key: " + err.Error()}
	}
	return nil
}

// ListEndorsements lists the tenant's endorsements.
func (s *attestationService) ListEndorsements(ctx context.Context, req *ListEndorsementsRequest) (*ListEndorsementsResponse, error) {
	const op = "AttestationService.ListEndorsements"
	if req == nil {
		req = &ListEndorsementsRequest{}
	}
	store, err := s.verifierStore(op)
	if err != nil {
		return nil, err
	}
	endorsements, err := s.loadEndorsements(ctx, store, req.Kind)
	if err != nil {
		return nil, verifierError(op, errors.ErrUnavailable, err)
	}
	return &ListEndorsementsResponse{Endorsements: endorsements}, nil
}

// loadEndorsements reads the tenant's endorsements, optionally of one kind.
func (s *attestationService) loadEndorsements(ctx context.Context, store AttestationStore, kind EndorsementKind) ([]*Endorsement, error) {
	prefix, err := attestationPrefix(ctx, endorsementSegment)
	if err != nil {
		return nil, err
	}
	records, err := store.Scan(ctx, prefix)
	if err != nil {
		return nil, err
	}
	out := make([]*Endorsement, 0, len(records))
	for _, data := range records {
		var e Endorsement
		if err := json.Unmarshal(data, &e); err != nil {
			continue
		}
		if kind == "" || e.Kind == kind {
			out = append(out, &e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// DeleteEndorsement removes an endorsement.
func (s *attestationService) DeleteEndorsement(ctx context.Context, req *DeleteEndorsementRequest) error {
	const op = "AttestationService.DeleteEndorsement"
	if req == nil {
		return ErrAttestationNilRequest
	}
	return s.deleteRecord(ctx, op, endorsementSegment, "endorsement", req.Name)
}

// deleteRecord removes a named record, reporting a missing one as not found.
func (s *attestationService) deleteRecord(ctx context.Context, op, segment, kind, name string) error {
	if err := validateAttestationName(name); err != nil {
		return verifierError(op, errors.ErrInvalidInput, err)
	}
	store, err := s.verifierStore(op)
	if err != nil {
		return err
	}
	prefix, err := attestationPrefix(ctx, segment)
	if err != nil {
		return err
	}
	key := prefix + name
	_, found, err := store.Get(ctx, key)
	if err != nil {
		return verifierError(op, errors.ErrUnavailable, err)
	}
	if !found {
		return verifierError(op, errors.ErrNotFound, &AttestationRecordNotFoundError{Kind: kind, Name: name})
	}
	if err := store.Delete(ctx, key); err != nil {
		return verifierError(op, errors.ErrUnavailable, err)
	}
	return nil
}

// PutReferenceValues verifies a signed CoRIM against the tenant's
// reference-signer endorsements and stores it.
func (s *attestationService) PutReferenceValues(ctx context.Context, req *PutReferenceValuesRequest) (*ReferenceValues, error) {
	const op = "AttestationService.PutReferenceValues"
	if req == nil {
		return nil, ErrAttestationNilRequest
	}
	if err := validateAttestationName(req.Name); err != nil {
		return nil, verifierError(op, errors.ErrInvalidInput, err)
	}
	if len(req.SignedCoRIM) == 0 {
		return nil, verifierError(op, errors.ErrInvalidInput, &ReferenceValuesRejectedError{Reason: "signed_corim is required"})
	}
	store, err := s.verifierStore(op)
	if err != nil {
		return nil, err
	}
	manifest, err := s.verifyCoRIM(ctx, store, req.SignedCoRIM)
	if err != nil {
		return nil, verifierError(op, errors.ErrInvalidInput, err)
	}
	record, err := referenceValuesRecord(req.Name, req.SignedCoRIM, manifest, s.now().UTC())
	if err != nil {
		return nil, verifierError(op, errors.ErrInvalidInput, err)
	}
	data, err := json.Marshal(record)
	if err != nil {
		return nil, verifierError(op, errors.ErrInternal, err)
	}
	prefix, err := attestationPrefix(ctx, referenceValuesSegment)
	if err != nil {
		return nil, err
	}
	if err := store.Put(ctx, prefix+req.Name, data); err != nil {
		return nil, verifierError(op, errors.ErrUnavailable, err)
	}
	return record, nil
}

// verifyCoRIM verifies a signed CoRIM against the tenant's reference-signer
// endorsements: CA certificates as the x5chain roots, then each pinned key.
func (s *attestationService) verifyCoRIM(ctx context.Context, store AttestationStore, signed []byte) (*refvalue.Manifest, error) {
	signers, err := s.loadEndorsements(ctx, store, EndorsementReferenceSigner)
	if err != nil {
		return nil, err
	}
	if len(signers) == 0 {
		return nil, &ReferenceValuesRejectedError{Reason: "no reference-signer endorsement is stored; reference values are never trusted on first use"}
	}
	now := s.now()
	var failures []error
	roots := x509.NewCertPool()
	haveRoots := false
	for _, signer := range signers {
		if len(signer.CertificatePEM) == 0 {
			continue
		}
		cert, err := parseCertificatePEM(signer.CertificatePEM)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		roots.AddCert(cert)
		haveRoots = true
	}
	if haveRoots {
		manifest, err := refvalue.VerifySigned(signed, refvalue.VerifyOptions{Roots: roots, Now: now})
		if err == nil {
			return manifest, nil
		}
		failures = append(failures, err)
	}
	for _, signer := range signers {
		if len(signer.PublicKeyPEM) == 0 {
			continue
		}
		key, err := parsePublicKeyPEM(signer.PublicKeyPEM)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		manifest, err := refvalue.VerifySigned(signed, refvalue.VerifyOptions{PublicKey: key, Now: now})
		if err == nil {
			return manifest, nil
		}
		failures = append(failures, err)
	}
	cause := stderrors.Join(failures...)
	reason := "no reference-signer endorsement verifies the signed CoRIM"
	if cause != nil {
		reason += ": " + cause.Error()
	}
	return nil, &ReferenceValuesRejectedError{Reason: reason, Cause: cause}
}

// referenceBanks are the PCR banks reference values may cover. SHA-1 is not
// one: a SHA-1 bank is never appraised.
var referenceBanks = []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512}

// referenceValuesRecord builds the stored record of a verified CoRIM.
func referenceValuesRecord(name string, signed []byte, manifest *refvalue.Manifest, storedAt time.Time) (*ReferenceValues, error) {
	indices := map[uint32]bool{}
	for _, hash := range referenceBanks {
		digests, err := manifest.PCRDigests(hash)
		if err != nil {
			return nil, &ReferenceValuesRejectedError{Reason: err.Error(), Cause: err}
		}
		for idx := range digests {
			indices[uint32(idx)] = true // #nosec G115 -- PCRDigests bounds idx to 0..23
		}
	}
	if len(indices) == 0 {
		return nil, &ReferenceValuesRejectedError{Reason: "the CoRIM carries no PCR reference values"}
	}
	pcrs := make([]uint32, 0, len(indices))
	for idx := range indices {
		pcrs = append(pcrs, idx)
	}
	sort.Slice(pcrs, func(i, j int) bool { return pcrs[i] < pcrs[j] })
	return &ReferenceValues{
		Name:        name,
		ManifestID:  manifest.ID,
		Profile:     manifest.Profile,
		Signer:      manifest.Signer,
		NotBefore:   manifest.NotBefore.UTC(),
		NotAfter:    manifest.NotAfter.UTC(),
		PCRIndices:  pcrs,
		StoredAt:    storedAt,
		SignedCoRIM: signed,
	}, nil
}

// GetReferenceValues returns stored reference values, with the signed CoRIM.
func (s *attestationService) GetReferenceValues(ctx context.Context, req *GetReferenceValuesRequest) (*ReferenceValues, error) {
	const op = "AttestationService.GetReferenceValues"
	if req == nil {
		return nil, ErrAttestationNilRequest
	}
	if err := validateAttestationName(req.Name); err != nil {
		return nil, verifierError(op, errors.ErrInvalidInput, err)
	}
	store, err := s.verifierStore(op)
	if err != nil {
		return nil, err
	}
	record, err := s.loadReferenceValues(ctx, store, req.Name)
	if err != nil {
		return nil, verifierError(op, referenceValuesLoadCode(err), err)
	}
	return record, nil
}

// referenceValuesLoadCode maps a load failure to its status code.
func referenceValuesLoadCode(err error) errors.ErrorCode {
	var missing *AttestationRecordNotFoundError
	if stderrors.As(err, &missing) {
		return errors.ErrNotFound
	}
	return errors.ErrUnavailable
}

// loadReferenceValues reads one stored record.
func (s *attestationService) loadReferenceValues(ctx context.Context, store AttestationStore, name string) (*ReferenceValues, error) {
	prefix, err := attestationPrefix(ctx, referenceValuesSegment)
	if err != nil {
		return nil, err
	}
	data, found, err := store.Get(ctx, prefix+name)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, &AttestationRecordNotFoundError{Kind: "reference values", Name: name}
	}
	var record ReferenceValues
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}
	return &record, nil
}

// ListReferenceValues lists stored reference values without their bodies.
func (s *attestationService) ListReferenceValues(ctx context.Context) (*ListReferenceValuesResponse, error) {
	const op = "AttestationService.ListReferenceValues"
	store, err := s.verifierStore(op)
	if err != nil {
		return nil, err
	}
	prefix, err := attestationPrefix(ctx, referenceValuesSegment)
	if err != nil {
		return nil, err
	}
	records, err := store.Scan(ctx, prefix)
	if err != nil {
		return nil, verifierError(op, errors.ErrUnavailable, err)
	}
	out := make([]*ReferenceValues, 0, len(records))
	for _, data := range records {
		var record ReferenceValues
		if err := json.Unmarshal(data, &record); err != nil {
			continue
		}
		record.SignedCoRIM = nil
		out = append(out, &record)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return &ListReferenceValuesResponse{ReferenceValues: out}, nil
}

// DeleteReferenceValues removes stored reference values.
func (s *attestationService) DeleteReferenceValues(ctx context.Context, req *DeleteReferenceValuesRequest) error {
	const op = "AttestationService.DeleteReferenceValues"
	if req == nil {
		return ErrAttestationNilRequest
	}
	return s.deleteRecord(ctx, op, referenceValuesSegment, "reference values", req.Name)
}

// AppraiseQuote appraises TPM quote evidence against stored, signed
// reference values and returns the attestation result. It returns an error
// only when the request is unusable or the store is unreachable; evidence that
// fails appraisal is a successful call whose result says Verified=false.
func (s *attestationService) AppraiseQuote(ctx context.Context, req *AppraiseQuoteRequest) (*AttestationResult, error) {
	result, _, err := s.appraiseQuote(ctx, req, nil)
	return result, err
}

// appraiseQuote is AppraiseQuote, also returning the PCRs the baseline found
// divergent, which a host appraiser reports in detail. launchPCRs are quoted
// registers extended at container launch: the event-log replay leaves them
// to the baseline.
func (s *attestationService) appraiseQuote(ctx context.Context, req *AppraiseQuoteRequest, launchPCRs []uint32) (*AttestationResult, []pcrDivergence, error) {
	const op = "AttestationService.AppraiseQuote"
	if req == nil {
		return nil, nil, ErrAttestationNilRequest
	}
	store, err := s.verifierStore(op)
	if err != nil {
		return nil, nil, err
	}
	now := s.now()
	result := &AttestationResult{AppraisedAt: now.UTC(), ReferenceValues: req.ReferenceValues}

	akKey, akCheck, err := s.appraiseAKCertificate(ctx, store, req.AKCertificatePEM, now)
	if err != nil {
		return nil, nil, verifierError(op, errors.ErrUnavailable, err)
	}
	result.Checks = append(result.Checks, akCheck)

	proven := make(map[int][]byte, len(req.PCRs))
	for idx, value := range req.PCRs {
		proven[int(idx)] = value
	}

	var quote *evidence.Quote
	if akKey == nil {
		result.Checks = append(result.Checks, absentCheck(AppraisalCheckQuote, "not evaluated: no verified attestation key"))
	} else {
		q, qErr := evidence.VerifyQuote(evidence.QuoteInput{
			Attest:         req.Quote,
			Signature:      req.Signature,
			Key:            akKey,
			QualifyingData: req.Nonce,
			PCRs:           proven,
		})
		result.Checks = append(result.Checks, evidenceCheck(AppraisalCheckQuote, qErr))
		if qErr == nil {
			quote = q
		}
	}

	result.Checks = append(result.Checks, appraiseEventLog(req.EventLog, quote, proven, launchPCRs))

	baseline, divergences, err := s.appraiseBaseline(ctx, store, req.ReferenceValues, quote, proven, result)
	if err != nil {
		return nil, nil, verifierError(op, errors.ErrUnavailable, err)
	}
	result.Checks = append(result.Checks, baseline)

	result.Verified = true
	for _, check := range result.Checks {
		switch check.Outcome {
		case AppraisalForged:
			result.Verified = false
			result.CryptographicFailure = true
		case AppraisalAbsent:
			result.Verified = false
		}
	}
	return result, divergences, nil
}

// appraiseAKCertificate chains the AK certificate to the tenant's ak-root
// endorsements. It returns the certified key when the check passes.
func (s *attestationService) appraiseAKCertificate(ctx context.Context, store AttestationStore, chainPEM []byte, now time.Time) (crypto.PublicKey, AppraisalCheck, error) {
	if len(chainPEM) == 0 {
		return nil, absentCheck(AppraisalCheckAKCertificate, "no attestation key certificate in evidence"), nil
	}
	roots, err := s.loadEndorsements(ctx, store, EndorsementAKRoot)
	if err != nil {
		return nil, AppraisalCheck{}, err
	}
	if len(roots) == 0 {
		return nil, absentCheck(AppraisalCheckAKCertificate, "no ak-root endorsement is stored; the attestation key certificate cannot be chained"), nil
	}
	pool := x509.NewCertPool()
	for _, root := range roots {
		// PutEndorsement only stores a parseable CA certificate; a record
		// that no longer parses anchors nothing and is passed over.
		cert, err := parseCertificatePEM(root.CertificatePEM)
		if err != nil {
			continue
		}
		pool.AddCert(cert)
	}
	leaf, extra, err := evidence.ParseCertificatesPEM(chainPEM)
	if err != nil {
		return nil, AppraisalCheck{Name: AppraisalCheckAKCertificate, Outcome: AppraisalForged, Reason: "attestation key certificate does not parse: " + err.Error()}, nil
	}
	key, err := evidence.VerifyAKCertificate(leaf, extra, evidence.AKCertificateOptions{Roots: pool, Now: now})
	if err != nil {
		return nil, evidenceCheck(AppraisalCheckAKCertificate, err), nil
	}
	return key, AppraisalCheck{Name: AppraisalCheckAKCertificate, Outcome: AppraisalPass}, nil
}

// appraiseEventLog replays the optional event log against the quoted boot
// PCRs: every quoted register except launchPCRs.
func appraiseEventLog(eventLog []byte, quote *evidence.Quote, proven map[int][]byte, launchPCRs []uint32) AppraisalCheck {
	if len(eventLog) == 0 {
		return AppraisalCheck{Name: AppraisalCheckEventLog, Outcome: AppraisalSkipped, Reason: "no event log in evidence"}
	}
	if quote == nil {
		return absentCheck(AppraisalCheckEventLog, "not evaluated: the quote did not verify")
	}
	log, err := evidence.ParseEventLog(eventLog)
	if err != nil {
		return AppraisalCheck{Name: AppraisalCheckEventLog, Outcome: AppraisalForged, Reason: err.Error()}
	}
	boot := bootPCRs(proven, launchPCRs)
	if len(boot) == 0 {
		return AppraisalCheck{Name: AppraisalCheckEventLog, Outcome: AppraisalSkipped, Reason: "no quoted register is one the boot event log records"}
	}
	return evidenceCheck(AppraisalCheckEventLog, evidence.VerifyEventLog(log, quote.Bank, boot))
}

// bootPCRs is proven without the launch registers: the registers the boot
// event log is authoritative for. A launch register is left out even when
// the log carries events for it, because the runtime's extension is never in
// the log; the baseline judges that register against the signed reference
// values instead.
func bootPCRs(proven map[int][]byte, launchPCRs []uint32) map[int][]byte {
	boot := make(map[int][]byte, len(proven))
	for idx, value := range proven {
		boot[idx] = value
	}
	for _, idx := range launchPCRs {
		delete(boot, int(idx))
	}
	return boot
}

// appraiseBaseline compares the proven PCRs with the named reference values,
// re-verifying their signature against the current endorsements first.
func (s *attestationService) appraiseBaseline(ctx context.Context, store AttestationStore, name string, quote *evidence.Quote, proven map[int][]byte, result *AttestationResult) (AppraisalCheck, []pcrDivergence, error) {
	if name == "" {
		return absentCheck(AppraisalCheckBaseline, "no reference values named"), nil, nil
	}
	if err := validateAttestationName(name); err != nil {
		return absentCheck(AppraisalCheckBaseline, err.Error()), nil, nil
	}
	record, err := s.loadReferenceValues(ctx, store, name)
	if err != nil {
		var missing *AttestationRecordNotFoundError
		if stderrors.As(err, &missing) {
			return absentCheck(AppraisalCheckBaseline, missing.Error()), nil, nil
		}
		return AppraisalCheck{}, nil, err
	}
	manifest, err := s.verifyCoRIM(ctx, store, record.SignedCoRIM)
	if err != nil {
		var rejected *ReferenceValuesRejectedError
		if stderrors.As(err, &rejected) {
			return absentCheck(AppraisalCheckBaseline, "reference values are no longer endorsed: "+rejected.Reason), nil, nil
		}
		return AppraisalCheck{}, nil, err
	}
	result.ManifestID, result.Signer, result.BaselineSource = manifest.ID, manifest.Signer, BaselineSourceSigned
	if quote == nil {
		return absentCheck(AppraisalCheckBaseline, "not evaluated: the quote did not verify"), nil, nil
	}
	// The reference digests are compared with the quoted PCR values, so they
	// are taken in the selected bank's algorithm. quote.Hash is the signing
	// scheme's hash, which a TPM may pair with a bank of another size.
	bankHash, err := tpm2.TPMIAlgHash(quote.Bank).Hash()
	if err != nil {
		return absentCheck(AppraisalCheckBaseline, "quoted PCR bank names no supported hash: "+err.Error()), nil, nil
	}
	reference, err := manifest.PCRDigests(bankHash)
	if err != nil {
		return absentCheck(AppraisalCheckBaseline, err.Error()), nil, nil
	}
	check, divergences := comparePCRBaseline(proven, reference)
	return check, divergences, nil
}

// comparePCRBaseline compares proven PCR values with reference values that
// may admit several acceptable digests per register. The index sets must be
// equal (an absence when they are not: the evidence does not cover what the
// reference describes); a value no reference admits is forged.
func comparePCRBaseline(proven map[int][]byte, reference map[int][][]byte) (AppraisalCheck, []pcrDivergence) {
	if len(reference) == 0 {
		return absentCheck(AppraisalCheckBaseline, "the reference values hold no digests in the quote's bank"), nil
	}
	provenIdx, referenceIdx := sortedPCRKeys(proven), sortedPCRKeys(reference)
	if !equalInts(provenIdx, referenceIdx) {
		return absentCheck(AppraisalCheckBaseline, "quoted PCR set "+evidence.FormatIndices(provenIdx)+
			" does not equal the reference set "+evidence.FormatIndices(referenceIdx)), uncoveredPCRs(proven, reference)
	}
	var diverged []int
	var divergences []pcrDivergence
	for _, idx := range referenceIdx {
		if !admits(reference[idx], proven[idx]) {
			diverged = append(diverged, idx)
			divergences = append(divergences, pcrDivergence{Index: idx, Expected: reference[idx], Quoted: proven[idx]})
		}
	}
	if len(diverged) > 0 {
		return AppraisalCheck{Name: AppraisalCheckBaseline, Outcome: AppraisalForged,
			Reason: "PCR " + evidence.FormatIndices(diverged) + " diverges from the signed reference values"}, divergences
	}
	return AppraisalCheck{Name: AppraisalCheckBaseline, Outcome: AppraisalPass}, nil
}

// pcrDivergence is one PCR whose proven value the reference values do not
// admit: a divergent value, or an index only one side covers.
type pcrDivergence struct {
	Index    int
	Expected [][]byte
	Quoted   []byte
}

// uncoveredPCRs lists, ascending, the indices that only one of proven and
// reference covers.
func uncoveredPCRs(proven map[int][]byte, reference map[int][][]byte) []pcrDivergence {
	var out []pcrDivergence
	for _, idx := range sortedPCRKeys(proven) {
		if _, ok := reference[idx]; !ok {
			out = append(out, pcrDivergence{Index: idx, Quoted: proven[idx]})
		}
	}
	for _, idx := range sortedPCRKeys(reference) {
		if _, ok := proven[idx]; !ok {
			out = append(out, pcrDivergence{Index: idx, Expected: reference[idx]})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out
}

// admits reports whether any acceptable digest equals value, in constant time
// per comparison.
func admits(acceptable [][]byte, value []byte) bool {
	for _, digest := range acceptable {
		if len(digest) == len(value) && subtle.ConstantTimeCompare(digest, value) == 1 {
			return true
		}
	}
	return false
}

func sortedPCRKeys[V any](m map[int]V) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// evidenceCheck maps a go-xkms evidence result onto a check outcome. A
// failure that is not classified absent is treated as forged: present
// evidence that did not verify fails closed.
func evidenceCheck(name string, err error) AppraisalCheck {
	if err == nil {
		return AppraisalCheck{Name: name, Outcome: AppraisalPass}
	}
	if stderrors.Is(err, evidence.ErrAbsent) {
		return AppraisalCheck{Name: name, Outcome: AppraisalAbsent, Reason: err.Error()}
	}
	return AppraisalCheck{Name: name, Outcome: AppraisalForged, Reason: err.Error()}
}

func absentCheck(name, reason string) AppraisalCheck {
	return AppraisalCheck{Name: name, Outcome: AppraisalAbsent, Reason: reason}
}

// parseCertificatePEM parses one PEM (or DER) certificate.
func parseCertificatePEM(data []byte) (*x509.Certificate, error) {
	der := data
	if block, _ := pem.Decode(data); block != nil {
		der = block.Bytes
	}
	return x509.ParseCertificate(der)
}

// parsePublicKeyPEM parses one PEM (or DER) PKIX public key.
func parsePublicKeyPEM(data []byte) (crypto.PublicKey, error) {
	der := data
	if block, _ := pem.Decode(data); block != nil {
		der = block.Bytes
	}
	return x509.ParsePKIXPublicKey(der)
}
