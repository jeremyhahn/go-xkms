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

package xkms

import (
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
)

// The attestation Verifier: appraisal of TPM evidence against a tenant's
// endorsements and signed reference values (pkg/attestation/appraisal). The
// Appraiser keeps its records per tenant in a qrdb DAO store:
//
//	store, _ := xkms.NewAttestationAppraisalStore(xkms.AttestationAppraisalStoreConfig{DAOs: daos})
//	appraiser, _ := xkms.NewAttestationAppraiser(store)
//	service.SetAttestationAppraiser(appraiser)
//
// The service verbs scope every call to the caller's tenant. An embedder
// that appraises in-process, such as a container runtime, calls the
// Appraiser with the tenant directly.

// AttestationAppraiser appraises TPM quotes, hosts and containers against a
// tenant's endorsements and reference values.
type AttestationAppraiser = appraisal.Appraiser

// AttestationAppraiserOption configures an AttestationAppraiser.
type AttestationAppraiserOption = appraisal.Option

// NewAttestationAppraiser constructs an AttestationAppraiser over a store.
var NewAttestationAppraiser = appraisal.NewAppraiser

// WithAttestationAppraiserClock sets the clock the Appraiser stamps records
// and results with.
var WithAttestationAppraiserClock = appraisal.WithClock

// WithAttestationSigningKeySource sets the source of the public keys that
// verify a repository's signatures; an XKMSService is one.
var WithAttestationSigningKeySource = appraisal.WithSigningKeySource

// AttestationAppraisalStore persists endorsements and reference values per
// tenant through a qrdb DAO.
type AttestationAppraisalStore = appraisal.Store

// AttestationAppraisalStoreConfig is the DAO factory of an
// AttestationAppraisalStore.
type AttestationAppraisalStoreConfig = appraisal.StoreConfig

// NewAttestationAppraisalStore constructs an AttestationAppraisalStore.
var NewAttestationAppraisalStore = appraisal.NewStore

// AttestationAppraisalDatabase is the qrdb database the store keeps its
// records in.
const AttestationAppraisalDatabase = appraisal.DatabaseName

// Endorsements: the trust anchors of a tenant's appraisals.
type (
	// AttestationEndorsement is a stored trust anchor.
	AttestationEndorsement = appraisal.Endorsement
	// AttestationEndorsementKind says what an endorsement anchors.
	AttestationEndorsementKind = appraisal.EndorsementKind
	// PutAttestationEndorsementRequest stores an endorsement.
	PutAttestationEndorsementRequest = appraisal.PutEndorsementRequest
	// ListAttestationEndorsementsRequest filters endorsements by kind.
	ListAttestationEndorsementsRequest = appraisal.ListEndorsementsRequest
	// ListAttestationEndorsementsResponse holds the listed endorsements.
	ListAttestationEndorsementsResponse = appraisal.ListEndorsementsResponse
	// DeleteAttestationEndorsementRequest names the endorsement to remove.
	DeleteAttestationEndorsementRequest = appraisal.DeleteEndorsementRequest
)

const (
	// AttestationEndorsementAKRoot anchors attestation-key certificates.
	AttestationEndorsementAKRoot = appraisal.EndorsementAKRoot
	// AttestationEndorsementReferenceSigner anchors signed CoRIM reference
	// values.
	AttestationEndorsementReferenceSigner = appraisal.EndorsementReferenceSigner
)

// Reference values: the signed baselines evidence is compared against.
type (
	// AttestationReferenceValues are stored reference values.
	AttestationReferenceValues = appraisal.ReferenceValues
	// PutAttestationReferenceValuesRequest stores a signed CoRIM.
	PutAttestationReferenceValuesRequest = appraisal.PutReferenceValuesRequest
	// GetAttestationReferenceValuesRequest names the reference values to read.
	GetAttestationReferenceValuesRequest = appraisal.GetReferenceValuesRequest
	// ListAttestationReferenceValuesResponse holds the listed reference values.
	ListAttestationReferenceValuesResponse = appraisal.ListReferenceValuesResponse
	// DeleteAttestationReferenceValuesRequest names the reference values to
	// remove.
	DeleteAttestationReferenceValuesRequest = appraisal.DeleteReferenceValuesRequest
)

// Signing keys: the tenant release key signs every repository's images and
// CoRIM unless a binding names another of the tenant's keys for it.
type (
	// AttestationSigningKeyBinding names the key that signs a repository.
	AttestationSigningKeyBinding = appraisal.SigningKeyBinding
	// SetAttestationSigningKeyBindingRequest binds a repository to a key.
	SetAttestationSigningKeyBindingRequest = appraisal.SetSigningKeyBindingRequest
	// GetAttestationSigningKeyBindingRequest names a repository's binding.
	GetAttestationSigningKeyBindingRequest = appraisal.GetSigningKeyBindingRequest
	// ListAttestationSigningKeyBindingsResponse holds the listed bindings.
	ListAttestationSigningKeyBindingsResponse = appraisal.ListSigningKeyBindingsResponse
	// DeleteAttestationSigningKeyBindingRequest names the binding to remove.
	DeleteAttestationSigningKeyBindingRequest = appraisal.DeleteSigningKeyBindingRequest
	// ResolveAttestationSigningKeyRequest names the repository to resolve.
	ResolveAttestationSigningKeyRequest = appraisal.ResolveSigningKeyRequest
	// AttestationSigningKeyResolution is the key that signs a repository.
	AttestationSigningKeyResolution = appraisal.SigningKeyResolution
	// AttestationSigningKeySource returns the public half of a tenant key.
	AttestationSigningKeySource = appraisal.SigningKeySource
	// AttestationTenantSigningKeys resolves the keys of one tenant's
	// repositories; it is an ImageSigningKeyResolver.
	AttestationTenantSigningKeys = appraisal.TenantSigningKeys
)

// AttestationReleaseSigningKeyID is the key ID of a tenant's release signing
// key.
const AttestationReleaseSigningKeyID = appraisal.ReleaseSigningKeyID

// Appraisal: evidence in, an attestation result out.
type (
	// AppraiseAttestationQuoteRequest is a TPM quote and the reference values
	// to appraise it against.
	AppraiseAttestationQuoteRequest = appraisal.AppraiseQuoteRequest
	// AttestationAppraisalResult is the outcome of appraising a quote.
	AttestationAppraisalResult = appraisal.AttestationResult
	// AttestationAppraisalCheck is one check's outcome in a result.
	AttestationAppraisalCheck = appraisal.AppraisalCheck
	// AttestationAppraisalOutcome is a check's outcome.
	AttestationAppraisalOutcome = appraisal.AppraisalOutcome
	// AttestationHostEvidence is a host's quote, PCRs and AK certificate.
	AttestationHostEvidence = appraisal.HostEvidence
	// AttestationHostAppraisal is a verified host's appraisal.
	AttestationHostAppraisal = appraisal.HostAppraisal
	// AttestationContainerEvidence is a container launch's host evidence and
	// the launch PCRs it measured into.
	AttestationContainerEvidence = appraisal.ContainerEvidence
	// AttestationPCRDivergence is a quoted PCR the reference values do not
	// admit.
	AttestationPCRDivergence = appraisal.PCRDivergence
)

const (
	// AttestationAppraisalPass reports evidence present and verified.
	AttestationAppraisalPass = appraisal.AppraisalPass
	// AttestationAppraisalForged reports evidence present and wrong.
	AttestationAppraisalForged = appraisal.AppraisalForged
	// AttestationAppraisalAbsent reports a check that could not run.
	AttestationAppraisalAbsent = appraisal.AppraisalAbsent
	// AttestationAppraisalSkipped reports optional evidence not sent.
	AttestationAppraisalSkipped = appraisal.AppraisalSkipped
)

// Typed errors of the Verifier. Match the sentinels with errors.Is and the
// types with errors.As.
type (
	AttestationAppraisalConfigError         = appraisal.ConfigError
	AttestationAppraisalNameError           = appraisal.NameError
	AttestationAppraisalTenantError         = appraisal.TenantError
	AttestationAppraisalStoreError          = appraisal.StoreError
	AttestationRecordNotFoundError          = appraisal.RecordNotFoundError
	AttestationEndorsementInvalidError      = appraisal.EndorsementInvalidError
	AttestationReferenceValuesRejectedError = appraisal.ReferenceValuesRejectedError
	AttestationReferenceBankUncoveredError  = appraisal.ReferenceBankUncoveredError
	AttestationHostAppraisalError           = appraisal.HostAppraisalError
	AttestationHostAppraisalFailure         = appraisal.HostAppraisalFailure
	AttestationQuoteBindingError            = appraisal.QuoteBindingError
	AttestationQuotedPCRDigestMismatchError = appraisal.QuotedPCRDigestMismatchError
	AttestationPCRBankUnavailableError      = appraisal.PCRBankUnavailableError
	AttestationRepositoryError              = appraisal.RepositoryError
	AttestationSigningKeyError              = appraisal.SigningKeyError
	AttestationSignerRefusedError           = appraisal.SignerRefusedError
)

var (
	ErrAttestationAppraisalNilRequest       = appraisal.ErrNilRequest
	ErrAttestationAppraisalInvalidName      = appraisal.ErrInvalidName
	ErrAttestationAppraisalInvalidConfig    = appraisal.ErrInvalidConfig
	ErrAttestationAppraisalInvalidTenant    = appraisal.ErrInvalidTenant
	ErrAttestationAppraisalStoreUnavailable = appraisal.ErrStoreUnavailable
	ErrAttestationRecordNotFound            = appraisal.ErrRecordNotFound
	ErrAttestationEndorsementInvalid        = appraisal.ErrEndorsementInvalid
	ErrAttestationReferenceValuesRejected   = appraisal.ErrReferenceValuesRejected
	ErrAttestationReferenceBankUncovered    = appraisal.ErrReferenceBankUncovered
	ErrAttestationHostNotVerified           = appraisal.ErrHostNotVerified
	ErrAttestationPCRMismatch               = appraisal.ErrPCRMismatch
	ErrAttestationQuoteNotBound             = appraisal.ErrQuoteNotBound
	ErrAttestationQuotedPCRDigestMismatch   = appraisal.ErrQuotedPCRDigestMismatch
	ErrAttestationPCRBankUnavailable        = appraisal.ErrPCRBankUnavailable
	ErrAttestationInvalidRepository         = appraisal.ErrInvalidRepository
	ErrAttestationInvalidSigningKey         = appraisal.ErrInvalidSigningKey
	ErrAttestationSigningKeyRefused         = appraisal.ErrSigningKeyRefused
)
