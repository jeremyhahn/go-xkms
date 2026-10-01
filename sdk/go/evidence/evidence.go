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

// Package evidence is the SDK surface of the attestation evidence
// primitives: TPM2_Quote, attestation-key and endorsement-key certificate,
// TCG event log, TPM2_Certify and IAK/IDevID checks, in one package. Every
// name here is an alias of the go-xkms implementation, so values pass
// between this package and the implementation without conversion.
//
// These are RFC 9334 evidence-level primitives. Appraisal against reference
// values is the Verifier's job and is not done here.
package evidence

import (
	pkgevidence "github.com/jeremyhahn/go-xkms/pkg/attestation/evidence"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/peer"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
)

// Failure classification.
type (
	// Class says what kind of failure an *Error reports.
	Class = pkgevidence.Class
	// Error is the failure of one evidence check.
	Error = pkgevidence.Error
	// EventLogError reports an event log that does not parse.
	EventLogError = pkgevidence.EventLogError
)

// Failure classes.
const (
	ClassForged = pkgevidence.ClassForged
	ClassAbsent = pkgevidence.ClassAbsent
)

// Check names carried by *Error.
const (
	CheckQuote          = pkgevidence.CheckQuote
	CheckSignature      = pkgevidence.CheckSignature
	CheckQualifyingData = pkgevidence.CheckQualifyingData
	CheckPCRDigest      = pkgevidence.CheckPCRDigest
	CheckBaseline       = pkgevidence.CheckBaseline
	CheckAKCertificate  = pkgevidence.CheckAKCertificate
	CheckEKCertificate  = pkgevidence.CheckEKCertificate
	CheckEventLog       = pkgevidence.CheckEventLog
)

// Sentinels.
var (
	ErrForged            = pkgevidence.ErrForged
	ErrAbsent            = pkgevidence.ErrAbsent
	ErrEventLogMalformed = pkgevidence.ErrEventLogMalformed
)

// TPM2_Quote.
type (
	Quote      = pkgevidence.Quote
	QuoteInput = pkgevidence.QuoteInput
	ClockInfo  = pkgevidence.ClockInfo
)

var (
	// ParseQuote parses a TPMS_ATTEST of type TPM_ST_ATTEST_QUOTE.
	ParseQuote = pkgevidence.ParseQuote
	// VerifyQuote runs parse, signature, qualifying-data and PCR-digest checks.
	VerifyQuote = pkgevidence.VerifyQuote
	// ComparePCRs compares proven PCR values with reference values.
	ComparePCRs = pkgevidence.ComparePCRs
	// BankDigestSize returns the register size of an accepted PCR bank.
	BankDigestSize = pkgevidence.BankDigestSize
	// FormatIndices renders PCR indices as "[0,1,7]".
	FormatIndices = pkgevidence.FormatIndices
)

// Attestation-key and endorsement-key certificates.
type (
	AKCertificateOptions = pkgevidence.AKCertificateOptions
	EKCertificateOptions = pkgevidence.EKCertificateOptions
)

var (
	OIDTCGVerifiedTPMRestricted       = pkgevidence.OIDTCGVerifiedTPMRestricted
	OIDTCGVerifiedTPMRestrictedPolicy = pkgevidence.OIDTCGVerifiedTPMRestrictedPolicy
	OIDTCGKpEKCertificate             = pkgevidence.OIDTCGKpEKCertificate

	ParseCertificatesPEM         = pkgevidence.ParseCertificatesPEM
	VerifyAKCertificate          = pkgevidence.VerifyAKCertificate
	CarriesVerifiedTPMRestricted = pkgevidence.CarriesVerifiedTPMRestricted
	ParseEKCertificateChain      = pkgevidence.ParseEKCertificateChain
	VerifyEKCertificate          = pkgevidence.VerifyEKCertificate
	HasEKCertificateEKU          = pkgevidence.HasEKCertificateEKU
	StripEKCertificateQuirks     = pkgevidence.StripEKCertificateQuirks
)

// TCG PC Client crypto-agile event logs.
type (
	EventLog = pkgevidence.EventLog
	Event    = pkgevidence.Event
	SpecID   = pkgevidence.SpecID
)

// Event log limits and event types.
const (
	EventNoAction    = pkgevidence.EventNoAction
	MaxEventDataSize = pkgevidence.MaxEventDataSize
	MaxEvents        = pkgevidence.MaxEvents
	MaxAlgorithms    = pkgevidence.MaxAlgorithms
)

var (
	ParseEventLog  = pkgevidence.ParseEventLog
	VerifyEventLog = pkgevidence.VerifyEventLog
	ResetValue     = pkgevidence.ResetValue
)

// TPM2_Certify verification (pkg/tpm2).
type (
	CertifyVerification  = tpm2.CertifyVerification
	VerifyCertifyOptions = tpm2.VerifyCertifyOptions
)

var (
	VerifyCertify              = tpm2.VerifyCertify
	VerifyCertifyByCertificate = tpm2.VerifyCertifyByCertificate
	VerifyCertifyRaw           = tpm2.VerifyCertifyRaw

	ErrCertifyMalformed              = tpm2.ErrCertifyMalformed
	ErrCertifyNotTPMGenerated        = tpm2.ErrCertifyNotTPMGenerated
	ErrCertifyWrongType              = tpm2.ErrCertifyWrongType
	ErrCertifySignature              = tpm2.ErrCertifySignature
	ErrCertifyNameMismatch           = tpm2.ErrCertifyNameMismatch
	ErrCertifyQualifyingDataMismatch = tpm2.ErrCertifyQualifyingDataMismatch
	ErrCertifyAttesterUnrestricted   = tpm2.ErrCertifyAttesterUnrestricted
)

// IAK and IDevID certificate checks (pkg/attestation/peer).
type DevIDPolicy = peer.DevIDPolicy

var (
	VerifyIAK    = peer.VerifyIAK
	VerifyIDevID = peer.VerifyIDevID
	IsIAK        = peer.IsIAK
	IsIDevID     = peer.IsIDevID
)
