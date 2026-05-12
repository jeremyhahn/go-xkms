// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package ct

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"time"
)

// OID definitions for CT extensions per RFC 6962.
var (
	// OIDPrecertPoison is the OID for the CT precert poison extension.
	// This extension marks a certificate as a precertificate that should
	// not be accepted by TLS clients.
	// OID: 1.3.6.1.4.1.11129.2.4.3
	OIDPrecertPoison = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}

	// OIDSCTList is the OID for the SCT list extension.
	// This extension contains the list of SCTs embedded in the certificate.
	// OID: 1.3.6.1.4.1.11129.2.4.2
	OIDSCTList = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

	// OIDSignedCertificateTimestampList is an alias for OIDSCTList.
	OIDSignedCertificateTimestampList = OIDSCTList
)

// SignatureAlgorithm identifies the signature algorithm used by a CT log.
type SignatureAlgorithm uint8

const (
	// SignatureAlgorithmAnonymous is an anonymous signature (should not be used).
	SignatureAlgorithmAnonymous SignatureAlgorithm = 0
	// SignatureAlgorithmRSA indicates RSA signatures.
	SignatureAlgorithmRSA SignatureAlgorithm = 1
	// SignatureAlgorithmDSA indicates DSA signatures.
	SignatureAlgorithmDSA SignatureAlgorithm = 2
	// SignatureAlgorithmECDSA indicates ECDSA signatures.
	SignatureAlgorithmECDSA SignatureAlgorithm = 3
)

// HashAlgorithm identifies the hash algorithm used in CT operations.
type HashAlgorithm uint8

const (
	// HashAlgorithmNone indicates no hash.
	HashAlgorithmNone HashAlgorithm = 0
	// HashAlgorithmMD5 indicates MD5 (should not be used).
	HashAlgorithmMD5 HashAlgorithm = 1
	// HashAlgorithmSHA1 indicates SHA-1 (should not be used).
	HashAlgorithmSHA1 HashAlgorithm = 2
	// HashAlgorithmSHA224 indicates SHA-224.
	HashAlgorithmSHA224 HashAlgorithm = 3
	// HashAlgorithmSHA256 indicates SHA-256 (standard for CT).
	HashAlgorithmSHA256 HashAlgorithm = 4
	// HashAlgorithmSHA384 indicates SHA-384.
	HashAlgorithmSHA384 HashAlgorithm = 5
	// HashAlgorithmSHA512 indicates SHA-512.
	HashAlgorithmSHA512 HashAlgorithm = 6
)

// Version indicates the SCT version.
type Version uint8

const (
	// V1 is SCT version 1 per RFC 6962.
	V1 Version = 0
)

// LogEntryType indicates the type of log entry.
type LogEntryType uint16

const (
	// X509LogEntryType indicates a standard X.509 certificate.
	X509LogEntryType LogEntryType = 0
	// PrecertLogEntryType indicates a pre-certificate.
	PrecertLogEntryType LogEntryType = 1
)

// DigitallySigned represents the signature component of an SCT.
type DigitallySigned struct {
	HashAlgorithm HashAlgorithm
	SigAlgorithm  SignatureAlgorithm
	Signature     []byte
}

// SignedCertificateTimestamp represents an SCT from a CT log.
type SignedCertificateTimestamp struct {
	// Version is the SCT version (always V1 for RFC 6962).
	Version Version

	// LogID is the SHA-256 hash of the log's public key.
	LogID [32]byte

	// Timestamp is when the log recorded the certificate, in milliseconds since epoch.
	Timestamp uint64

	// Extensions is reserved for future use (currently empty).
	Extensions []byte

	// Signature is the log's signature over the SCT data.
	Signature DigitallySigned
}

// Time returns the SCT timestamp as a time.Time.
func (sct *SignedCertificateTimestamp) Time() time.Time {
	return time.UnixMilli(int64(sct.Timestamp))
}

// LogGroup represents a CT log configuration.
type LogGroup struct {
	// Name is a human-readable name for the log.
	Name string

	// Operator identifies the log operator (e.g., "Google", "Cloudflare").
	Operator string

	// URL is the log's submission endpoint.
	URL string

	// PublicKey is the log's public key for signature verification.
	PublicKey crypto.PublicKey

	// LogID is the SHA-256 hash of the log's SubjectPublicKeyInfo.
	LogID [32]byte

	// StartTime is when the log started accepting certificates (temporal shard start).
	StartTime time.Time

	// EndTime is when the log stops accepting certificates (temporal shard end).
	// Zero value indicates no end time (log is still active).
	EndTime time.Time

	// IsTiled indicates whether the log uses the static-ct-api (tiled) format.
	// RFC6962-compliant logs have IsTiled = false.
	IsTiled bool

	// MaxChainLength is the maximum certificate chain length the log accepts.
	MaxChainLength int
}

// IsTemporallyValid returns true if the certificate expiry falls within
// the log's temporal window.
func (lg *LogGroup) IsTemporallyValid(certExpiry time.Time) bool {
	// Certificate expiry must be after log start time
	if certExpiry.Before(lg.StartTime) {
		return false
	}

	// If log has no end time, it accepts all future certificates
	if lg.EndTime.IsZero() {
		return true
	}

	// Certificate expiry must be before or equal to log end time
	return !certExpiry.After(lg.EndTime)
}

// IsRFC6962Compliant returns true if the log is RFC6962-compliant (not tiled).
func (lg *LogGroup) IsRFC6962Compliant() bool {
	return !lg.IsTiled
}

// PolicyConfig configures CT policy requirements.
type PolicyConfig struct {
	// LogGroups contains the available CT logs.
	LogGroups []LogGroup

	// MinSCTs is the minimum number of SCTs required (typically 2).
	MinSCTs int

	// MinOperators is the minimum number of distinct operators required (typically 2).
	MinOperators int

	// RequireRFC6962Log requires at least one SCT from an RFC6962-compliant log.
	RequireRFC6962Log bool

	// StaggerDelay is the delay between log submissions to prevent thundering herd.
	StaggerDelay time.Duration

	// SubmissionTimeout is the timeout for each log submission.
	SubmissionTimeout time.Duration

	// MaxParallelSubmissions limits concurrent submissions.
	MaxParallelSubmissions int
}

// DefaultPolicyConfig returns a default CT policy configuration.
func DefaultPolicyConfig() PolicyConfig {
	return PolicyConfig{
		MinSCTs:                2,
		MinOperators:           2,
		RequireRFC6962Log:      true,
		StaggerDelay:           50 * time.Millisecond,
		SubmissionTimeout:      10 * time.Second,
		MaxParallelSubmissions: 10,
	}
}

// SCTResult contains the result of an SCT submission attempt.
type SCTResult struct {
	// SCT is the signed certificate timestamp (nil if failed).
	SCT *SignedCertificateTimestamp

	// Log is the log that produced this result.
	Log LogGroup

	// Error is set if submission failed.
	Error error
}

// LogSubmitter defines the interface for submitting certificates to CT logs.
type LogSubmitter interface {
	// SubmitPrecert submits a precertificate to the CT log and returns an SCT.
	SubmitPrecert(ctx interface{}, precertDER []byte, chain [][]byte, log LogGroup) (*SignedCertificateTimestamp, error)
}

// KeyToLogID computes the log ID from a public key.
// The log ID is the SHA-256 hash of the SubjectPublicKeyInfo.
func KeyToLogID(pubKey crypto.PublicKey) ([32]byte, error) {
	var logID [32]byte

	spkiDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return logID, err
	}

	// Use crypto/sha256 for the hash
	hash := crypto.SHA256.New()
	hash.Write(spkiDER)
	copy(logID[:], hash.Sum(nil))

	return logID, nil
}

// ECDSAPublicKeyToLogID computes the log ID from an ECDSA public key.
func ECDSAPublicKeyToLogID(pubKey *ecdsa.PublicKey) ([32]byte, error) {
	return KeyToLogID(pubKey)
}
