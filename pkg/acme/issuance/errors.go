package issuance

import "errors"

var (
	// ErrInvalidConfig reports an Issuer configured without a required
	// dependency.
	ErrInvalidConfig = errors.New("issuance: invalid configuration")

	// ErrNilRequest reports a request without a certificate request.
	ErrNilRequest = errors.New("issuance: nil request")

	// ErrBadPublicKey reports a public key goodkey refuses; the cause names
	// the goodkey check that failed.
	ErrBadPublicKey = errors.New("issuance: public key refused")

	// ErrSerialReservation reports a serial number the CA could not reserve.
	ErrSerialReservation = errors.New("issuance: serial reservation failed")

	// ErrPrecertificate reports a precertificate the CA did not sign.
	ErrPrecertificate = errors.New("issuance: precertificate signing failed")

	// ErrCertificate reports a final certificate the CA did not sign.
	ErrCertificate = errors.New("issuance: certificate signing failed")

	// ErrTBSMismatch reports a final certificate whose tbsCertificate is not
	// its precertificate's apart from the poison and SCT list extensions
	// (RFC 6962 §3.1).
	ErrTBSMismatch = errors.New("issuance: certificate does not match its precertificate")

	// ErrCertificateTransparency reports a precertificate whose verified
	// SCTs do not meet the Certificate Transparency policy, or whose
	// submission could not be made (RFC 6962 §3.3, §4.2); the cause holds
	// each log's error.
	ErrCertificateTransparency = errors.New("issuance: certificate transparency failed")

	// ErrAudit reports an audit event that could not be recorded.
	ErrAudit = errors.New("issuance: audit failed")
)
