package tlog

import (
	"context"
	"encoding/json"
	"fmt"
)

// The logs go-xkms appends to itself, one per event family.
const (
	LogIssuance     = "issuance"
	LogImageSigning = "image-signing"
	LogRevocation   = "revocation"
)

// The entry kinds go-xkms appends itself (docs/SPEC.md, transparency-log).
const (
	KindCertIssued  = "cert-issued"
	KindImageSigned = "image-signed"
	KindRevoked     = "revoked"
)

// Entry is a transparency-log entry: its kind and the log it belongs to.
type Entry interface {
	Kind() string
	Log() string
}

// CertIssued records an issued certificate. SHA256 is the hex SHA-256 of
// the certificate DER; Serial is the lower-case hex serial.
type CertIssued struct {
	SHA256  string `json:"sha256"`
	Serial  string `json:"serial"`
	Profile string `json:"profile,omitempty"`
	Tenant  string `json:"tenant,omitempty"`
}

// Kind returns KindCertIssued.
func (CertIssued) Kind() string { return KindCertIssued }

// Log returns LogIssuance.
func (CertIssued) Log() string { return LogIssuance }

// MarshalJSON encodes the entry with its kind.
func (e CertIssued) MarshalJSON() ([]byte, error) {
	type fields CertIssued
	return json.Marshal(struct {
		Kind string `json:"kind"`
		fields
	}{KindCertIssued, fields(e)})
}

// ImageSigned records an image signature. ImageDigest is the signed
// manifest digest, EnvelopeSHA256 the hex SHA-256 of the DSSE envelope and
// Signer the hex SHA-256 of the signing certificate DER.
type ImageSigned struct {
	ImageDigest    string `json:"image_digest"`
	EnvelopeSHA256 string `json:"envelope_sha256"`
	Signer         string `json:"signer"`
}

// Kind returns KindImageSigned.
func (ImageSigned) Kind() string { return KindImageSigned }

// Log returns LogImageSigning.
func (ImageSigned) Log() string { return LogImageSigning }

// MarshalJSON encodes the entry with its kind.
func (e ImageSigned) MarshalJSON() ([]byte, error) {
	type fields ImageSigned
	return json.Marshal(struct {
		Kind string `json:"kind"`
		fields
	}{KindImageSigned, fields(e)})
}

// Revoked records a revocation: the lower-case hex serial and the reason.
type Revoked struct {
	Serial string `json:"serial"`
	Reason string `json:"reason"`
}

// Kind returns KindRevoked.
func (Revoked) Kind() string { return KindRevoked }

// Log returns LogRevocation.
func (Revoked) Log() string { return LogRevocation }

// MarshalJSON encodes the entry with its kind.
func (e Revoked) MarshalJSON() ([]byte, error) {
	type fields Revoked
	return json.Marshal(struct {
		Kind string `json:"kind"`
		fields
	}{KindRevoked, fields(e)})
}

// Encode returns the JSON body of an entry.
func Encode(e Entry) ([]byte, error) { return json.Marshal(e) }

// Appender appends one entry body to a named log.
type Appender interface {
	Append(ctx context.Context, log string, entry []byte) error
}

// AppendError reports an entry that could not be encoded or appended.
type AppendError struct {
	Log string
	Err error
}

func (e *AppendError) Error() string {
	return fmt.Sprintf("transparency log %q: append: %v", e.Log, e.Err)
}

// Unwrap returns the cause.
func (e *AppendError) Unwrap() error { return e.Err }

// AppendEntry encodes e and appends it to its log. A nil Appender is a
// no-op; any failure is an *AppendError.
func AppendEntry(ctx context.Context, a Appender, e Entry) error {
	if a == nil {
		return nil
	}
	body, err := Encode(e)
	if err != nil {
		return &AppendError{Log: e.Log(), Err: err}
	}
	if err := a.Append(ctx, e.Log(), body); err != nil {
		return &AppendError{Log: e.Log(), Err: err}
	}
	return nil
}
