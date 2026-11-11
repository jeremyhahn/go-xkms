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

package tlog

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"net/url"
	"strconv"
	"unicode/utf8"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/spiffe"
)

// EncodingVersion is the version byte of the entry encoding this package
// writes and reads.
const EncodingVersion byte = 1

// maxFieldLen is the largest field the two-byte length prefix can carry.
const maxFieldLen = 0xffff

// Kind is the kind of a log entry, the second byte of its encoding.
type Kind byte

// The entry kinds. go-xkms appends the first three itself; the layers above
// append KindExternal entries under the caller's SPIFFE ID.
const (
	KindCertIssued  Kind = 1
	KindImageSigned Kind = 2
	KindRevoked     Kind = 3
	KindExternal    Kind = 4
)

var kindNames = map[Kind]string{
	KindCertIssued:  "cert-issued",
	KindImageSigned: "image-signed",
	KindRevoked:     "revoked",
	KindExternal:    "external",
}

// String returns the kind's name, as docs/SPEC.md names it.
func (k Kind) String() string {
	if name, ok := kindNames[k]; ok {
		return name
	}
	return "kind(" + strconv.Itoa(int(k)) + ")"
}

// An Entry is one record of the transparency log.
//
// Encoding, version 1. An entry is the bytes
//
//	version (1 byte, EncodingVersion) || kind (1 byte) || field_1 || ... || field_n
//
// where every field is its length as a big-endian uint16 followed by that
// many bytes, the kind fixes the number and order of the fields, and nothing
// follows the last field. A string field is UTF-8; a serial number is the
// minimal big-endian magnitude of a positive integer (no leading zero byte);
// a digest is its raw bytes. Each value therefore has exactly one encoding,
// so the leaf hash go-qrdb computes over it (RFC 9162 §2.1.1) is a function
// of the entry alone.
type Entry interface {
	// Kind is the entry's kind.
	Kind() Kind

	// fields validates the entry and returns its fields in encoding order.
	fields() ([][]byte, error)
}

// CertIssued records a certificate the CA issued.
type CertIssued struct {
	// CertSHA256 is the SHA-256 of the certificate's DER.
	CertSHA256 [sha256.Size]byte

	// Serial is the certificate's serial number.
	Serial *big.Int

	// Profile is the issuance profile that shaped the certificate.
	Profile string

	// Tenant is the tenant the certificate was issued in.
	Tenant string
}

// Kind returns KindCertIssued.
func (CertIssued) Kind() Kind { return KindCertIssued }

func (e CertIssued) fields() ([][]byte, error) {
	serial, err := encodeSerial(e.Serial)
	if err != nil {
		return nil, err
	}
	if e.CertSHA256 == ([sha256.Size]byte{}) {
		return nil, &errs.Detail{Err: ErrInvalidEntry, Detail: "cert-issued: empty certificate hash"}
	}
	profile, err := encodeString("profile", e.Profile)
	if err != nil {
		return nil, err
	}
	tenant, err := encodeString("tenant", e.Tenant)
	if err != nil {
		return nil, err
	}
	return [][]byte{e.CertSHA256[:], serial, profile, tenant}, nil
}

// ImageSigned records an image signature the CA made.
type ImageSigned struct {
	// ImageDigest is the signed image's digest, e.g. "sha256:<hex>".
	ImageDigest string

	// EnvelopeDigest is the digest of the signature envelope.
	EnvelopeDigest string

	// Signer names the key or identity that signed.
	Signer string
}

// Kind returns KindImageSigned.
func (ImageSigned) Kind() Kind { return KindImageSigned }

func (e ImageSigned) fields() ([][]byte, error) {
	image, err := encodeString("image digest", e.ImageDigest)
	if err != nil {
		return nil, err
	}
	envelope, err := encodeString("envelope digest", e.EnvelopeDigest)
	if err != nil {
		return nil, err
	}
	signer, err := encodeString("signer", e.Signer)
	if err != nil {
		return nil, err
	}
	return [][]byte{image, envelope, signer}, nil
}

// Revoked records a certificate the CA revoked.
type Revoked struct {
	// Serial is the revoked certificate's serial number.
	Serial *big.Int

	// Reason is the RFC 5280 §5.3.1 CRLReason code.
	Reason uint8
}

// Kind returns KindRevoked.
func (Revoked) Kind() Kind { return KindRevoked }

func (e Revoked) fields() ([][]byte, error) {
	serial, err := encodeSerial(e.Serial)
	if err != nil {
		return nil, err
	}
	if err := checkReason(e.Reason); err != nil {
		return nil, err
	}
	return [][]byte{serial, {e.Reason}}, nil
}

// External records a payload a layer above go-xkms appended, under the
// SPIFFE ID of the caller that appended it.
type External struct {
	// SPIFFEID is the appending caller's SPIFFE ID, in the canonical form
	// spiffe.ID.String writes.
	SPIFFEID string

	// Payload is the caller's opaque payload, 1 to 65535 bytes.
	Payload []byte
}

// Kind returns KindExternal.
func (External) Kind() Kind { return KindExternal }

func (e External) fields() ([][]byte, error) {
	id, err := encodeSPIFFEID(e.SPIFFEID)
	if err != nil {
		return nil, err
	}
	if len(e.Payload) == 0 {
		return nil, &errs.Detail{Err: ErrInvalidEntry, Detail: "external: empty payload"}
	}
	return [][]byte{id, e.Payload}, nil
}

// Marshal returns e's version-1 encoding.
func Marshal(e Entry) ([]byte, error) {
	if e == nil {
		return nil, &errs.Detail{Err: ErrInvalidEntry, Detail: "nil entry"}
	}
	fields, err := e.fields()
	if err != nil {
		return nil, err
	}
	out := []byte{EncodingVersion, byte(e.Kind())}
	for _, f := range fields {
		if len(f) > maxFieldLen {
			return nil, &errs.Detail{Err: ErrInvalidEntry, Detail: e.Kind().String() + ": field longer than 65535 bytes"}
		}
		out = binary.BigEndian.AppendUint16(out, uint16(len(f)))
		out = append(out, f...)
	}
	return out, nil
}

// decoder rebuilds one kind's entry from its fields.
type decoder func(fields [][]byte) (Entry, error)

// decoders maps each kind to its decoder and its field count.
var decoders = map[Kind]struct {
	count  int
	decode decoder
}{
	KindCertIssued:  {4, decodeCertIssued},
	KindImageSigned: {3, decodeImageSigned},
	KindRevoked:     {2, decodeRevoked},
	KindExternal:    {2, decodeExternal},
}

// Unmarshal decodes a version-1 entry, refusing any bytes Marshal would not
// have written.
func Unmarshal(b []byte) (Entry, error) {
	if len(b) < 2 {
		return nil, &errs.Detail{Err: ErrMalformedEntry, Detail: "shorter than its header"}
	}
	if b[0] != EncodingVersion {
		return nil, &errs.Detail{Err: ErrUnsupportedVersion, Detail: strconv.Itoa(int(b[0]))}
	}
	kind := Kind(b[1])
	d, ok := decoders[kind]
	if !ok {
		return nil, &errs.Detail{Err: ErrUnknownKind, Detail: kind.String()}
	}
	fields := make([][]byte, 0, d.count)
	rest := b[2:]
	for len(rest) > 0 {
		if len(fields) == d.count {
			return nil, &errs.Detail{Err: ErrMalformedEntry, Detail: kind.String() + ": trailing bytes"}
		}
		if len(rest) < 2 {
			return nil, &errs.Detail{Err: ErrMalformedEntry, Detail: kind.String() + ": truncated field length"}
		}
		n := int(binary.BigEndian.Uint16(rest))
		if len(rest) < 2+n {
			return nil, &errs.Detail{Err: ErrMalformedEntry, Detail: kind.String() + ": truncated field"}
		}
		fields = append(fields, rest[2:2+n])
		rest = rest[2+n:]
	}
	if len(fields) != d.count {
		return nil, &errs.Detail{Err: ErrMalformedEntry, Detail: kind.String() + ": missing fields"}
	}
	e, err := d.decode(fields)
	if err != nil {
		return nil, err
	}
	// A decoded entry must pass the checks Marshal applies, so an
	// entry this package reads back is one it could have written.
	if _, err := e.fields(); err != nil {
		return nil, &errs.Joined{Lead: ErrMalformedEntry, Detail: kind.String(), Cause: err}
	}
	return e, nil
}

func decodeCertIssued(fields [][]byte) (Entry, error) {
	if len(fields[0]) != sha256.Size {
		return nil, &errs.Detail{Err: ErrMalformedEntry, Detail: "cert-issued: certificate hash is not 32 bytes"}
	}
	serial, err := decodeSerial(fields[1])
	if err != nil {
		return nil, err
	}
	e := CertIssued{Serial: serial, Profile: string(fields[2]), Tenant: string(fields[3])}
	copy(e.CertSHA256[:], fields[0])
	return e, nil
}

func decodeImageSigned(fields [][]byte) (Entry, error) {
	return ImageSigned{ImageDigest: string(fields[0]), EnvelopeDigest: string(fields[1]), Signer: string(fields[2])}, nil
}

func decodeRevoked(fields [][]byte) (Entry, error) {
	serial, err := decodeSerial(fields[0])
	if err != nil {
		return nil, err
	}
	if len(fields[1]) != 1 {
		return nil, &errs.Detail{Err: ErrMalformedEntry, Detail: "revoked: reason is not one byte"}
	}
	return Revoked{Serial: serial, Reason: fields[1][0]}, nil
}

// decodeExternal copies the payload so the entry does not alias the bytes
// it was decoded from.
func decodeExternal(fields [][]byte) (Entry, error) {
	return External{SPIFFEID: string(fields[0]), Payload: bytes.Clone(fields[1])}, nil
}

// encodeSerial returns a positive serial's minimal big-endian magnitude
// (RFC 5280 §4.1.2.2 requires a positive serial).
func encodeSerial(serial *big.Int) ([]byte, error) {
	if serial == nil || serial.Sign() <= 0 {
		return nil, &errs.Detail{Err: ErrInvalidEntry, Detail: "serial is not a positive integer"}
	}
	return serial.Bytes(), nil
}

// decodeSerial refuses a serial with a leading zero byte, which has a
// shorter encoding.
func decodeSerial(b []byte) (*big.Int, error) {
	if len(b) > 0 && b[0] == 0 {
		return nil, &errs.Detail{Err: ErrMalformedEntry, Detail: "serial has a leading zero byte"}
	}
	return new(big.Int).SetBytes(b), nil
}

// encodeString refuses an empty or non-UTF-8 string field.
func encodeString(name, s string) ([]byte, error) {
	if s == "" {
		return nil, &errs.Detail{Err: ErrInvalidEntry, Detail: "empty " + name}
	}
	if !utf8.ValidString(s) {
		return nil, &errs.Detail{Err: ErrInvalidEntry, Detail: name + " is not UTF-8"}
	}
	return []byte(s), nil
}

// encodeSPIFFEID refuses a string that is not a SPIFFE ID spiffe.ParseID
// accepts, or not in the canonical form spiffe.ID.String writes, so each
// caller has exactly one encoding.
func encodeSPIFFEID(s string) ([]byte, error) {
	b, err := encodeString("external: spiffe id", s)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrInvalidEntry, Detail: "external: spiffe id", Cause: err}
	}
	id, ok, err := spiffe.ParseID(u)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrInvalidEntry, Detail: "external: spiffe id", Cause: err}
	}
	if !ok || id.String() != s {
		return nil, &errs.Detail{Err: ErrInvalidEntry, Detail: "external: " + strconv.Quote(s) + " is not a canonical SPIFFE ID"}
	}
	return b, nil
}

// checkReason refuses a code RFC 5280 §5.3.1 does not assign: above
// aACompromise (10), or the unused value 7.
func checkReason(reason uint8) error {
	if reason > 10 || reason == 7 {
		return &errs.Detail{Err: ErrInvalidEntry, Detail: "revocation reason " + strconv.Itoa(int(reason)) + " is not an RFC 5280 CRLReason"}
	}
	return nil
}
