// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package ct

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/binary"

	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
)

// MakeSCTListExtension creates the SCT list extension for embedding in certificates.
// The extension is encoded per RFC 6962 Section 3.3.
//
// The SCT list is encoded as:
//   - 2 bytes: total length of the serialized SCT list
//   - For each SCT:
//   - 2 bytes: length of the serialized SCT
//   - N bytes: the serialized SCT
//
// Parameters:
//   - scts: The list of SCTs to embed
//
// Returns the extension or an error if encoding fails.
func MakeSCTListExtension(scts []SignedCertificateTimestamp) (pkix.Extension, error) {
	if len(scts) == 0 {
		return pkix.Extension{}, ErrNilInput
	}

	// Serialize each SCT
	var serializedSCTs [][]byte
	totalLen := 0
	for i := range scts {
		serialized, err := SerializeSCT(&scts[i])
		if err != nil {
			return pkix.Extension{}, caerrors.SerializationFailureError("SCT %d encoding failed: %v", i, err)
		}
		serializedSCTs = append(serializedSCTs, serialized)
		// 2 bytes for length prefix + serialized SCT
		totalLen += 2 + len(serialized)
	}

	// Build the SCT list
	// Format: 2-byte total length + (2-byte length + serialized SCT) for each SCT
	buf := new(bytes.Buffer)

	// Write total length of all SCTs (including their individual length prefixes)
	if err := binary.Write(buf, binary.BigEndian, uint16(totalLen)); err != nil {
		return pkix.Extension{}, caerrors.SerializationFailureError("SCT encoding failed: writing total length: %v", err)
	}

	// Write each SCT with its length prefix
	for _, serialized := range serializedSCTs {
		if err := binary.Write(buf, binary.BigEndian, uint16(len(serialized))); err != nil {
			return pkix.Extension{}, caerrors.SerializationFailureError("SCT encoding failed: writing SCT length: %v", err)
		}
		if _, err := buf.Write(serialized); err != nil {
			return pkix.Extension{}, caerrors.SerializationFailureError("SCT encoding failed: writing SCT: %v", err)
		}
	}

	// The SCT list extension value is the raw bytes wrapped in an OCTET STRING
	// per RFC 6962 Section 3.3
	value := buf.Bytes()

	// Wrap in OCTET STRING for the extension value
	// The extension value in X.509 is already an OCTET STRING,
	// but the SCT list itself is also encoded as a variable-length structure
	// that needs to be wrapped in an ASN.1 OCTET STRING
	wrappedValue := wrapInOctetString(value)

	return pkix.Extension{
		Id:       OIDSCTList,
		Critical: false,
		Value:    wrappedValue,
	}, nil
}

// wrapInOctetString wraps data in an ASN.1 OCTET STRING.
func wrapInOctetString(data []byte) []byte {
	// ASN.1 OCTET STRING tag is 0x04
	// Length encoding: if len < 128, single byte; otherwise, multi-byte
	length := len(data)

	var result []byte
	result = append(result, 0x04) // OCTET STRING tag

	switch {
	case length < 128:
		result = append(result, byte(length))
	case length < 256:
		result = append(result, 0x81, byte(length))
	case length < 65536:
		result = append(result, 0x82, byte(length>>8), byte(length&0xff))
	default:
		// Lengths > 65535 need 3+ bytes, but SCT lists shouldn't be that large
		result = append(result, 0x83, byte(length>>16), byte((length>>8)&0xff), byte(length&0xff))
	}

	result = append(result, data...)
	return result
}

// MakePrecertPoisonExtension creates the poison extension for precertificates.
// This extension marks a certificate as a precertificate per RFC 6962 Section 3.1.
//
// The poison extension:
//   - OID: 1.3.6.1.4.1.11129.2.4.3
//   - Critical: true
//   - Value: ASN.1 NULL (0x05 0x00)
//
// Returns the extension.
func MakePrecertPoisonExtension() pkix.Extension {
	// The value is ASN.1 NULL: tag 0x05, length 0x00
	return pkix.Extension{
		Id:       OIDPrecertPoison,
		Critical: true,
		Value:    []byte{0x05, 0x00}, // ASN.1 NULL
	}
}

// SerializeSCT serializes an SCT to its wire format per RFC 6962.
//
// Format:
//
//	struct {
//	    Version sct_version;             // 1 byte
//	    LogID id;                        // 32 bytes
//	    uint64 timestamp;                // 8 bytes
//	    CtExtensions extensions;         // 2 bytes length + data
//	    digitally-signed struct { ... }  // signature
//	}
func SerializeSCT(sct *SignedCertificateTimestamp) ([]byte, error) {
	if sct == nil {
		return nil, ErrNilInput
	}

	buf := new(bytes.Buffer)

	// Version (1 byte)
	buf.WriteByte(byte(sct.Version))

	// LogID (32 bytes)
	buf.Write(sct.LogID[:])

	// Timestamp (8 bytes, big-endian)
	if err := binary.Write(buf, binary.BigEndian, sct.Timestamp); err != nil {
		return nil, caerrors.SerializationFailureError("SCT encoding failed: writing timestamp: %v", err)
	}

	// Extensions (2 bytes length + data)
	if err := binary.Write(buf, binary.BigEndian, uint16(len(sct.Extensions))); err != nil {
		return nil, caerrors.SerializationFailureError("SCT encoding failed: writing extensions length: %v", err)
	}
	if len(sct.Extensions) > 0 {
		buf.Write(sct.Extensions)
	}

	// Signature
	// Hash algorithm (1 byte)
	buf.WriteByte(byte(sct.Signature.HashAlgorithm))

	// Signature algorithm (1 byte)
	buf.WriteByte(byte(sct.Signature.SigAlgorithm))

	// Signature (2 bytes length + data)
	if err := binary.Write(buf, binary.BigEndian, uint16(len(sct.Signature.Signature))); err != nil {
		return nil, caerrors.SerializationFailureError("SCT encoding failed: writing signature length: %v", err)
	}
	buf.Write(sct.Signature.Signature)

	return buf.Bytes(), nil
}

// DeserializeSCT deserializes an SCT from its wire format.
func DeserializeSCT(data []byte) (*SignedCertificateTimestamp, error) {
	if len(data) < 47 { // Minimum: 1 + 32 + 8 + 2 + 1 + 1 + 2 = 47 bytes
		return nil, ErrInvalidSCT
	}

	r := bytes.NewReader(data)
	sct := &SignedCertificateTimestamp{}

	// Version (1 byte)
	version, err := r.ReadByte()
	if err != nil {
		return nil, caerrors.SerializationFailureError("SCT decoding failed: reading version: %v", err)
	}
	sct.Version = Version(version)

	// LogID (32 bytes)
	if _, err := r.Read(sct.LogID[:]); err != nil {
		return nil, caerrors.SerializationFailureError("SCT decoding failed: reading log ID: %v", err)
	}

	// Timestamp (8 bytes)
	if err := binary.Read(r, binary.BigEndian, &sct.Timestamp); err != nil {
		return nil, caerrors.SerializationFailureError("SCT decoding failed: reading timestamp: %v", err)
	}

	// Extensions (2 bytes length + data)
	var extLen uint16
	if err := binary.Read(r, binary.BigEndian, &extLen); err != nil {
		return nil, caerrors.SerializationFailureError("SCT decoding failed: reading extensions length: %v", err)
	}
	if extLen > 0 {
		sct.Extensions = make([]byte, extLen)
		if _, err := r.Read(sct.Extensions); err != nil {
			return nil, caerrors.SerializationFailureError("SCT decoding failed: reading extensions: %v", err)
		}
	}

	// Hash algorithm (1 byte)
	hashAlg, err := r.ReadByte()
	if err != nil {
		return nil, caerrors.SerializationFailureError("SCT decoding failed: reading hash algorithm: %v", err)
	}
	sct.Signature.HashAlgorithm = HashAlgorithm(hashAlg)

	// Signature algorithm (1 byte)
	sigAlg, err := r.ReadByte()
	if err != nil {
		return nil, caerrors.SerializationFailureError("SCT decoding failed: reading signature algorithm: %v", err)
	}
	sct.Signature.SigAlgorithm = SignatureAlgorithm(sigAlg)

	// Signature (2 bytes length + data)
	var sigLen uint16
	if err := binary.Read(r, binary.BigEndian, &sigLen); err != nil {
		return nil, caerrors.SerializationFailureError("SCT decoding failed: reading signature length: %v", err)
	}
	sct.Signature.Signature = make([]byte, sigLen)
	if _, err := r.Read(sct.Signature.Signature); err != nil {
		return nil, caerrors.SerializationFailureError("SCT decoding failed: reading signature: %v", err)
	}

	return sct, nil
}

// ParseSCTList parses an SCT list extension value into individual SCTs.
func ParseSCTList(data []byte) ([]SignedCertificateTimestamp, error) {
	if len(data) == 0 {
		return nil, ErrNilInput
	}

	// Check for OCTET STRING wrapper
	if data[0] == 0x04 {
		var err error
		data, err = unwrapOctetString(data)
		if err != nil {
			return nil, err
		}
	}

	if len(data) < 2 {
		return nil, ErrInvalidSCT
	}

	r := bytes.NewReader(data)

	// Read total length
	var totalLen uint16
	if err := binary.Read(r, binary.BigEndian, &totalLen); err != nil {
		return nil, caerrors.SerializationFailureError("SCT decoding failed: reading total length: %v", err)
	}

	if int(totalLen) > r.Len() {
		return nil, caerrors.MalformedError("invalid SCT: declared length %d exceeds data length %d",
			totalLen, r.Len())
	}

	var scts []SignedCertificateTimestamp

	// Read each SCT
	bytesRead := 0
	for bytesRead < int(totalLen) {
		// Read SCT length
		var sctLen uint16
		if err := binary.Read(r, binary.BigEndian, &sctLen); err != nil {
			return nil, caerrors.SerializationFailureError("SCT decoding failed: reading SCT length: %v", err)
		}
		bytesRead += 2

		// Read SCT data
		sctData := make([]byte, sctLen)
		if _, err := r.Read(sctData); err != nil {
			return nil, caerrors.SerializationFailureError("SCT decoding failed: reading SCT data: %v", err)
		}
		bytesRead += int(sctLen)

		// Parse the SCT
		sct, err := DeserializeSCT(sctData)
		if err != nil {
			return nil, err
		}
		scts = append(scts, *sct)
	}

	return scts, nil
}

// unwrapOctetString removes the ASN.1 OCTET STRING wrapper.
func unwrapOctetString(data []byte) ([]byte, error) {
	if len(data) < 2 {
		return nil, ErrInvalidSCT
	}

	if data[0] != 0x04 {
		return nil, caerrors.MalformedError("invalid SCT: expected OCTET STRING tag 0x04, got 0x%02x", data[0])
	}

	// Parse length
	length := int(data[1])
	offset := 2

	if length&0x80 != 0 {
		// Multi-byte length
		numBytes := length & 0x7f
		if len(data) < offset+numBytes {
			return nil, ErrInvalidSCT
		}
		length = 0
		for i := 0; i < numBytes; i++ {
			length = length<<8 | int(data[offset])
			offset++
		}
	}

	if len(data) < offset+length {
		return nil, ErrInvalidSCT
	}

	return data[offset : offset+length], nil
}

// HasPrecertPoison checks if a certificate contains the precert poison extension.
func HasPrecertPoison(extensions []pkix.Extension) bool {
	for _, ext := range extensions {
		if ext.Id.Equal(OIDPrecertPoison) {
			return true
		}
	}
	return false
}

// ValidatePrecertPoison validates the precert poison extension.
// Returns nil if valid, an error otherwise.
func ValidatePrecertPoison(extensions []pkix.Extension) error {
	for _, ext := range extensions {
		if ext.Id.Equal(OIDPrecertPoison) {
			// Must be critical
			if !ext.Critical {
				return ErrPrecertPoisonInvalid
			}

			// Value must be ASN.1 NULL (0x05 0x00)
			if len(ext.Value) != 2 || ext.Value[0] != 0x05 || ext.Value[1] != 0x00 {
				return ErrPrecertPoisonInvalid
			}

			return nil
		}
	}
	return ErrPrecertPoisonMissing
}

// HasSCTList checks if a certificate contains the SCT list extension.
func HasSCTList(extensions []pkix.Extension) bool {
	for _, ext := range extensions {
		if ext.Id.Equal(OIDSCTList) {
			return true
		}
	}
	return false
}

// GetSCTListExtension extracts the SCT list extension from a certificate.
// Returns nil if not found.
func GetSCTListExtension(extensions []pkix.Extension) *pkix.Extension {
	for i := range extensions {
		if extensions[i].Id.Equal(OIDSCTList) {
			return &extensions[i]
		}
	}
	return nil
}
