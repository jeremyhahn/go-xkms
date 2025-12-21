// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package tpm2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
)

// ProdCaData errors
var (
	ErrInvalidProdCaData  = errors.New("tpm: invalid ProdCaData structure")
	ErrProdCaDataTooLarge = errors.New("tpm: ProdCaData field too large")
)

// ProdCaData represents CA-specific data that is included in the TCG-CSR-IDEVID.
// Per TCG TPM 2.0 Keys for Device Identity and Attestation specification,
// the prodCaData field is intended for CA-specific required data.
//
// This implementation uses ProdCaData to carry TPM attestation data (Quote + PCRs)
// from the client to the server during enrollment, enabling the server to store
// the device's initial attestation state upon successful IDevID issuance.
//
// Structure format (all fields are big-endian):
//   - Version:      4 bytes - structure version (0x00000001)
//   - QuotedSz:     4 bytes - size of Quoted data
//   - SignatureSz:  4 bytes - size of Signature
//   - NonceSz:      4 bytes - size of Nonce
//   - PCRsSz:       4 bytes - size of PCRs
//   - Quoted:       QuotedSz bytes - TPM2_Quote TPMS_ATTEST structure
//   - Signature:    SignatureSz bytes - Quote signature
//   - Nonce:        NonceSz bytes - Qualifying data used in quote
//   - PCRs:         PCRsSz bytes - Encoded PCR values
type ProdCaData struct {
	Version     uint32
	QuotedSz    uint32
	SignatureSz uint32
	NonceSz     uint32
	PCRsSz      uint32
	Quoted      []byte
	Signature   []byte
	Nonce       []byte
	PCRs        []byte
}

// ProdCaDataVersion is the current version of the ProdCaData structure
const ProdCaDataVersion uint32 = 0x00000001

// NewProdCaData creates a ProdCaData structure from a Quote.
// Returns nil if the quote is nil or empty.
func NewProdCaData(quote *Quote) (*ProdCaData, error) {
	if quote == nil {
		return nil, nil
	}

	// Validate sizes don't exceed uint32
	if len(quote.Quoted) > math.MaxUint32 {
		return nil, ErrProdCaDataTooLarge
	}
	if len(quote.Signature) > math.MaxUint32 {
		return nil, ErrProdCaDataTooLarge
	}
	if len(quote.Nonce) > math.MaxUint32 {
		return nil, ErrProdCaDataTooLarge
	}
	if len(quote.PCRs) > math.MaxUint32 {
		return nil, ErrProdCaDataTooLarge
	}

	return &ProdCaData{
		Version:     ProdCaDataVersion,
		QuotedSz:    uint32(len(quote.Quoted)),    // #nosec G115 -- validated above
		SignatureSz: uint32(len(quote.Signature)), // #nosec G115 -- validated above
		NonceSz:     uint32(len(quote.Nonce)),     // #nosec G115 -- validated above
		PCRsSz:      uint32(len(quote.PCRs)),      // #nosec G115 -- validated above
		Quoted:      quote.Quoted,
		Signature:   quote.Signature,
		Nonce:       quote.Nonce,
		PCRs:        quote.PCRs,
	}, nil
}

// ToQuote converts ProdCaData back to a Quote structure.
// Note: EventLog is not included in ProdCaData (it's in BootEvntLog field).
func (p *ProdCaData) ToQuote() *Quote {
	return &Quote{
		Quoted:    p.Quoted,
		Signature: p.Signature,
		Nonce:     p.Nonce,
		PCRs:      p.PCRs,
		EventLog:  nil, // EventLog is carried in BootEvntLog, not ProdCaData
	}
}

// PackProdCaData serializes a ProdCaData structure into a big-endian byte array.
func PackProdCaData(data *ProdCaData) ([]byte, error) {
	if data == nil {
		return nil, nil
	}

	var buf bytes.Buffer

	// Write header fields (version and sizes)
	if err := binary.Write(&buf, binary.BigEndian, data.Version); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, data.QuotedSz); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, data.SignatureSz); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, data.NonceSz); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, data.PCRsSz); err != nil {
		return nil, err
	}

	// Write payload fields
	if _, err := buf.Write(data.Quoted); err != nil {
		return nil, err
	}
	if _, err := buf.Write(data.Signature); err != nil {
		return nil, err
	}
	if _, err := buf.Write(data.Nonce); err != nil {
		return nil, err
	}
	if _, err := buf.Write(data.PCRs); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// UnpackProdCaData deserializes a big-endian byte array into a ProdCaData structure.
func UnpackProdCaData(data []byte) (*ProdCaData, error) {
	if len(data) == 0 {
		return nil, nil
	}

	reader := bytes.NewReader(data)

	// Read header fields
	var version, quotedSz, signatureSz, nonceSz, pcrsSz uint32

	if err := binary.Read(reader, binary.BigEndian, &version); err != nil {
		return nil, ErrInvalidProdCaData
	}

	// Validate version
	if version != ProdCaDataVersion {
		return nil, ErrInvalidProdCaData
	}

	if err := binary.Read(reader, binary.BigEndian, &quotedSz); err != nil {
		return nil, ErrInvalidProdCaData
	}
	if err := binary.Read(reader, binary.BigEndian, &signatureSz); err != nil {
		return nil, ErrInvalidProdCaData
	}
	if err := binary.Read(reader, binary.BigEndian, &nonceSz); err != nil {
		return nil, ErrInvalidProdCaData
	}
	if err := binary.Read(reader, binary.BigEndian, &pcrsSz); err != nil {
		return nil, ErrInvalidProdCaData
	}

	// Validate that remaining data is sufficient
	headerSize := 5 * 4 // 5 uint32 fields
	expectedDataSize := int64(headerSize) + int64(quotedSz) + int64(signatureSz) + int64(nonceSz) + int64(pcrsSz)
	if int64(len(data)) < expectedDataSize {
		return nil, ErrInvalidProdCaData
	}

	// Read payload fields (skip reads when size is 0 to avoid EOF at boundary)
	var quoted []byte
	if quotedSz > 0 {
		quoted = make([]byte, quotedSz)
		if _, err := reader.Read(quoted); err != nil {
			return nil, ErrInvalidProdCaData
		}
	}

	var signature []byte
	if signatureSz > 0 {
		signature = make([]byte, signatureSz)
		if _, err := reader.Read(signature); err != nil {
			return nil, ErrInvalidProdCaData
		}
	}

	var nonce []byte
	if nonceSz > 0 {
		nonce = make([]byte, nonceSz)
		if _, err := reader.Read(nonce); err != nil {
			return nil, ErrInvalidProdCaData
		}
	}

	var pcrs []byte
	if pcrsSz > 0 {
		pcrs = make([]byte, pcrsSz)
		if _, err := reader.Read(pcrs); err != nil {
			return nil, ErrInvalidProdCaData
		}
	}

	return &ProdCaData{
		Version:     version,
		QuotedSz:    quotedSz,
		SignatureSz: signatureSz,
		NonceSz:     nonceSz,
		PCRsSz:      pcrsSz,
		Quoted:      quoted,
		Signature:   signature,
		Nonce:       nonce,
		PCRs:        pcrs,
	}, nil
}
