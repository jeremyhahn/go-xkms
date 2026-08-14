package tpm2

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
)

// Encode returns the hexadecimal form of bytes.
func Encode(bytes []byte) string {
	return hex.EncodeToString(bytes)
}

// Decode parses the hexadecimal form s into a byte slice.
func Decode(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

// Encodes a quote to binary using the encoding/gob package
func EncodeQuote(quote Quote) ([]byte, error) {
	buf := new(bytes.Buffer)
	encoder := gob.NewEncoder(buf)
	if err := encoder.Encode(quote); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Decodes a quote from binary using the encoding/gob package
func DecodeQuote(quote []byte) (Quote, error) {
	var q Quote
	buf := bytes.NewBuffer(quote)
	decoder := gob.NewDecoder(buf)
	if err := decoder.Decode(&q); err != nil {
		return Quote{}, err
	}
	return q, nil
}

// Encodes a PCR bank slice to binary using the encoding/gob package
func EncodePCRs(pcrBanks []PCRBank) ([]byte, error) {
	buf := new(bytes.Buffer)
	encoder := gob.NewEncoder(buf)
	if err := encoder.Encode(pcrBanks); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Decodes a PCR bank slice from binary using the encoding/gob package
func DecodePCRs(pcrBanks []byte) ([]PCRBank, error) {
	banks := make([]PCRBank, 0)
	buf := bytes.NewBuffer(pcrBanks)
	decoder := gob.NewDecoder(buf)
	if err := decoder.Decode(&banks); err != nil {
		return nil, err
	}
	return banks, nil
}
