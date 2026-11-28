package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

// importParamsFile is the file that key get-import-params --output writes
// and key wrap / key unwrap --params read. ImportParameters carries the
// wrapping public key as a crypto.PublicKey interface, which JSON decodes
// back as a string; the file holds the key bytes as a []byte (base64 in
// JSON) so they round-trip.
type importParamsFile struct {
	WrappingPublicKey []byte
	ImportToken       []byte
	Algorithm         client.WrappingAlgorithm
	ExpiresAt         *time.Time
	KeySpec           string
}

// errImportParamsNoWrappingKey reports import parameters without a
// wrapping public key, which key wrap needs.
var errImportParamsNoWrappingKey = errors.New("import parameters have no WrappingPublicKey")

// wrappingKeyBytes returns the wrapping public key bytes of params.
func wrappingKeyBytes(params *client.ImportParameters) ([]byte, error) {
	pubKey, ok := params.WrappingPublicKey.([]byte)
	if !ok {
		return nil, &WrappedDetailError{Sentinel: ErrWrappingKeyUnexpectedType, Detail: fmt.Sprintf("%T", params.WrappingPublicKey)}
	}
	if len(pubKey) == 0 {
		return nil, errImportParamsNoWrappingKey
	}
	return pubKey, nil
}

// encodeImportParams renders params as the import-params file.
func encodeImportParams(params *client.ImportParameters) ([]byte, error) {
	pubKey, err := wrappingKeyBytes(params)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(importParamsFile{
		WrappingPublicKey: pubKey,
		ImportToken:       params.ImportToken,
		Algorithm:         params.Algorithm,
		ExpiresAt:         params.ExpiresAt,
		KeySpec:           params.KeySpec,
	}, "", "  ")
}

// decodeImportParams parses an import-params file.
func decodeImportParams(data []byte) (*client.ImportParameters, error) {
	var f importParamsFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	return &client.ImportParameters{
		WrappingPublicKey: f.WrappingPublicKey,
		ImportToken:       f.ImportToken,
		Algorithm:         f.Algorithm,
		ExpiresAt:         f.ExpiresAt,
		KeySpec:           f.KeySpec,
	}, nil
}
