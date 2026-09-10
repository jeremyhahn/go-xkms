// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package wire holds the REST bodies of the BYOK ceremony (import parameters,
// wrap, unwrap, import) and their translation to and from the transport
// contract. It is a leaf so the REST and QUIC client transports can build the
// bodies by name; the REST server package aliases these types, so the client
// and the handler are one definition.
package wire

import (
	"crypto/x509"
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/encoding"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// ErrWrappingPublicKeyNotDER is returned when a transport request's wrapping
// public key is not DER-encoded PKIX, the encoding the transport contract
// specifies and the one this package turns into the PEM the REST body carries.
var ErrWrappingPublicKeyNotDER = errors.New("rest/wire: wrapping public key is not DER-encoded PKIX")

// WrappingPublicKeyError carries the parse failure behind
// ErrWrappingPublicKeyNotDER.
type WrappingPublicKeyError struct {
	Err error
}

func (e *WrappingPublicKeyError) Error() string {
	return ErrWrappingPublicKeyNotDER.Error() + ": " + e.Err.Error()
}

func (e *WrappingPublicKeyError) Unwrap() error { return e.Err }

func (e *WrappingPublicKeyError) Is(target error) bool { return target == ErrWrappingPublicKeyNotDER }

// The BYOK ceremony (import parameters, wrap, unwrap, import) is the one
// place the REST body and the transport contract spell the same fields
// differently: the REST body carries the wrapped material as "wrapped_key"
// and the wrapping key as PEM text under "wrapping_public_key_pem", while
// transport.*Request carries "wrapped_key_material" and DER bytes under
// "wrapping_public_key". The REST and QUIC client transports used to marshal
// the transport struct straight onto the route, so every import, wrap and
// unwrap over those two transports arrived with the material or the wrapping
// key absent, and the import-parameters response came back with no wrapping
// key. These constructors are the one place the translation lives: the client
// transports build the REST body by name, so the two sides are linked at
// compile time, and the contract test in this package pins every field.

// NewGetImportParametersRequest builds the REST body for the transport
// request.
func NewGetImportParametersRequest(req *transport.GetImportParametersRequest) GetImportParametersRequest {
	return GetImportParametersRequest{
		Backend:   req.Backend,
		KeyID:     req.KeyID,
		KeyType:   req.KeyType,
		Algorithm: req.Algorithm,
		KeySize:   req.KeySize,
		Curve:     req.Curve,
	}
}

// Transport converts the REST response to the transport contract, decoding
// the PEM wrapping key to the DER the contract carries.
func (r GetImportParametersResponse) Transport() (*transport.GetImportParametersResponse, error) {
	resp := &transport.GetImportParametersResponse{
		ImportToken: r.ImportToken,
		Algorithm:   r.Algorithm,
		ExpiresAt:   r.ExpiresAt,
		KeySpec:     r.KeySpec,
	}
	if r.WrappingPublicKeyPEM == "" {
		return resp, nil
	}
	der, err := wrappingPublicKeyDER(r.WrappingPublicKeyPEM)
	if err != nil {
		return nil, err
	}
	resp.WrappingPublicKey = der
	return resp, nil
}

// NewWrapKeyRequest builds the REST body for the transport request, encoding
// the DER wrapping key as the PEM the body carries.
func NewWrapKeyRequest(req *transport.WrapKeyRequest) (WrapKeyRequest, error) {
	pem, err := wrappingPublicKeyPEM(req.WrappingPublicKey)
	if err != nil {
		return WrapKeyRequest{}, err
	}
	return WrapKeyRequest{
		Backend:              req.Backend,
		KeyMaterial:          req.KeyMaterial,
		WrappingPublicKeyPEM: pem,
		ImportToken:          req.ImportToken,
		Algorithm:            req.Algorithm,
		KeySpec:              req.KeySpec,
	}, nil
}

// Transport converts the REST wrap response to the transport contract.
func (r WrapKeyResponse) Transport() *transport.WrapKeyResponse {
	return &transport.WrapKeyResponse{
		WrappedKeyMaterial: r.WrappedKey,
		Algorithm:          r.Algorithm,
		Metadata:           r.Metadata,
	}
}

// NewUnwrapKeyRequest builds the REST body for the transport request.
func NewUnwrapKeyRequest(req *transport.UnwrapKeyRequest) (UnwrapKeyRequest, error) {
	pem, err := wrappingPublicKeyPEM(req.WrappingPublicKey)
	if err != nil {
		return UnwrapKeyRequest{}, err
	}
	return UnwrapKeyRequest{
		Backend:              req.Backend,
		WrappedKey:           req.WrappedKeyMaterial,
		WrappingPublicKeyPEM: pem,
		ImportToken:          req.ImportToken,
		Algorithm:            req.Algorithm,
		KeySpec:              req.KeySpec,
		Metadata:             req.Metadata,
	}, nil
}

// NewImportKeyRequest builds the REST body for the transport request.
func NewImportKeyRequest(req *transport.ImportKeyRequest) ImportKeyRequest {
	return ImportKeyRequest{
		Backend:     req.Backend,
		KeyID:       req.KeyID,
		KeyType:     req.KeyType,
		WrappedKey:  req.WrappedKeyMaterial,
		ImportToken: req.ImportToken,
		Algorithm:   req.Algorithm,
		KeySize:     req.KeySize,
		Curve:       req.Curve,
		Hash:        req.Hash,
		AESKeySize:  req.AESKeySize,
		Partition:   req.Partition,
		Metadata:    req.Metadata,
		Exportable:  req.Exportable,
		Sensitive:   req.Sensitive,
	}
}

// wrappingPublicKeyPEM turns the transport contract's DER wrapping key into
// the PEM text the REST body carries; an absent key stays absent.
func wrappingPublicKeyPEM(der []byte) (string, error) {
	if len(der) == 0 {
		return "", nil
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return "", &WrappingPublicKeyError{Err: err}
	}
	pem, err := encoding.EncodePublicKeyPEM(pub)
	if err != nil {
		return "", &errs.Wrapped{Msg: "rest: encode wrapping public key", Err: err}
	}
	return string(pem), nil
}

// wrappingPublicKeyDER turns the REST body's PEM wrapping key into the DER
// the transport contract carries.
func wrappingPublicKeyDER(pem string) ([]byte, error) {
	pub, err := encoding.DecodePublicKeyPEM([]byte(pem))
	if err != nil {
		return nil, &errs.Wrapped{Msg: "rest: decode wrapping public key", Err: err}
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "rest: encode wrapping public key", Err: err}
	}
	return der, nil
}
