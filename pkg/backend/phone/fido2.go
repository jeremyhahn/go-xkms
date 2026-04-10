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

package phone

import (
	"context"

	phoneproto "github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

// ListFido2Credentials retrieves FIDO2 credentials from the phone that are
// registered for the given relying party identifier. The phone returns
// credential metadata without exposing private key material.
func (b *Backend) ListFido2Credentials(ctx context.Context, rpID string) ([]phoneproto.Fido2CredentialInfo, error) {
	if b.closed.Load() {
		return nil, ErrBackendClosed
	}
	if rpID == "" {
		return nil, ErrInvalidRpID
	}

	resp, err := b.sendLocalRequest(ctx, phoneproto.MethodLocalListFido2Credentials, &phoneproto.LocalListFido2CredentialsParams{
		RpID: rpID,
	})
	if err != nil {
		return nil, err
	}

	result, err := phoneproto.DecodeResult[phoneproto.LocalListFido2CredentialsResult](resp)
	if err != nil {
		return nil, ErrInvalidResponse
	}

	return result.Credentials, nil
}

// SignFido2Assertion requests the phone to produce a FIDO2 assertion signature
// for the specified credential. The phone performs user verification if required,
// increments the signature counter, and returns the authenticator data and
// signature. Private keys never leave the phone's secure hardware.
func (b *Backend) SignFido2Assertion(ctx context.Context, params *phoneproto.LocalSignFido2AssertionParams) (*phoneproto.LocalSignFido2AssertionResult, error) {
	if b.closed.Load() {
		return nil, ErrBackendClosed
	}
	if params == nil {
		return nil, ErrInvalidConfig
	}
	if len(params.CredentialID) == 0 {
		return nil, ErrInvalidCredentialID
	}
	if len(params.ClientDataHash) == 0 {
		return nil, ErrInvalidClientDataHash
	}
	if params.RpID == "" {
		return nil, ErrInvalidRpID
	}

	resp, err := b.sendLocalRequest(ctx, phoneproto.MethodLocalSignFido2Assertion, params)
	if err != nil {
		return nil, err
	}

	result, err := phoneproto.DecodeResult[phoneproto.LocalSignFido2AssertionResult](resp)
	if err != nil {
		return nil, ErrInvalidResponse
	}

	return result, nil
}

// GetFido2CredentialInfo retrieves detailed information about a key stored on
// the phone. When the key type is "fido2", the result includes FIDO2-specific
// fields such as relying party ID, user handle, and signature counter.
func (b *Backend) GetFido2CredentialInfo(ctx context.Context, keyID string) (*phoneproto.LocalGetKeyInfoResult, error) {
	if b.closed.Load() {
		return nil, ErrBackendClosed
	}
	if keyID == "" {
		return nil, ErrEmptyKeyID
	}

	resp, err := b.sendLocalRequest(ctx, phoneproto.MethodLocalGetKeyInfo, &phoneproto.LocalGetKeyInfoParams{
		KeyID: keyID,
	})
	if err != nil {
		return nil, err
	}

	result, err := phoneproto.DecodeResult[phoneproto.LocalGetKeyInfoResult](resp)
	if err != nil {
		return nil, ErrInvalidResponse
	}

	return result, nil
}
