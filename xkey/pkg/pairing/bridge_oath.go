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

package pairing

import (
	"context"
	"encoding/json"
)

// handleOATHAdd handles remote.oathAdd - the phone sends an OATH credential
// to the laptop for storage.
//
// This is a placeholder implementation. The bridge will be connected to the
// OATH store in the CLI layer when the OATH command is invoked. The actual
// credential storage logic will be implemented via a setter or functional
// option on the Bridge.
func (b *Bridge) handleOATHAdd(_ context.Context, params json.RawMessage) (interface{}, error) {
	var p RemoteOATHAddParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, ErrBridgeInvalidParams
	}

	if p.Credential.Name == "" {
		return nil, ErrBridgeInvalidParams
	}

	if p.Credential.Secret == "" {
		return nil, ErrBridgeInvalidParams
	}

	b.logger.Info("OATH credential add requested",
		"name", p.Credential.Name,
		"issuer", p.Credential.Issuer,
		"type", p.Credential.Type)

	return &RemoteOATHAddResult{
		Success:      true,
		CredentialID: "",
		Message:      "credential received",
	}, nil
}

// handleOATHGenerate handles remote.oathGenerate - the phone requests the
// laptop to generate the current OTP code for a credential.
//
// This is a placeholder implementation. The actual OTP generation logic
// (looking up the credential, computing TOTP/HOTP) will be implemented
// via an OATH store and generator wired in when the feature is enabled.
func (b *Bridge) handleOATHGenerate(_ context.Context, params json.RawMessage) (interface{}, error) {
	var p RemoteOATHGenerateParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, ErrBridgeInvalidParams
	}

	if p.CredentialID == "" {
		return nil, ErrBridgeInvalidParams
	}

	b.logger.Info("OATH code generation requested",
		"credentialID", p.CredentialID)

	return &RemoteOATHGenerateResult{
		Code:      "",
		ExpiresIn: 0,
	}, nil
}
