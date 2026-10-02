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
	"errors"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
)

// handleOATHAdd handles remote.oathAdd - the phone sends an OATH credential
// to the laptop for storage.
//
// The credential is stored through the Bridge's configured oath.Store (see
// BridgeConfig.OATHStore), the same Store interface xkey's "oath" command
// family and its file/composite stores implement. When no store is
// configured, ErrOATHNotConfigured is returned rather than a fabricated
// success.
func (b *Bridge) handleOATHAdd(_ context.Context, params json.RawMessage) (interface{}, error) {
	var p RemoteOATHAddParams
	defer p.Credential.Destroy()
	if err := unmarshalParams(params, &p); err != nil {
		return nil, ErrBridgeInvalidParams
	}

	if p.Credential.Name == "" {
		return nil, ErrBridgeInvalidParams
	}

	if p.Credential.Secret.IsZero() {
		return nil, ErrBridgeInvalidParams
	}

	if b.oathStore == nil {
		return nil, ErrOATHNotConfigured
	}

	b.logger.Info("OATH credential add requested",
		"name", p.Credential.Name,
		"issuer", p.Credential.Issuer,
		"type", p.Credential.Type)

	cred, err := oathCredentialFromWire(&p.Credential)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrOATHStoreFailed, Cause: err}
	}

	if err := b.oathStore.Add(cred); err != nil {
		if errors.Is(err, oath.ErrCredentialExists) {
			return nil, ErrKeyExists
		}
		return nil, &SentinelCauseError{Sentinel: ErrOATHStoreFailed, Cause: err}
	}

	return &RemoteOATHAddResult{
		Success:      true,
		CredentialID: cred.ID,
		Message:      "credential stored",
	}, nil
}

// handleOATHGenerate handles remote.oathGenerate - the phone requests the
// laptop to generate the current OTP code for a credential.
//
// The credential is looked up in the Bridge's configured oath.Store and the
// code is produced by oath.Generator, the same generator the "oath" command
// family uses. When no store is configured, ErrOATHNotConfigured is
// returned.
func (b *Bridge) handleOATHGenerate(_ context.Context, params json.RawMessage) (interface{}, error) {
	var p RemoteOATHGenerateParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, ErrBridgeInvalidParams
	}

	if p.CredentialID == "" {
		return nil, ErrBridgeInvalidParams
	}

	if b.oathStore == nil {
		return nil, ErrOATHNotConfigured
	}

	b.logger.Info("OATH code generation requested",
		"credentialID", p.CredentialID)

	cred, err := b.oathStore.Get(p.CredentialID)
	if err != nil {
		if errors.Is(err, oath.ErrCredentialNotFound) {
			return nil, ErrOATHCredentialNotFound
		}
		return nil, &SentinelCauseError{Sentinel: ErrOATHStoreFailed, Cause: err}
	}

	gen, err := oath.NewGenerator(cred)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrOATHGenerateFailed, Cause: err}
	}

	code, err := gen.Generate()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrOATHGenerateFailed, Cause: err}
	}

	var expiresIn int
	if cred.Type == oath.TypeTOTP && cred.Period > 0 {
		expiresIn = cred.Period - int(time.Now().Unix()%int64(cred.Period))
	}

	return &RemoteOATHGenerateResult{
		Code:      code,
		ExpiresIn: expiresIn,
	}, nil
}

// oathCredentialFromWire builds an oath.Credential from a phone-supplied
// OATHCredentialInfo, applying the same defaults NewCredentialFromManualEntry
// applies when the phone omits optional fields, and minting the ID with the
// package's own GenerateCredentialID so it matches what every store already
// keys entries by.
func oathCredentialFromWire(info *OATHCredentialInfo) (*oath.Credential, error) {
	accountForID := info.AccountName
	if accountForID == "" {
		accountForID = info.Name
	}

	cred := &oath.Credential{
		ID:          oath.GenerateCredentialID(info.Issuer, accountForID),
		Name:        info.Name,
		Issuer:      info.Issuer,
		AccountName: info.AccountName,
		Type:        info.Type,
		Algorithm:   info.Algorithm,
		Digits:      info.Digits,
		Period:      info.Period,
		Counter:     info.Counter,
		CreatedAt:   time.Now(),
	}

	if cred.Type == "" {
		cred.Type = oath.TypeTOTP
	}
	if cred.Algorithm == "" {
		cred.Algorithm = oath.DefaultAlgorithm
	}
	if cred.Digits == 0 {
		cred.Digits = oath.DefaultDigits
	}
	if cred.Type == oath.TypeTOTP && cred.Period == 0 {
		cred.Period = oath.DefaultPeriod
	}

	if err := setCredentialSecret(cred, info.Secret); err != nil {
		return nil, err
	}

	return cred, nil
}

// setCredentialSecret copies the secret a phone supplied into cred's protected
// memory. The plaintext exists only for the duration of the call.
func setCredentialSecret(cred *oath.Credential, secret xkms.SecretText) error {
	plain, err := secret.Copy()
	if err != nil {
		return err
	}
	defer secure.Wipe(plain)
	return cred.SetSecret(plain)
}
