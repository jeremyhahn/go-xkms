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

package tpm2

import (
	"log/slog"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// storageKeyTemplates maps a parent's key type to the child storage key
// template of the same family: a restricted decryption key with an
// AES-128-CFB symmetric definition, RSA 2048 or ECC P-256 (TCG TPM v2.0
// Provisioning Guidance, section 7.5.1).
var storageKeyTemplates = map[tpm2.TPMAlgID]tpm2.TPMTPublic{
	tpm2.TPMAlgRSA: tpm2.RSASRKTemplate,
	tpm2.TPMAlgECC: tpm2.ECCSRKTemplate,
}

// CreateStorageKey creates a restricted-decrypt storage key under
// attrs.Parent, in the parent's key family, with attrs.Password as its
// authValue, and saves its blobs in backend under attrs.CN. backend may be
// nil, in which case the platform backend is used.
//
// This is a tenant's storage key in "shared" TPM mode: a child of the
// Platform SRK whose authValue is the tenant's secret, so one tenant cannot
// load another's objects. The key is not left loaded. To create keys beneath
// it, load it with LoadKeyPair, set the returned handle and Name on its
// TPMAttributes, and name it as their Parent; CreateSession then authorizes
// it with its password.
//
// The key is NoDA, like the templates it is built from: its authValue is a
// random secret, so dictionary-attack protection would only let one tenant's
// failed attempts lock the TPM out for every tenant.
func (tpm *TPM2) CreateStorageKey(attrs *types.KeyAttributes, backend store.KeyBackend) error {
	if attrs == nil {
		return store.ErrInvalidKeyAttributes
	}
	if attrs.Parent == nil || attrs.Parent.TPMAttributes == nil {
		return store.ErrInvalidParentAttributes
	}

	parentHandle := attrs.Parent.TPMAttributes.Handle
	parentName, parentPub, err := tpm.ReadHandle(parentHandle)
	if err != nil {
		return err
	}
	template, ok := storageKeyTemplates[parentPub.Type]
	if !ok {
		return store.ErrUnsupportedKeyAlgorithm
	}
	template.NameAlg = tpm.algID

	var keyAuth []byte
	if attrs.Password != nil {
		keyAuth = attrs.Password.Bytes()
	}

	session, closer, err := tpm.CreateSession(attrs)
	if err != nil {
		return err
	}
	defer tpm.closeSession(closer, "storage key parent")

	// The sensitive area carries the new key's authValue; see CreateRSA.
	encSession, closeEncSession, err := tpm.encryptionSession(encryptIn)
	if err != nil {
		return err
	}
	defer tpm.closeSession(closeEncSession, "storage key creation encryption")

	response, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: parentHandle,
			Name:   parentName,
			Auth:   session,
		},
		InPublic: tpm2.New2B(template),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{Buffer: keyAuth},
			},
		},
	}.Execute(tpm.transport, encSession)
	if err != nil {
		tpm.logger.Error("tpm: failed to create storage key",
			slog.String("cn", attrs.CN),
			slog.String("error", err.Error()))
		return err
	}

	pub, err := response.OutPublic.Contents()
	if err != nil {
		return err
	}
	name, err := tpm2.ObjectName(pub)
	if err != nil {
		return err
	}
	if attrs.TPMAttributes == nil {
		attrs.TPMAttributes = &types.TPMAttributes{}
	}
	attrs.TPMAttributes.Name = *name
	attrs.TPMAttributes.Public = *pub

	return tpm.SaveKeyPair(attrs, response.OutPrivate, response.OutPublic, backend, false)
}
