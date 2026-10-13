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

// Package enclaveprovider is the hardware bridge for go-enclave's provider
// seam. It implements enclave.KeyProtector (ModePerOperation) and
// enclave.RootUnsealer (ModeRootKey) over any go-xkms types.Sealer, so a
// go-enclave Sealer can keep its keys under a TPM 2.0, a PKCS#11 token,
// AWS KMS, Azure Key Vault, GCP Cloud KMS or HashiCorp Vault:
//
//	protector, err := enclaveprovider.NewKeyProtector(tpm, sealingKey)
//	if err != nil {
//		return err
//	}
//	sealer, err := enclave.NewSealer(enclave.WithKeyProtector(protector))
//
// For ModeRootKey, ProvisionRoot generates a root key in locked memory and
// seals it once; the caller persists the returned blob and hands it to
// NewRootUnsealer on every later start.
//
// Every blob is a versioned envelope around the backend's types.SealedData.
// The sealer binds a purpose-specific AAD, so a protected data key never
// opens as a sealed root and the reverse, and an HMAC-SHA256 tag keyed from
// the protected key covers every byte of the envelope, including the fields
// a backend ignores when it unseals. Anything the provider did not produce
// fails with an error matching enclave.ErrSealedAuthentication; a failure of
// the backend itself keeps the backend's own error.
package enclaveprovider
