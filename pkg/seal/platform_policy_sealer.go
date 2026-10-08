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

package seal

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Compile-time interface check.
var _ types.Sealer = (*PlatformPolicySealer)(nil)

// PlatformPolicySealer wraps a raw TPM2 types.Sealer so every Seal/Unseal
// call is parented to the enrolled Platform SRK (go-xkms never seals under
// the TCG Shared SRK) and binds the sealed object itself to the built-in
// "platform" TPM policy (types.TPMPolicyPlatform), whatever key attributes
// the caller supplied.
//
// It exists because pkg/storage/sealed.Backend, which a PlatformStore is
// composed over, always unseals with nil *types.UnsealOptions, so neither
// the parent nor the policy can be threaded through the caller's options on
// the unseal side. This type supplies both on both paths instead. The
// caller's AAD is passed through, so a value sealed under one AAD fails
// with types.ErrSealedDataAuthentication under another.
//
// It is the one such adapter: the qrdb-backed platform store (pkg/server)
// and the pre-barrier store (pkg/preseal) both wrap their TPM with it, each
// under its own CN.
type PlatformPolicySealer struct {
	inner     types.Sealer
	cn        string
	psrkAttrs *types.KeyAttributes
}

// NewPlatformPolicySealer returns a PlatformPolicySealer that parents every
// Seal/Unseal of inner to psrkAttrs, the caller's enrolled Platform SRK,
// and names the sealed object cn.
func NewPlatformPolicySealer(inner types.Sealer, cn string, psrkAttrs *types.KeyAttributes) *PlatformPolicySealer {
	return &PlatformPolicySealer{inner: inner, cn: cn, psrkAttrs: psrkAttrs}
}

// CanSeal delegates to the wrapped sealer.
func (p *PlatformPolicySealer) CanSeal() bool {
	return p.inner.CanSeal()
}

// keyAttrs builds a fresh KeyAttributes identifying the sealed object. A
// fresh value is built per call because the TPM library mutates a sealed
// object's KeyAttributes in place (SealData, TPMAttributes.Name/Handle), and
// reusing one would leak state from one call into the next.
func (p *PlatformPolicySealer) keyAttrs() *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:        p.cn,
		Parent:    p.psrkAttrs,
		TPMPolicy: types.TPMPolicyPlatform,
	}
}

// Seal seals data under the Platform SRK and the platform policy, keeping
// only the AAD of opts.
func (p *PlatformPolicySealer) Seal(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	sealOpts := &types.SealOptions{KeyAttributes: p.keyAttrs()}
	if opts != nil {
		sealOpts.AAD = opts.AAD
	}
	return p.inner.Seal(ctx, data, sealOpts)
}

// Unseal unseals data under the Platform SRK and the platform policy,
// keeping only the AAD of opts. The policy session is built from the live
// PCRs, so a platform state that no longer matches the one the object was
// sealed under fails TPM2_PolicyPCR and surfaces as an unseal error, never
// a fallback.
func (p *PlatformPolicySealer) Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	unsealOpts := &types.UnsealOptions{KeyAttributes: p.keyAttrs()}
	if opts != nil {
		unsealOpts.AAD = opts.AAD
	}
	return p.inner.Unseal(ctx, sealed, unsealOpts)
}
