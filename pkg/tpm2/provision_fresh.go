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
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// ErrFreshProvisionConfig is returned by ProvisionFresh when the
// configuration lacks the EK, Shared SRK or Platform SRK section.
var ErrFreshProvisionConfig = errors.New("tpm: fresh provisioning requires EK, SSRK and PlatformSRK configs")

// ProvisionFresh provisions a freshly-manufactured TPM that xkms itself
// created -- the development simulator, or a tenant's vTPM -- from cfg: the
// endorsement key, the TCG-standard Shared SRK, and the Platform SRK xkms
// parents its own objects under.
//
// Such a TPM's owner and endorsement hierarchies carry empty auth, so no
// hierarchy authorization is needed. A physical TPM is never provisioned
// this way: that is an operator action (`xkmsd init`, `xkey tpm provision`).
func ProvisionFresh(tpm TrustedPlatformModule, cfg *Config) error {
	if tpm == nil {
		return ErrPlatformKeyStoreNilTPM
	}
	if cfg == nil || cfg.EK == nil || cfg.SSRK == nil || cfg.PlatformSRK == nil {
		return ErrFreshProvisionConfig
	}
	ekAttrs, err := EKAttributesFromConfig(*cfg.EK, nil, nil)
	if err != nil {
		return &errs.Wrapped{Msg: "EK attributes", Err: err}
	}
	if err := tpm.CreateEK(ekAttrs); err != nil {
		return &errs.Wrapped{Msg: "create EK", Err: err}
	}

	// The Shared SRK is provisioned per spec even though xkms parents its
	// own objects under the Platform SRK: other TCG-aware software sharing
	// the TPM expects it at its well-known handle.
	ssrkAttrs, err := SRKAttributesFromConfig(*cfg.SSRK)
	if err != nil {
		return &errs.Wrapped{Msg: "SSRK attributes", Err: err}
	}
	ssrkAttrs.Parent = ekAttrs
	if err := tpm.CreateSRK(ssrkAttrs); err != nil {
		return &errs.Wrapped{Msg: "create SSRK", Err: err}
	}

	platformSRKAttrs, err := PlatformSRKAttributesFromConfig(cfg)
	if err != nil {
		return &errs.Wrapped{Msg: "Platform SRK attributes", Err: err}
	}
	platformSRKAttrs.Parent = ekAttrs
	if err := tpm.CreateSRK(platformSRKAttrs); err != nil {
		return &errs.Wrapped{Msg: "create Platform SRK", Err: err}
	}
	return nil
}
