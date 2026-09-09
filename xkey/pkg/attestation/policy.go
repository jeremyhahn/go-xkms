// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0)
// for non-commercial use. Commercial licenses are available.
// See LICENSE and LICENSE-COMMERCIAL for details.

package attestation

import (
	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// AllowUnattestablePairing resolves what a pairing does when the phone's
// attestation cannot be verified, across the two planes the owner ruling of
// 2026-08-23 on #95 defines:
//
//   - the USER's setting, devices.yaml `attestation_policy.allow_unattestable_devices`,
//     which the caller has already read from its own record of that file;
//   - the ENTERPRISE/SO setting, the policy section of xkey.yaml, which
//     reaches this function only as a config.VerifiedPolicy.
//
// It lives here rather than in the command package because there are two
// pairing surfaces, the CLI's `xkey device pair` and the GUI's
// PhoneService.Pair, and a policy that resolved differently on each would be
// the #95 defect one level up (#115). Both consume this one function.
//
// The enterprise plane is honoured in BOTH directions, the permissive one
// included, because it can only arrive here verified (#118): unsealed, the
// section is the user's own file and carries the user's authority;
// sealed-and-verified under the SO PIN, it carries the SO's.
// LockPairingAttestationPolicy is what "enterprise config may lock the
// setting" means concretely: unset, the user's answer is used; set,
// PairingAllowUnattestableDevices is used and the user's answer is ignored.
// Nothing else in the resolution consults the user plane, so a locked
// deployment cannot be widened by editing devices.yaml.
//
// A sealed section that was NOT verified never reaches this function as a
// policy: it arrives as nil, and nil means the enterprise plane exists but is
// unknown, so the answer is the fail-closed default -- refuse -- whatever
// devices.yaml says. That replaced the monotone mitigation of #110, under
// which an unverified section could make the answer stricter but never wider.
// It closed the fail-open Codex found (anyone who could edit xkey.yaml could
// lock the setting open) but could never honour a deployment that legitimately
// locks it open; a verified policy can, and an unverified one grants nothing.
//
// Every absent value resolves to false -- refuse. That is the default the
// ruling names, and it is reached by the zero value rather than by a defaults
// table, deliberately: a config file carrying a partial `policy:` block used
// to resolve the keys it omits to false rather than to their defaults (#114),
// and a design whose secure state came from that table would have been
// insecure for exactly the deployments that write a minimal policy file.
func AllowUnattestablePairing(userAllows bool, policy *config.VerifiedPolicy) bool {
	if policy == nil {
		return false
	}
	if policy.Policy.LockPairingAttestationPolicy {
		return policy.Policy.PairingAllowUnattestableDevices
	}
	return userAllows
}
