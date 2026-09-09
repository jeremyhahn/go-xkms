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
//   - the ENTERPRISE/SO setting, the HMAC-sealed config.PolicySection, nil when
//     no unified config is loaded.
//
// It lives here rather than in the command package because there are two
// pairing surfaces, the CLI's `xkey device pair` and the GUI's
// PhoneService.Pair, and a policy that resolved differently on each would be
// the #95 defect one level up (#115). Both consume this one function.
//
// The enterprise plane wins only while it says it does. LockPairingAttestationPolicy
// is what "enterprise config may lock the setting" means concretely: unset, the
// user's answer is used; set, PairingAllowUnattestableDevices is used and the
// user's answer is ignored. Nothing else in the resolution consults the user
// plane, so a locked deployment cannot be widened by editing devices.yaml.
//
// Every absent value resolves to false -- refuse. That is the default the
// ruling names, and it is reached by the zero value rather than by a defaults
// table, deliberately: this package cannot rely on config.DefaultPolicy(),
// because a config file carrying a partial `policy:` block resolves the keys it
// omits to false rather than to their defaults (measured; #114). A design whose
// secure state came from that table would be insecure for exactly the
// deployments that write a minimal policy file.
func AllowUnattestablePairing(userAllows bool, enterprise *config.PolicySection) bool {
	// The enterprise plane may only ever make the answer STRICTER.
	//
	// This is narrower than "the sealed section decides", and the narrowing is
	// forced rather than chosen. The section arrives as whatever was loaded
	// from xkey.yaml; nothing on a pairing path calls config.VerifyPolicyHMAC,
	// and nothing on it CAN -- verification needs the SO PIN, which a pairing
	// does not have and must not start demanding. Treating those fields as
	// authoritative in both directions therefore meant any user who can edit
	// xkey.yaml could write
	//
	//     policy:
	//       lock_pairing_attestation_policy: true
	//       pairing_allow_unattestable_devices: true
	//
	// and pair an unattestable device, over the top of a devices.yaml that
	// refuses. That is a fail-open reached by editing an UNAUTHENTICATED file,
	// and it is worse than having no enterprise plane at all, because it looks
	// like enforcement.
	//
	// Monotone consumption removes it without needing the SO PIN: an
	// unverified section can only ever REFUSE, which is the direction no
	// attacker wants, and refusing is already what an absent section gets you.
	// Locking the setting OPEN needs authenticated policy and is filed as
	// go-xkms#118; until then this function cannot honour it, and silently
	// honouring it anyway was the defect.
	if enterprise != nil && enterprise.LockPairingAttestationPolicy &&
		!enterprise.PairingAllowUnattestableDevices {
		return false
	}
	return userAllows
}
