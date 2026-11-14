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

package pairing

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/pairingproto"
)

// Attested-application refusals, shared by every decision that reads the
// attestationApplicationId: pairing, re-attestation and LDevID enrollment.
var (
	// ErrApplicationDenied means the attested application is not on the
	// allow-list, by package name or by signing certificate digest, or the
	// attestation names no application at all.
	ErrApplicationDenied = errors.New("pairing: attested application is not allowed")

	// ErrApplicationPolicyUnconfigured means no application is allow-listed,
	// so there is nothing to judge the attested application against and every
	// device is refused until an operator lists the builds it trusts.
	//
	// It wraps xkms.ErrAndroidNilApplicationMatcher, the library's sentinel
	// for a verification given no application policy, so errors.Is against
	// that one sentinel matches an unconfigured policy on every path: this
	// package's Match, attestation.LoadTrust, and the library's own
	// refusal of a trust that carries no matcher (#1721).
	ErrApplicationPolicyUnconfigured error = &applicationPolicyUnconfiguredError{}
)

// applicationPolicyUnconfiguredError is the type of
// ErrApplicationPolicyUnconfigured: xkey's operator-facing text over the
// library's sentinel for the same condition.
type applicationPolicyUnconfiguredError struct{}

// Error names what to configure.
func (*applicationPolicyUnconfiguredError) Error() string {
	return "pairing: no application is allow-listed for device attestation - " +
		"configure allowed_applications (package_name and signing_digests)"
}

// Unwrap returns the library sentinel this error refines.
func (*applicationPolicyUnconfiguredError) Unwrap() error {
	return xkms.ErrAndroidNilApplicationMatcher
}

// AllowedApplication pins one application build.
//
// The package name alone is not an identity: anybody can build an APK claiming
// any package name. What makes it an identity is the signing certificate
// digest, which changes the moment the APK is rebuilt with a different key. So
// a rule with no digests is accepted only when the policy explicitly says
// unpinned builds are allowed.
type AllowedApplication struct {
	// PackageName is the Android package, e.g. com.automatethethings.xkey.
	// Compared exactly: Android package names are case-sensitive.
	PackageName string `json:"package_name" yaml:"package_name"`

	// SigningDigests are hex SHA-256 digests of acceptable signing
	// certificates. Empty means any signature, which is only honoured when
	// ApplicationPolicy.AllowUnpinnedSignatures is set.
	SigningDigests []string `json:"signing_digests,omitempty" yaml:"signing_digests"`
}

// ApplicationPolicy is the allow-list of application builds whose hardware
// attestation is accepted.
//
// Without it, a verified chain proves only that SOME application on a locked,
// verified-boot handset generated the key -- any app the handset runs could
// have produced the evidence. The attestationApplicationId, written by the
// Keystore daemon rather than by the calling app, is what narrows that to this
// application signed by this key.
//
// The zero value allow-lists nothing and refuses every device.
type ApplicationPolicy struct {
	// AllowedApplications lists the application builds that are accepted.
	AllowedApplications []AllowedApplication `json:"allowed_applications" yaml:"allowed_applications,omitempty"`

	// AllowUnpinnedSignatures honours allow-list entries that carry no signing
	// digests. Useful while developing against a debug build; leaving it on in
	// production means any APK claiming the package name is accepted.
	AllowUnpinnedSignatures bool `json:"allow_unpinned_signatures" yaml:"allow_unpinned_signatures,omitempty"`
}

// Configured reports whether any application is allow-listed.
func (p ApplicationPolicy) Configured() bool {
	return len(p.AllowedApplications) > 0
}

// Match checks the attested application against the allow-list and returns
// the package name and hex signing digest that matched.
//
// It refuses with ErrApplicationPolicyUnconfigured when nothing is
// allow-listed, and with ErrApplicationDenied when the attestation names no
// application or none of the named packages is allow-listed under one of its
// signing digests.
func (p ApplicationPolicy) Match(appID *xkms.AndroidAttestationApplicationID) (string, string, error) {
	if !p.Configured() {
		return "", "", ErrApplicationPolicyUnconfigured
	}
	if appID == nil || len(appID.Packages) == 0 {
		return "", "", &pairingproto.DetailError{Err: ErrApplicationDenied, Detail: ": the attestation names no application"}
	}

	digests := make([]string, 0, len(appID.SignatureDigests))
	for _, d := range appID.SignatureDigests {
		digests = append(digests, hex.EncodeToString(d))
	}

	unpinnedRefused := false
	names := make([]string, 0, len(appID.Packages))
	for _, pkg := range appID.Packages {
		names = append(names, pkg.Name)
		for _, allowed := range p.AllowedApplications {
			if pkg.Name != allowed.PackageName {
				continue
			}
			if len(allowed.SigningDigests) == 0 && !p.AllowUnpinnedSignatures {
				unpinnedRefused = true
				continue
			}
			if digest, ok := signerAllowed(allowed, digests); ok {
				return pkg.Name, digest, nil
			}
		}
	}

	detail := fmt.Sprintf(": packages %v signed by %v", names, digests)
	if unpinnedRefused {
		detail += " (an allow-listed entry carries no signing digest and allow_unpinned_signatures is off)"
	}
	return "", "", &pairingproto.DetailError{Err: ErrApplicationDenied, Detail: detail}
}

// signerAllowed reports whether one of the attested signing digests satisfies
// the entry, and which. An unpinned entry -- the caller has already checked it
// is permitted -- accepts any signer.
func signerAllowed(allowed AllowedApplication, digests []string) (string, bool) {
	if len(allowed.SigningDigests) == 0 {
		if len(digests) == 0 {
			return "", true
		}
		return digests[0], true
	}
	for _, want := range allowed.SigningDigests {
		for _, got := range digests {
			if strings.EqualFold(strings.TrimSpace(want), got) {
				return got, true
			}
		}
	}
	return "", false
}
