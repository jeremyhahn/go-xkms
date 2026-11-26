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

package attestation

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/android"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// AndroidDeviceTrust is what a hardware-held Android device key is
// verified against: the attestation roots its chain must anchor in, and
// the policy naming the applications allowed to hold it.
//
// Roots is the one set of anchors: the chain is verified against it and
// the reported anchor is read back out of that verification. A second list
// kept beside it for lookups once let a peer append a certificate stored
// for another purpose and have it named as the anchor.
type AndroidDeviceTrust struct {
	// Roots are the attestation roots, normally the Google hardware
	// attestation roots plus any the operator added.
	Roots *x509.CertPool

	// Applications decides which attesting applications are allowed.
	Applications android.ApplicationMatcher

	// Revocation supplies the attestation certificate revocation status
	// list every chain certificate is checked against: an
	// *android.HTTPStatusList fetching Google's list, or an
	// *android.StatusList loaded from a file on a host that cannot reach
	// it. It is required.
	Revocation android.StatusListSource
}

// AndroidDeviceKey is a verified Android device-key attestation.
type AndroidDeviceKey struct {
	// Chain is the parsed certificate chain, leaf first. Chain[0]
	// certifies the device key.
	Chain []*x509.Certificate

	// Description is the verified key description from the leaf.
	Description *android.KeyDescription

	// RootOfTrust is the hardware-enforced boot state: locked and verified.
	RootOfTrust *android.RootOfTrust

	// TrustAnchor is the root in trust.Roots the chain anchored in.
	TrustAnchor *x509.Certificate
}

// VerifyAndroidDeviceKey verifies a DER-encoded Android key attestation
// chain as a hardware-held device key. The chain must anchor in
// trust.Roots, no certificate of the chain or its anchor may be on
// trust.Revocation's status list, the key must be generated in at least a
// TEE and may sign, the bootloader must be locked with a verified boot
// state, and the attesting application must satisfy trust.Applications.
// A status list the source cannot supply fails the verification.
//
// It makes no freshness claim: the leaf carries the key's genesis
// challenge (see android.DeviceVerifyOptions), so the caller proves
// liveness separately, by having the key sign a live nonce.
func VerifyAndroidDeviceKey(chainDER [][]byte, trust *AndroidDeviceTrust) (*AndroidDeviceKey, error) {
	if trust == nil || trust.Roots == nil {
		return nil, ErrNoTrustAnchors
	}

	if trust.Revocation == nil {
		return nil, ErrNoRevocationSource
	}

	chain, err := ParseDERChain(chainDER)
	if err != nil {
		return nil, err
	}
	opts := android.DeviceVerifyOptions(trust.Roots)
	opts.Revocation = trust.Revocation
	desc, err := android.VerifyKeyAttestation(chain, opts)
	if err != nil {
		return nil, err
	}
	anchor, err := VerifiedTrustAnchor(chain, trust.Roots)
	if err != nil {
		return nil, err
	}
	rot, err := android.RequireAttestedBootState(desc)
	if err != nil {
		return nil, err
	}
	if err := android.RequireAttestedKeyOrigin(desc); err != nil {
		return nil, err
	}
	if err := android.RequireAttestedApplication(desc, trust.Applications); err != nil {
		return nil, err
	}

	return &AndroidDeviceKey{
		Chain:       chain,
		Description: desc,
		RootOfTrust: rot,
		TrustAnchor: anchor,
	}, nil
}

// ParseDERChain parses a DER-encoded certificate chain, leaf first.
func ParseDERChain(derChain [][]byte) ([]*x509.Certificate, error) {
	if len(derChain) == 0 {
		return nil, ErrEmptyCertificateChain
	}
	chain := make([]*x509.Certificate, 0, len(derChain))
	for i, der := range derChain {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, &errs.Detail{Err: ErrCertificateParseFailed, Detail: fmt.Sprintf("certificate %d: %v", i, err)}
		}
		chain = append(chain, cert)
	}
	return chain, nil
}

// VerifiedTrustAnchor verifies chain against roots and returns the root
// the verified path ends in. Certificates after chain[0] are offered only
// as intermediates, so one the peer appended can never become the anchor.
func VerifiedTrustAnchor(chain []*x509.Certificate, roots *x509.CertPool) (*x509.Certificate, error) {
	if len(chain) == 0 {
		return nil, ErrEmptyCertificateChain
	}
	if roots == nil {
		return nil, ErrNoTrustAnchors
	}
	paths, err := verifyX509Chain(chain, roots, time.Time{})
	if err != nil {
		return nil, &errs.Detail{Err: ErrChainNotAnchored, Detail: fmt.Sprintf("%v", err)}
	}
	if len(paths) == 0 || len(paths[0]) == 0 {
		return nil, &errs.Detail{Err: ErrChainNotAnchored, Detail: "verification returned no chain"}
	}
	path := paths[0]
	return path[len(path)-1], nil
}

// FormatTrustAnchor names a trust anchor for display: its common name,
// else its first organization, else its full subject. A nil certificate
// is "unknown".
func FormatTrustAnchor(cert *x509.Certificate) string {
	if cert == nil {
		return "unknown"
	}
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	if len(cert.Subject.Organization) > 0 {
		return cert.Subject.Organization[0]
	}
	return cert.Subject.String()
}
