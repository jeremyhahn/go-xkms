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

package xkms

import (
	initialize "github.com/jeremyhahn/go-xkms/pkg/init"
)

// CeremonyCA is the narrow slice of the CA the init ceremony and first-boot
// enrollment depend on: lifecycle, issuance, and the CA's own trust chain.
// Any full TrustedCA satisfies it.
type CeremonyCA = initialize.CeremonyCA

// CAAdapter bridges a go-xkms CA to go-qrdb's ceremony and first-boot
// interfaces. It satisfies qrdb's CeremonyCA (init ceremony issuance) and its
// admin-mTLS first-boot seams CertProvider (Path A, generate-and-distribute)
// and CertSigner (Path B, CSR-sign). A downstream deployment embedding a qrdb
// node wires this adapter into firstboot so admin enrollment is issued by the
// xkms CA — the stack's single hardware-backed certificate authority — rather
// than a parallel one.
type CAAdapter = initialize.CAAdapter

// NewCAAdapter constructs a CAAdapter over the given CA. trustDomain is the
// operator-configured SPIFFE trust domain; when empty no SPIFFE SAN is
// stamped on issued certificates.
var NewCAAdapter = initialize.NewCAAdapter

// ---------------------------------------------------------------------------
// Init ceremony hardware seams
//
// go-qrdb owns the ceremony state machine, holder enrolment, Shamir custody
// and the share-claim handshake, and serves them on every node transport.
// go-xkms fills the seams qrdb deliberately leaves open: a CA whose signing
// key may live in a TPM / PKCS#11 token (CAAdapter), and administrator login
// factors performed against real FIDO2 and PIV hardware.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Administrator login-factor enrollment (hardware)
// ---------------------------------------------------------------------------

// AdminEnrollmentConfig describes the administrator whose login factors the
// ceremony enrolls and the hardware available to enroll them.
type AdminEnrollmentConfig = initialize.AdminEnrollmentConfig

// AdminEnrollmentContext carries the per-factor inputs the hardware ceremonies
// need beyond the factor plan itself.
type AdminEnrollmentContext = initialize.AdminEnrollmentContext

// NewAdminFactorRegistry builds the canonical go-xkms factor registry with the
// attached-authenticator driver wired in, so a planned fido2 factor can both
// answer the availability probe and run its CTAP2 ceremony.
var NewAdminFactorRegistry = initialize.NewAdminFactorRegistry

// PreflightAdminFactors refuses the ceremony before it changes any state when a
// planned factor cannot succeed — a missing security key costs one retry
// instead of leaving an initialized barrier behind an administrator who cannot
// log in.
var PreflightAdminFactors = initialize.PreflightAdminFactors

// EnrollAdminFactors runs the planned login factors for the administrator the
// ceremony created. Enrolled factors are returned even on error so callers can
// report what is live.
var EnrollAdminFactors = initialize.EnrollAdminFactors

// NewAdminEnrollmentParams returns the per-factor input provider used by
// EnrollAdminFactors. Exposed for callers driving enrollment themselves.
var NewAdminEnrollmentParams = initialize.NewAdminEnrollmentParams
