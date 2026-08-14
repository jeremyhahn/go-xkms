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
// Init ceremony orchestration
//
// This is the single init-ceremony surface for the stack. go-qrdb owns the
// ceremony state machine, Shamir splitting, and the officer claim handshake;
// go-xkms wraps it with the hardware-backed pieces qrdb deliberately does not
// implement — a CA whose signing key may live in a TPM / PKCS#11 token, and
// administrator login factors performed against real FIDO2 and PIV hardware.
//
// Downstream projects consume the ceremony from HERE rather than reaching for
// go-qrdb's constructor directly. Going straight to qrdb yields a ceremony
// that can only ever do software crypto, which is a layering violation: qrdb
// sits below go-xkms and exposes seams (pkg/authfactors.FactorRegistry,
// ceremony.CeremonyCA) precisely so go-xkms can fill them.
// ---------------------------------------------------------------------------

// InitCeremonyService drives the initialization ceremony: barrier init, Shamir
// splitting, officer certificate enrollment, and credential sealing, issuing
// from the go-xkms CA.
type InitCeremonyService = initialize.CeremonyService

// InitCeremonyConfig configures the ceremony (SO / user PINs, threshold,
// officers, hostname, data dir).
type InitCeremonyConfig = initialize.CeremonyConfig

// InitCeremonyState is the ceremony's current state.
type InitCeremonyState = initialize.CeremonyState

// Init ceremony states.
const (
	// InitStateAwaitingInit means the barrier has not been initialized.
	InitStateAwaitingInit = initialize.StateAwaitingInit

	// InitStateEnrolling means M-of-N mode is live and officers are claiming
	// their certificates and shares.
	InitStateEnrolling = initialize.StateEnrolling

	// InitStateOperational means the system is ready for service.
	InitStateOperational = initialize.StateOperational
)

// InitCeremonyResult reports the outcome of a ceremony initialization.
type InitCeremonyResult = initialize.InitResult

// InitOfficerConfig describes one Security Officer enrolled by the ceremony.
type InitOfficerConfig = initialize.OfficerConfig

// NewInitCeremonyService constructs the ceremony over a barrier and credential
// service. The barrier type is go-qrdb's StorageBarrier, so a node built
// through this SDK passes its own barrier straight in.
var NewInitCeremonyService = initialize.NewCeremonyService

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

// ---------------------------------------------------------------------------
// Security Officer enrolment
//
// Step 1 of go-qrdb's Security Officer distribution model, surfaced here so
// every project composed on go-xkms offers the SAME officer flow. Nothing here
// returns share bytes: registration assigns a share INDEX, and each share is
// released to its officer exactly once through the live claim handshake.
// ---------------------------------------------------------------------------

// RegisterOfficerRequest carries one officer's enrolment material (username,
// CSR, and the authenticator backing their credential).
type RegisterOfficerRequest = initialize.RegisterOfficerRequest

// RegisterOfficerResult returns the signed certificate and the officer's
// assigned Shamir share index.
type RegisterOfficerResult = initialize.RegisterOfficerResult

// CeremonyOfficerStatus is a non-secret view of an enrolled officer.
type CeremonyOfficerStatus = initialize.OfficerStatus

// EnrollExternalOfficerRequest enrols an officer whose key material was issued
// by an external CA rather than minted from a CSR by the ceremony CA.
type EnrollExternalOfficerRequest = initialize.EnrollExternalOfficerRequest

// EnrollExternalOfficerResponse reports the outcome of an external enrolment.
type EnrollExternalOfficerResponse = initialize.EnrollExternalOfficerResponse
