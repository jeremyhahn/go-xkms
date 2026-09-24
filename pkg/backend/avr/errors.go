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

package avr

import "errors"

// Configuration and construction failures.
var (
	// ErrNilConfig indicates NewBackend was called with no configuration.
	ErrNilConfig = errors.New("avr backend: nil configuration")

	// ErrNilDevice indicates NewBackend was called with no device. The
	// backend has nothing to fall back on: every answer it gives comes from
	// the attached device, so there is no useful degraded mode.
	ErrNilDevice = errors.New("avr backend: nil device")

	// ErrMissingKeyCN indicates Config.KeyCN was set to the empty string.
	// The device's identity key needs a name to be addressed by, and an
	// empty one would match every KeyAttributes that forgot to set a CN.
	ErrMissingKeyCN = errors.New("avr backend: key common name is required")

	// ErrInvalidSlot indicates Config.Slot names a slot the firmware does
	// not assign to the device identity keypair.
	ErrInvalidSlot = errors.New("avr backend: invalid element slot")

	// ErrBackendClosed indicates the backend has been closed.
	ErrBackendClosed = errors.New("avr backend: closed")

	// ErrInvalidKeyAttributes indicates nil key attributes were supplied.
	ErrInvalidKeyAttributes = errors.New("avr backend: invalid key attributes")

	// ErrUnknownKey indicates the requested common name is not the one the
	// device's identity key is configured under. An AVR device holds exactly
	// one key and it is not addressable by any other name.
	ErrUnknownKey = errors.New("avr backend: unknown key")

	// ErrInvalidNonce indicates the attestation challenge is not the width the
	// enrolment profile carries.
	//
	// It is 32 bytes because it is SHA-256 of the ACME key authorization, and
	// the caller hashes it with deviceattest01.DICENonce. The device's OTHER
	// nonce -- the 16 bytes riding in the evidence frame -- is runtime
	// freshness and is not this one; handing over the shorter of the two would
	// enrol against a truncated challenge and the device cannot tell.
	ErrInvalidNonce = errors.New("avr backend: attestation nonce is not the enrolment width")

	// ErrTrustStoreInit indicates the configured attestation trust store could
	// not be loaded.
	ErrTrustStoreInit = errors.New("avr backend: trust store initialization failed")
)

// Capability refusals.
//
// Each of these is a permanent property of the wire protocol or of the part,
// not a gap waiting to be filled. They are separate sentinels rather than one
// "not supported" so a caller can tell a device that will never do this from a
// device that could not do it now.
var (
	// ErrSigningUnsupported indicates the device cannot sign a digest the
	// host supplied.
	//
	// This is a deliberate property of the protocol. The device signs its own
	// attestation evidence and its own alias certificate, both of which it
	// builds itself; a signature over opaque bytes a host handed it would be
	// a signature over whatever the holder of those bytes says it is.
	ErrSigningUnsupported = errors.New("avr backend: the device signs no host-supplied digest")

	// ErrDecryptionUnsupported indicates the wire protocol defines no
	// decryption command. The element's key is a signing identity.
	ErrDecryptionUnsupported = errors.New("avr backend: decryption not supported")

	// ErrGenerationUnsupported indicates key generation is refused.
	//
	// Generating the identity keypair REPLACES the device's identity, so it
	// exists only on a provisioning jig's firmware and is gone from the image
	// the part ships with. A key provider that could reach it would destroy
	// the identity every other answer here is about.
	ErrGenerationUnsupported = errors.New("avr backend: key generation is a provisioning operation")

	// ErrDeletionUnsupported indicates key deletion is refused. The identity
	// lives in a locked zone of the element; locking cannot be undone and the
	// key cannot be erased.
	ErrDeletionUnsupported = errors.New("avr backend: the element's key cannot be deleted")

	// ErrRotationUnsupported indicates in-place rotation is refused, for the
	// same reason as deletion. A new identity means a new part.
	ErrRotationUnsupported = errors.New("avr backend: key rotation not supported")
)

// Attestation failures.
//
// Each of these means the evidence in hand does not establish what a verifier
// needs, and none of them is recoverable by trying again with the same device
// and the same challenge.
var (
	// ErrMalformedCertificate indicates the bytes the device returned are not
	// a certificate this host can parse.
	ErrMalformedCertificate = errors.New("avr backend: device returned an unparseable certificate")

	// THE ATTESTATION REFUSALS BELONG TO dice, NOT HERE.
	//
	// dice.Verify enforces device residency (ECDSA P-256 subject key,
	// ECDSA-SHA256 signature), matches the nonce in constant time and anchors
	// the chain. This package used to declare its own sentinel for each,
	// because dice.Verify demanded a DiceTcbInfo extension the AVR alias
	// profile does not carry and could not be called at all. That was fixed in
	// dice -- r23 section 6.1.4 permits UCCS "in place of" DiceTcbInfo -- so
	// the checks have one implementation and one vocabulary:
	//
	//	dice.ErrUnsupportedKeyType             subject key is not P-256
	//	dice.ErrUnsupportedSignatureAlgorithm  not signed ECDSA-SHA256
	//	dice.ErrNonceMismatch                  a replay, or another challenge
	//	dice.ErrChainVerificationFailed        does not reach a trusted root
	//	dice.ErrUccsEvidenceNotFound           no evidence extension
	//	dice.ErrNonceClaimMissing              evidence with no nonce claim
	//
	// Re-declaring them here would be two sentinels for one fact, which is how
	// a caller ends up checking the one that never fires.

)

// Device answers this host cannot use.
var (
	// ErrProtocolVersion indicates the device speaks a protocol major this
	// host does not. Nothing past CAPS can be trusted to mean what it appears
	// to mean, because the frames themselves may not parse the same way.
	ErrProtocolVersion = errors.New("avr backend: device speaks an unsupported protocol version")

	// ErrUnknownCryptoTier indicates Caps.CryptoTier is a value this host has
	// no name for.
	//
	// Reported as an error and never as hardware. Tiers extend and never
	// renumber, so a newer one is not necessarily stronger, and a host that
	// assumed it was would grant an unknown root of trust the trust it
	// reserves for a secure element.
	ErrUnknownCryptoTier = errors.New("avr backend: unrecognised crypto tier")

	// ErrNoDeviceKey indicates the device reports no crypto provider at all,
	// so there is no identity key to address.
	ErrNoDeviceKey = errors.New("avr backend: device has no crypto provider")

	// ErrInvalidDevicePoint indicates the public point the device returned is
	// not a valid P-256 point. It is refused rather than stored: an identity
	// that is not on the curve is not an identity.
	ErrInvalidDevicePoint = errors.New("avr backend: device returned an invalid public point")
)

// Failures the device itself reported, mapped from the wire status.
//
// The wire's status codes extend and never renumber, so a status this host has
// no mapping for lands on ErrDeviceRefused rather than on the nearest known
// one — degraded to the generic refusal, never misclassified as a different
// known failure.
var (
	// ErrDeviceUnreachable indicates the byte stream underneath the protocol
	// failed, or the device did not answer in time.
	ErrDeviceUnreachable = errors.New("avr backend: device did not answer")

	// ErrDeviceProtocol indicates the device answered with a frame this host
	// could not read: a truncated reply, a bad checksum, a malformed frame.
	ErrDeviceProtocol = errors.New("avr backend: unreadable reply from device")

	// ErrDeviceRefused indicates the device answered and refused.
	ErrDeviceRefused = errors.New("avr backend: device refused the command")

	// ErrCommandUnavailable indicates this firmware build has no handler for
	// the command.
	//
	// The ordinary case, not a fault: provisioning commands are compiled out
	// of a production image on purpose, because a device that can be
	// re-provisioned over its own command channel has no identity worth
	// attesting to.
	ErrCommandUnavailable = errors.New("avr backend: this firmware carries no handler for the command")

	// ErrNotProvisioned indicates the device has no provisioned identity and
	// refuses to speak for one it does not have.
	ErrNotProvisioned = errors.New("avr backend: device has no provisioned identity")

	// ErrDeviceCrypto indicates the device's crypto provider failed.
	ErrDeviceCrypto = errors.New("avr backend: device crypto provider failed")

	// ErrAuthRequired indicates the command needs an authenticated session.
	ErrAuthRequired = errors.New("avr backend: command requires an authenticated session")

	// ErrDeviceBusy indicates a peripheral on the device was busy.
	ErrDeviceBusy = errors.New("avr backend: device peripheral busy")

	// ErrProtectedRegion indicates the target is platform-reserved on the
	// device and writes to it are refused by the firmware.
	ErrProtectedRegion = errors.New("avr backend: target is platform-reserved on the device")

	// ErrDeviceInternal indicates the firmware reported an internal error.
	ErrDeviceInternal = errors.New("avr backend: device reported an internal error")

	// ErrUnsupportedByDevice indicates the firmware has the handler and
	// refuses on this build or this part.
	//
	// A DIFFERENT fact from ErrCommandUnavailable, and the difference is the
	// useful one: a software-tier device asked to mint an alias certificate
	// knows exactly what a certificate is and has no public half to certify,
	// so it answers this. "Unknown command" would instead say the feature was
	// compiled out.
	ErrUnsupportedByDevice = errors.New("avr backend: unsupported on this build or part")

	// ErrElementUnreachable indicates the secure element did not answer its
	// bus.
	//
	// The firmware cannot tell an absent part from one whose bus is miswired
	// or clocked too fast for the wake pulse, and does not pretend to: this
	// points at the bus, which is where the fault usually is.
	ErrElementUnreachable = errors.New("avr backend: secure element did not answer its bus")

	// ErrInvalidArgument indicates an argument the wire cannot carry, refused
	// before it reached the device or refused by the device on arrival.
	ErrInvalidArgument = errors.New("avr backend: argument outside the range the wire carries")
)
