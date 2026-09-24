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

package xkms

import (
	"github.com/jeremyhahn/go-xkms/pkg/backend/avr"
)

// ---------------------------------------------------------------------------
// AVR device backend (from pkg/backend/avr/, go-xkms#646)
//
// One attached AVR device -- an 8-bit part with an ATECC608A secure element --
// presented as an xkms key provider. It generates nothing and signs nothing a
// host hands it: what it does is mint an alias certificate carrying the
// verifier's challenge in the eat_nonce claim of its tcg-dice-UCCS-evidence
// extension, which is the DICE evidence path.
//
// THIS FILE IS WHY THE BACKEND IS REACHABLE AT ALL. BackendTypeAVR was exported
// on its own, which named a capability with no way to construct or configure
// it: a consumer had to import go-xkms/pkg/backend/avr, and go-trusted-platform's
// layer guard refuses a pkg/ import outright. An enum value with no constructor
// behind it is an internal capability with a public label.
//
// The device itself comes from github.com/jeremyhahn/arduino-generic/sdk/go,
// which is a separate Layer 0 module a consumer imports directly -- it is not
// go-xkms internals and there is nothing here to re-export it through. Open the
// link, wrap it in an aggeneric.Device, and hand that to NewAVRBackend.
// ---------------------------------------------------------------------------

// AVRBackend is one attached AVR device as a key provider. It is a
// types.KeyProvider and an attesting provider; it is deliberately not a signer,
// because the wire protocol defines no command that signs a digest the host
// supplied -- a device that did would be a signing oracle for anyone who
// reached the serial line.
type AVRBackend = avr.Backend

// AVRConfig configures the backend: the common name the device's one key is
// addressed by, the element slot holding it, the per-command timeout, and what
// an attestation must prove.
type AVRConfig = avr.Config

// AVRAttestationConfig is what an alias certificate must prove: the roots it
// must descend from and the intermediates between. Both are optional, and a nil
// AVRAttestationConfig is the unanchored profile -- the challenge, the curve
// and the signature algorithm are still checked, and AVRAttestation.Anchored
// reports false so a caller cannot mistake one for the other.
type AVRAttestationConfig = avr.AttestationConfig

// AVRAttestation is what the device answered and what the host made of it: the
// alias certificate, the device's own bytes of it, the decoded CWT claims set,
// the challenge that was matched, and whether anchoring ran.
type AVRAttestation = avr.Attestation

// AVRIdentity is the element's hardware identity -- serial number, die revision
// and the lock state of both zones. A fielded device refuses to report it,
// because the provisioning commands are compiled out of the image a part ships
// with; that refusal is the ordinary answer and not a fault.
type AVRIdentity = avr.Identity

// AVRHealth is the device's runtime state. Nothing in it is a timestamp: the
// part has no clock, so uptime and the reset cause are what distinguish a
// device that keeps restarting from one that is simply up.
type AVRHealth = avr.Health

// AVRDeviceKey is a handle on the device's identity key, with the public point
// read from the element. It is not a crypto.Signer, for the reason AVRBackend
// is not.
type AVRDeviceKey = avr.DeviceKey

// AVRAlgorithms reports what the device's crypto provider can perform, from the
// device's own CAPS bitmap rather than from this host's expectations.
type AVRAlgorithms = avr.Algorithms

// AVRAlgorithm names one algorithm a device may report.
type AVRAlgorithm = avr.Algorithm

const (
	// AVRAlgorithmECDSAP256SHA256 is what a secure element performs, and what
	// the DeviceID keypair is.
	AVRAlgorithmECDSAP256SHA256 = avr.AlgorithmECDSAP256SHA256

	// AVRAlgorithmEd25519 is in the vocabulary because the wire defines a bit
	// for it, not because the usual part performs it: an ATECC608A has no
	// hardware Ed25519 and never sets the bit.
	AVRAlgorithmEd25519 = avr.AlgorithmEd25519

	// AVRAlgorithmHMACSHA256 is TCG's DICE Symmetric profile. A verifier
	// holding the key can forge the response, so it admits a device to a local
	// trust domain behind an attested gateway and never to a public one.
	AVRAlgorithmHMACSHA256 = avr.AlgorithmHMACSHA256

	// AVRFormatDICE is the attestation format this backend produces. It is the
	// same string the ACME device-attest-01 challenge uses for the same
	// evidence, so a caller routing on format need not learn a second name.
	AVRFormatDICE = avr.FormatDICE

	// AVRDefaultKeyCN is the common name the device's identity key is
	// addressed by when the configuration names none.
	AVRDefaultKeyCN = avr.DefaultKeyCN

	// AVRDefaultRequestTimeout bounds one command. Generous on purpose: a
	// device deriving a key in software spends seconds inside one command on a
	// 16 MHz part.
	AVRDefaultRequestTimeout = avr.DefaultRequestTimeout
)

// NewAVRBackend connects a backend to an already-open device, reading the
// device's CAPS reply once so the backend either exists and knows what it is
// talking to or does not exist.
//
// The link underneath belongs to the caller and is not closed by the backend.
// The per-command deadline does not: NewAVRBackend applies AVRConfig's
// RequestTimeout to the device, because a backend that issues every command on
// that link owns the deadline those commands are given.
var NewAVRBackend = avr.NewBackend

// DefaultAVRConfig returns a configuration addressing the identity key of an
// ordinary device.
var DefaultAVRConfig = avr.DefaultConfig

// AVR backend refusals, re-exported so a consumer can tell them apart with
// errors.Is without importing pkg/.
//
// Several of them are permanent properties of the part rather than transient
// failures, and the distinction is the whole reason they are separate values: a
// caller must be able to tell a device that will never do this from a device
// that could not do it now.
var (
	// ErrAVRNilConfig reports construction with no configuration.
	ErrAVRNilConfig = avr.ErrNilConfig

	// ErrAVRNilDevice reports construction with no device. There is no
	// degraded mode: every answer the backend gives comes from the device.
	ErrAVRNilDevice = avr.ErrNilDevice

	// ErrAVRMissingKeyCN reports an empty key common name, refused rather than
	// defaulted because it would otherwise match every request that forgot to
	// set one.
	ErrAVRMissingKeyCN = avr.ErrMissingKeyCN

	// ErrAVRInvalidSlot reports a slot the firmware does not assign to the
	// device identity keypair.
	ErrAVRInvalidSlot = avr.ErrInvalidSlot

	// ErrAVRBackendClosed reports use after Close.
	ErrAVRBackendClosed = avr.ErrBackendClosed

	// ErrAVRInvalidKeyAttributes reports nil key attributes.
	ErrAVRInvalidKeyAttributes = avr.ErrInvalidKeyAttributes

	// ErrAVRUnknownKey reports a common name that is not the one the device's
	// single identity key is configured under.
	ErrAVRUnknownKey = avr.ErrUnknownKey

	// ErrAVRInvalidNonce reports a challenge that is not the enrolment width.
	// It is 32 bytes because it is SHA-256 of the ACME key authorization; the
	// device's other nonce, 16 bytes, is runtime freshness and is not this one.
	ErrAVRInvalidNonce = avr.ErrInvalidNonce

	// ErrAVRTrustStoreInit reports an attestation trust store that would not
	// load, which fails construction rather than the first enrolment.
	ErrAVRTrustStoreInit = avr.ErrTrustStoreInit

	// ErrAVRSigningUnsupported reports the deliberate absence of a command
	// that signs a host-supplied digest.
	ErrAVRSigningUnsupported = avr.ErrSigningUnsupported

	// ErrAVRDecryptionUnsupported reports that the element's key is a signing
	// identity and the wire defines no decryption command.
	ErrAVRDecryptionUnsupported = avr.ErrDecryptionUnsupported

	// ErrAVRGenerationUnsupported reports that generating the identity keypair
	// is a provisioning operation, absent from the image a part ships with.
	ErrAVRGenerationUnsupported = avr.ErrGenerationUnsupported

	// ErrAVRDeletionUnsupported reports that the identity lives in a zone
	// locked irreversibly during provisioning.
	ErrAVRDeletionUnsupported = avr.ErrDeletionUnsupported

	// ErrAVRRotationUnsupported reports that a new identity means a new part.
	ErrAVRRotationUnsupported = avr.ErrRotationUnsupported

	// ErrAVRMalformedCertificate reports bytes from the device that are not a
	// certificate this host can parse.
	ErrAVRMalformedCertificate = avr.ErrMalformedCertificate

	// ErrAVRProtocolVersion reports a device speaking a protocol major this
	// host does not, past which nothing can be trusted to parse the same way.
	ErrAVRProtocolVersion = avr.ErrProtocolVersion

	// ErrAVRUnknownCryptoTier reports a tier this host cannot classify. The
	// level degrades to unattested rather than being assumed stronger.
	ErrAVRUnknownCryptoTier = avr.ErrUnknownCryptoTier

	// ErrAVRNoDeviceKey reports a device with no crypto provider to hold an
	// identity.
	ErrAVRNoDeviceKey = avr.ErrNoDeviceKey

	// ErrAVRInvalidDevicePoint reports a public point the element returned that
	// is not on the curve.
	ErrAVRInvalidDevicePoint = avr.ErrInvalidDevicePoint

	// ErrAVRDeviceUnreachable reports a device that did not answer.
	ErrAVRDeviceUnreachable = avr.ErrDeviceUnreachable

	// ErrAVRDeviceProtocol reports a reply this host could not parse.
	ErrAVRDeviceProtocol = avr.ErrDeviceProtocol

	// ErrAVRDeviceRefused reports a command the device declined.
	ErrAVRDeviceRefused = avr.ErrDeviceRefused

	// ErrAVRCommandUnavailable reports a command absent from this firmware
	// build, which for the provisioning commands is the ordinary state of a
	// fielded part.
	ErrAVRCommandUnavailable = avr.ErrCommandUnavailable

	// ErrAVRNotProvisioned reports a part with no identity yet.
	ErrAVRNotProvisioned = avr.ErrNotProvisioned

	// ErrAVRDeviceCrypto reports a cryptographic operation the element failed.
	ErrAVRDeviceCrypto = avr.ErrDeviceCrypto

	// ErrAVRAuthRequired reports an operation the device requires
	// authorization for.
	ErrAVRAuthRequired = avr.ErrAuthRequired

	// ErrAVRDeviceBusy reports a device already doing something else.
	ErrAVRDeviceBusy = avr.ErrDeviceBusy

	// ErrAVRProtectedRegion reports an access the device's configuration
	// forbids.
	ErrAVRProtectedRegion = avr.ErrProtectedRegion

	// ErrAVRDeviceInternal reports a fault inside the device.
	ErrAVRDeviceInternal = avr.ErrDeviceInternal

	// ErrAVRUnsupportedByDevice reports a capability this part does not have.
	ErrAVRUnsupportedByDevice = avr.ErrUnsupportedByDevice

	// ErrAVRElementUnreachable reports a secure element the firmware could not
	// talk to.
	ErrAVRElementUnreachable = avr.ErrElementUnreachable

	// ErrAVRInvalidArgument reports an argument the device rejected.
	ErrAVRInvalidArgument = avr.ErrInvalidArgument
)
