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

import (
	"context"
	"crypto/x509"
	"strconv"

	aggeneric "github.com/jeremyhahn/arduino-generic/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/dice"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Compile-time interface check.
var _ types.AttestingKeyProvider = (*Backend)(nil)

// FormatDICE is the attestation format this backend produces: an X.509 alias
// certificate whose tcg-dice-UCCS-evidence extension carries the verifier's
// challenge. It is the string pkg/acme/challenges/device-attest-01 uses for the
// same evidence, so a caller routing on format need not learn a second name.
const FormatDICE = "dice"

// AttestationConfig configures what an attestation must prove.
type AttestationConfig struct {
	// TrustStore names the roots an alias certificate must descend from.
	//
	// Optional, and the shape of the decision rather than an oversight. A
	// device on a bench has nowhere to anchor to and its certificate is still
	// worth collecting; a device enrolling with a CA is anchored by the CA,
	// which holds the roots and is not this process. When it is nil, Attest
	// still checks everything that does not need a root -- the challenge, the
	// curve, the signature algorithm -- and reports Anchored false so a caller
	// cannot mistake one for the other.
	TrustStore *truststore.Config `yaml:"trust_store" json:"trust_store"`

	// Intermediates are DER certificates between the device's alias
	// certificate and a root: the DeviceID certificate, an embedded CA. The
	// device does not send them -- it has nowhere to keep them -- so an
	// operator supplies them here.
	Intermediates [][]byte `yaml:"intermediates" json:"intermediates"`
}

// Attestation is what the device answered and what this host made of it.
type Attestation struct {
	// Format is FormatDICE.
	Format string

	// Certificate is the parsed alias certificate the device minted for this
	// challenge.
	Certificate *x509.Certificate

	// CertificateDER is the same certificate as the device sent it. Kept
	// because a relaying gateway must forward the device's bytes verbatim
	// rather than re-encode them: a re-encoding is a different document, and
	// the signature is over the original.
	CertificateDER []byte

	// Claims is the decoded CWT claims set from the leaf's
	// tcg-dice-UCCS-evidence extension. Its Nonce is the challenge that was
	// matched; Other carries every claim this profile does not model -- the
	// ueid at key 256 and the firmware measurement at key 273 -- as the raw
	// CBOR the device encoded, so a caller reads exactly what the device said.
	Claims *dice.ClaimsSet

	// Ueid is the device's unique identifier, type byte included, read by
	// dice.DeviceUeid. The AVR profile states it as CWT claim 256 inside the
	// evidence extension rather than as a tcg-dice-Ueid extension; Claims.Other
	// carries the same claim as the raw CBOR the device encoded.
	Ueid []byte

	// Nonce is the challenge this host issued, echoed and verified.
	Nonce []byte

	// AttestLevel is what the device's crypto tier establishes, stamped from
	// the same one place every other answer here takes it from.
	AttestLevel types.AttestLevel

	// CryptoTier is the tier verbatim, for a caller recording what the device
	// said rather than this host's classification of it.
	CryptoTier aggeneric.CryptoTier

	// RootType is where the device keeps its Unique Device Secret, as the
	// certificate's DiceTcbInfo declares it (dice.RootType). An alias
	// certificate that carries only tcg-dice-UCCS-evidence declares nothing
	// and reports dice.RootTypeUnreported, and so does any certificate when
	// no roots are configured: CA m452 believes the declaration only from a
	// chain that verified to one.
	RootType dice.RootType

	// Anchored reports whether the certificate was verified against configured
	// roots. False means no roots were configured -- never that anchoring was
	// attempted and skipped, which refuses.
	Anchored bool
}

// AttestKey asks the device to mint an alias certificate carrying the
// challenge, and checks what it answered.
//
// The challenge is 32 bytes and it is SHA-256 of the ACME key authorization.
// Compute it with deviceattest01.DICENonce, which exists so a device, a
// provisioning tool and a test cannot each hash something slightly different --
// a trailing newline, the token rather than the whole authorization -- and
// produce a mismatch whose cause is invisible from either end. THIS FUNCTION
// DOES NOT HASH: a caller that passed a raw key authorization would be refused
// for its width rather than quietly enrolled against something else.
//
// What is checked, in order, and every one of them refuses:
//
//  1. The challenge is the enrolment width. Refused here, before a frame is
//     built, because the device's other nonce is 16 bytes and a device handed
//     the shorter one cannot tell it was truncated.
//  2. The bytes parse as a certificate.
//  3. Its key is on P-256 and its signature is ECDSA-SHA256. The element holds
//     a key on no other curve and makes no other signature, so anything else
//     was not minted by that hardware.
//  4. Its tcg-dice-UCCS-evidence extension is readable.
//  5. The eat_nonce claim is the challenge this host issued. A DICE device has
//     no clock: this nonce is the only thing separating a live answer from a
//     replayed recording, and it is compared in constant time.
//  6. When roots are configured, the certificate descends from one.
//
// The nonce check is NOT conditional on anything. Anchoring is, because roots
// belong to whoever configured them and a bench device has none; Anchored says
// which happened.
func (b *Backend) AttestKey(ctx context.Context, attrs *types.KeyAttributes, nonce []byte) (interface{}, error) {
	if b.closed.Load() {
		return nil, ErrBackendClosed
	}
	if attrs == nil {
		return nil, ErrInvalidKeyAttributes
	}
	if attrs.CN != b.config.KeyCN {
		return nil, &errs.Detail{Err: ErrUnknownKey, Detail: attrs.CN}
	}
	if len(nonce) != aggeneric.AliasNonceLen {
		return nil, &errs.Detail{
			Err: ErrInvalidNonce,
			Detail: "expected " + strconv.Itoa(aggeneric.AliasNonceLen) +
				" bytes from deviceattest01.DICENonce, got " + strconv.Itoa(len(nonce)),
		}
	}
	if !b.hasDeviceKey() {
		return nil, ErrNoDeviceKey
	}

	// Held across the WHOLE of AttestCert, which is several Do calls: the
	// device regenerates its pages for each nonce and keeps no copy, so a
	// second attestation interleaved between two page reads would splice two
	// certificates together.
	//
	// The deadline is set AFTER the wire is acquired, not before: see the
	// comment in Backend.Identity. It matters more here than anywhere else,
	// because AttestCert is the multi-frame exchange every other caller is
	// queued behind.
	b.wire.Lock()
	ctx, cancel := context.WithTimeout(ctx, b.config.RequestTimeout)
	der, err := b.device.AttestCert(ctx, nonce)
	cancel()
	b.wire.Unlock()
	if err != nil {
		return nil, deviceError(err)
	}
	return b.checkAliasCertificate(der, nonce)
}

// checkAliasCertificate is everything that happens after the bytes arrive.
//
// Separated from the round trip so the checks are one readable sequence, and
// so a test can drive them against the frozen certificate the firmware's own
// vectors pin without standing up a device.
func (b *Backend) checkAliasCertificate(der, nonce []byte) (*Attestation, error) {
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrMalformedCertificate, Cause: err}
	}

	// dice.Verify does all of it: the P-256 device-residency constraint, the
	// chain, the nonce in constant time, the operational flags and the UEID.
	//
	// This used to be an open-coded sequence here, because dice.Verify demanded
	// a DiceTcbInfo extension and the AVR alias certificate carries only
	// tcg-dice-UCCS-evidence. That was the verifier being wrong rather than the
	// device: r23 section 6.1.4 says UCCS "MAY be used in addition to or in
	// place of DiceTcbInfoSeq or DiceTcbInfo". Fixed there, so the long way
	// round is gone and there is one implementation of what DICE evidence means.
	chain := append([]*x509.Certificate{leaf}, b.intermediateCerts...)
	opts := dice.VerifyOptions{
		ExpectedNonce: nonce,
		TrustedRoots:  b.roots,
		// The alias certificate is signed by the DeviceID key, which is in the
		// same element. That is a fact about THIS profile and nothing in the
		// chain states it: the DeviceID certificate belongs to whoever
		// provisioned the part, so the ordinary chain here is the alias leaf
		// alone or a DeviceID intermediate carrying no DICE extension of its
		// own. dice.Verify checks a signature algorithm on what a
		// device-resident key signed, which in both shapes is no certificate at
		// all -- so without this an alias signed with ECDSA-SHA384 would pass a
		// backend whose documentation promises the one algorithm the element
		// emits.
		RequireDeviceSignedLeaf: true,
	}
	evidence, err := dice.Verify(chain, &opts)
	if err != nil {
		return nil, err
	}

	// Not fatal, and deliberately so -- see the identical fail-safe-to-
	// unattested comment where AttestLevel is first read in NewBackend. The
	// DICE chain above has already proved this evidence is genuine; a crypto
	// tier this host cannot yet classify only degrades the reported trust
	// level to Unattested, it does not invalidate the attestation itself.
	level, err := b.AttestLevel()
	if err != nil {
		b.logger.Warn("device reports a crypto tier this host cannot classify",
			"crypto_tier", uint8(b.caps.CryptoTier),
			"error", err,
		)
	}
	echoed := make([]byte, len(nonce))
	copy(echoed, nonce)

	return &Attestation{
		Format:         FormatDICE,
		Certificate:    leaf,
		CertificateDER: der,
		Claims:         evidence.Claims,
		Ueid:           evidence.Ueid,
		Nonce:          echoed,
		AttestLevel:    level,
		CryptoTier:     b.caps.CryptoTier,
		RootType:       evidence.RootType,
		// Whether anchoring RAN, never conflated with whether it passed: a
		// chain from an unknown issuer with roots configured is refused above,
		// not reported here with Anchored false.
		Anchored: b.roots != nil,
	}, nil
}
