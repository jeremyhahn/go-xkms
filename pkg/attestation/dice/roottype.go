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

package dice

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// RootType is where a DICE device keeps its Unique Device Secret (UDS), the
// secret every identity in its chain is derived from.
//
// The device's DICE chain declares it in DiceTcbInfo (TCG DICE Attestation
// Architecture r0.23 section 6.1.1): vendorInfo names the root type with one
// of the OIDRootOfTrust values, and the flags field's notSecure bit is set for
// a software root and clear for a hardware root. Either sign of a software
// root, on any layer, makes the identity software-rooted (CA m452). Neither the
// specification nor RFC 9711 defines a root-type field or claim, so the
// vendorInfo values are go-xkms's own, under its private arc.
//
// The values are stable: they are persisted with ACME device attestations.
type RootType uint8

const (
	// RootTypeUnreported is the zero value: the evidence names no root type.
	// Every format other than DICE reports this, as does a DICE chain whose
	// DiceTcbInfo carries no root-type vendorInfo.
	RootTypeUnreported RootType = iota

	// RootTypeHardware is a UDS held in a secure element.
	RootTypeHardware

	// RootTypeSoftware is a UDS held in device storage, as on an AVR device
	// without a secure element.
	RootTypeSoftware
)

var rootTypeNames = map[RootType]string{
	RootTypeUnreported: "unreported",
	RootTypeHardware:   "hardware",
	RootTypeSoftware:   "software",
}

// String returns the root type's name, or "unknown" for a value outside the
// defined ones.
func (r RootType) String() string {
	if name, ok := rootTypeNames[r]; ok {
		return name
	}
	return "unknown"
}

// The vendorInfo values that name a root type. Each is the DER encoding of an
// OBJECT IDENTIFIER under id-tp-diceRootOfTrust (1.3.6.1.4.1.29377.101.24),
// in the private arc go-xkms's other extensions use, so a vendorInfo another
// vendor defines cannot be mistaken for one.
var (
	// OIDRootOfTrust is id-tp-diceRootOfTrust, the arc of the root-type
	// vendorInfo values.
	OIDRootOfTrust = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 24}

	// OIDRootOfTrustHardware is id-tp-diceRootOfTrust-hardware, the
	// vendorInfo value for RootTypeHardware.
	OIDRootOfTrustHardware = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 24, 1}

	// OIDRootOfTrustSoftware is id-tp-diceRootOfTrust-software, the
	// vendorInfo value for RootTypeSoftware.
	OIDRootOfTrustSoftware = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 24, 2}
)

var rootTypeOIDs = map[RootType]asn1.ObjectIdentifier{
	RootTypeHardware: OIDRootOfTrustHardware,
	RootTypeSoftware: OIDRootOfTrustSoftware,
}

// rootTypesByOID is rootTypeOIDs inverted, keyed by the OID's dotted form.
var rootTypesByOID = map[string]RootType{
	OIDRootOfTrustHardware.String(): RootTypeHardware,
	OIDRootOfTrustSoftware.String(): RootTypeSoftware,
}

// RootTypeVendorInfo returns the DiceTcbInfo vendorInfo value that names
// root, for a device or test minting its chain. It returns
// ErrUnknownRootType for RootTypeUnreported and any undefined value.
func RootTypeVendorInfo(root RootType) ([]byte, error) {
	oid, ok := rootTypeOIDs[root]
	if !ok {
		return nil, &errs.Detail{Err: ErrUnknownRootType, Detail: root.String()}
	}
	return asn1.Marshal(oid)
}

// rootTypeFromVendorInfo returns the root type a vendorInfo value names, or
// RootTypeUnreported when it names none. vendorInfo is vendor-defined, so a
// value that is not exactly one of the DER root-type OIDs is another
// vendor's data and says nothing about the root of trust.
func rootTypeFromVendorInfo(vendorInfo []byte) RootType {
	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(vendorInfo, &oid)
	if err != nil || len(rest) != 0 {
		return RootTypeUnreported
	}
	return rootTypesByOID[oid.String()]
}

// declaredRootType returns the root type one DiceTcbInfo declares (section
// 6.1.1). A set notSecure flag declares a software root whatever vendorInfo
// says, and a software vendorInfo declares one whatever the flag says: a
// software root anywhere makes the identity software-rooted (CA m452).
// Otherwise a hardware vendorInfo declares a hardware root, and anything else
// declares nothing.
func declaredRootType(info *TcbInfo) RootType {
	if info.Flags != nil && info.Flags.NotSecure {
		return RootTypeSoftware
	}
	return rootTypeFromVendorInfo(info.VendorInfo)
}

// rootTypeStrength orders root types from the least to the most trusted, so
// that several verified paths report the weakest of their answers.
var rootTypeStrength = map[RootType]int{
	RootTypeSoftware:   0,
	RootTypeUnreported: 1,
	RootTypeHardware:   2,
}

// RootTypeFromPaths derives the device's root type from the DiceTcbInfo of
// the certificates on paths, the paths x509.Certificate.Verify authenticated
// from the leaf to a configured trusted root. CA m452: "The root type must be
// read only from a chain that verified to a trusted root (an unauthenticated
// chain carries no DiceTcbInfo you may believe)."
//
// No path -- no trusted root configured, or none reached -- reports
// RootTypeUnreported, whatever the certificates declare, and a supplied
// certificate on no path is never read.
//
// On one path, a software declaration on any certificate, leaf or ancestor,
// makes the root software; otherwise a hardware declaration makes it
// hardware; otherwise it is unreported (declaredRootType). Across several
// paths the result is the weakest -- software, then unreported, then hardware
// -- so a declaration that only some paths authenticate never strengthens it.
// An unreadable DiceTcbInfo is returned as its own error.
func RootTypeFromPaths(paths [][]*x509.Certificate) (RootType, error) {
	if len(paths) == 0 {
		return RootTypeUnreported, nil
	}
	weakest := RootTypeHardware
	for _, path := range paths {
		root, err := pathRootType(path)
		if err != nil {
			return RootTypeUnreported, err
		}
		if rootTypeStrength[root] < rootTypeStrength[weakest] {
			weakest = root
		}
	}
	return weakest, nil
}

// pathRootType returns the root type the certificates on one verified path
// declare. Every certificate is read, so an unreadable DiceTcbInfo is refused
// wherever it sits.
func pathRootType(path []*x509.Certificate) (RootType, error) {
	declared := RootTypeUnreported
	for _, cert := range path {
		info, err := TcbInfoFromCertificate(cert)
		if errors.Is(err, ErrTcbInfoNotFound) {
			continue
		}
		if err != nil {
			return RootTypeUnreported, err
		}
		switch declaredRootType(info) {
		case RootTypeSoftware:
			declared = RootTypeSoftware
		case RootTypeHardware:
			if declared == RootTypeUnreported {
				declared = RootTypeHardware
			}
		}
	}
	return declared, nil
}
