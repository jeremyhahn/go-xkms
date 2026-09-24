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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"strconv"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/ecpoint"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// devicePointLen is the length of the uncompressed P-256 point the device
// returns: the affine X and Y coordinates, 32 bytes each, with no SEC 1 prefix
// byte. The element has no other public key format.
const devicePointLen = 64

// DeviceKey is a handle on the identity keypair inside the device's element.
//
// It carries the public point and the slot, and it is DELIBERATELY NOT a
// crypto.Signer. A type that offered Sign and failed every call would put the
// discovery that this device cannot sign at the end of a protocol exchange,
// where the caller has already committed to it. Failing the type assertion
// puts it at the start, which is where a negotiation can still do something
// about it. Backend.Signer refuses for the same reason and says why.
//
// It satisfies crypto.PrivateKey, which is the empty interface, because that
// is what types.KeyProvider.GetKey returns; the private half it stands for is
// in the element and no part of it is in this process.
type DeviceKey struct {
	pub  *ecdsa.PublicKey
	slot uint8
	cn   string
}

// Public returns the device's identity public key.
func (k *DeviceKey) Public() crypto.PublicKey { return k.pub }

// Slot returns the element slot the key lives in.
func (k *DeviceKey) Slot() uint8 { return k.slot }

// CN returns the common name the key is addressed by.
func (k *DeviceKey) CN() string { return k.cn }

// Equal reports whether other is a DeviceKey in the same slot with the same
// public point. It compares the point rather than the slot alone: two devices
// hold their identities in the same slot and are not the same key.
func (k *DeviceKey) Equal(other crypto.PrivateKey) bool {
	o, ok := other.(*DeviceKey)
	if !ok {
		return false
	}
	return k.slot == o.slot && k.pub.Equal(o.pub)
}

// newDeviceKey validates the point the device returned and builds a handle on
// it.
//
// The point is checked against the curve rather than assumed onto it. A
// coordinate pair that is not on P-256 is not an identity, and storing one
// would give every later answer about this device — its key ID, its enrolment
// record, the subject of a certificate request — a value that cannot verify
// anything.
func newDeviceKey(point []byte, slot uint8, cn string) (*DeviceKey, error) {
	if len(point) != devicePointLen {
		return nil, &errs.Detail{
			Err:    ErrInvalidDevicePoint,
			Detail: "expected " + strconv.Itoa(devicePointLen) + " bytes, got " + strconv.Itoa(len(point)),
		}
	}
	half := devicePointLen / 2
	pub, err := ecpoint.PublicKey(elliptic.P256(), point[:half], point[half:])
	if err != nil {
		return nil, &errs.Detail{Err: ErrInvalidDevicePoint, Detail: err.Error()}
	}
	return &DeviceKey{pub: pub, slot: slot, cn: cn}, nil
}

// keyAttributes describes the device's identity key the way the rest of xkms
// describes a key.
//
// AttestLevel is stamped from the device's own crypto tier and from nothing
// else, so a record written here says what the device said about its root of
// trust rather than what the backend would like to be true about it.
func (b *Backend) keyAttributes() *types.KeyAttributes {
	level, _ := b.AttestLevel()
	return &types.KeyAttributes{
		CN:            b.config.KeyCN,
		KeyAlgorithm:  x509.ECDSA,
		KeyType:       types.KeyTypeIDevID,
		StoreType:     types.StoreAVR,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
		Hash:          crypto.SHA256,
		AttestLevel:   level,
		KeyOrigin:     types.KeyOriginGenerated,
		Exportable:    false,
		Sensitive:     true,
	}
}
