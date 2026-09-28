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

package storage

import (
	"context"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
)

// CertificateSerialCollisionError indicates that the DAO row selected for a
// certificate's EntityID() - an FNV-1a hash of its full Serial, used only to
// satisfy the generic DAO's uint64 entity-ID requirement (go-xkms#744) - is
// already occupied by a DIFFERENT certificate. A 64-bit hash collision
// between two distinct serials is astronomically unlikely but not
// impossible, and the entire point of keying certificate identity on the
// full Serial is to never paper over that by silently overwriting one
// certificate with another.
type CertificateSerialCollisionError struct {
	// Wanted is the serial of the certificate that could not be stored.
	Wanted string
	// Existing is the serial of the certificate already stored at the row
	// Wanted's EntityID() hashes to.
	Existing string
}

// Error implements the error interface.
func (e *CertificateSerialCollisionError) Error() string {
	return "acme: certificate serial " + e.Wanted +
		" collides in storage with existing serial " + e.Existing
}

// SaveCertificateNoCollision persists cert without ever silently overwriting
// a DIFFERENT certificate that happens to hash to the same DAO row
// (entities.ACMECertificate.EntityID() is an FNV-1a hash of the full
// serial, not the serial itself, so a hash collision - not just a duplicate
// save of the same certificate - is possible in principle).
//
// When the DAO's backing KVStore supports atomic writes, the create is
// atomic (GenericDAO.SaveIfAbsent), so a collision is detected exactly:
// SaveIfAbsent reports whether the row was empty, and if it was not, the
// existing record's Serial is compared to cert's Serial.
//
// GenericDAO.SaveIfAbsent returns dao.ErrAtomicWriteUnsupported when the
// backing store lacks atomic support, but that sentinel is a go-qrdb
// pkg/dao internal that sdk/go does not re-export, and xkms may not import
// pkg/dao directly (see the SDK boundary in this repository's CLAUDE.md).
// This function therefore cannot distinguish "no atomic support" from a
// genuine SaveIfAbsent failure by sentinel or type. Any SaveIfAbsent error
// falls back to a Get-then-compare-then-Save sequence: if the row is
// genuinely empty (Get returns not-found), the fallback path's own Get and
// Save calls succeed or fail independently of whatever SaveIfAbsent's error
// was, so a real backend fault still surfaces - it just costs one extra
// round trip. If the row is occupied, the fallback compares serials exactly
// as the atomic path does.
//
// The fallback is NOT atomic against a second, concurrent caller racing to
// create a certificate that hashes to the same row: two callers can both
// observe "not found" and both Save, and the second Save wins silently. This
// is a real, currently-unclosed gap on any backend that does not satisfy
// qrdbsdk.AtomicKVStore (see pkg/storage/kvadapter for which backends do).
// Closing it fully would need a create-only compare-and-swap primitive
// exposed through go-qrdb's SDK boundary, which does not exist today; this
// function does not add one.
func SaveCertificateNoCollision(
	ctx context.Context,
	certDAO qrdbsdk.GenericDAO[*entities.ACMECertificate],
	cert *entities.ACMECertificate,
) error {
	stored, err := certDAO.SaveIfAbsent(ctx, cert)
	if err == nil {
		if stored {
			return nil
		}
		return refuseOnCollision(ctx, certDAO, cert)
	}

	// SaveIfAbsent failed. This may mean the backend doesn't support atomic
	// writes (see the doc comment above for why that can't be distinguished
	// here from a genuine failure) - fall back to Get-then-Save, which
	// surfaces a genuine backend fault on its own.
	existing, getErr := certDAO.Get(ctx, cert.EntityID())
	if getErr == nil {
		return collisionOrNil(cert, existing)
	}
	if !qrdbsdk.IsDAONotFound(getErr) {
		return getErr
	}
	return certDAO.Save(ctx, cert)
}

// refuseOnCollision is called after SaveIfAbsent atomically reports the row
// was already occupied: it fetches the occupant and refuses the save if it
// is a different certificate.
func refuseOnCollision(
	ctx context.Context,
	certDAO qrdbsdk.GenericDAO[*entities.ACMECertificate],
	cert *entities.ACMECertificate,
) error {
	existing, err := certDAO.Get(ctx, cert.EntityID())
	if err != nil {
		return err
	}
	return collisionOrNil(cert, existing)
}

// collisionOrNil returns a *CertificateSerialCollisionError if existing is a
// different certificate than cert, and nil if it is the same certificate
// (an idempotent re-save).
func collisionOrNil(cert, existing *entities.ACMECertificate) error {
	if existing.Serial != cert.Serial {
		return &CertificateSerialCollisionError{Wanted: cert.Serial, Existing: existing.Serial}
	}
	return nil
}
