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

package deviceattest01

import "github.com/jeremyhahn/go-xkms/pkg/acme/entities"

// Record and FromRecord carry a VerifiedAttestation across the ACME server's
// own storage boundary (go-xkms#789, go-xkms#828). The challenge and the
// finalize are two requests, and a server that is not a single process must
// write the evidence down in between; entities.DeviceAttestation is the
// storage-shaped form, persisted on the ACMEChallenge that validated it
// (pkg/acme/entities.ACMEChallenge.DeviceAttestation) through the same ACME
// DAOs every other challenge outcome goes through, not a side store.

// Record converts a verified attestation, together with the device identity
// already checked against the order it authorizes, into the form
// pkg/acme/storage persists.
//
// deviceIdentityType and deviceIdentityValue are recorded as given rather
// than recomputed: they are what the authorization decision was actually
// made against, and a record should say what happened, not what a future
// re-derivation happens to produce from the same bytes.
func (v *VerifiedAttestation) Record(deviceIdentityType, deviceIdentityValue string) *entities.DeviceAttestation {
	return &entities.DeviceAttestation{
		Format:              string(v.Format),
		DeviceIdentityType:  deviceIdentityType,
		DeviceIdentityValue: deviceIdentityValue,
		KeyAuthorization:    v.KeyAuthorization,
		LeafDER:             v.LeafDER,
		Algorithm:           v.Algorithm,
		CertInfo:            v.CertInfo,
		Signature:           v.Signature,
		PubArea:             v.PubArea,
	}
}

// FromRecord reconstructs the VerifiedAttestation a persisted record carries,
// so BindCSRKey can judge it at finalization exactly as it would have judged
// the record VerifyAttestation itself returned at the challenge.
func FromRecord(rec *entities.DeviceAttestation) (*VerifiedAttestation, error) {
	if rec == nil {
		return nil, ErrNoVerifiedAttestation
	}
	return &VerifiedAttestation{
		Format:           AttestationFormat(rec.Format),
		KeyAuthorization: rec.KeyAuthorization,
		LeafDER:          rec.LeafDER,
		Algorithm:        rec.Algorithm,
		CertInfo:         rec.CertInfo,
		Signature:        rec.Signature,
		PubArea:          rec.PubArea,
	}, nil
}
