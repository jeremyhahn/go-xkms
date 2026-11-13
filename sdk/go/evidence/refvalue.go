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

package evidence

import "github.com/jeremyhahn/go-xkms/pkg/attestation/refvalue"

// Signed reference values (CoRIM). These re-export pkg/attestation/refvalue:
// VerifySignedCoRIM verifies a COSE_Sign1 signed CoRIM against a pinned key
// or a certificate chain and returns its reference-value triples.

// CoRIMVerifyOptions selects the signer trust source and verification time.
type CoRIMVerifyOptions = refvalue.VerifyOptions

// ReferenceManifest is a verified CoRIM's identity and reference values.
type ReferenceManifest = refvalue.Manifest

// ReferenceValue is one reference-value triple.
type ReferenceValue = refvalue.ReferenceValue

// ReferenceEnvironment identifies a reference value's target environment.
type ReferenceEnvironment = refvalue.Environment

// ReferenceMeasurement is one expected measurement.
type ReferenceMeasurement = refvalue.Measurement

// MeasurementKey is a measurement's key (mkey).
type MeasurementKey = refvalue.MeasurementKey

// ReferenceDigest is one expected digest with its IANA hash identifier.
type ReferenceDigest = refvalue.Digest

// Measurement key kinds.
const (
	MeasurementKeyNone                = refvalue.KeyKindNone
	MeasurementKeyUint                = refvalue.KeyKindUint
	MeasurementKeyOID                 = refvalue.KeyKindOID
	MeasurementKeyUUID                = refvalue.KeyKindUUID
	MeasurementKeyPSARefValID         = refvalue.KeyKindPSARefValID
	MeasurementKeyCCAPlatformConfigID = refvalue.KeyKindCCAPlatformConfigID
)

// VerifySignedCoRIM verifies a COSE_Sign1 signed CoRIM and returns its
// reference values.
var VerifySignedCoRIM = refvalue.VerifySigned

// SignCoRIM wraps an unsigned CoRIM in the COSE_Sign1 signed-corim of
// draft-ietf-rats-corim-11 §4.2, signed with a crypto.Signer.
var SignCoRIM = refvalue.Sign

// CoRIMMeta is the corim-meta-map SignCoRIM puts in the protected header,
// §4.2.3: the signer and an optional signature validity.
type CoRIMMeta = refvalue.Meta

// CoRIM verification errors, matched with errors.Is.
var (
	ErrCoRIMTrustSource     = refvalue.ErrTrustSource
	ErrCoRIMMalformed       = refvalue.ErrMalformed
	ErrCoRIMSignerChain     = refvalue.ErrSignerChain
	ErrCoRIMSignature       = refvalue.ErrSignature
	ErrCoRIMNotYetValid     = refvalue.ErrNotYetValid
	ErrCoRIMExpired         = refvalue.ErrExpired
	ErrCoRIMPCRIndex        = refvalue.ErrPCRIndex
	ErrCoRIMDigestLength    = refvalue.ErrDigestLength
	ErrCoRIMUnsupportedHash = refvalue.ErrUnsupportedHash
	ErrCoRIMComponentDigest = refvalue.ErrComponentDigest
	ErrCoRIMSignerKey       = refvalue.ErrSignerKey
	ErrCoRIMMeta            = refvalue.ErrMeta
	ErrCoRIMSign            = refvalue.ErrSign
)
