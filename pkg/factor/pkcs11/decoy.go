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

package pkcs11

import (
	"crypto/x509"
	"encoding/hex"
	"strconv"
	"strings"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/factor/internal/decoy"
)

// decoyLabel versions the PKCS#11 decoy derivation. Anything that changes
// what a given (seed, userID, like) derives needs a new label.
const decoyLabel = "xkms/pkcs11-decoy/v1"

// shapeOf classifies a PKIX public key. It reports false for a key the decoy
// cannot imitate or the factor does not enrol.
func shapeOf(der []byte) (decoy.KeyShape, bool) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return decoy.KeyShape{}, false
	}
	s, ok := decoy.ShapeOfKey(pub)
	if !ok || s.Algorithm != publicKeyAlgorithm(pub) {
		return decoy.KeyShape{}, false
	}
	return s, true
}

// DecoyEnrollment returns the stand-in enrollment go-qrdb challenges userID
// with when userID holds no PKCS#11 enrollment, so the challenge cannot be
// told from a real holder's (go-qrdb authfactors.DecoyEnroller).
//
// The result is a function of (seed, userID, like). Its key has the type and
// size predominant among like's keys, and its mechanism, key id, token label,
// slot and ttl follow the values predominant in like's metadata; a key id
// that is hex, as a CKA_ID is, is replaced by derived hex of the same length.
// An empty like yields the form New(cfg).Enroll records for a key of the
// configured default mechanism: ECDSA P-256, or RSA-2048 when that mechanism
// is an RSA one. The private key is discarded, so Verify fails against the
// decoy for any response.
func (f *Factor) DecoyEnrollment(seed []byte, userID string, like []*qrdbsdk.AuthFactorEnrollment) (*qrdbsdk.AuthFactorEnrollment, error) {
	d, err := decoy.New(decoyLabel, seed, userID)
	if err != nil {
		return nil, err
	}

	shape := f.decoyShape(like)
	key, err := d.Key("key", shape)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, &decoy.DerivationError{Purpose: "public key"}
	}

	var mechanisms []string
	for _, m := range decoy.MetadataValues(like, "mechanism") {
		if mechanismFamily(m) == shape.Algorithm {
			mechanisms = append(mechanisms, m)
		}
	}
	metadata := map[string]string{
		"algorithm": shape.Algorithm,
		"mechanism": decoy.Predominant(mechanisms, f.defaultMechanismFor(shape.Algorithm)),
		"ttl":       decoy.Predominant(decoy.NonEmpty(decoy.MetadataValues(like, "ttl")), strconv.Itoa(f.cfg.ChallengeTTLSeconds)),
	}
	if v := decoy.Predominant(decoy.MetadataValues(like, "key_id"), ""); v != "" {
		keyID, err := decoyKeyID(d, v)
		if err != nil {
			return nil, err
		}
		metadata["key_id"] = keyID
	}
	for _, key := range []string{"token_label", "slot"} {
		if v := decoy.Predominant(decoy.MetadataValues(like, key), ""); v != "" {
			metadata[key] = v
		}
	}
	return d.Enrollment(FactorName, like, der, metadata)
}

// decoyShape returns the key shape predominant among like's keys, or the
// shape of the configured default mechanism.
func (f *Factor) decoyShape(like []*qrdbsdk.AuthFactorEnrollment) decoy.KeyShape {
	fallback := decoy.KeyShape{Algorithm: decoy.AlgorithmECDSA, Curve: "P-256"}
	if mechanismFamily(f.cfg.DefaultMechanism) == decoy.AlgorithmRSA {
		fallback = decoy.KeyShape{Algorithm: decoy.AlgorithmRSA, Bits: 2048}
	}
	shapes := make([]decoy.KeyShape, 0, len(like))
	for _, e := range like {
		if e == nil {
			continue
		}
		if s, ok := shapeOf(e.PublicKey); ok {
			shapes = append(shapes, s)
		}
	}
	return decoy.Predominant(shapes, fallback)
}

// defaultMechanismFor returns the mechanism Enroll records for a key of
// algorithm enrolled without an explicit one.
func (f *Factor) defaultMechanismFor(algorithm string) string {
	if mechanismFamily(f.cfg.DefaultMechanism) == algorithm {
		return f.cfg.DefaultMechanism
	}
	if algorithm == "rsa" {
		return defaultRSAMechanism
	}
	return defaultMechanism
}

// decoyKeyID imitates the key id sample. A hex id, as a CKA_ID is, belongs
// to one key, so the decoy derives its own of the same length and case; any
// other id is a label shared by every holder's key and is kept as is.
func decoyKeyID(d *decoy.Deriver, sample string) (string, error) {
	if len(sample)%2 != 0 {
		return sample, nil
	}
	if _, err := hex.DecodeString(sample); err != nil {
		return sample, nil
	}
	b, err := d.Bytes("key-id", len(sample)/2)
	if err != nil {
		return "", err
	}
	id := hex.EncodeToString(b)
	if sample != strings.ToLower(sample) {
		id = strings.ToUpper(id)
	}
	return id, nil
}
