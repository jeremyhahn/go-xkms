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

package fido2

import (
	"crypto/elliptic"
	"encoding/base64"
	"math/big"
	"strconv"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/factor/internal/decoy"
)

// decoyLabel versions the FIDO2 decoy derivation. Anything that changes what
// a given (seed, userID, like) derives needs a new label.
const decoyLabel = "xkms/fido2-decoy/v1"

// COSE key parameters (RFC 9052, RFC 9053) a decoy key is encoded with.
const (
	coseKeyType    = 1
	coseAlgorithm  = 3
	coseParamMinus = -1 // crv (EC2, OKP) or n (RSA)
	coseParamX     = -2 // x (EC2, OKP) or e (RSA)
	coseParamY     = -3 // y (EC2)

	coseKtyOKP     = 1
	coseKtyEC2     = 2
	coseKtyRSA     = 3
	coseCrvEd25519 = 6
	coseAlgEdDSA   = -8
	ed25519KeySize = 32
)

// rsaExponent is the only RSA public exponent a decoy key can carry.
var rsaExponent = []byte{0x01, 0x00, 0x01}

// decoyCurves maps each COSE EC2 curve a decoy can imitate to the curve.
var decoyCurves = map[int64]elliptic.Curve{
	1: elliptic.P256(),
	2: elliptic.P384(),
	3: elliptic.P521(),
}

// credentialIDEncodings are the encodings a credential id is recognised in,
// most specific first: a base64url id without '-' or '_' also decodes as
// unpadded standard base64, and is taken to be base64url.
var credentialIDEncodings = []*base64.Encoding{
	base64.RawURLEncoding,
	base64.URLEncoding,
	base64.StdEncoding,
	base64.RawStdEncoding,
}

// defaultCredentialIDSize is the byte length of a decoy credential id when
// like has none to imitate.
const defaultCredentialIDSize = 32

// coseShape is the type and size of an enrolled COSE key: the part of the
// key a challenge reveals besides the key itself.
type coseShape struct {
	kty int64
	alg int64
	// crv is the EC2 or OKP curve.
	crv int64
	// bits is the RSA modulus size.
	bits int
}

// credentialIDShape is the encoding and decoded length of a credential id.
type credentialIDShape struct {
	encoding int
	size     int
}

// relyingParty is an enrollment's rp id together with its origins, which are
// chosen together so that the decoy never pairs one holder's rp id with
// another's origins.
type relyingParty struct {
	rpID    string
	origins string
}

// shapeOfCOSE classifies a COSE public key. It reports false for a key the
// decoy cannot imitate.
func shapeOfCOSE(cose []byte) (coseShape, bool) {
	parsed, err := webauthncose.ParsePublicKey(cose)
	if err != nil {
		return coseShape{}, false
	}
	switch key := parsed.(type) {
	case webauthncose.EC2PublicKeyData:
		if _, ok := decoyCurves[key.Curve]; ok {
			return coseShape{kty: coseKtyEC2, alg: key.Algorithm, crv: key.Curve}, true
		}
	case webauthncose.OKPPublicKeyData:
		// go-webauthn does not decode an OKP key's curve; Ed25519 is the one
		// EdDSA curve with 32-byte keys.
		if key.Algorithm == coseAlgEdDSA && len(key.XCoord) == ed25519KeySize {
			return coseShape{kty: coseKtyOKP, alg: coseAlgEdDSA, crv: coseCrvEd25519}, true
		}
	case webauthncose.RSAPublicKeyData:
		bits := new(big.Int).SetBytes(key.Modulus).BitLen()
		if decoy.RSASizeSupported(bits) && new(big.Int).SetBytes(key.Exponent).Cmp(new(big.Int).SetBytes(rsaExponent)) == 0 {
			return coseShape{kty: coseKtyRSA, alg: key.Algorithm, bits: bits}, true
		}
	}
	return coseShape{}, false
}

// derive derives a COSE public key of the shape, in the canonical CTAP2
// encoding authenticators produce.
func (s coseShape) derive(d *decoy.Deriver) ([]byte, error) {
	key := map[int]any{coseKeyType: s.kty, coseAlgorithm: s.alg}
	switch s.kty {
	case coseKtyRSA:
		priv, err := d.RSAKey("key", s.bits)
		if err != nil {
			return nil, err
		}
		key[coseParamMinus] = priv.N.Bytes()
		key[coseParamX] = rsaExponent
	case coseKtyOKP:
		priv, err := d.Ed25519Key("key")
		if err != nil {
			return nil, err
		}
		key[coseParamMinus] = s.crv
		// An Ed25519 private key is its seed followed by its public key.
		key[coseParamX] = []byte(priv[ed25519KeySize:])
	default:
		priv, err := d.ECDSAKey("key", decoyCurves[s.crv])
		if err != nil {
			return nil, err
		}
		point, err := priv.PublicKey.Bytes()
		if err != nil {
			return nil, &decoy.DerivationError{Purpose: "key"}
		}
		size := (len(point) - 1) / 2
		key[coseParamMinus] = s.crv
		key[coseParamX] = point[1 : 1+size]
		key[coseParamY] = point[1+size:]
	}
	cose, err := webauthncbor.Marshal(key)
	if err != nil {
		return nil, &decoy.DerivationError{Purpose: "key"}
	}
	return cose, nil
}

// shapeOfCredentialID classifies a credential id. It reports false for an id
// in none of credentialIDEncodings.
func shapeOfCredentialID(id string) (credentialIDShape, bool) {
	for i, enc := range credentialIDEncodings {
		if raw, err := enc.DecodeString(id); err == nil && len(raw) > 0 {
			return credentialIDShape{encoding: i, size: len(raw)}, true
		}
	}
	return credentialIDShape{}, false
}

// DecoyEnrollment returns the stand-in enrollment go-qrdb challenges userID
// with when userID holds no FIDO2 enrollment, so the challenge cannot be told
// from a real holder's (go-qrdb authfactors.DecoyEnroller).
//
// The result is a function of (seed, userID, like). Its COSE key has the
// type, algorithm and size predominant among like's keys, its credential id
// is derived in the encoding and length predominant among like's, and its rp
// id with origins, user-verification requirement, AAGUID and ttl follow the
// values predominant in like's metadata. An empty like yields the form
// New(cfg).Enroll records for an ES256 P-256 credential with a 32-byte id
// and no other MethodParams. No private key exists, so Verify fails against
// the decoy for any assertion.
func (f *Factor) DecoyEnrollment(seed []byte, userID string, like []*qrdbsdk.AuthFactorEnrollment) (*qrdbsdk.AuthFactorEnrollment, error) {
	d, err := decoy.New(decoyLabel, seed, userID)
	if err != nil {
		return nil, err
	}

	keyShapes := make([]coseShape, 0, len(like))
	idShapes := make([]credentialIDShape, 0, len(like))
	parties := make([]relyingParty, 0, len(like))
	for _, e := range like {
		if e == nil {
			continue
		}
		if s, ok := shapeOfCOSE(e.PublicKey); ok {
			keyShapes = append(keyShapes, s)
		}
		if s, ok := shapeOfCredentialID(e.Metadata["credential_id"]); ok {
			idShapes = append(idShapes, s)
		}
		if rpID := e.Metadata["rp_id"]; rpID != "" {
			parties = append(parties, relyingParty{rpID: rpID, origins: e.Metadata["origins"]})
		}
	}

	cose, err := decoy.Predominant(keyShapes, coseShape{kty: coseKtyEC2, alg: int64(webauthncose.AlgES256), crv: 1}).derive(d)
	if err != nil {
		return nil, err
	}
	idShape := decoy.Predominant(idShapes, credentialIDShape{encoding: 0, size: defaultCredentialIDSize})
	rawID, err := d.Bytes("credential-id", idShape.size)
	if err != nil {
		return nil, err
	}
	party := decoy.Predominant(parties, relyingParty{rpID: f.cfg.RPID, origins: "https://" + f.cfg.RPID})

	metadata := map[string]string{
		"credential_id": credentialIDEncodings[idShape.encoding].EncodeToString(rawID),
		"rp_id":         party.rpID,
		"ttl":           decoy.Predominant(decoy.NonEmpty(decoy.MetadataValues(like, "ttl")), strconv.Itoa(f.cfg.ChallengeTTLSeconds)),
		"origins":       party.origins,
		"require_uv":    decoy.Predominant(decoy.NonEmpty(decoy.MetadataValues(like, "require_uv")), "true"),
	}
	if v := decoy.Predominant(decoy.MetadataValues(like, "aaguid"), ""); v != "" {
		metadata["aaguid"] = v
	}
	return d.Enrollment(FactorName, like, cose, metadata)
}
