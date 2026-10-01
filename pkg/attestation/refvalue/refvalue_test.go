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

package refvalue

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	cose "github.com/veraison/go-cose"
	"github.com/veraison/swid"
)

// fixedNow is the verification time every test uses, so no test depends on
// the wall clock.
var fixedNow = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

// pcr0SHA256 and friends are the reference digests the fixtures carry.
var (
	pcr0SHA256 = sha256.Sum256([]byte("pcr0"))
	pcr7SHA256 = sha256.Sum256([]byte("pcr7"))
	pcr0SHA384 = sha512.Sum384([]byte("pcr0"))
)

// buildCoMID returns a CoMID with one TPM-style reference value: a class
// naming the platform, a bytes instance, PCR 0 with SHA-256 and SHA-384
// digests and an SVN, PCR 7 with a SHA-256 digest, and an OID-keyed
// measurement with a raw value.
func buildCoMID(t *testing.T) comid.Comid {
	t.Helper()
	inst, err := comid.NewBytesInstance([]byte{0xde, 0xad, 0xbe, 0xef})
	if err != nil {
		t.Fatalf("instance: %v", err)
	}
	class := comid.NewClassOID("1.3.6.1.4.1.29377.200.1")
	class.SetVendor("Example Vendor").SetModel("Example Board").SetLayer(0).SetIndex(1)

	m0, err := comid.NewMeasurement(uint64(0), comid.UintType)
	if err != nil {
		t.Fatalf("measurement 0: %v", err)
	}
	m0.AddDigest(swid.Sha256, pcr0SHA256[:]).AddDigest(swid.Sha384, pcr0SHA384[:]).SetSVN(3)

	m7, err := comid.NewMeasurement(uint64(7), comid.UintType)
	if err != nil {
		t.Fatalf("measurement 7: %v", err)
	}
	m7.AddDigest(swid.Sha256, pcr7SHA256[:]).SetMinSVN(2)

	mOID, err := comid.NewMeasurement("1.2.3.4", comid.OIDType)
	if err != nil {
		t.Fatalf("measurement oid: %v", err)
	}
	mOID.SetRawValueBytes([]byte{1, 2, 3}, nil)

	measurements := comid.NewMeasurements().AddMeasurement(m0).AddMeasurement(m7).AddMeasurement(mOID)
	c := comid.NewComid().SetTagIdentity("tpm-reference-values", 0).AddReferenceValue(comid.ReferenceValue{
		Environment:  comid.Environment{Class: class, Instance: inst},
		Measurements: *measurements,
	})
	if c == nil {
		t.Fatal("comid builder rejected the reference value")
	}
	if err := c.Valid(); err != nil {
		t.Fatalf("comid invalid: %v", err)
	}
	return *c
}

// buildUnsigned returns an unsigned CoRIM around c.
func buildUnsigned(t *testing.T, c comid.Comid, rimValidity *corim.Validity) []byte {
	t.Helper()
	u := corim.NewUnsignedCorim().SetID("corim-1").AddComid(c).AddProfile("tag:example.com,2026:tpm-pcr")
	if u == nil {
		t.Fatal("unsigned corim builder failed")
	}
	u.RimValidity = rimValidity
	payload, err := u.ToCBOR()
	if err != nil {
		t.Fatalf("unsigned corim cbor: %v", err)
	}
	return payload
}

// signOptions shapes one signed-CoRIM fixture.
type signOptions struct {
	alg        cose.Algorithm
	key        crypto.Signer
	chain      [][]byte
	unprotect  bool // carry x5chain in the unprotected header
	validity   *corim.Validity
	rim        *corim.Validity
	tamperByte bool
}

// signCoRIM builds a COSE_Sign1 signed CoRIM the way the specification lays
// it out: alg, content type and corim-meta protected, x5chain optional.
func signCoRIM(t *testing.T, o signOptions) []byte {
	t.Helper()
	payload := buildUnsigned(t, buildCoMID(t), o.rim)

	meta := corim.NewMeta().SetSigner("Example Reference Value Provider", nil)
	meta.Validity = o.validity
	metaCBOR, err := meta.ToCBOR()
	if err != nil {
		t.Fatalf("meta cbor: %v", err)
	}

	msg := cose.NewSign1Message()
	msg.Payload = payload
	msg.Headers.Protected.SetAlgorithm(o.alg)
	msg.Headers.Protected[cose.HeaderLabelContentType] = corim.ContentType
	msg.Headers.Protected[corim.HeaderLabelCorimMeta] = metaCBOR
	if o.chain != nil {
		chain := make([]any, len(o.chain))
		for i, der := range o.chain {
			chain[i] = der
		}
		if o.unprotect {
			msg.Headers.Unprotected[cose.HeaderLabelX5Chain] = chain
		} else {
			msg.Headers.Protected[cose.HeaderLabelX5Chain] = chain
		}
	}
	signer, err := cose.NewSigner(o.alg, o.key)
	if err != nil {
		t.Fatalf("cose signer: %v", err)
	}
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		t.Fatalf("cose sign: %v", err)
	}
	if o.tamperByte {
		msg.Signature[0] ^= 0xff
	}
	out, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatalf("cose marshal: %v", err)
	}
	return out
}

func newKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	return k
}

// pki is a root and a signer leaf issued by it.
type pki struct {
	root    *x509.Certificate
	leaf    *x509.Certificate
	leafKey *ecdsa.PrivateKey
}

func newPKI(t *testing.T) pki {
	t.Helper()
	rootKey := newKey(t, elliptic.P384())
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Reference Value Root"},
		NotBefore:             fixedNow.Add(-time.Hour),
		NotAfter:              fixedNow.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("root parse: %v", err)
	}
	leafKey := newKey(t, elliptic.P256())
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Reference Value Signer"},
		NotBefore:    fixedNow.Add(-time.Hour),
		NotAfter:     fixedNow.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, leafKey.Public(), rootKey)
	if err != nil {
		t.Fatalf("leaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("leaf parse: %v", err)
	}
	return pki{root: root, leaf: leaf, leafKey: leafKey}
}

func (p pki) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.root)
	return pool
}

func window(from, to time.Time) *corim.Validity {
	return &corim.Validity{NotBefore: &from, NotAfter: to}
}

// checkManifest asserts the fixture's content came through intact.
func checkManifest(t *testing.T, m *Manifest) {
	t.Helper()
	if m.ID != "corim-1" || m.Profile != "tag:example.com,2026:tpm-pcr" || m.Signer != "Example Reference Value Provider" {
		t.Fatalf("identity = %q %q %q", m.ID, m.Profile, m.Signer)
	}
	if len(m.ReferenceValues) != 1 {
		t.Fatalf("reference values = %d, want 1", len(m.ReferenceValues))
	}
	rv := m.ReferenceValues[0]
	env := rv.Environment
	if env.Vendor != "Example Vendor" || env.Model != "Example Board" || env.ClassIDType != "oid" || env.ClassID != "1.3.6.1.4.1.29377.200.1" {
		t.Fatalf("environment class = %+v", env)
	}
	if env.Layer == nil || *env.Layer != 0 || env.Index == nil || *env.Index != 1 {
		t.Fatalf("layer/index = %v/%v", env.Layer, env.Index)
	}
	if env.InstanceType != "bytes" || !bytes.Equal(env.InstanceBytes, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Fatalf("instance = %q %x", env.InstanceType, env.InstanceBytes)
	}
	if len(rv.Measurements) != 3 {
		t.Fatalf("measurements = %d, want 3", len(rv.Measurements))
	}
	m0 := rv.Measurements[0]
	if m0.Key.Kind != KeyKindUint || m0.Key.Uint != 0 || len(m0.Digests) != 2 || m0.SVN == nil || *m0.SVN != 3 {
		t.Fatalf("pcr0 measurement = %+v", m0)
	}
	m7 := rv.Measurements[1]
	if m7.MinSVN == nil || *m7.MinSVN != 2 || m7.SVN != nil {
		t.Fatalf("pcr7 svn = %v min %v", m7.SVN, m7.MinSVN)
	}
	mOID := rv.Measurements[2]
	if mOID.Key.Kind != KeyKindOID || mOID.Key.String != "1.2.3.4" || !bytes.Equal(mOID.RawValue, []byte{1, 2, 3}) {
		t.Fatalf("oid measurement = %+v", mOID)
	}
}

func TestVerifySigned_PublicKey(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alg   cose.Algorithm
		curve elliptic.Curve
	}{
		{"ES256", cose.AlgorithmES256, elliptic.P256()},
		{"ES384", cose.AlgorithmES384, elliptic.P384()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := newKey(t, tc.curve)
			validity := window(fixedNow.Add(-time.Hour), fixedNow.Add(time.Hour))
			data := signCoRIM(t, signOptions{alg: tc.alg, key: key, validity: validity, rim: validity})
			m, err := VerifySigned(data, VerifyOptions{PublicKey: key.Public(), Now: fixedNow})
			if err != nil {
				t.Fatalf("VerifySigned: %v", err)
			}
			checkManifest(t, m)
			if !m.NotBefore.Equal(fixedNow.Add(-time.Hour)) || !m.NotAfter.Equal(fixedNow.Add(time.Hour)) {
				t.Fatalf("validity = %v..%v", m.NotBefore, m.NotAfter)
			}
		})
	}
}

func TestVerifySigned_Roots(t *testing.T) {
	p := newPKI(t)
	for _, unprotect := range []bool{false, true} {
		data := signCoRIM(t, signOptions{
			alg: cose.AlgorithmES256, key: p.leafKey,
			chain: [][]byte{p.leaf.Raw, p.root.Raw}, unprotect: unprotect,
		})
		m, err := VerifySigned(data, VerifyOptions{Roots: p.pool(), Now: fixedNow})
		if err != nil {
			t.Fatalf("VerifySigned(unprotected=%v): %v", unprotect, err)
		}
		checkManifest(t, m)
	}

	// A single-certificate x5chain (a bare byte string) is also accepted, with
	// the intermediates pool supplementing it.
	single := signCoRIMSingleCert(t, p)
	if _, err := VerifySigned(single, VerifyOptions{Roots: p.pool(), Intermediates: x509.NewCertPool(), Now: fixedNow}); err != nil {
		t.Fatalf("single-cert x5chain: %v", err)
	}
}

// signCoRIMSingleCert carries the leaf alone as a bare x5chain byte string.
func signCoRIMSingleCert(t *testing.T, p pki) []byte {
	t.Helper()
	payload := buildUnsigned(t, buildCoMID(t), nil)
	metaCBOR, err := corim.NewMeta().SetSigner("Example Reference Value Provider", nil).ToCBOR()
	if err != nil {
		t.Fatalf("meta: %v", err)
	}
	msg := cose.NewSign1Message()
	msg.Payload = payload
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	msg.Headers.Protected[cose.HeaderLabelContentType] = corim.ContentType
	msg.Headers.Protected[corim.HeaderLabelCorimMeta] = metaCBOR
	msg.Headers.Protected[cose.HeaderLabelX5Chain] = p.leaf.Raw
	signer, err := cose.NewSigner(cose.AlgorithmES256, p.leafKey)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		t.Fatalf("sign: %v", err)
	}
	out, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return out
}

func TestVerifySigned_Failures(t *testing.T) {
	key := newKey(t, elliptic.P256())
	other := newKey(t, elliptic.P256())
	p := newPKI(t)
	wrongRoot := newPKI(t)
	good := signCoRIM(t, signOptions{alg: cose.AlgorithmES256, key: key})

	unsigned := buildUnsigned(t, buildCoMID(t), nil)

	tests := []struct {
		name string
		data []byte
		opts VerifyOptions
		want error
	}{
		{"neither trust source", good, VerifyOptions{Now: fixedNow}, ErrTrustSource},
		{"both trust sources", good, VerifyOptions{PublicKey: key.Public(), Roots: p.pool(), Now: fixedNow}, ErrTrustSource},
		{"wrong key", good, VerifyOptions{PublicKey: other.Public(), Now: fixedNow}, ErrSignature},
		{"tampered signature", signCoRIM(t, signOptions{alg: cose.AlgorithmES256, key: key, tamperByte: true}), VerifyOptions{PublicKey: key.Public(), Now: fixedNow}, ErrSignature},
		{"unsigned input", unsigned, VerifyOptions{PublicKey: key.Public(), Now: fixedNow}, ErrMalformed},
		{"garbage", []byte{0x01, 0x02}, VerifyOptions{PublicKey: key.Public(), Now: fixedNow}, ErrMalformed},
		{"signature expired", signCoRIM(t, signOptions{alg: cose.AlgorithmES256, key: key, validity: window(fixedNow.Add(-2*time.Hour), fixedNow.Add(-time.Hour))}), VerifyOptions{PublicKey: key.Public(), Now: fixedNow}, ErrExpired},
		{"signature not yet valid", signCoRIM(t, signOptions{alg: cose.AlgorithmES256, key: key, validity: window(fixedNow.Add(time.Hour), fixedNow.Add(2*time.Hour))}), VerifyOptions{PublicKey: key.Public(), Now: fixedNow}, ErrNotYetValid},
		{"rim expired", signCoRIM(t, signOptions{alg: cose.AlgorithmES256, key: key, rim: window(fixedNow.Add(-2*time.Hour), fixedNow.Add(-time.Hour))}), VerifyOptions{PublicKey: key.Public(), Now: fixedNow}, ErrExpired},
		{"chain to wrong root", signCoRIM(t, signOptions{alg: cose.AlgorithmES256, key: p.leafKey, chain: [][]byte{p.leaf.Raw}}), VerifyOptions{Roots: wrongRoot.pool(), Now: fixedNow}, ErrSignerChain},
		{"no x5chain", good, VerifyOptions{Roots: p.pool(), Now: fixedNow}, ErrSignerChain},
		{"x5chain garbage cert", signCoRIM(t, signOptions{alg: cose.AlgorithmES256, key: p.leafKey, chain: [][]byte{{0x30, 0x00}}}), VerifyOptions{Roots: p.pool(), Now: fixedNow}, ErrSignerChain},
		{"chain valid but signed by another key", signCoRIM(t, signOptions{alg: cose.AlgorithmES256, key: key, chain: [][]byte{p.leaf.Raw}}), VerifyOptions{Roots: p.pool(), Now: fixedNow}, ErrSignature},
		{"chain expired at verification time", signCoRIM(t, signOptions{alg: cose.AlgorithmES256, key: p.leafKey, chain: [][]byte{p.leaf.Raw}}), VerifyOptions{Roots: p.pool(), Now: fixedNow.Add(48 * time.Hour)}, ErrSignerChain},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := VerifySigned(tc.data, tc.opts)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if m != nil {
				t.Fatal("a manifest was returned with an error")
			}
		})
	}
}

func TestVerifySigned_DefaultsNowToWallClock(t *testing.T) {
	key := newKey(t, elliptic.P256())
	// A window around the real present: the zero Now must resolve to it.
	now := time.Now()
	data := signCoRIM(t, signOptions{alg: cose.AlgorithmES256, key: key, validity: window(now.Add(-time.Hour), now.Add(time.Hour))})
	if _, err := VerifySigned(data, VerifyOptions{PublicKey: key.Public()}); err != nil {
		t.Fatalf("VerifySigned with zero Now: %v", err)
	}
}

func TestParseX5Chain_Shapes(t *testing.T) {
	if _, err := parseX5Chain(42); !errors.Is(err, ErrSignerChain) {
		t.Fatalf("int: %v", err)
	}
	if _, err := parseX5Chain([]any{"not bytes"}); !errors.Is(err, ErrSignerChain) {
		t.Fatalf("string element: %v", err)
	}
	if _, err := parseX5Chain([]any{}); !errors.Is(err, ErrSignerChain) {
		t.Fatalf("empty: %v", err)
	}
}

func TestPCRDigests(t *testing.T) {
	key := newKey(t, elliptic.P256())
	m, err := VerifySigned(signCoRIM(t, signOptions{alg: cose.AlgorithmES256, key: key}), VerifyOptions{PublicKey: key.Public(), Now: fixedNow})
	if err != nil {
		t.Fatalf("VerifySigned: %v", err)
	}

	sha256Values, err := m.PCRDigests(crypto.SHA256)
	if err != nil {
		t.Fatalf("PCRDigests(SHA256): %v", err)
	}
	if len(sha256Values) != 2 || !bytes.Equal(sha256Values[0][0], pcr0SHA256[:]) || !bytes.Equal(sha256Values[7][0], pcr7SHA256[:]) {
		t.Fatalf("sha256 values = %x", sha256Values)
	}
	sha384Values, err := m.PCRDigests(crypto.SHA384)
	if err != nil {
		t.Fatalf("PCRDigests(SHA384): %v", err)
	}
	if len(sha384Values) != 1 || !bytes.Equal(sha384Values[0][0], pcr0SHA384[:]) {
		t.Fatalf("sha384 values = %x", sha384Values)
	}
	// The result must not alias the manifest.
	sha256Values[0][0][0] ^= 0xff
	if m.ReferenceValues[0].Measurements[0].Digests[0].Value[0] == sha256Values[0][0][0] {
		t.Fatal("PCRDigests aliases the manifest's digest")
	}
}

func TestPCRDigests_Errors(t *testing.T) {
	uintMeasurement := func(idx uint64, d Digest) *Manifest {
		return &Manifest{ReferenceValues: []ReferenceValue{{Measurements: []Measurement{{
			Key:     MeasurementKey{Kind: KeyKindUint, Uint: idx, String: "pcr"},
			Digests: []Digest{d},
		}}}}}
	}
	good := pcr0SHA256

	if _, err := uintMeasurement(24, Digest{Algorithm: swid.Sha256, Value: good[:]}).PCRDigests(crypto.SHA256); !errors.Is(err, ErrPCRIndex) {
		t.Fatalf("index 24: %v", err)
	}
	if _, err := uintMeasurement(0, Digest{Algorithm: swid.Sha256, Value: good[:20]}).PCRDigests(crypto.SHA256); !errors.Is(err, ErrDigestLength) {
		t.Fatalf("short digest: %v", err)
	}
	if _, err := uintMeasurement(0, Digest{Algorithm: swid.Sha256, Value: good[:]}).PCRDigests(crypto.SHA1); !errors.Is(err, ErrUnsupportedHash) {
		t.Fatalf("sha1: %v", err)
	}
}

func TestDigestHash(t *testing.T) {
	for alg, want := range map[uint64]crypto.Hash{swid.Sha256: crypto.SHA256, swid.Sha384: crypto.SHA384, swid.Sha512: crypto.SHA512} {
		if got, ok := (Digest{Algorithm: alg}).Hash(); !ok || got != want {
			t.Fatalf("alg %d = %v %v", alg, got, ok)
		}
	}
	if _, ok := (Digest{Algorithm: swid.Sha256_128}).Hash(); ok {
		t.Fatal("truncated sha-256 must not map to a hash")
	}
}
