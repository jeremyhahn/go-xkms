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

package mtls

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/factor/internal/decoy"
)

// decoyLabel versions the mTLS decoy derivation. Anything that changes what
// a given (seed, userID, like) derives needs a new label.
const decoyLabel = "xkms/mtls-decoy/v1"

// defaultSerialSize and defaultValidity shape the decoy certificate when like
// holds no certificate to imitate: a 128-bit serial, valid for a year.
const (
	defaultSerialSize = 16
	defaultValidity   = 365 * 24 * time.Hour
)

// Extensions whose values name the certificate's own key or holder, which a
// decoy replaces rather than copies.
var (
	oidSubjectKeyID   = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidAuthorityKeyID = asn1.ObjectIdentifier{2, 5, 29, 35}
)

// issuerShapes maps each signature algorithm a decoy can sign with
// deterministically to the shape of the key that signs it. An RSA issuer's
// size is read from the imitated certificate's signature.
var issuerShapes = map[x509.SignatureAlgorithm]decoy.KeyShape{
	x509.ECDSAWithSHA256: {Algorithm: decoy.AlgorithmECDSA, Curve: "P-256"},
	x509.ECDSAWithSHA384: {Algorithm: decoy.AlgorithmECDSA, Curve: "P-384"},
	x509.ECDSAWithSHA512: {Algorithm: decoy.AlgorithmECDSA, Curve: "P-521"},
	x509.SHA256WithRSA:   {Algorithm: decoy.AlgorithmRSA},
	x509.SHA384WithRSA:   {Algorithm: decoy.AlgorithmRSA},
	x509.SHA512WithRSA:   {Algorithm: decoy.AlgorithmRSA},
	x509.PureEd25519:     {Algorithm: decoy.AlgorithmEd25519},
}

// nameEncoders maps the (class, tag) of each name value a holder's user id
// can appear in — the string types of a subject attribute, and the
// rfc822Name, dNSName and URI forms of a GeneralName — to how a user id is
// written there: as UTF-8, or percent-encoded where the value is an ASCII
// IA5String.
var nameEncoders = map[[2]int]func(string) string{
	{asn1.ClassUniversal, asn1.TagUTF8String}:      validUTF8,
	{asn1.ClassUniversal, asn1.TagPrintableString}: validUTF8,
	{asn1.ClassUniversal, asn1.TagIA5String}:       url.PathEscape,
	{asn1.ClassContextSpecific, 1}:                 url.PathEscape,
	{asn1.ClassContextSpecific, 2}:                 url.PathEscape,
	{asn1.ClassContextSpecific, 6}:                 url.PathEscape,
}

// certShape is what an enrolled certificate reveals of how it was issued.
type certShape struct {
	key        decoy.KeyShape
	selfSigned bool
	// issuer is the raw issuer name of a certificate that is not self-signed.
	issuer    string
	signature x509.SignatureAlgorithm
}

// nameAttribute is a subject attribute whose value keeps its encoding.
type nameAttribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue
}

// nameAttributeSET is a relative distinguished name. encoding/asn1 encodes a
// slice type whose name ends in SET as a SET.
type nameAttributeSET []nameAttribute

// authorityKeyID is the AuthorityKeyIdentifier extension value as
// crypto/x509 encodes it: the key identifier alone.
type authorityKeyID struct {
	ID []byte `asn1:"optional,tag:0"`
}

// subjectPublicKeyInfo splits a SubjectPublicKeyInfo to reach the key bits a
// subject key identifier is computed over.
type subjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// DecoyEnrollment returns the stand-in enrollment go-qrdb challenges userID
// with when userID holds no mTLS enrollment, so the challenge cannot be told
// from a real holder's (go-qrdb authfactors.DecoyEnroller).
//
// The result is a function of (seed, userID, like). Its certificate imitates
// an enrolled certificate of the predominant shape — key type and size,
// issuer and signature algorithm — over a derived key: the same subject,
// subject alternative names and extensions in the same order, with the
// holder's user id replaced by userID, a derived serial of the predominant
// length and a derived validity start within the span of like's
// certificates, keeping the template's validity period. A certificate whose
// template was CA-issued names the same issuer and authority key identifier
// but is signed by a derived key, since the CA's is not available; that
// signature cannot tell the decoy apart because Challenge exposes only the
// certificate's public key, never the certificate. An empty
// like yields a self-signed ECDSA P-256 client certificate naming userID. No
// private key is kept, so Verify fails against the decoy for any response.
func (f *Factor) DecoyEnrollment(seed []byte, userID string, like []*qrdbsdk.AuthFactorEnrollment) (*qrdbsdk.AuthFactorEnrollment, error) {
	d, err := decoy.New(decoyLabel, seed, userID)
	if err != nil {
		return nil, err
	}

	certs := decoy.Certificates(like)
	serialSizes := make([]int, 0, len(certs))
	for _, cert := range certs {
		serialSizes = append(serialSizes, cert.SerialNumber.BitLen()/8+1)
	}
	serial, err := d.Serial("serial", decoy.Predominant(serialSizes, defaultSerialSize))
	if err != nil {
		return nil, err
	}
	from, to := decoy.NotBeforeSpan(certs)
	notBefore, err := d.Time("not-before", from, to)
	if err != nil {
		return nil, err
	}

	var der []byte
	if tmpl, holder, ok := decoyTemplate(like); ok {
		der, err = imitate(d, tmpl, holder, userID, serial, notBefore)
	} else {
		der, err = defaultCertificate(d, userID, serial, notBefore)
	}
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, &decoy.DerivationError{Purpose: "certificate"}
	}

	metadata := map[string]string{
		"cert_cn":              cert.Subject.CommonName,
		"cert_serial":          cert.SerialNumber.String(),
		"cert_not_before":      cert.NotBefore.UTC().Format(time.RFC3339),
		"cert_not_after":       cert.NotAfter.UTC().Format(time.RFC3339),
		"cert_spki_thumbprint": qrdbsdk.ComputeSPKIThumbprint(cert),
		"ttl":                  decoy.Predominant(decoy.NonEmpty(decoy.MetadataValues(like, "ttl")), strconv.Itoa(f.cfg.ChallengeTTLSeconds)),
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return d.Enrollment(FactorName, like, certPEM, metadata)
}

// shapeOfCert classifies an enrolled certificate. It reports false for a
// certificate the decoy cannot imitate.
func shapeOfCert(cert *x509.Certificate) (certShape, bool) {
	key, ok := decoy.ShapeOfKey(cert.PublicKey)
	if !ok {
		return certShape{}, false
	}
	s := certShape{key: key, selfSigned: bytes.Equal(cert.RawIssuer, cert.RawSubject), signature: cert.SignatureAlgorithm}
	if s.selfSigned {
		_, ok = issuerShapes[cert.SignatureAlgorithm]
		return s, ok
	}
	s.issuer = string(cert.RawIssuer)
	_, ok = issuerShape(cert)
	return s, ok
}

// issuerShape returns the shape of a key that signs as cert's issuer signed.
func issuerShape(cert *x509.Certificate) (decoy.KeyShape, bool) {
	s, ok := issuerShapes[cert.SignatureAlgorithm]
	if !ok {
		return decoy.KeyShape{}, false
	}
	if s.Algorithm == decoy.AlgorithmRSA {
		s.Bits = len(cert.Signature) * 8
		return s, decoy.RSASizeSupported(s.Bits)
	}
	return s, true
}

// decoyTemplate returns the first of like's certificates of the predominant
// shape, with the user id of the holder it was enrolled for.
func decoyTemplate(like []*qrdbsdk.AuthFactorEnrollment) (*x509.Certificate, string, bool) {
	type template struct {
		cert   *x509.Certificate
		holder string
	}
	shapes := make([]certShape, 0, len(like))
	first := make(map[certShape]template, len(like))
	for _, e := range like {
		if e == nil {
			continue
		}
		cert, err := parseCertPEM(e.PublicKey)
		if err != nil {
			continue
		}
		s, ok := shapeOfCert(cert)
		if !ok {
			continue
		}
		shapes = append(shapes, s)
		if _, seen := first[s]; !seen {
			first[s] = template{cert: cert, holder: e.UserID}
		}
	}
	if len(shapes) == 0 {
		return nil, "", false
	}
	t := first[decoy.Predominant(shapes, certShape{})]
	return t.cert, t.holder, true
}

// imitate issues the decoy of tmpl, the certificate of holder, for userID.
func imitate(d *decoy.Deriver, tmpl *x509.Certificate, holder, userID string, serial *big.Int, notBefore time.Time) ([]byte, error) {
	shape, ok := decoy.ShapeOfKey(tmpl.PublicKey)
	if !ok {
		return nil, &decoy.DerivationError{Purpose: "key"}
	}
	key, err := d.Key("key", shape)
	if err != nil {
		return nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, &decoy.DerivationError{Purpose: "key"}
	}
	subject, err := substituteName(tmpl.RawSubject, holder, userID)
	if err != nil {
		return nil, err
	}
	ski, err := subjectKeyID(d, tmpl, spki)
	if err != nil {
		return nil, err
	}
	selfSigned := bytes.Equal(tmpl.RawIssuer, tmpl.RawSubject)
	extensions, err := imitateExtensions(tmpl, holder, userID, ski, selfSigned)
	if err != nil {
		return nil, err
	}

	cert := &x509.Certificate{
		SerialNumber:       serial,
		RawSubject:         subject,
		NotBefore:          notBefore,
		NotAfter:           notBefore.Add(tmpl.NotAfter.Sub(tmpl.NotBefore)),
		SignatureAlgorithm: tmpl.SignatureAlgorithm,
		ExtraExtensions:    extensions,
	}
	parent, issuerKey := cert, key
	if !selfSigned {
		s, ok := issuerShape(tmpl)
		if !ok {
			return nil, &decoy.DerivationError{Purpose: "issuer key"}
		}
		if issuerKey, err = d.Key("issuer-key", s); err != nil {
			return nil, err
		}
		parent = &x509.Certificate{RawSubject: tmpl.RawIssuer, PublicKey: issuerKey.Public()}
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, parent, key.Public(), decoy.Signer(issuerKey))
	if err != nil {
		return nil, &decoy.DerivationError{Purpose: "certificate"}
	}
	return der, nil
}

// defaultCertificate issues the decoy for an empty roster: a self-signed
// ECDSA P-256 client certificate naming userID.
func defaultCertificate(d *decoy.Deriver, userID string, serial *big.Int, notBefore time.Time) ([]byte, error) {
	key, err := d.Key("key", decoy.KeyShape{Algorithm: decoy.AlgorithmECDSA, Curve: "P-256"})
	if err != nil {
		return nil, err
	}
	cert := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: userID},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(defaultValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), decoy.Signer(key))
	if err != nil {
		return nil, &decoy.DerivationError{Purpose: "certificate"}
	}
	return der, nil
}

// imitateExtensions copies tmpl's extensions in order, replacing the subject
// key identifier with ski, the subject alternative names' mentions of holder
// with userID, and a self-signed certificate's authority key identifier with
// ski too.
func imitateExtensions(tmpl *x509.Certificate, holder, userID string, ski []byte, selfSigned bool) ([]pkix.Extension, error) {
	extensions := make([]pkix.Extension, 0, len(tmpl.Extensions))
	for _, ext := range tmpl.Extensions {
		var err error
		switch {
		case ext.Id.Equal(oidSubjectKeyID):
			ext.Value, err = asn1.Marshal(ski)
		case ext.Id.Equal(oidAuthorityKeyID) && selfSigned:
			ext.Value, err = asn1.Marshal(authorityKeyID{ID: ski})
		case ext.Id.Equal(oidSubjectAltName):
			ext.Value, err = substituteNames(ext.Value, holder, userID)
		}
		if err != nil {
			return nil, &decoy.DerivationError{Purpose: "extension " + ext.Id.String()}
		}
		extensions = append(extensions, ext)
	}
	return extensions, nil
}

// subjectKeyID derives the decoy's subject key identifier the way tmpl's was
// made: crypto/x509's truncated SHA-256 of the key bits, or derived bytes of
// the same length when tmpl's is anything else. It returns nil when tmpl has
// none.
func subjectKeyID(d *decoy.Deriver, tmpl *x509.Certificate, decoySPKI []byte) ([]byte, error) {
	size := len(tmpl.SubjectKeyId)
	if size == 0 {
		return nil, nil
	}
	if sum, ok := keyBitsDigest(tmpl.RawSubjectPublicKeyInfo); ok && size <= len(sum) && bytes.Equal(tmpl.SubjectKeyId, sum[:size]) {
		sum, ok := keyBitsDigest(decoySPKI)
		if !ok {
			return nil, &decoy.DerivationError{Purpose: "subject key id"}
		}
		return sum[:size], nil
	}
	return d.Bytes("subject-key-id", size)
}

// keyBitsDigest returns the SHA-256 digest of a SubjectPublicKeyInfo's key
// bits, which crypto/x509 truncates into a subject key identifier.
func keyBitsDigest(spki []byte) ([]byte, bool) {
	var info subjectPublicKeyInfo
	if _, err := asn1.Unmarshal(spki, &info); err != nil {
		return nil, false
	}
	sum := sha256.Sum256(info.PublicKey.RightAlign())
	return sum[:], true
}

// substituteName returns the raw name with every mention of from in its
// attribute values replaced by to, every other byte unchanged.
func substituteName(raw []byte, from, to string) ([]byte, error) {
	var rdns []nameAttributeSET
	if rest, err := asn1.Unmarshal(raw, &rdns); err != nil || len(rest) != 0 {
		return nil, &decoy.DerivationError{Purpose: "subject"}
	}
	for _, rdn := range rdns {
		for i := range rdn {
			rdn[i].Value = substituteValue(rdn[i].Value, from, to)
		}
	}
	out, err := asn1.Marshal(rdns)
	if err != nil {
		return nil, &decoy.DerivationError{Purpose: "subject"}
	}
	return out, nil
}

// substituteNames returns the raw GeneralNames with every mention of from in
// its textual names replaced by to.
func substituteNames(raw []byte, from, to string) ([]byte, error) {
	var names []asn1.RawValue
	if rest, err := asn1.Unmarshal(raw, &names); err != nil || len(rest) != 0 {
		return nil, &decoy.DerivationError{Purpose: "subject alternative names"}
	}
	for i := range names {
		names[i] = substituteValue(names[i], from, to)
	}
	return asn1.Marshal(names)
}

// substituteValue replaces from with to in a textual name value, both written
// as nameEncoders writes them for its tag, which it keeps; a PrintableString
// that no longer is one becomes a UTF8String. Any other value is returned as
// it is.
func substituteValue(v asn1.RawValue, from, to string) asn1.RawValue {
	encode, ok := nameEncoders[[2]int{v.Class, v.Tag}]
	if from == "" || v.IsCompound || !ok {
		return v
	}
	old := []byte(encode(from))
	if !bytes.Contains(v.Bytes, old) {
		return v
	}
	out := asn1.RawValue{Class: v.Class, Tag: v.Tag, Bytes: bytes.ReplaceAll(v.Bytes, old, []byte(encode(to)))}
	if out.Class == asn1.ClassUniversal && out.Tag == asn1.TagPrintableString && !printable(out.Bytes) {
		out.Tag = asn1.TagUTF8String
	}
	return out
}

// validUTF8 returns s with any invalid UTF-8 replaced, as a UTF8String
// requires.
func validUTF8(s string) string {
	return strings.ToValidUTF8(s, "�")
}

// printable reports whether b is a valid ASN.1 PrintableString.
func printable(b []byte) bool {
	for _, c := range b {
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case strings.IndexByte(" '()+,-./:=?", c) >= 0:
		default:
			return false
		}
	}
	return true
}
