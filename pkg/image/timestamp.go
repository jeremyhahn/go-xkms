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

package image

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

const (
	// DefaultTimestampTimeout bounds one TSA request.
	DefaultTimestampTimeout = 30 * time.Second

	// maxTimestampSize bounds a TimeStampResp read.
	maxTimestampSize = 1 << 20

	// nonceBits is the size of a timestamp request's random nonce.
	nonceBits = 64

	// pkiStatusGranted and pkiStatusGrantedWithMods are the RFC 3161
	// statuses that carry a token.
	pkiStatusGranted         = 0
	pkiStatusGrantedWithMods = 1

	// asn1SetTag is the DER identifier of a constructed SET, which replaces
	// the [0] IMPLICIT tag of signed attributes before they are verified.
	asn1SetTag = 0x31
)

var (
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidSignedData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSTInfo          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidExtKeyUsage      = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidAttContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}

	oidRSAEncryption   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
)

// hashAlgorithm is a digest algorithm a timestamp token may use.
type hashAlgorithm struct {
	hash crypto.Hash
	sum  func(data []byte) []byte
}

// hashAlgorithms maps a digest algorithm OID to its definition.
var hashAlgorithms = map[string]hashAlgorithm{
	oidSHA256.String(): {hash: crypto.SHA256, sum: sha256Sum},
	oidSHA384.String(): {hash: crypto.SHA384, sum: sha384Sum},
	oidSHA512.String(): {hash: crypto.SHA512, sum: sha512Sum},
}

// signatureAlgorithms maps a token signature algorithm OID to the public
// key algorithm the TSA certificate must have.
var signatureAlgorithms = map[string]x509.PublicKeyAlgorithm{
	oidRSAEncryption.String():   x509.RSA,
	oidSHA256WithRSA.String():   x509.RSA,
	oidSHA384WithRSA.String():   x509.RSA,
	oidSHA512WithRSA.String():   x509.RSA,
	oidECDSAWithSHA256.String(): x509.ECDSA,
	oidECDSAWithSHA384.String(): x509.ECDSA,
	oidECDSAWithSHA512.String(): x509.ECDSA,
}

func sha384Sum(data []byte) []byte {
	sum := sha512.Sum384(data)
	return sum[:]
}

// Timestamper obtains an RFC 3161 timestamp over data and returns the DER
// TimeStampResp.
type Timestamper interface {
	Timestamp(ctx context.Context, data []byte) ([]byte, error)
}

// RFC3161Client is a Timestamper that asks an RFC 3161 timestamp
// authority over HTTP. The answer is signed, so plain http TSAs are fine.
type RFC3161Client struct {
	url  string
	http *http.Client
}

// TimestampInfo describes a verified RFC 3161 timestamp.
type TimestampInfo struct {
	// Time is the token's genTime.
	Time time.Time

	// SerialNumber is the token's serial number.
	SerialNumber *big.Int

	// Certificate is the TSA certificate that signed the token.
	Certificate *x509.Certificate
}

// timeStampReq is RFC 3161's TimeStampReq.
type timeStampReq struct {
	Version        int
	MessageImprint messageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
	Extensions     []pkix.Extension      `asn1:"optional,tag:0"`
}

type messageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

// timeStampResp is RFC 3161's TimeStampResp.
type timeStampResp struct {
	Status         pkiStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

type pkiStatusInfo struct {
	Status       int
	StatusString []string       `asn1:"optional"`
	FailInfo     asn1.BitString `asn1:"optional"`
}

// contentInfo is RFC 5652's ContentInfo; a timestamp token is one.
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

// signedData is RFC 5652's SignedData.
type signedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo encapsulatedContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

type encapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"explicit,optional,tag:0"`
}

// signerInfo is RFC 5652's SignerInfo. SID is an issuerAndSerialNumber or
// a [0] subjectKeyIdentifier.
type signerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type issuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// tstInfo is RFC 3161's TSTInfo.
type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        time.Time        `asn1:"generalized"`
	Accuracy       accuracy         `asn1:"optional"`
	Ordering       bool             `asn1:"optional,default:false"`
	Nonce          *big.Int         `asn1:"optional"`
	TSA            asn1.RawValue    `asn1:"optional,explicit,tag:0"`
	Extensions     []pkix.Extension `asn1:"optional,tag:1"`
}

type accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"optional,tag:0"`
	Micros  int `asn1:"optional,tag:1"`
}

// timestampToken is a decoded timestamp token.
type timestampToken struct {
	info       tstInfo
	content    []byte
	signedData signedData
}

// NewRFC3161Client returns a client of the TSA at tsaURL, an http or https
// URL. A nil httpClient uses one bounded by DefaultTimestampTimeout.
func NewRFC3161Client(tsaURL string, httpClient *http.Client) (*RFC3161Client, error) {
	parsed, err := url.Parse(tsaURL)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrTimestampURLInvalid, Cause: err}
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, &errs.Detail{Err: ErrTimestampURLInvalid, Detail: strconv.Quote(tsaURL)}
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: DefaultTimestampTimeout}
	}
	return &RFC3161Client{url: parsed.String(), http: httpClient}, nil
}

// Timestamp asks the TSA for a timestamp over the SHA-256 digest of data,
// with a random nonce and the TSA certificate requested, checks the answer
// covers data and the nonce, and returns the DER TimeStampResp.
func (c *RFC3161Client) Timestamp(ctx context.Context, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, ErrTimestampDataRequired
	}
	nonce, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), nonceBits))
	if err != nil {
		return nil, &errs.Joined{Lead: ErrTimestampFailed, Detail: "nonce", Cause: err}
	}
	query, err := asn1.Marshal(timeStampReq{
		Version: 1,
		MessageImprint: messageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256},
			HashedMessage: sha256Sum(data),
		},
		Nonce:   nonce,
		CertReq: true,
	})
	if err != nil {
		return nil, &errs.Joined{Lead: ErrEncodingFailed, Cause: err}
	}

	response, err := c.post(ctx, query)
	if err != nil {
		return nil, err
	}
	token, err := parseTimestampResponse(response)
	if err != nil {
		return nil, err
	}
	if err := token.covers(data); err != nil {
		return nil, err
	}
	if token.info.Nonce == nil || token.info.Nonce.Cmp(nonce) != 0 {
		return nil, &errs.Detail{Err: ErrTimestampMismatch, Detail: "nonce"}
	}
	return response, nil
}

// post sends a DER TimeStampReq and returns the answer body.
func (c *RFC3161Client) post(ctx context.Context, query []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(query))
	if err != nil {
		return nil, &errs.Joined{Lead: ErrTimestampFailed, Cause: err}
	}
	req.Header.Set("Content-Type", "application/timestamp-query")
	req.Header.Set("Accept", "application/timestamp-reply")
	req.Header.Set("User-Agent", DefaultUserAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrTimestampFailed, Cause: err}
	}
	body, err := readBody(resp, maxTimestampSize)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &errs.Detail{Err: ErrTimestampFailed, Detail: resp.Status}
	}
	return body, nil
}

// VerifyTimestamp verifies that response, a DER TimeStampResp, is a
// granted timestamp over data whose token signature verifies and whose TSA
// certificate chains to roots for timestamping at the token's genTime.
func VerifyTimestamp(response, data []byte, roots *x509.CertPool) (*TimestampInfo, error) {
	if roots == nil {
		return nil, ErrTimestampRootsRequired
	}
	if len(data) == 0 {
		return nil, ErrTimestampDataRequired
	}
	token, err := parseTimestampResponse(response)
	if err != nil {
		return nil, err
	}
	if err := token.covers(data); err != nil {
		return nil, err
	}
	signer, certificates, err := token.verifySignature()
	if err != nil {
		return nil, err
	}
	if err := checkTimestampingUsage(signer); err != nil {
		return nil, err
	}

	intermediates := x509.NewCertPool()
	for _, certificate := range certificates {
		intermediates.AddCert(certificate)
	}
	if _, err := signer.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   token.info.GenTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}); err != nil {
		return nil, &errs.Joined{Lead: ErrTimestampUntrusted, Cause: err}
	}
	return &TimestampInfo{Time: token.info.GenTime, SerialNumber: token.info.SerialNumber, Certificate: signer}, nil
}

// checkTimestampingUsage enforces RFC 3161 section 2.3 on the TSA
// certificate: its extended key usage extension lists id-kp-timeStamping
// and nothing else, and is marked critical. x509.Verify alone accepts a
// certificate with no extended key usage at all.
func checkTimestampingUsage(certificate *x509.Certificate) error {
	if len(certificate.ExtKeyUsage) != 1 || certificate.ExtKeyUsage[0] != x509.ExtKeyUsageTimeStamping ||
		len(certificate.UnknownExtKeyUsage) != 0 {
		return ErrTimestampExtKeyUsage
	}
	for _, extension := range certificate.Extensions {
		if extension.Id.Equal(oidExtKeyUsage) && extension.Critical {
			return nil
		}
	}
	return ErrTimestampExtKeyUsage
}

// parseTimestampResponse decodes a granted TimeStampResp down to its
// TSTInfo.
func parseTimestampResponse(response []byte) (*timestampToken, error) {
	var resp timeStampResp
	if err := unmarshalDER(response, &resp, "TimeStampResp"); err != nil {
		return nil, err
	}
	if status := resp.Status.Status; status != pkiStatusGranted && status != pkiStatusGrantedWithMods {
		detail := "status " + strconv.Itoa(status)
		if len(resp.Status.StatusString) > 0 {
			detail += ": " + strings.Join(resp.Status.StatusString, "; ")
		}
		return nil, &errs.Detail{Err: ErrTimestampRejected, Detail: detail}
	}
	if len(resp.TimeStampToken.FullBytes) == 0 {
		return nil, &errs.Detail{Err: ErrInvalidTimestamp, Detail: "no timestamp token"}
	}

	var content contentInfo
	if err := unmarshalDER(resp.TimeStampToken.FullBytes, &content, "ContentInfo"); err != nil {
		return nil, err
	}
	if !content.ContentType.Equal(oidSignedData) {
		return nil, &errs.Detail{Err: ErrInvalidTimestamp, Detail: "content type " + content.ContentType.String()}
	}
	token := &timestampToken{}
	if err := unmarshalDER(content.Content.Bytes, &token.signedData, "SignedData"); err != nil {
		return nil, err
	}
	encapsulated := token.signedData.EncapContentInfo
	if !encapsulated.EContentType.Equal(oidTSTInfo) {
		return nil, &errs.Detail{Err: ErrInvalidTimestamp, Detail: "encapsulated content type " + encapsulated.EContentType.String()}
	}
	token.content = encapsulated.EContent
	if err := unmarshalDER(token.content, &token.info, "TSTInfo"); err != nil {
		return nil, err
	}
	return token, nil
}

// covers returns nil when the token's message imprint is data's digest.
func (t *timestampToken) covers(data []byte) error {
	imprint := t.info.MessageImprint
	algorithm, ok := hashAlgorithms[imprint.HashAlgorithm.Algorithm.String()]
	if !ok {
		return &errs.Detail{Err: ErrUnsupportedAlgorithm, Detail: "imprint " + imprint.HashAlgorithm.Algorithm.String()}
	}
	if !bytes.Equal(algorithm.sum(data), imprint.HashedMessage) {
		return &errs.Detail{Err: ErrTimestampMismatch, Detail: "message imprint"}
	}
	return nil
}

// verifySignature verifies the token's one signer over its signed
// attributes, which must bind the TSTInfo content type and digest, and
// returns the signer certificate and every certificate the token carries.
func (t *timestampToken) verifySignature() (*x509.Certificate, []*x509.Certificate, error) {
	certificates, err := x509.ParseCertificates(t.signedData.Certificates.Bytes)
	if err != nil {
		return nil, nil, &errs.Joined{Lead: ErrInvalidTimestamp, Detail: "certificates", Cause: err}
	}
	if len(t.signedData.SignerInfos) != 1 {
		return nil, nil, &errs.Detail{Err: ErrInvalidTimestamp, Detail: strconv.Itoa(len(t.signedData.SignerInfos)) + " signers"}
	}
	signer := t.signedData.SignerInfos[0]
	certificate, err := signerCertificate(signer.SID, certificates)
	if err != nil {
		return nil, nil, err
	}

	digest, ok := hashAlgorithms[signer.DigestAlgorithm.Algorithm.String()]
	if !ok {
		return nil, nil, &errs.Detail{Err: ErrUnsupportedAlgorithm, Detail: "digest " + signer.DigestAlgorithm.Algorithm.String()}
	}
	keyAlgorithm, ok := signatureAlgorithms[signer.SignatureAlgorithm.Algorithm.String()]
	if !ok || keyAlgorithm != certificate.PublicKeyAlgorithm {
		return nil, nil, &errs.Detail{Err: ErrUnsupportedAlgorithm, Detail: "signature " + signer.SignatureAlgorithm.Algorithm.String()}
	}

	if len(signer.SignedAttrs.FullBytes) == 0 {
		return nil, nil, &errs.Detail{Err: ErrInvalidTimestamp, Detail: "no signed attributes"}
	}
	signed := slices.Clone(signer.SignedAttrs.FullBytes)
	signed[0] = asn1SetTag
	if err := checkSignedAttributes(signed, digest.sum(t.content)); err != nil {
		return nil, nil, err
	}

	verifier := types.NewVerifier(&types.VerifyOpts{Hash: digest.hash})
	if err := verifier.Verify(certificate.PublicKey, digest.sum(signed), signer.Signature); err != nil {
		return nil, nil, &errs.Joined{Lead: ErrTimestampSignatureInvalid, Cause: err}
	}
	return certificate, certificates, nil
}

// checkSignedAttributes checks that the DER SET of signed attributes names
// TSTInfo as the content type and contentDigest as the message digest.
func checkSignedAttributes(signed, contentDigest []byte) error {
	var attributes []attribute
	if _, err := asn1.UnmarshalWithParams(signed, &attributes, "set"); err != nil {
		return &errs.Joined{Lead: ErrInvalidTimestamp, Detail: "signed attributes", Cause: err}
	}

	value, err := attributeValue(attributes, oidAttContentType)
	if err != nil {
		return err
	}
	var contentType asn1.ObjectIdentifier
	if err := unmarshalDER(value.FullBytes, &contentType, "content type attribute"); err != nil {
		return err
	}
	if !contentType.Equal(oidTSTInfo) {
		return &errs.Detail{Err: ErrInvalidTimestamp, Detail: "content type attribute " + contentType.String()}
	}

	value, err = attributeValue(attributes, oidAttMessageDigest)
	if err != nil {
		return err
	}
	var messageDigest []byte
	if err := unmarshalDER(value.FullBytes, &messageDigest, "message digest attribute"); err != nil {
		return err
	}
	if !bytes.Equal(messageDigest, contentDigest) {
		return &errs.Detail{Err: ErrTimestampSignatureInvalid, Detail: "message digest attribute"}
	}
	return nil
}

// attributeValue returns the single value of the attribute oid names.
func attributeValue(attributes []attribute, oid asn1.ObjectIdentifier) (asn1.RawValue, error) {
	for _, attr := range attributes {
		if !attr.Type.Equal(oid) {
			continue
		}
		if len(attr.Values) != 1 {
			return asn1.RawValue{}, &errs.Detail{Err: ErrInvalidTimestamp, Detail: "attribute " + oid.String() + " has " + strconv.Itoa(len(attr.Values)) + " values"}
		}
		return attr.Values[0], nil
	}
	return asn1.RawValue{}, &errs.Detail{Err: ErrInvalidTimestamp, Detail: "no attribute " + oid.String()}
}

// signerCertificate returns the certificate sid identifies, by issuer and
// serial number or by [0] subject key identifier.
func signerCertificate(sid asn1.RawValue, certificates []*x509.Certificate) (*x509.Certificate, error) {
	if sid.Class == asn1.ClassContextSpecific && sid.Tag == 0 {
		for _, certificate := range certificates {
			if len(sid.Bytes) > 0 && bytes.Equal(certificate.SubjectKeyId, sid.Bytes) {
				return certificate, nil
			}
		}
		return nil, &errs.Detail{Err: ErrInvalidTimestamp, Detail: "no certificate for the signer key identifier"}
	}

	var issuer issuerAndSerialNumber
	if err := unmarshalDER(sid.FullBytes, &issuer, "signer identifier"); err != nil {
		return nil, err
	}
	for _, certificate := range certificates {
		if bytes.Equal(certificate.RawIssuer, issuer.Issuer.FullBytes) && certificate.SerialNumber.Cmp(issuer.SerialNumber) == 0 {
			return certificate, nil
		}
	}
	return nil, &errs.Detail{Err: ErrInvalidTimestamp, Detail: "no certificate for the signer issuer and serial number"}
}

// unmarshalDER decodes data, named what in errors, into value and refuses
// trailing bytes.
func unmarshalDER(data []byte, value any, what string) error {
	rest, err := asn1.Unmarshal(data, value)
	if err != nil {
		return &errs.Joined{Lead: ErrInvalidTimestamp, Detail: what, Cause: err}
	}
	if len(rest) != 0 {
		return &errs.Detail{Err: ErrInvalidTimestamp, Detail: what + " has trailing data"}
	}
	return nil
}
