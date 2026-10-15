// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-quicbaas.
//
// go-quicbaas is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// Package attestationtest builds real attestation evidence for tests of the
// Verifier: an attestation-key CA and an AK certificate carrying
// tcg-cap-verifiedTPMRestricted, a COSE_Sign1 signed CoRIM with PCR
// reference digests, and a TPMS_ATTEST quote over those PCRs signed by the
// AK. Every artifact is produced with the same libraries a real attester and
// reference-value provider use, so a test exercises the go-xkms primitives
// for real rather than through a double.
package attestationtest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"sort"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	cose "github.com/veraison/go-cose"
	"github.com/veraison/swid"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/evidence"
)

// FixtureError reports a fixture that could not be built.
type FixtureError struct {
	Step  string
	Cause error
}

// Error returns a human-readable description.
func (e *FixtureError) Error() string {
	if e.Cause == nil {
		return "attestationtest: " + e.Step
	}
	return "attestationtest: " + e.Step + ": " + e.Cause.Error()
}

// Unwrap returns the cause.
func (e *FixtureError) Unwrap() error { return e.Cause }

var serial atomic.Int64

// Authority is a CA: a certificate and its key.
type Authority struct {
	Certificate *x509.Certificate
	Key         *ecdsa.PrivateKey
}

// CertificatePEM returns the CA certificate as PEM.
func (a *Authority) CertificatePEM() []byte {
	return pemCertificate(a.Certificate)
}

// PublicKeyPEM returns the CA key's public key as PKIX PEM.
func (a *Authority) PublicKeyPEM() ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(&a.Key.PublicKey)
	if err != nil {
		return nil, &FixtureError{Step: "marshal public key", Cause: err}
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// NewAuthority creates a self-signed CA.
func NewAuthority(commonName string) (*Authority, error) {
	// local-keygen-ok: models an external AK or reference-value CA (a TPM vendor, a provider); the Verifier only verifies under it.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, &FixtureError{Step: "generate CA key", Cause: err}
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial.Add(1)),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	cert, err := createCertificate(tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &Authority{Certificate: cert, Key: key}, nil
}

// AttestationKey is an AK with its certificate.
type AttestationKey struct {
	Certificate *x509.Certificate
	Key         *ecdsa.PrivateKey
}

// CertificatePEM returns the AK certificate as PEM.
func (k *AttestationKey) CertificatePEM() []byte {
	return pemCertificate(k.Certificate)
}

// IssueAttestationKey issues an AK certificate under ca. restricted controls
// whether it carries tcg-cap-verifiedTPMRestricted, which a Verifier requires.
func IssueAttestationKey(ca *Authority, restricted bool) (*AttestationKey, error) {
	// local-keygen-ok: stands in for a TPM-resident attestation key, which no keystore of this stack holds.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, &FixtureError{Step: "generate AK", Cause: err}
	}
	cert, err := CertifyAttestationKey(ca, &key.PublicKey, restricted)
	if err != nil {
		return nil, err
	}
	return &AttestationKey{Certificate: cert, Key: key}, nil
}

// CertifyAttestationKey issues an AK certificate under ca for a key the caller
// already holds, such as the IAK of a real or simulated TPM, standing in for
// the CA that enrolls it. restricted controls whether it carries
// tcg-cap-verifiedTPMRestricted, which a Verifier requires.
func CertifyAttestationKey(ca *Authority, pub crypto.PublicKey, restricted bool) (*x509.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial.Add(1)),
		Subject:      pkix.Name{CommonName: "attestation key " + strconv.FormatInt(serial.Load(), 10)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if restricted {
		tmpl.Policies = []x509.OID{evidence.OIDTCGVerifiedTPMRestrictedPolicy}
	}
	return createCertificate(tmpl, ca.Certificate, pub, ca.Key)
}

// PCRValues returns deterministic SHA-256 register values for the indices.
func PCRValues(indices ...uint32) map[uint32][]byte {
	out := make(map[uint32][]byte, len(indices))
	for _, idx := range indices {
		sum := sha256.Sum256([]byte("pcr-" + strconv.FormatUint(uint64(idx), 10)))
		out[idx] = sum[:]
	}
	return out
}

// SignCoRIM builds a COSE_Sign1 signed CoRIM whose reference values are the
// given SHA-256 PCR digests, signed by signer. When chain is non-nil it rides
// the protected x5chain header (leaf first), so a Verifier anchored on the
// chain's root accepts it; otherwise the signature verifies only under a
// pinned public key.
func SignCoRIM(pcrs map[uint32][]byte, signer crypto.Signer, chain []*x509.Certificate) ([]byte, error) {
	return SignCoRIMDigests(SHA256Digests(pcrs), signer, chain)
}

// SHA256Digests returns pcrs as SHA-256 bank digests; nil stays nil.
func SHA256Digests(pcrs map[uint32][]byte) []PCRDigest {
	if pcrs == nil {
		return nil
	}
	digests := make([]PCRDigest, 0, len(pcrs))
	for idx, value := range pcrs {
		digests = append(digests, PCRDigest{Index: idx, Hash: crypto.SHA256, Value: value})
	}
	return digests
}

// PCRDigest is one reference digest for a PCR in the bank of Hash.
type PCRDigest struct {
	Index uint32
	Hash  crypto.Hash
	Value []byte
}

// swidHashAlgs maps a PCR bank's hash to its CoRIM digest algorithm.
var swidHashAlgs = map[crypto.Hash]uint64{
	crypto.SHA256: swid.Sha256,
	crypto.SHA384: swid.Sha384,
	crypto.SHA512: swid.Sha512,
}

// SignCoRIMDigests is SignCoRIM over digests in any mix of PCR banks: one
// measurement per PCR, carrying every digest given for it.
func SignCoRIMDigests(digests []PCRDigest, signer crypto.Signer, chain []*x509.Certificate) ([]byte, error) {
	byIndex := make(map[uint32][]PCRDigest)
	for _, d := range digests {
		byIndex[d.Index] = append(byIndex[d.Index], d)
	}
	indices := make([]uint32, 0, len(byIndex))
	for idx := range byIndex {
		indices = append(indices, idx)
	}
	sort.Slice(indices, func(i, j int) bool { return indices[i] < indices[j] })

	measurements := comid.NewMeasurements()
	for _, idx := range indices {
		m, err := comid.NewMeasurement(uint64(idx), comid.UintType)
		if err != nil {
			return nil, &FixtureError{Step: "measurement", Cause: err}
		}
		for _, d := range byIndex[idx] {
			alg, ok := swidHashAlgs[d.Hash]
			if !ok {
				return nil, &FixtureError{Step: "measurement digest " + d.Hash.String()}
			}
			m.AddDigest(alg, d.Value)
		}
		measurements.AddMeasurement(m)
	}
	class := comid.NewClassOID("1.3.6.1.4.1.29377.200.1")
	class.SetVendor("Example Vendor").SetModel("Example Platform")
	c := comid.NewComid().SetTagIdentity("platform-reference-values", 0).AddReferenceValue(comid.ReferenceValue{
		Environment:  comid.Environment{Class: class},
		Measurements: *measurements,
	})
	if c == nil {
		return nil, &FixtureError{Step: "comid"}
	}
	if err := c.Valid(); err != nil {
		return nil, &FixtureError{Step: "comid", Cause: err}
	}
	unsigned := corim.NewUnsignedCorim().SetID("corim-" + strconv.FormatInt(serial.Add(1), 10)).AddComid(*c).AddProfile("tag:example.com,2026:tpm-pcr")
	if unsigned == nil {
		return nil, &FixtureError{Step: "unsigned corim"}
	}
	payload, err := unsigned.ToCBOR()
	if err != nil {
		return nil, &FixtureError{Step: "corim cbor", Cause: err}
	}
	meta, err := corim.NewMeta().SetSigner("Example Reference Value Provider", nil).ToCBOR()
	if err != nil {
		return nil, &FixtureError{Step: "corim meta", Cause: err}
	}

	msg := cose.NewSign1Message()
	msg.Payload = payload
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	msg.Headers.Protected[cose.HeaderLabelContentType] = corim.ContentType
	msg.Headers.Protected[corim.HeaderLabelCorimMeta] = meta
	if chain != nil {
		ders := make([]any, len(chain))
		for i, cert := range chain {
			ders[i] = cert.Raw
		}
		msg.Headers.Protected[cose.HeaderLabelX5Chain] = ders
	}
	coseSigner, err := cose.NewSigner(cose.AlgorithmES256, signer)
	if err != nil {
		return nil, &FixtureError{Step: "cose signer", Cause: err}
	}
	if err := msg.Sign(rand.Reader, nil, coseSigner); err != nil {
		return nil, &FixtureError{Step: "cose sign", Cause: err}
	}
	out, err := msg.MarshalCBOR()
	if err != nil {
		return nil, &FixtureError{Step: "cose marshal", Cause: err}
	}
	return out, nil
}

// SignerUnder issues a leaf signing certificate under ca for a reference-value
// provider and returns it with its key.
func SignerUnder(ca *Authority) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	// local-keygen-ok: models an external reference-value provider's signing key; the Verifier only verifies its CoRIMs.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, &FixtureError{Step: "generate signer key", Cause: err}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial.Add(1)),
		Subject:      pkix.Name{CommonName: "reference value signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	cert, err := createCertificate(tmpl, ca.Certificate, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// Quote is TPM quote evidence.
type Quote struct {
	Attest    []byte
	Signature []byte
	Nonce     []byte
	PCRs      map[uint32][]byte
}

// SignQuote builds a TPMS_ATTEST of type quote over the SHA-256 bank values
// pcrs with nonce as qualifying data, signed by ak, as TPM2_Quote produces.
func SignQuote(ak *AttestationKey, pcrs map[uint32][]byte, nonce []byte) (*Quote, error) {
	indices := make([]uint32, 0, len(pcrs))
	for idx := range pcrs {
		indices = append(indices, idx)
	}
	sort.Slice(indices, func(i, j int) bool { return indices[i] < indices[j] })
	h := sha256.New()
	selection := make([]uint, 0, len(indices))
	for _, idx := range indices {
		h.Write(pcrs[idx])
		selection = append(selection, uint(idx))
	}
	attest := tpm2.Marshal(tpm2.TPMSAttest{
		Magic:           tpm2.TPMGeneratedValue,
		Type:            tpm2.TPMSTAttestQuote,
		QualifiedSigner: tpm2.TPM2BName{Buffer: []byte("ak")},
		ExtraData:       tpm2.TPM2BData{Buffer: nonce},
		ClockInfo:       tpm2.TPMSClockInfo{Clock: 1, Safe: true},
		Attested: tpm2.NewTPMUAttest(tpm2.TPMSTAttestQuote, &tpm2.TPMSQuoteInfo{
			PCRSelect: tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(selection...),
			}}},
			PCRDigest: tpm2.TPM2BDigest{Buffer: h.Sum(nil)},
		}),
	})
	signature, err := SignAttest(ak, attest)
	if err != nil {
		return nil, err
	}
	return &Quote{Attest: attest, Signature: signature, Nonce: nonce, PCRs: pcrs}, nil
}

// SignAttest signs a marshaled TPMS_ATTEST with ak the way a TPM signs a
// quote: ECDSA, ASN.1-encoded, over the SHA-256 of the structure. It lets a
// fake TPM that builds its own TPMS_ATTEST produce a signature the Verifier
// accepts.
func SignAttest(ak *AttestationKey, attest []byte) ([]byte, error) {
	digest := sha256.Sum256(attest)
	signature, err := ecdsa.SignASN1(rand.Reader, ak.Key, digest[:])
	if err != nil {
		return nil, &FixtureError{Step: "sign quote", Cause: err}
	}
	return signature, nil
}

func createCertificate(tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) (*x509.Certificate, error) {
	// local-keygen-ok: issues certificates for the external parties above (custom TCG policy OIDs no go-xkms profile issues).
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		return nil, &FixtureError{Step: "create certificate", Cause: err}
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, &FixtureError{Step: "parse certificate", Cause: err}
	}
	return cert, nil
}

func pemCertificate(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}
