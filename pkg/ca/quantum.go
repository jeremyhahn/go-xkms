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

// Package ca provides quantum certificate signing for ML-DSA algorithms.
//
// Go's standard library x509.CreateCertificate does not support ML-DSA
// (FIPS 204) signature algorithms. This file implements custom ASN.1
// certificate construction and signing for ML-DSA-44, ML-DSA-65, and
// ML-DSA-87 per NIST FIPS 204 and the assigned NIST OIDs.
//
// The implementation constructs the TBSCertificate ASN.1 structure
// manually, signs it with the ML-DSA private key, and wraps the result
// in an X.509 Certificate ASN.1 envelope.
package ca

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"

	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/quantum"
)

// ML-DSA algorithm OIDs per NIST FIPS 204.
var (
	oidMLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	oidMLDSA65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	oidMLDSA87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
)

// Quantum certificate error types.

// QuantumCertError indicates an error during quantum certificate operations.
type QuantumCertError struct {
	Op  string
	Err error
}

func (e *QuantumCertError) Error() string {
	return "ca: quantum cert " + e.Op + ": " + e.Err.Error()
}

func (e *QuantumCertError) Unwrap() error {
	return e.Err
}

// QuantumAlgorithmError indicates an unsupported quantum algorithm was provided.
type QuantumAlgorithmError struct {
	Algorithm string
}

func (e *QuantumAlgorithmError) Error() string {
	return "ca: unsupported quantum algorithm: " + e.Algorithm
}

// QuantumVerificationError indicates quantum signature verification failed.
type QuantumVerificationError struct {
	Reason string
}

func (e *QuantumVerificationError) Error() string {
	return "ca: quantum verification failed: " + e.Reason
}

// algorithmOIDMap maps ML-DSA algorithm strings to their OIDs using O(1) dispatch.
var algorithmOIDMap = map[string]asn1.ObjectIdentifier{
	"ML-DSA-44": oidMLDSA44,
	"ML-DSA-65": oidMLDSA65,
	"ML-DSA-87": oidMLDSA87,
}

// ASN.1 structures for X.509 certificate construction.

// tbsCertificateASN1 represents the TBSCertificate structure per RFC 5280.
type tbsCertificateASN1 struct {
	Version            asn1.RawValue            `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int                 `asn1:""`
	SignatureAlgorithm pkix.AlgorithmIdentifier `asn1:""`
	Issuer             asn1.RawValue            `asn1:""`
	Validity           validity                 `asn1:""`
	Subject            asn1.RawValue            `asn1:""`
	PublicKeyInfo      publicKeyInfo            `asn1:""`
	Extensions         asn1.RawValue            `asn1:"optional,explicit,tag:3"`
}

// validity represents the X.509 Validity structure.
type validity struct {
	NotBefore time.Time `asn1:""`
	NotAfter  time.Time `asn1:""`
}

// publicKeyInfo represents the SubjectPublicKeyInfo ASN.1 structure.
type publicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier `asn1:""`
	PublicKey asn1.BitString           `asn1:""`
}

// certificate represents the full X.509 Certificate ASN.1 structure.
type certificate struct {
	TBSCertificate     asn1.RawValue            `asn1:""`
	SignatureAlgorithm pkix.AlgorithmIdentifier `asn1:""`
	SignatureValue     asn1.BitString           `asn1:""`
}

// signCertificateWithQuantum creates a DER-encoded X.509 certificate signed
// with an ML-DSA private key. Since Go's x509.CreateCertificate does not
// support post-quantum algorithms, this function manually constructs the
// ASN.1 TBSCertificate, signs it, and assembles the final certificate.
//
// Parameters:
//   - template: The certificate template (serial, subject, validity, etc.)
//   - parent: The issuer certificate (for self-signed, pass template)
//   - pubKey: The subject's public key to embed in the certificate
//   - privKey: The ML-DSA private key used for signing
//
// Returns the DER-encoded certificate bytes or an error.
func signCertificateWithQuantum(
	template, parent *x509.Certificate,
	pubKey crypto.PublicKey,
	privKey *quantum.MLDSAPrivateKey,
) ([]byte, error) {

	if template == nil {
		return nil, &QuantumCertError{Op: "sign", Err: fmt.Errorf("template certificate is nil")}
	}
	if parent == nil {
		return nil, &QuantumCertError{Op: "sign", Err: fmt.Errorf("parent certificate is nil")}
	}
	if privKey == nil {
		return nil, &QuantumCertError{Op: "sign", Err: fmt.Errorf("private key is nil")}
	}

	// Determine the OID based on the algorithm
	sigOID, err := quantumAlgorithmOID(privKey.Algorithm)
	if err != nil {
		return nil, err
	}

	sigAlgID := pkix.AlgorithmIdentifier{
		Algorithm: sigOID,
	}

	// Encode the public key into SubjectPublicKeyInfo
	subjectPKInfo, err := encodeQuantumPublicKey(pubKey)
	if err != nil {
		return nil, &QuantumCertError{Op: "sign", Err: fmt.Errorf("encode public key: %w", err)}
	}

	// Encode issuer name
	issuerRaw, err := asn1.Marshal(parent.Subject.ToRDNSequence())
	if err != nil {
		return nil, &QuantumCertError{Op: "sign", Err: fmt.Errorf("marshal issuer: %w", err)}
	}

	// Encode subject name
	subjectRaw, err := asn1.Marshal(template.Subject.ToRDNSequence())
	if err != nil {
		return nil, &QuantumCertError{Op: "sign", Err: fmt.Errorf("marshal subject: %w", err)}
	}

	// Build extensions
	extensionsRaw, err := buildCertExtensions(template)
	if err != nil {
		return nil, &QuantumCertError{Op: "sign", Err: fmt.Errorf("build extensions: %w", err)}
	}

	// Construct the TBSCertificate
	tbs := tbsCertificateASN1{
		Version: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      mustMarshal(2), // v3
		},
		SerialNumber:       template.SerialNumber,
		SignatureAlgorithm: sigAlgID,
		Issuer:             asn1.RawValue{FullBytes: issuerRaw},
		Validity: validity{
			NotBefore: template.NotBefore,
			NotAfter:  template.NotAfter,
		},
		Subject:       asn1.RawValue{FullBytes: subjectRaw},
		PublicKeyInfo: *subjectPKInfo,
		Extensions:    extensionsRaw,
	}

	// Marshal TBSCertificate
	tbsRaw, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, &QuantumCertError{Op: "sign", Err: fmt.Errorf("marshal TBS: %w", err)}
	}

	// Sign the TBS with ML-DSA (no pre-hashing)
	signature, err := privKey.Sign(nil, tbsRaw, crypto.Hash(0))
	if err != nil {
		return nil, &QuantumCertError{Op: "sign", Err: fmt.Errorf("ML-DSA signing: %w", err)}
	}

	// Assemble the final certificate
	cert := certificate{
		TBSCertificate:     asn1.RawValue{FullBytes: tbsRaw},
		SignatureAlgorithm: sigAlgID,
		SignatureValue:     asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	}

	certDER, err := asn1.Marshal(cert)
	if err != nil {
		return nil, &QuantumCertError{Op: "sign", Err: fmt.Errorf("marshal certificate: %w", err)}
	}

	return certDER, nil
}

// verifyQuantumCertificate verifies the ML-DSA signature on a DER-encoded
// certificate using the issuer's ML-DSA public key.
//
// This function parses the ASN.1 certificate structure, extracts the
// TBSCertificate and signature, determines the algorithm from the
// signatureAlgorithm field, and performs verification.
//
// Parameters:
//   - certDER: The DER-encoded certificate to verify
//   - issuerPubKey: The issuer's ML-DSA public key
//
// Returns nil if verification succeeds, or an error describing the failure.
func verifyQuantumCertificate(certDER []byte, issuerPubKey *quantum.MLDSAPublicKey) error {
	if len(certDER) == 0 {
		return &QuantumVerificationError{Reason: "empty certificate data"}
	}
	if issuerPubKey == nil {
		return &QuantumVerificationError{Reason: "issuer public key is nil"}
	}

	// Parse the outer certificate SEQUENCE
	var rawCert asn1.RawValue
	rest, err := asn1.Unmarshal(certDER, &rawCert)
	if err != nil {
		return &QuantumCertError{Op: "verify", Err: fmt.Errorf("unmarshal outer: %w", err)}
	}
	if len(rest) > 0 {
		return &QuantumCertError{Op: "verify", Err: fmt.Errorf("trailing data after certificate")}
	}

	// Parse the three certificate components
	var inner struct {
		TBSCertificate     asn1.RawValue            `asn1:""`
		SignatureAlgorithm pkix.AlgorithmIdentifier `asn1:""`
		SignatureValue     asn1.BitString           `asn1:""`
	}
	if _, err := asn1.Unmarshal(rawCert.FullBytes, &inner); err != nil {
		return &QuantumCertError{Op: "verify", Err: fmt.Errorf("unmarshal inner: %w", err)}
	}

	// Determine algorithm from OID
	algorithm, err := oidToQuantumAlgorithm(inner.SignatureAlgorithm.Algorithm)
	if err != nil {
		return err
	}

	// Verify the algorithm matches the issuer key
	if issuerPubKey.Algorithm != algorithm {
		return &QuantumVerificationError{
			Reason: fmt.Sprintf("algorithm mismatch: cert uses %s, key is %s",
				algorithm, issuerPubKey.Algorithm),
		}
	}

	// Reconstruct the typed public key and verify
	tbsRaw := inner.TBSCertificate.FullBytes
	sigBytes := inner.SignatureValue.Bytes

	valid, err := verifyMLDSASignature(algorithm, issuerPubKey.Key, tbsRaw, sigBytes)
	if err != nil {
		return &QuantumCertError{Op: "verify", Err: err}
	}
	if !valid {
		return &QuantumVerificationError{Reason: "signature verification failed"}
	}

	return nil
}

// quantumAlgorithmOID returns the ASN.1 OID for the given ML-DSA algorithm string.
func quantumAlgorithmOID(algorithm string) (asn1.ObjectIdentifier, error) {
	oid, ok := algorithmOIDMap[algorithm]
	if !ok {
		return nil, &QuantumAlgorithmError{Algorithm: algorithm}
	}
	return oid, nil
}

// oidToQuantumAlgorithm returns the algorithm name for the given OID.
func oidToQuantumAlgorithm(oid asn1.ObjectIdentifier) (string, error) {
	for algo, algOID := range algorithmOIDMap {
		if oid.Equal(algOID) {
			return algo, nil
		}
	}
	return "", &QuantumAlgorithmError{Algorithm: oid.String()}
}

// verifyMLDSASignature verifies an ML-DSA signature using the appropriate
// algorithm-specific verification function.
func verifyMLDSASignature(algorithm string, pubKeyBytes, message, signature []byte) (bool, error) {
	switch algorithm {
	case "ML-DSA-44":
		var pk mldsa44.PublicKey
		if err := pk.UnmarshalBinary(pubKeyBytes); err != nil {
			return false, fmt.Errorf("unmarshal ML-DSA-44 public key: %w", err)
		}
		return mldsa44.Verify(&pk, message, nil, signature), nil

	case "ML-DSA-65":
		var pk mldsa65.PublicKey
		if err := pk.UnmarshalBinary(pubKeyBytes); err != nil {
			return false, fmt.Errorf("unmarshal ML-DSA-65 public key: %w", err)
		}
		return mldsa65.Verify(&pk, message, nil, signature), nil

	case "ML-DSA-87":
		var pk mldsa87.PublicKey
		if err := pk.UnmarshalBinary(pubKeyBytes); err != nil {
			return false, fmt.Errorf("unmarshal ML-DSA-87 public key: %w", err)
		}
		return mldsa87.Verify(&pk, message, nil, signature), nil

	default:
		return false, &QuantumAlgorithmError{Algorithm: algorithm}
	}
}

// encodeQuantumPublicKey creates a SubjectPublicKeyInfo structure for
// an ML-DSA public key. For quantum keys, the algorithm identifier uses
// the ML-DSA OID and the public key is the raw byte encoding.
func encodeQuantumPublicKey(pubKey crypto.PublicKey) (*publicKeyInfo, error) {
	mldsaPubKey, ok := pubKey.(*quantum.MLDSAPublicKey)
	if !ok {
		return nil, fmt.Errorf("expected *quantum.MLDSAPublicKey, got %T", pubKey)
	}

	algOID, err := quantumAlgorithmOID(mldsaPubKey.Algorithm)
	if err != nil {
		return nil, err
	}

	return &publicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: algOID,
		},
		PublicKey: asn1.BitString{
			Bytes:     mldsaPubKey.Key,
			BitLength: len(mldsaPubKey.Key) * 8,
		},
	}, nil
}

// buildCertExtensions constructs the extensions raw value for a certificate
// template. This handles BasicConstraints and KeyUsage which are the most
// critical extensions for CA certificates.
func buildCertExtensions(template *x509.Certificate) (asn1.RawValue, error) {
	var extensions []pkix.Extension

	// BasicConstraints
	if template.BasicConstraintsValid {
		bc := struct {
			IsCA       bool `asn1:"optional"`
			MaxPathLen int  `asn1:"optional,default:-1"`
		}{
			IsCA: template.IsCA,
		}
		if template.IsCA {
			if template.MaxPathLenZero || template.MaxPathLen > 0 {
				bc.MaxPathLen = template.MaxPathLen
			} else {
				bc.MaxPathLen = -1
			}
		}

		var bcBytes []byte
		var marshalErr error
		if template.IsCA && (template.MaxPathLenZero || template.MaxPathLen > 0) {
			bcBytes, marshalErr = asn1.Marshal(bc)
		} else if template.IsCA {
			bcBytes, marshalErr = asn1.Marshal(struct {
				IsCA bool `asn1:"optional"`
			}{IsCA: true})
		} else {
			bcBytes, marshalErr = asn1.Marshal(struct {
				IsCA bool `asn1:"optional"`
			}{IsCA: false})
		}
		if marshalErr != nil {
			return asn1.RawValue{}, marshalErr
		}

		extensions = append(extensions, pkix.Extension{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 19}, // basicConstraints
			Critical: true,
			Value:    bcBytes,
		})
	}

	// KeyUsage
	if template.KeyUsage != 0 {
		kuBytes, err := marshalKeyUsage(template.KeyUsage)
		if err != nil {
			return asn1.RawValue{}, err
		}
		extensions = append(extensions, pkix.Extension{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 15}, // keyUsage
			Critical: true,
			Value:    kuBytes,
		})
	}

	// Include any extra extensions from the template
	extensions = append(extensions, template.ExtraExtensions...)

	if len(extensions) == 0 {
		return asn1.RawValue{}, nil
	}

	extBytes, err := asn1.Marshal(extensions)
	if err != nil {
		return asn1.RawValue{}, err
	}

	return asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        3,
		IsCompound: true,
		Bytes:      extBytes,
	}, nil
}

// marshalKeyUsage encodes x509.KeyUsage as an ASN.1 BIT STRING.
func marshalKeyUsage(usage x509.KeyUsage) ([]byte, error) {
	// X.509 KeyUsage is a 9-bit field encoded in big-endian
	var ku [2]byte
	ku[0] = byte(reverseBitsInByte(byte(usage & 0xff)))
	ku[1] = byte(reverseBitsInByte(byte((usage >> 8) & 0xff)))

	// Calculate padding bits
	bitLen := 9
	if usage&0x100 == 0 {
		bitLen = 8
		if usage&0x80 == 0 {
			bitLen = 7
		}
	}

	padding := (len(ku)*8 - bitLen) % 8
	bs := asn1.BitString{
		Bytes:     ku[:],
		BitLength: len(ku)*8 - padding,
	}

	return asn1.Marshal(bs)
}

// reverseBitsInByte reverses the bits in a byte (X.509 KeyUsage encoding).
func reverseBitsInByte(b byte) byte {
	var result byte
	for i := 0; i < 8; i++ {
		result = (result << 1) | (b & 1)
		b >>= 1
	}
	return result
}

// mustMarshal marshals a value to ASN.1 and panics on error.
// Only used for known-good values during certificate construction.
func mustMarshal(val any) []byte {
	data, err := asn1.Marshal(val)
	if err != nil {
		panic("ca: mustMarshal: " + err.Error())
	}
	return data
}
