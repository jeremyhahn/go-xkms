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

package ct

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	// oidPrecertSigningEKU marks a Precertificate Signing Certificate
	// (RFC 6962 §3.1).
	oidPrecertSigningEKU = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 4}

	// oidAuthorityKeyID is the Authority Key Identifier extension
	// (RFC 5280 §4.2.1.1).
	oidAuthorityKeyID = asn1.ObjectIdentifier{2, 5, 29, 35}

	// tbsExtensionsTag is the explicit [3] tag of TBSCertificate.extensions
	// (RFC 5280 §4.1).
	tbsExtensionsTag = cbasn1.Tag(3).Constructed().ContextSpecific()
)

// signatureTypeCertificateTimestamp is SignatureType certificate_timestamp
// (RFC 6962 §3.2).
const signatureTypeCertificateTimestamp = 0

// tbsIssuerPosition is the 1-based position of the issuer among the
// universal-class fields of a TBSCertificate: serialNumber, signature,
// issuer (RFC 5280 §4.1).
const tbsIssuerPosition = 3

// tbsRewrite carries the changes RFC 6962 §3.2 makes to a TBSCertificate
// that a Precertificate Signing Certificate signed: the issuer becomes the
// final issuer's subject, and the Authority Key Identifier becomes the one
// in the Precertificate Signing Certificate.
type tbsRewrite struct {
	issuer         []byte
	authorityKeyID []byte
}

// VerifySCT verifies an SCT a log returned for a precertificate. It checks,
// in order:
//
//   - the SCT is version v1 (RFC 6962 §3.2);
//   - the log key is one RFC 6962 §2.1.4 allows;
//   - the SCT's log ID is the SHA-256 hash of the log key (§3.2);
//   - the signature uses SHA-256 with the algorithm of the log key (§2.1.4);
//   - the signature verifies over the digitally-signed struct of §3.2 for a
//     precert_entry: the issuer_key_hash and the TBSCertificate with the
//     poison extension removed.
//
// chain is the chain submitted with the precertificate (§4.2): chain[0]
// issued it, and when chain[0] is a Precertificate Signing Certificate,
// chain[1] is the final issuer (§3.1).
func VerifySCT(sct *SignedCertificateTimestamp, log LogGroup, precertDER []byte, chain [][]byte) error {
	if sct == nil || len(precertDER) == 0 {
		return ErrNilInput
	}
	if sct.Version != V1 {
		return ErrInvalidSCT
	}
	if err := checkLogPublicKey(log.PublicKey); err != nil {
		return err
	}

	logID, err := KeyToLogID(log.PublicKey)
	if err != nil {
		return ErrLogPublicKeyUnsupported
	}
	if sct.LogID != logID {
		return ErrSCTLogIDMismatch
	}

	issuerKeyHash, tbs, err := precertEntry(precertDER, chain)
	if err != nil {
		return err
	}

	signed, err := sctSignedData(sct, issuerKeyHash, tbs)
	if err != nil {
		return err
	}
	return verifyDigitallySigned(log.PublicKey, sct.Signature, signed)
}

// sctSignedData encodes the digitally-signed struct of RFC 6962 §3.2 for a
// precert_entry:
//
//	Version sct_version;
//	SignatureType signature_type = certificate_timestamp;
//	uint64 timestamp;
//	LogEntryType entry_type = precert_entry;
//	PreCert { opaque issuer_key_hash[32]; TBSCertificate tbs_certificate<1..2^24-1>; };
//	CtExtensions extensions<0..2^16-1>;
func sctSignedData(sct *SignedCertificateTimestamp, issuerKeyHash [32]byte, tbs []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(uint8(sct.Version))
	b.AddUint8(signatureTypeCertificateTimestamp)
	b.AddUint64(sct.Timestamp)
	b.AddUint16(uint16(PrecertLogEntryType))
	b.AddBytes(issuerKeyHash[:])
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(tbs)
	})
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(sct.Extensions)
	})

	signed, err := b.Bytes()
	if err != nil {
		return nil, ErrInvalidSCT
	}
	return signed, nil
}

// verifyDigitallySigned verifies a digitally-signed element (RFC 5246
// §4.7) with the log key. RFC 6962 §2.1.4 allows SHA-256 with ECDSA on
// P-256 or with RSASSA-PKCS1-v1_5.
func verifyDigitallySigned(pub crypto.PublicKey, ds DigitallySigned, signed []byte) error {
	if ds.HashAlgorithm != HashAlgorithmSHA256 {
		return ErrUnsupportedSCTAlgorithm
	}
	digest := sha256.Sum256(signed)

	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		if ds.SigAlgorithm != SignatureAlgorithmECDSA {
			return ErrUnsupportedSCTAlgorithm
		}
		if !ecdsa.VerifyASN1(key, digest[:], ds.Signature) {
			return ErrInvalidSignature
		}
	case *rsa.PublicKey:
		if ds.SigAlgorithm != SignatureAlgorithmRSA {
			return ErrUnsupportedSCTAlgorithm
		}
		if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], ds.Signature); err != nil {
			return ErrInvalidSignature
		}
	default:
		return ErrLogPublicKeyUnsupported
	}
	return nil
}

// precertEntry returns the issuer_key_hash and tbs_certificate of the
// PreCert a log signs for precertDER (RFC 6962 §3.2).
func precertEntry(precertDER []byte, chain [][]byte) ([32]byte, []byte, error) {
	var issuerKeyHash [32]byte

	precert, err := x509.ParseCertificate(precertDER)
	if err != nil {
		return issuerKeyHash, nil, ErrPrecertMalformed
	}
	if err := ValidatePrecertPoison(precert.Extensions); err != nil {
		return issuerKeyHash, nil, err
	}

	if len(chain) == 0 {
		return issuerKeyHash, nil, ErrPrecertIssuerMissing
	}
	issuer, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return issuerKeyHash, nil, ErrPrecertIssuerMissing
	}

	var rewrite *tbsRewrite
	if isPrecertSigningCert(issuer) {
		// §3.1: the Precertificate Signing Certificate is directly
		// certified by the CA that issues the final certificate.
		if len(chain) < 2 {
			return issuerKeyHash, nil, ErrPrecertIssuerMissing
		}
		finalIssuer, err := x509.ParseCertificate(chain[1])
		if err != nil {
			return issuerKeyHash, nil, ErrPrecertIssuerMissing
		}
		rewrite, err = newTBSRewrite(issuer, finalIssuer)
		if err != nil {
			return issuerKeyHash, nil, err
		}
		issuer = finalIssuer
	}

	tbs, err := precertTBS(precert.RawTBSCertificate, rewrite)
	if err != nil {
		return issuerKeyHash, nil, err
	}

	// §3.2: issuer_key_hash is the SHA-256 hash of the final issuer's
	// SubjectPublicKeyInfo.
	issuerKeyHash = sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
	return issuerKeyHash, tbs, nil
}

// isPrecertSigningCert reports whether cert carries the Certificate
// Transparency extended key usage (RFC 6962 §3.1).
func isPrecertSigningCert(cert *x509.Certificate) bool {
	for _, eku := range cert.UnknownExtKeyUsage {
		if eku.Equal(oidPrecertSigningEKU) {
			return true
		}
	}
	return false
}

// newTBSRewrite builds the §3.2 rewrite for a precertificate signed by the
// Precertificate Signing Certificate psc on behalf of finalIssuer.
func newTBSRewrite(psc, finalIssuer *x509.Certificate) (*tbsRewrite, error) {
	rewrite := &tbsRewrite{issuer: finalIssuer.RawSubject}
	for _, ext := range psc.Extensions {
		if !ext.Id.Equal(oidAuthorityKeyID) {
			continue
		}
		der, err := asn1.Marshal(ext)
		if err != nil {
			return nil, ErrPrecertMalformed
		}
		rewrite.authorityKeyID = der
	}
	return rewrite, nil
}

// precertTBS re-encodes a precertificate's TBSCertificate as RFC 6962 §3.2
// requires: without the poison extension and, for a precertificate signed
// by a Precertificate Signing Certificate, with rewrite applied.
func precertTBS(rawTBS []byte, rewrite *tbsRewrite) ([]byte, error) {
	input := cryptobyte.String(rawTBS)
	var fields cryptobyte.String
	if !input.ReadASN1(&fields, cbasn1.SEQUENCE) || !input.Empty() {
		return nil, ErrPrecertMalformed
	}

	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		universal := 0
		for !fields.Empty() {
			var field cryptobyte.String
			var tag cbasn1.Tag
			if !fields.ReadAnyASN1Element(&field, &tag) {
				b.SetError(ErrPrecertMalformed)
				return
			}

			switch {
			case tag == tbsExtensionsTag:
				extensions, err := precertExtensions(field, rewrite)
				if err != nil {
					b.SetError(err)
					return
				}
				b.AddBytes(extensions)
			case tag&0xc0 == 0:
				universal++
				if universal == tbsIssuerPosition && rewrite != nil {
					b.AddBytes(rewrite.issuer)
					continue
				}
				b.AddBytes(field)
			default:
				b.AddBytes(field)
			}
		}
	})
	return b.Bytes()
}

// precertExtensions re-encodes the [3] extensions field of a TBSCertificate
// without the poison extension. It returns nil when no extension remains,
// since Extensions is SIZE (1..MAX) and the field is then omitted
// (RFC 5280 §4.1).
func precertExtensions(field cryptobyte.String, rewrite *tbsRewrite) ([]byte, error) {
	var wrapper, extensions cryptobyte.String
	if !field.ReadASN1(&wrapper, tbsExtensionsTag) ||
		!wrapper.ReadASN1(&extensions, cbasn1.SEQUENCE) || !wrapper.Empty() {
		return nil, ErrPrecertMalformed
	}

	var kept [][]byte
	poisons := 0
	for !extensions.Empty() {
		var extension, content cryptobyte.String
		var oid asn1.ObjectIdentifier
		if !extensions.ReadASN1Element(&extension, cbasn1.SEQUENCE) {
			return nil, ErrPrecertMalformed
		}
		element := extension
		if !element.ReadASN1(&content, cbasn1.SEQUENCE) || !content.ReadASN1ObjectIdentifier(&oid) {
			return nil, ErrPrecertMalformed
		}

		switch {
		case oid.Equal(OIDPrecertPoison):
			poisons++
		case oid.Equal(oidAuthorityKeyID) && rewrite != nil:
			// §3.2: an Authority Key Identifier in the TBSCertificate
			// must also be present in the Precertificate Signing
			// Certificate, and is replaced by it.
			if rewrite.authorityKeyID == nil {
				return nil, ErrPrecertMalformed
			}
			kept = append(kept, rewrite.authorityKeyID)
		default:
			kept = append(kept, extension)
		}
	}
	if poisons != 1 {
		return nil, ErrPrecertPoisonInvalid
	}
	if len(kept) == 0 {
		return nil, nil
	}

	var b cryptobyte.Builder
	b.AddASN1(tbsExtensionsTag, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			for _, extension := range kept {
				b.AddBytes(extension)
			}
		})
	})
	return b.Bytes()
}
