package tpm2

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// CertificateToTPMPublic converts an X.509 certificate's public key to a TPM public structure.
// This is used to load external EK certificates onto the TPM for MakeCredential operations.
func CertificateToTPMPublic(cert *x509.Certificate) (*tpm2.TPMTPublic, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate is nil")
	}

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return rsaPublicKeyToTPMPublic(pub)
	case *ecdsa.PublicKey:
		return ecdsaPublicKeyToTPMPublic(pub)
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", cert.PublicKey)
	}
}

// rsaPublicKeyToTPMPublic converts an RSA public key to TPM public structure.
// Uses EK default attributes (restricted decryption with null scheme).
func rsaPublicKeyToTPMPublic(pub *rsa.PublicKey) (*tpm2.TPMTPublic, error) {
	if pub == nil {
		return nil, fmt.Errorf("RSA public key is nil")
	}

	keyBits := uint16(pub.N.BitLen())

	// EK uses restricted decryption with null scheme
	rsaParams := tpm2.TPMSRSAParms{
		Symmetric: tpm2.TPMTSymDefObject{
			Algorithm: tpm2.TPMAlgAES,
			KeyBits:   tpm2.NewTPMUSymKeyBits(tpm2.TPMAlgAES, tpm2.TPMKeyBits(128)),
			Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
		},
		Scheme: tpm2.TPMTRSAScheme{
			Scheme: tpm2.TPMAlgNull,
		},
		KeyBits:  tpm2.TPMKeyBits(keyBits),
		Exponent: uint32(pub.E),
	}

	return &tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        false,
			AdminWithPolicy:     true,
			Restricted:          true,
			Decrypt:             true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&rsaParams,
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: pub.N.Bytes(),
			},
		),
	}, nil
}

// ecdsaPublicKeyToTPMPublic converts an ECDSA public key to TPM public structure.
// Uses EK default attributes (restricted decryption with null scheme).
func ecdsaPublicKeyToTPMPublic(pub *ecdsa.PublicKey) (*tpm2.TPMTPublic, error) {
	if pub == nil {
		return nil, fmt.Errorf("ECDSA public key is nil")
	}

	var curveID tpm2.TPMECCCurve
	switch pub.Curve.Params().Name {
	case "P-256":
		curveID = tpm2.TPMECCNistP256
	case "P-384":
		curveID = tpm2.TPMECCNistP384
	case "P-521":
		curveID = tpm2.TPMECCNistP521
	default:
		return nil, fmt.Errorf("unsupported ECC curve: %s", pub.Curve.Params().Name)
	}

	eccParams := tpm2.TPMSECCParms{
		Symmetric: tpm2.TPMTSymDefObject{
			Algorithm: tpm2.TPMAlgAES,
			KeyBits:   tpm2.NewTPMUSymKeyBits(tpm2.TPMAlgAES, tpm2.TPMKeyBits(128)),
			Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
		},
		Scheme: tpm2.TPMTECCScheme{
			Scheme: tpm2.TPMAlgNull,
		},
		CurveID: curveID,
		KDF: tpm2.TPMTKDFScheme{
			Scheme: tpm2.TPMAlgNull,
		},
	}

	// Pad coordinates to curve size
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	xBytes := pub.X.Bytes() //nolint:staticcheck // TPM2 wire format requires raw EC coordinates
	yBytes := pub.Y.Bytes() //nolint:staticcheck // TPM2 wire format requires raw EC coordinates

	// Pad to fixed size
	xPadded := make([]byte, byteLen)
	yPadded := make([]byte, byteLen)
	copy(xPadded[byteLen-len(xBytes):], xBytes)
	copy(yPadded[byteLen-len(yBytes):], yBytes)

	return &tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        false,
			AdminWithPolicy:     true,
			Restricted:          true,
			Decrypt:             true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&eccParams,
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: xPadded},
				Y: tpm2.TPM2BECCParameter{Buffer: yPadded},
			},
		),
	}, nil
}

// writeCertToStore writes a certificate to the certificate store.
func (tpm *TPM2) writeCertToStore(keyAttrs *types.KeyAttributes, cert *x509.Certificate) error {
	if tpm.certStore == nil {
		return ErrCertStoreNotConfigured
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	_, err := tpm.certStore.ImportCertificate(keyAttrs, certPEM)
	return err
}

// validateCertPublicKey validates that the certificate's public key matches the TPM key.
func validateCertPublicKey(cert *x509.Certificate, keyAttrs *types.KeyAttributes) error {
	if keyAttrs == nil || keyAttrs.TPMAttributes == nil {
		return ErrInvalidKeyAttributes
	}

	// Get the public key bytes from the TPM key
	tpmPubBytes := keyAttrs.TPMAttributes.BPublic.Bytes()

	// For now, we verify by comparing the public key from the certificate
	// with the TPM's public area. This is a basic validation.
	certPubDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return err
	}

	// The TPM public area format is different from PKIX, so we need to
	// reconstruct the public key from the TPM public area and compare.
	pub := keyAttrs.TPMAttributes.Public

	var reconstructedPubDER []byte

	switch pub.Type {
	case tpm2.TPMAlgRSA:
		rsaDetail, err := pub.Parameters.RSADetail()
		if err != nil {
			return err
		}
		rsaUnique, err := pub.Unique.RSA()
		if err != nil {
			return err
		}
		rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
		if err != nil {
			return err
		}
		reconstructedPubDER, err = x509.MarshalPKIXPublicKey(rsaPub)
		if err != nil {
			return err
		}

	case tpm2.TPMAlgECC:
		ecDetail, err := pub.Parameters.ECCDetail()
		if err != nil {
			return err
		}
		crv, err := ecDetail.CurveID.Curve()
		if err != nil {
			return err
		}
		eccUnique, err := pub.Unique.ECC()
		if err != nil {
			return err
		}
		ecPub := &ecdsa.PublicKey{
			Curve: crv,
			X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
			Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
		}
		reconstructedPubDER, err = x509.MarshalPKIXPublicKey(ecPub)
		if err != nil {
			return err
		}

	default:
		// For unsupported types, just verify that the public bytes are present
		if len(tpmPubBytes) == 0 {
			return ErrInvalidKeyAttributes
		}
		return nil
	}

	if !bytes.Equal(certPubDER, reconstructedPubDER) {
		return ErrCertPublicKeyMismatch
	}

	return nil
}
