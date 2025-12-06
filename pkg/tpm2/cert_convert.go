package tpm2

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"github.com/google/go-tpm/tpm2"
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
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()

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
