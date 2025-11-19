package tpm2

import (
	"crypto/elliptic"
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/internal/tpm/store"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestHandleTypeValidation(t *testing.T) {
	t.Run("persistent handle type is valid", func(t *testing.T) {
		handleType := tpm2.TPMHTPersistent
		assert.Equal(t, tpm2.TPMHTPersistent, handleType)
	})

	t.Run("transient handle type is valid", func(t *testing.T) {
		handleType := tpm2.TPMHTTransient
		assert.Equal(t, tpm2.TPMHTTransient, handleType)
	})

	t.Run("persistent handle range starts at 0x81000000", func(t *testing.T) {
		// Standard persistent handle for SRK
		handle := tpm2.TPMHandle(0x81000001)
		assert.True(t, handle >= 0x81000000)
		assert.True(t, handle <= 0x81FFFFFF)
	})

	t.Run("transient handle range starts at 0x80000000", func(t *testing.T) {
		handle := tpm2.TPMHandle(0x80000000)
		assert.True(t, handle >= 0x80000000)
		assert.True(t, handle < 0x81000000)
	})

	t.Run("EK handle is in persistent range", func(t *testing.T) {
		ekHandle := tpm2.TPMHandle(0x81010001)
		assert.True(t, ekHandle >= 0x81000000)
		assert.True(t, ekHandle <= 0x81FFFFFF)
	})

	t.Run("IAK handle is in persistent range", func(t *testing.T) {
		iakHandle := tpm2.TPMHandle(0x81010002)
		assert.True(t, iakHandle >= 0x81000000)
		assert.True(t, iakHandle <= 0x81FFFFFF)
	})

	t.Run("IDevID handle is in persistent range", func(t *testing.T) {
		idevidHandle := tpm2.TPMHandle(0x81020000)
		assert.True(t, idevidHandle >= 0x81000000)
		assert.True(t, idevidHandle <= 0x81FFFFFF)
	})
}

func TestHierarchyValidation(t *testing.T) {
	t.Run("endorsement hierarchy is valid", func(t *testing.T) {
		hierarchy := tpm2.TPMRHEndorsement
		assert.Equal(t, tpm2.TPMRHEndorsement, hierarchy)
	})

	t.Run("owner hierarchy is valid", func(t *testing.T) {
		hierarchy := tpm2.TPMRHOwner
		assert.Equal(t, tpm2.TPMRHOwner, hierarchy)
	})

	t.Run("platform hierarchy is valid", func(t *testing.T) {
		hierarchy := tpm2.TPMRHPlatform
		assert.Equal(t, tpm2.TPMRHPlatform, hierarchy)
	})

	t.Run("null hierarchy is valid", func(t *testing.T) {
		hierarchy := tpm2.TPMRHNull
		assert.Equal(t, tpm2.TPMRHNull, hierarchy)
	})

	t.Run("ParseHierarchy returns endorsement for ENDORSEMENT", func(t *testing.T) {
		h, err := ParseHierarchy("ENDORSEMENT")
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMRHEndorsement, h)
	})

	t.Run("ParseHierarchy returns owner for OWNER", func(t *testing.T) {
		h, err := ParseHierarchy("OWNER")
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMRHOwner, h)
	})

	t.Run("ParseHierarchy returns platform for PLATFORM", func(t *testing.T) {
		h, err := ParseHierarchy("PLATFORM")
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMRHPlatform, h)
	})

	t.Run("ParseHierarchy returns error for invalid hierarchy", func(t *testing.T) {
		_, err := ParseHierarchy("INVALID")
		assert.Equal(t, ErrInvalidHierarchyType, err)
	})

	t.Run("HierarchyName returns ENDORSEMENT for TPMRHEndorsement", func(t *testing.T) {
		name := HierarchyName(tpm2.TPMRHEndorsement)
		assert.Equal(t, "ENDORSEMENT", name)
	})

	t.Run("HierarchyName returns OWNER for TPMRHOwner", func(t *testing.T) {
		name := HierarchyName(tpm2.TPMRHOwner)
		assert.Equal(t, "OWNER", name)
	})

	t.Run("HierarchyName returns PLATFORM for TPMRHPlatform", func(t *testing.T) {
		name := HierarchyName(tpm2.TPMRHPlatform)
		assert.Equal(t, "PLATFORM", name)
	})

	t.Run("HierarchyName returns NULL for TPMRHNull", func(t *testing.T) {
		name := HierarchyName(tpm2.TPMRHNull)
		assert.Equal(t, "NULL", name)
	})
}

func TestKeyAttributeCreation(t *testing.T) {
	t.Run("creates valid RSA key attributes", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-key",
			KeyAlgorithm: x509.RSA,
			KeyType:      types.KeyTypeStorage,
			StoreType:    types.StoreTPM2,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
			TPMAttributes: &types.TPMAttributes{
				Handle:     tpm2.TPMHandle(0x81000001),
				HandleType: tpm2.TPMHTPersistent,
				Hierarchy:  tpm2.TPMRHOwner,
			},
		}
		assert.NotNil(t, attrs)
		assert.Equal(t, "test-key", attrs.CN)
		assert.Equal(t, x509.RSA, attrs.KeyAlgorithm)
		assert.Equal(t, 2048, attrs.RSAAttributes.KeySize)
	})

	t.Run("creates valid ECDSA key attributes", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-ecc-key",
			KeyAlgorithm: x509.ECDSA,
			KeyType:      types.KeyTypeStorage,
			StoreType:    types.StoreTPM2,
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P256(),
			},
			TPMAttributes: &types.TPMAttributes{
				Handle:     tpm2.TPMHandle(0x81000002),
				HandleType: tpm2.TPMHTPersistent,
				Hierarchy:  tpm2.TPMRHOwner,
			},
		}
		assert.NotNil(t, attrs)
		assert.Equal(t, "test-ecc-key", attrs.CN)
		assert.Equal(t, x509.ECDSA, attrs.KeyAlgorithm)
		assert.Equal(t, elliptic.P256(), attrs.ECCAttributes.Curve)
	})

	t.Run("creates EK key attributes with endorsement hierarchy", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "ek",
			KeyAlgorithm: x509.RSA,
			KeyType:      types.KeyTypeEndorsement,
			StoreType:    types.StoreTPM2,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
			TPMAttributes: &types.TPMAttributes{
				Handle:     tpm2.TPMHandle(0x81010001),
				HandleType: tpm2.TPMHTPersistent,
				Hierarchy:  tpm2.TPMRHEndorsement,
			},
		}
		assert.Equal(t, types.KeyTypeEndorsement, attrs.KeyType)
		assert.Equal(t, tpm2.TPMRHEndorsement, attrs.TPMAttributes.Hierarchy)
	})

	t.Run("creates IAK key attributes with attestation type", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:                 "iak",
			KeyAlgorithm:       x509.RSA,
			KeyType:            types.KeyTypeAttestation,
			SignatureAlgorithm: x509.SHA256WithRSAPSS,
			StoreType:          types.StoreTPM2,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
			TPMAttributes: &types.TPMAttributes{
				Handle:     tpm2.TPMHandle(0x81010002),
				HandleType: tpm2.TPMHTPersistent,
				Hierarchy:  tpm2.TPMRHEndorsement,
				HashAlg:    tpm2.TPMAlgSHA256,
			},
		}
		assert.Equal(t, types.KeyTypeAttestation, attrs.KeyType)
		assert.Equal(t, x509.SHA256WithRSAPSS, attrs.SignatureAlgorithm)
		assert.Equal(t, tpm2.TPMAlgSHA256, attrs.TPMAttributes.HashAlg)
	})

	t.Run("creates IDevID key attributes", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:                 "idevid",
			KeyAlgorithm:       x509.RSA,
			KeyType:            types.KeyTypeIDevID,
			SignatureAlgorithm: x509.SHA256WithRSAPSS,
			StoreType:          types.StoreTPM2,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
			TPMAttributes: &types.TPMAttributes{
				Handle:     tpm2.TPMHandle(0x81020000),
				HandleType: tpm2.TPMHTPersistent,
				Hierarchy:  tpm2.TPMRHEndorsement,
				HashAlg:    tpm2.TPMAlgSHA256,
			},
		}
		assert.Equal(t, types.KeyTypeIDevID, attrs.KeyType)
		assert.Equal(t, tpm2.TPMRHEndorsement, attrs.TPMAttributes.Hierarchy)
	})
}

func TestKeyAttributeValidation(t *testing.T) {
	t.Run("key attributes with nil TPMAttributes are valid struct", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test",
			KeyAlgorithm: x509.RSA,
		}
		assert.Nil(t, attrs.TPMAttributes)
	})

	t.Run("key attributes with nil parent are valid struct", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:     "test",
			Parent: nil,
		}
		assert.Nil(t, attrs.Parent)
	})

	t.Run("key attributes with parent hierarchy auth", func(t *testing.T) {
		parentAttrs := &types.KeyAttributes{
			CN: "parent",
			TPMAttributes: &types.TPMAttributes{
				HierarchyAuth: store.NewClearPassword([]byte("password")),
			},
		}
		attrs := &types.KeyAttributes{
			CN:     "child",
			Parent: parentAttrs,
		}
		assert.NotNil(t, attrs.Parent)
		assert.NotNil(t, attrs.Parent.TPMAttributes.HierarchyAuth)
	})

	t.Run("key attributes with platform policy", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:             "test",
			PlatformPolicy: true,
			TPMAttributes: &types.TPMAttributes{
				Handle: tpm2.TPMHandle(0x81000001),
			},
		}
		assert.True(t, attrs.PlatformPolicy)
	})

	t.Run("key attributes without platform policy", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:             "test",
			PlatformPolicy: false,
		}
		assert.False(t, attrs.PlatformPolicy)
	})

	t.Run("key attributes with password", func(t *testing.T) {
		password := store.NewClearPassword([]byte("test-password"))
		attrs := &types.KeyAttributes{
			CN:       "test",
			Password: password,
		}
		assert.NotNil(t, attrs.Password)
		passBytes := attrs.Password.Bytes()
		assert.Equal(t, []byte("test-password"), passBytes)
	})

	t.Run("key attributes with empty password", func(t *testing.T) {
		password := store.NewClearPassword([]byte{})
		attrs := &types.KeyAttributes{
			CN:       "test",
			Password: password,
		}
		passBytes := attrs.Password.Bytes()
		assert.Empty(t, passBytes)
	})

	t.Run("key attributes with nil password", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:       "test",
			Password: nil,
		}
		assert.Nil(t, attrs.Password)
	})
}

func TestTPMAttributesCreation(t *testing.T) {
	t.Run("creates TPMAttributes with all fields", func(t *testing.T) {
		tpmAttrs := &types.TPMAttributes{
			Handle:        tpm2.TPMHandle(0x81000001),
			HandleType:    tpm2.TPMHTPersistent,
			Hierarchy:     tpm2.TPMRHOwner,
			HashAlg:       tpm2.TPMAlgSHA256,
			HierarchyAuth: store.NewClearPassword([]byte("auth")),
			Template:      RSASSATemplate,
		}
		assert.NotNil(t, tpmAttrs)
		assert.Equal(t, tpm2.TPMHandle(0x81000001), tpmAttrs.Handle)
		assert.Equal(t, tpm2.TPMHTPersistent, tpmAttrs.HandleType)
		assert.Equal(t, tpm2.TPMRHOwner, tpmAttrs.Hierarchy)
		assert.Equal(t, tpm2.TPMAlgSHA256, tpmAttrs.HashAlg)
	})

	t.Run("TPMAttributes with cert handle", func(t *testing.T) {
		tpmAttrs := &types.TPMAttributes{
			Handle:     tpm2.TPMHandle(0x81010001),
			CertHandle: tpm2.TPMHandle(0x01C00002),
		}
		assert.Equal(t, tpm2.TPMHandle(0x01C00002), tpmAttrs.CertHandle)
	})

	t.Run("TPMAttributes with PCR selection", func(t *testing.T) {
		pcrSelection := tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(16),
				},
			},
		}
		tpmAttrs := &types.TPMAttributes{
			Handle:       tpm2.TPMHandle(0x81000001),
			PCRSelection: pcrSelection,
		}
		pcrSel := tpmAttrs.PCRSelection.(tpm2.TPMLPCRSelection)
		assert.Equal(t, 1, len(pcrSel.PCRSelections))
		assert.Equal(t, tpm2.TPMAlgSHA256, pcrSel.PCRSelections[0].Hash)
	})

	t.Run("TPMAttributes with name and public key bytes", func(t *testing.T) {
		tpmAttrs := &types.TPMAttributes{
			Handle: tpm2.TPMHandle(0x81000001),
			Name: tpm2.TPM2BName{
				Buffer: []byte{0x01, 0x02, 0x03},
			},
			PublicKeyBytes: []byte{0x04, 0x05, 0x06},
		}
		n := tpmAttrs.Name.(tpm2.TPM2BName)
		assert.Equal(t, []byte{0x01, 0x02, 0x03}, n.Buffer)
		assert.Equal(t, []byte{0x04, 0x05, 0x06}, tpmAttrs.PublicKeyBytes)
	})

	t.Run("TPMAttributes with signature and certify info", func(t *testing.T) {
		tpmAttrs := &types.TPMAttributes{
			Handle:      tpm2.TPMHandle(0x81010002),
			CertifyInfo: []byte{0x10, 0x20, 0x30},
			Signature:   []byte{0x40, 0x50, 0x60},
		}
		assert.Equal(t, []byte{0x10, 0x20, 0x30}, tpmAttrs.CertifyInfo)
		assert.Equal(t, []byte{0x40, 0x50, 0x60}, tpmAttrs.Signature)
	})
}

func TestKeyTypeValidation(t *testing.T) {
	t.Run("KEY_TYPE_ENDORSEMENT is valid", func(t *testing.T) {
		keyType := types.KeyTypeEndorsement
		assert.Equal(t, types.KeyTypeEndorsement, keyType)
	})

	t.Run("KEY_TYPE_STORAGE is valid", func(t *testing.T) {
		keyType := types.KeyTypeStorage
		assert.Equal(t, types.KeyTypeStorage, keyType)
	})

	t.Run("KEY_TYPE_ATTESTATION is valid", func(t *testing.T) {
		keyType := types.KeyTypeAttestation
		assert.Equal(t, types.KeyTypeAttestation, keyType)
	})

	t.Run("KEY_TYPE_IDEVID is valid", func(t *testing.T) {
		keyType := types.KeyTypeIDevID
		assert.Equal(t, types.KeyTypeIDevID, keyType)
	})

	t.Run("KEY_TYPE_TPM is valid", func(t *testing.T) {
		keyType := types.KeyTypeTPM
		assert.Equal(t, types.KeyTypeTPM, keyType)
	})
}

func TestStoreTypeValidation(t *testing.T) {
	t.Run("STORE_TPM2 is valid", func(t *testing.T) {
		storeType := types.StoreTPM2
		assert.Equal(t, types.StoreTPM2, storeType)
	})
}

func TestRSAAttributesValidation(t *testing.T) {
	t.Run("2048-bit RSA key size is valid", func(t *testing.T) {
		rsaAttrs := &types.RSAAttributes{
			KeySize: 2048,
		}
		assert.Equal(t, 2048, rsaAttrs.KeySize)
	})

	t.Run("3072-bit RSA key size is valid", func(t *testing.T) {
		rsaAttrs := &types.RSAAttributes{
			KeySize: 3072,
		}
		assert.Equal(t, 3072, rsaAttrs.KeySize)
	})

	t.Run("4096-bit RSA key size is valid", func(t *testing.T) {
		rsaAttrs := &types.RSAAttributes{
			KeySize: 4096,
		}
		assert.Equal(t, 4096, rsaAttrs.KeySize)
	})
}

func TestECCAttributesValidation(t *testing.T) {
	t.Run("P256 curve is valid", func(t *testing.T) {
		eccAttrs := &types.ECCAttributes{
			Curve: elliptic.P256(),
		}
		assert.Equal(t, elliptic.P256(), eccAttrs.Curve)
	})

	t.Run("P384 curve is valid", func(t *testing.T) {
		eccAttrs := &types.ECCAttributes{
			Curve: elliptic.P384(),
		}
		assert.Equal(t, elliptic.P384(), eccAttrs.Curve)
	})

	t.Run("P521 curve is valid", func(t *testing.T) {
		eccAttrs := &types.ECCAttributes{
			Curve: elliptic.P521(),
		}
		assert.Equal(t, elliptic.P521(), eccAttrs.Curve)
	})
}

func TestSignatureAlgorithmValidation(t *testing.T) {
	t.Run("SHA256WithRSA is valid", func(t *testing.T) {
		sigAlgo := x509.SHA256WithRSA
		assert.Equal(t, x509.SHA256WithRSA, sigAlgo)
	})

	t.Run("SHA256WithRSAPSS is valid", func(t *testing.T) {
		sigAlgo := x509.SHA256WithRSAPSS
		assert.Equal(t, x509.SHA256WithRSAPSS, sigAlgo)
	})

	t.Run("SHA384WithRSAPSS is valid", func(t *testing.T) {
		sigAlgo := x509.SHA384WithRSAPSS
		assert.Equal(t, x509.SHA384WithRSAPSS, sigAlgo)
	})

	t.Run("SHA512WithRSAPSS is valid", func(t *testing.T) {
		sigAlgo := x509.SHA512WithRSAPSS
		assert.Equal(t, x509.SHA512WithRSAPSS, sigAlgo)
	})

	t.Run("ECDSAWithSHA256 is valid", func(t *testing.T) {
		sigAlgo := x509.ECDSAWithSHA256
		assert.Equal(t, x509.ECDSAWithSHA256, sigAlgo)
	})

	t.Run("ECDSAWithSHA384 is valid", func(t *testing.T) {
		sigAlgo := x509.ECDSAWithSHA384
		assert.Equal(t, x509.ECDSAWithSHA384, sigAlgo)
	})

	t.Run("ECDSAWithSHA512 is valid", func(t *testing.T) {
		sigAlgo := x509.ECDSAWithSHA512
		assert.Equal(t, x509.ECDSAWithSHA512, sigAlgo)
	})
}

func TestKeyAlgorithmValidation(t *testing.T) {
	t.Run("RSA key algorithm is valid", func(t *testing.T) {
		keyAlgo := x509.RSA
		assert.Equal(t, x509.RSA, keyAlgo)
	})

	t.Run("ECDSA key algorithm is valid", func(t *testing.T) {
		keyAlgo := x509.ECDSA
		assert.Equal(t, x509.ECDSA, keyAlgo)
	})
}

func TestParentChildRelationship(t *testing.T) {
	t.Run("child key can reference parent", func(t *testing.T) {
		parent := &types.KeyAttributes{
			CN:           "parent-key",
			KeyAlgorithm: x509.RSA,
			TPMAttributes: &types.TPMAttributes{
				Handle:    tpm2.TPMHandle(0x81000001),
				Hierarchy: tpm2.TPMRHOwner,
			},
		}
		child := &types.KeyAttributes{
			CN:           "child-key",
			KeyAlgorithm: x509.RSA,
			Parent:       parent,
		}
		assert.Equal(t, parent, child.Parent)
		assert.Equal(t, "parent-key", child.Parent.CN)
	})

	t.Run("EK as parent of IAK", func(t *testing.T) {
		ekAttrs := &types.KeyAttributes{
			CN:      "ek",
			KeyType: types.KeyTypeEndorsement,
			TPMAttributes: &types.TPMAttributes{
				Handle:        tpm2.TPMHandle(0x81010001),
				Hierarchy:     tpm2.TPMRHEndorsement,
				HierarchyAuth: store.NewClearPassword([]byte("auth")),
			},
		}
		iakAttrs := &types.KeyAttributes{
			CN:      "iak",
			KeyType: types.KeyTypeAttestation,
			Parent:  ekAttrs,
		}
		assert.Equal(t, types.KeyTypeEndorsement, iakAttrs.Parent.KeyType)
		assert.Equal(t, tpm2.TPMRHEndorsement, iakAttrs.Parent.TPMAttributes.Hierarchy)
	})

	t.Run("parent hierarchy auth is accessible from child", func(t *testing.T) {
		parent := &types.KeyAttributes{
			CN: "parent",
			TPMAttributes: &types.TPMAttributes{
				HierarchyAuth: store.NewClearPassword([]byte("hierarchy-auth")),
			},
		}
		child := &types.KeyAttributes{
			CN:     "child",
			Parent: parent,
		}
		auth := child.Parent.TPMAttributes.HierarchyAuth.Bytes()
		assert.Equal(t, []byte("hierarchy-auth"), auth)
	})
}
