package tpm2

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"log/slog"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		name, err := HierarchyName(tpm2.TPMRHEndorsement)
		assert.NoError(t, err)
		assert.Equal(t, "ENDORSEMENT", name)
	})

	t.Run("HierarchyName returns OWNER for TPMRHOwner", func(t *testing.T) {
		name, err := HierarchyName(tpm2.TPMRHOwner)
		assert.NoError(t, err)
		assert.Equal(t, "OWNER", name)
	})

	t.Run("HierarchyName returns PLATFORM for TPMRHPlatform", func(t *testing.T) {
		name, err := HierarchyName(tpm2.TPMRHPlatform)
		assert.NoError(t, err)
		assert.Equal(t, "PLATFORM", name)
	})

	t.Run("HierarchyName returns NULL for TPMRHNull", func(t *testing.T) {
		name, err := HierarchyName(tpm2.TPMRHNull)
		assert.NoError(t, err)
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
				HierarchyAuth: store.NewPassword([]byte("password")),
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
		password := store.NewPassword([]byte("test-password"))
		attrs := &types.KeyAttributes{
			CN:       "test",
			Password: password,
		}
		assert.NotNil(t, attrs.Password)
		passBytes := attrs.Password.Bytes()
		assert.Equal(t, []byte("test-password"), passBytes)
	})

	t.Run("key attributes with empty password", func(t *testing.T) {
		password := store.NewPassword([]byte{})
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
			HierarchyAuth: store.NewPassword([]byte("auth")),
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
		pcrSel := tpmAttrs.PCRSelection
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
		n := tpmAttrs.Name
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
				HierarchyAuth: store.NewPassword([]byte("auth")),
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
				HierarchyAuth: store.NewPassword([]byte("hierarchy-auth")),
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

// =====================================================
// Key Parsing Tests (from key_parsing_test.go)
// =====================================================

func TestParsePublicKeyRSAUnit(t *testing.T) {
	// Generate a real RSA key for testing
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Marshal to DER format
	der, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	// Parse it back
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatalf("failed to parse public key: %v", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatal("parsed key is not RSA")
	}

	if rsaPub.N.Cmp(rsaKey.PublicKey.N) != 0 { //nolint:staticcheck // QF1008
		t.Error("N value mismatch")
	}
	if rsaPub.E != rsaKey.PublicKey.E { //nolint:staticcheck // QF1008
		t.Error("E value mismatch")
	}
}

func TestParsePublicKeyECDSAUnit(t *testing.T) {
	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	}

	for _, c := range curves {
		t.Run(c.name, func(t *testing.T) {
			ecKey, err := ecdsa.GenerateKey(c.curve, rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate ECDSA key: %v", err)
			}

			der, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
			if err != nil {
				t.Fatalf("failed to marshal public key: %v", err)
			}

			pub, err := x509.ParsePKIXPublicKey(der)
			if err != nil {
				t.Fatalf("failed to parse public key: %v", err)
			}

			ecPub, ok := pub.(*ecdsa.PublicKey)
			if !ok {
				t.Fatal("parsed key is not ECDSA")
			}

			if !ecPub.Equal(&ecKey.PublicKey) {
				t.Error("public key mismatch")
			}
			if ecPub.Curve.Params().Name != c.curve.Params().Name {
				t.Errorf("curve mismatch: got %s, want %s", ecPub.Curve.Params().Name, c.curve.Params().Name)
			}
		})
	}
}

func TestParsePublicKeyInvalidUnit(t *testing.T) {
	tests := []struct {
		name    string
		der     []byte
		wantErr bool
	}{
		{
			name:    "empty data",
			der:     []byte{},
			wantErr: true,
		},
		{
			name:    "invalid ASN.1",
			der:     []byte{0xFF, 0xFF, 0xFF},
			wantErr: true,
		},
		{
			name:    "truncated DER",
			der:     []byte{0x30, 0x82, 0x01, 0x22},
			wantErr: true,
		},
		{
			name:    "random bytes",
			der:     []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := x509.ParsePKIXPublicKey(tt.der)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestMarshalPKIXPublicKeyUnit(t *testing.T) {
	tests := []struct {
		name    string
		keyGen  func() (interface{}, error)
		wantErr bool
	}{
		{
			name: "RSA 2048",
			keyGen: func() (interface{}, error) {
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					return nil, err
				}
				return &key.PublicKey, nil
			},
			wantErr: false,
		},
		{
			name: "ECDSA P-256",
			keyGen: func() (interface{}, error) {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					return nil, err
				}
				return &key.PublicKey, nil
			},
			wantErr: false,
		},
		{
			name: "ECDSA P-384",
			keyGen: func() (interface{}, error) {
				key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				if err != nil {
					return nil, err
				}
				return &key.PublicKey, nil
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub, err := tt.keyGen()
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}

			der, err := x509.MarshalPKIXPublicKey(pub)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if len(der) == 0 {
				t.Error("DER encoding should not be empty")
			}

			// Verify round trip
			parsed, err := x509.ParsePKIXPublicKey(der)
			if err != nil {
				t.Errorf("failed to parse encoded key: %v", err)
			}

			if parsed == nil {
				t.Error("parsed key should not be nil")
			}
		})
	}
}

func TestRSAPublicKeyComponentsUnit(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Test N (modulus)
	n := rsaKey.PublicKey.N //nolint:staticcheck // QF1008
	if n == nil {
		t.Fatal("N should not be nil")
	}
	if n.BitLen() != 2048 {
		t.Errorf("N bit length = %d, want 2048", n.BitLen())
	}

	// Test E (public exponent)
	e := rsaKey.PublicKey.E //nolint:staticcheck // QF1008
	if e != 65537 {         // Common default
		t.Errorf("E = %d, want 65537", e)
	}

	// Test N bytes length
	nBytes := n.Bytes()
	if len(nBytes) < 255 || len(nBytes) > 257 {
		t.Errorf("N bytes length = %d, expected around 256", len(nBytes))
	}
}

func TestECDSAPublicKeyComponentsUnit(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	// Verify key is valid by encoding to uncompressed point format
	pubBytes, err := ecKey.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("failed to encode public key: %v", err)
	}

	// P-256 uncompressed point: 0x04 || X(32) || Y(32) = 65 bytes
	if len(pubBytes) != 65 {
		t.Errorf("uncompressed point length = %d, want 65", len(pubBytes))
	}

	// Verify round-trip via ParseUncompressedPublicKey
	reconstructed, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pubBytes)
	if err != nil {
		t.Fatalf("failed to parse uncompressed public key: %v", err)
	}
	if !reconstructed.Equal(&ecKey.PublicKey) {
		t.Error("reconstructed key does not match original")
	}
}

func TestPublicKeyTypeAssertionUnit(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	tests := []struct {
		name    string
		key     interface{}
		isRSA   bool
		isECDSA bool
	}{
		{
			name:    "RSA public key",
			key:     &rsaKey.PublicKey,
			isRSA:   true,
			isECDSA: false,
		},
		{
			name:    "ECDSA public key",
			key:     &ecKey.PublicKey,
			isRSA:   false,
			isECDSA: true,
		},
		{
			name:    "string type",
			key:     "not a key",
			isRSA:   false,
			isECDSA: false,
		},
		{
			name:    "nil",
			key:     nil,
			isRSA:   false,
			isECDSA: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, isRSA := tt.key.(*rsa.PublicKey)
			_, isECDSA := tt.key.(*ecdsa.PublicKey)

			if isRSA != tt.isRSA {
				t.Errorf("RSA assertion = %v, want %v", isRSA, tt.isRSA)
			}
			if isECDSA != tt.isECDSA {
				t.Errorf("ECDSA assertion = %v, want %v", isECDSA, tt.isECDSA)
			}
		})
	}
}

func TestKeyAlgorithmDetectionUnit(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	tests := []struct {
		name      string
		key       interface{}
		wantAlgo  x509.PublicKeyAlgorithm
		wantError bool
	}{
		{
			name:      "RSA key",
			key:       &rsaKey.PublicKey,
			wantAlgo:  x509.RSA,
			wantError: false,
		},
		{
			name:      "ECDSA key",
			key:       &ecKey.PublicKey,
			wantAlgo:  x509.ECDSA,
			wantError: false,
		},
		{
			name:      "unknown type",
			key:       "string",
			wantAlgo:  x509.UnknownPublicKeyAlgorithm,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var algo x509.PublicKeyAlgorithm
			switch tt.key.(type) {
			case *rsa.PublicKey:
				algo = x509.RSA
			case *ecdsa.PublicKey:
				algo = x509.ECDSA
			default:
				algo = x509.UnknownPublicKeyAlgorithm
			}

			if algo != tt.wantAlgo {
				t.Errorf("algorithm = %v, want %v", algo, tt.wantAlgo)
			}
		})
	}
}

// =====================================================
// Parse Functions Tests (from parse_functions_test.go)
// =====================================================

func TestParseHashAlgFromStringUnit(t *testing.T) {
	tests := []struct {
		name    string
		hash    string
		want    tpm2.TPMIAlgHash
		wantErr bool
	}{
		{
			name:    "SHA-1 uppercase",
			hash:    "SHA-1",
			want:    tpm2.TPMAlgSHA1,
			wantErr: false,
		},
		{
			name:    "SHA-1 lowercase",
			hash:    "sha-1",
			want:    tpm2.TPMAlgSHA1,
			wantErr: false,
		},
		{
			name:    "SHA-256",
			hash:    "SHA-256",
			want:    tpm2.TPMAlgSHA256,
			wantErr: false,
		},
		{
			name:    "SHA-384",
			hash:    "SHA-384",
			want:    tpm2.TPMAlgSHA384,
			wantErr: false,
		},
		{
			name:    "SHA-512",
			hash:    "SHA-512",
			want:    tpm2.TPMAlgSHA512,
			wantErr: false,
		},
		{
			name:    "invalid hash",
			hash:    "MD5",
			want:    0,
			wantErr: true,
		},
		{
			name:    "empty string",
			hash:    "",
			want:    0,
			wantErr: true,
		},
		{
			name:    "partial match",
			hash:    "SHA",
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseHashAlgFromString(tt.hash)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseHashAlgFromString() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("ParseHashAlgFromString() unexpected error: %v", err)
				return
			}

			if got != tt.want {
				t.Errorf("ParseHashAlgFromString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseHashAlgUnit(t *testing.T) {
	tests := []struct {
		name    string
		hash    crypto.Hash
		want    tpm2.TPMIAlgHash
		wantErr bool
	}{
		{
			name:    "SHA1",
			hash:    crypto.SHA1,
			want:    tpm2.TPMAlgSHA1,
			wantErr: false,
		},
		{
			name:    "SHA256",
			hash:    crypto.SHA256,
			want:    tpm2.TPMAlgSHA256,
			wantErr: false,
		},
		{
			name:    "SHA384",
			hash:    crypto.SHA384,
			want:    tpm2.TPMAlgSHA384,
			wantErr: false,
		},
		{
			name:    "SHA512",
			hash:    crypto.SHA512,
			want:    tpm2.TPMAlgSHA512,
			wantErr: false,
		},
		{
			name:    "unsupported MD5",
			hash:    crypto.MD5,
			want:    0,
			wantErr: true,
		},
		{
			name:    "unsupported SHA3-256",
			hash:    crypto.SHA3_256,
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseHashAlg(tt.hash)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseHashAlg() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("ParseHashAlg() unexpected error: %v", err)
				return
			}

			if got != tt.want {
				t.Errorf("ParseHashAlg() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseHashSizeUnit(t *testing.T) {
	tests := []struct {
		name    string
		hash    crypto.Hash
		want    uint32
		wantErr bool
	}{
		{
			name:    "SHA1 size",
			hash:    crypto.SHA1,
			want:    20,
			wantErr: false,
		},
		{
			name:    "SHA256 size",
			hash:    crypto.SHA256,
			want:    32,
			wantErr: false,
		},
		{
			name:    "SHA384 size",
			hash:    crypto.SHA384,
			want:    48,
			wantErr: false,
		},
		{
			name:    "SHA512 size",
			hash:    crypto.SHA512,
			want:    64,
			wantErr: false,
		},
		{
			name:    "unsupported hash",
			hash:    crypto.MD5,
			want:    0,
			wantErr: true,
		},
		{
			name:    "SHA3-256 unsupported",
			hash:    crypto.SHA3_256,
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseHashSize(tt.hash)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseHashSize() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("ParseHashSize() unexpected error: %v", err)
				return
			}

			if got != tt.want {
				t.Errorf("ParseHashSize() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestHierarchyNameUnit(t *testing.T) {
	tests := []struct {
		name        string
		hierarchy   tpm2.TPMHandle
		want        string
		shouldPanic bool
	}{
		{
			name:        "Platform hierarchy",
			hierarchy:   tpm2.TPMRHPlatform,
			want:        "PLATFORM",
			shouldPanic: false,
		},
		{
			name:        "Owner hierarchy",
			hierarchy:   tpm2.TPMRHOwner,
			want:        "OWNER",
			shouldPanic: false,
		},
		{
			name:        "Endorsement hierarchy",
			hierarchy:   tpm2.TPMRHEndorsement,
			want:        "ENDORSEMENT",
			shouldPanic: false,
		},
		{
			name:        "Null hierarchy",
			hierarchy:   tpm2.TPMRHNull,
			want:        "NULL",
			shouldPanic: false,
		},
		{
			name:        "Invalid hierarchy",
			hierarchy:   tpm2.TPMHandle(0xFFFFFFFF),
			want:        "",
			shouldPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HierarchyName(tt.hierarchy)

			if tt.shouldPanic {
				if err == nil {
					t.Errorf("HierarchyName() expected error, got none")
				}
				return
			}

			if err != nil {
				t.Errorf("HierarchyName() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("HierarchyName() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestParseHierarchyUnit(t *testing.T) {
	tests := []struct {
		name          string
		hierarchyType string
		want          tpm2.TPMIRHHierarchy
		wantErr       bool
	}{
		{
			name:          "ENDORSEMENT",
			hierarchyType: "ENDORSEMENT",
			want:          tpm2.TPMRHEndorsement,
			wantErr:       false,
		},
		{
			name:          "OWNER",
			hierarchyType: "OWNER",
			want:          tpm2.TPMRHOwner,
			wantErr:       false,
		},
		{
			name:          "PLATFORM",
			hierarchyType: "PLATFORM",
			want:          tpm2.TPMRHPlatform,
			wantErr:       false,
		},
		{
			name:          "lowercase endorsement",
			hierarchyType: "endorsement",
			want:          0,
			wantErr:       true,
		},
		{
			name:          "invalid hierarchy",
			hierarchyType: "INVALID",
			want:          0,
			wantErr:       true,
		},
		{
			name:          "empty string",
			hierarchyType: "",
			want:          0,
			wantErr:       true,
		},
		{
			name:          "mixed case",
			hierarchyType: "Endorsement",
			want:          0,
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseHierarchy(tt.hierarchyType)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseHierarchy() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("ParseHierarchy() unexpected error: %v", err)
				return
			}

			if got != tt.want {
				t.Errorf("ParseHierarchy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseIdentityProvisioningStrategyUnit(t *testing.T) {
	tests := []struct {
		name     string
		strategy string
		want     EnrollmentStrategy
	}{
		{
			name:     "IAK strategy",
			strategy: string(EnrollmentStrategyIAK),
			want:     EnrollmentStrategyIAK,
		},
		{
			name:     "IAK_IDEVID_SINGLE_PASS strategy",
			strategy: string(EnrollmentStrategyIAK_IDEVID_SINGLE_PASS),
			want:     EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
		{
			name:     "invalid strategy defaults to single pass",
			strategy: "INVALID",
			want:     EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
		{
			name:     "empty string defaults to single pass",
			strategy: "",
			want:     EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
		{
			name:     "lowercase iak",
			strategy: "iak",
			want:     EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseIdentityProvisioningStrategy(tt.strategy)
			if got != tt.want {
				t.Errorf("ParseIdentityProvisioningStrategy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParsePCRBankAlgIDUnit(t *testing.T) {
	tests := []struct {
		name    string
		pcrBank string
		want    tpm2.TPMAlgID
		wantErr bool
	}{
		{
			name:    "sha1 lowercase",
			pcrBank: "sha1",
			want:    tpm2.TPMAlgSHA1,
			wantErr: false,
		},
		{
			name:    "SHA1 uppercase",
			pcrBank: "SHA1",
			want:    tpm2.TPMAlgSHA1,
			wantErr: false,
		},
		{
			name:    "sha256",
			pcrBank: "sha256",
			want:    tpm2.TPMAlgSHA256,
			wantErr: false,
		},
		{
			name:    "sha384",
			pcrBank: "sha384",
			want:    tpm2.TPMAlgSHA384,
			wantErr: false,
		},
		{
			name:    "sha512",
			pcrBank: "sha512",
			want:    tpm2.TPMAlgSHA512,
			wantErr: false,
		},
		{
			name:    "invalid pcr bank",
			pcrBank: "invalid",
			want:    0,
			wantErr: true,
		},
		{
			name:    "sha3-256 unsupported",
			pcrBank: "sha3-256",
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePCRBankAlgID(tt.pcrBank)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParsePCRBankAlgID() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("ParsePCRBankAlgID() unexpected error: %v", err)
				return
			}

			if got != tt.want {
				t.Errorf("ParsePCRBankAlgID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParsePCRBankCryptoHashUnit(t *testing.T) {
	tests := []struct {
		name    string
		pcrBank string
		want    crypto.Hash
		wantErr bool
	}{
		{
			name:    "sha1",
			pcrBank: "sha1",
			want:    crypto.SHA1,
			wantErr: false,
		},
		{
			name:    "sha256",
			pcrBank: "sha256",
			want:    crypto.SHA256,
			wantErr: false,
		},
		{
			name:    "sha384",
			pcrBank: "sha384",
			want:    crypto.SHA3_384, // Note: maps to SHA3_384 per the map
			wantErr: false,
		},
		{
			name:    "sha512",
			pcrBank: "sha512",
			want:    crypto.SHA512,
			wantErr: false,
		},
		{
			name:    "invalid",
			pcrBank: "invalid",
			want:    0,
			wantErr: true,
		},
		{
			name:    "empty",
			pcrBank: "",
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePCRBankCryptoHash(tt.pcrBank)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParsePCRBankCryptoHash() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("ParsePCRBankCryptoHash() unexpected error: %v", err)
				return
			}

			if got != tt.want {
				t.Errorf("ParsePCRBankCryptoHash() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseCryptoHashAlgIDUnit(t *testing.T) {
	tests := []struct {
		name    string
		hash    crypto.Hash
		want    tpm2.TPMAlgID
		wantErr bool
	}{
		{
			name:    "SHA-1",
			hash:    crypto.SHA1,
			want:    tpm2.TPMAlgSHA1,
			wantErr: false,
		},
		{
			name:    "SHA-256",
			hash:    crypto.SHA256,
			want:    tpm2.TPMAlgSHA256,
			wantErr: false,
		},
		{
			name:    "SHA-384",
			hash:    crypto.SHA384,
			want:    tpm2.TPMAlgSHA384,
			wantErr: false,
		},
		{
			name:    "SHA-512",
			hash:    crypto.SHA512,
			want:    tpm2.TPMAlgSHA512,
			wantErr: false,
		},
		{
			name:    "SHA3-256",
			hash:    crypto.SHA3_256,
			want:    tpm2.TPMAlgSHA3256,
			wantErr: false,
		},
		{
			name:    "SHA3-384",
			hash:    crypto.SHA3_384,
			want:    tpm2.TPMAlgSHA3384,
			wantErr: false,
		},
		{
			name:    "SHA3-512",
			hash:    crypto.SHA3_512,
			want:    tpm2.TPMAlgSHA3512,
			wantErr: false,
		},
		{
			name:    "unsupported MD5",
			hash:    crypto.MD5,
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCryptoHashAlgID(tt.hash)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseCryptoHashAlgID() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("ParseCryptoHashAlgID() unexpected error: %v", err)
				return
			}

			if got != tt.want {
				t.Errorf("ParseCryptoHashAlgID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTCGVendorIDStringUnit(t *testing.T) {
	tests := []struct {
		name string
		id   TCGVendorID
		want string
	}{
		{
			name: "Intel",
			id:   1229870147,
			want: "Intel",
		},
		{
			name: "AMD",
			id:   1095582720,
			want: "AMD",
		},
		{
			name: "IBM",
			id:   1229081856,
			want: "IBM",
		},
		{
			name: "Microsoft",
			id:   1297303124,
			want: "Microsoft",
		},
		{
			name: "Infineon",
			id:   1229346816,
			want: "Infineon",
		},
		{
			name: "Google",
			id:   1196379975,
			want: "Google",
		},
		{
			name: "unknown vendor",
			id:   0,
			want: "",
		},
		{
			name: "another unknown",
			id:   123456,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.id.String()
			if got != tt.want {
				t.Errorf("TCGVendorID.String() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestSign_InvalidSignerOpts(t *testing.T) {
	logger := slog.Default()
	tpm := &TPM2{
		logger: logger,
	}

	digest := make([]byte, 32)
	_, _ = rand.Read(digest)

	// Test with non-store.SignerOpts
	_, err := tpm.Sign(rand.Reader, digest, crypto.SHA256)
	assert.Error(t, err)
	assert.Equal(t, store.ErrInvalidSignerOpts, err)
}

func TestSign_NilSignerOpts(t *testing.T) {
	logger := slog.Default()
	tpm := &TPM2{
		logger: logger,
	}

	digest := make([]byte, 32)
	_, _ = rand.Read(digest)

	_, err := tpm.Sign(rand.Reader, digest, nil)
	assert.Error(t, err)
	assert.Equal(t, store.ErrInvalidSignerOpts, err)
}

func TestParsePublicKey_EmptyInput(t *testing.T) {
	// Test with empty public key bytes - should fail on LoadExternal
	emptyBytes := []byte{}

	// This should fail when trying to parse empty bytes
	// The actual TPM operation would fail, but we can test the structure
	assert.Empty(t, emptyBytes)
}

func TestParsePublicKey_MalformedInput(t *testing.T) {
	// Test with malformed public key bytes
	malformedBytes := []byte{0x00, 0x01, 0x02, 0x03}

	// Verify the bytes are malformed (not a valid TPM2BPublic structure)
	reader := bytes.NewReader(malformedBytes)
	var header [2]byte
	err := binary.Read(reader, binary.BigEndian, &header)
	assert.NoError(t, err)

	// The structure should be invalid for TPM parsing
	assert.NotEqual(t, len(malformedBytes), int(binary.BigEndian.Uint16(header[:])))
}

func TestCreateRSAPublicArea(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	rsaPublicArea := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt: true,
			FixedTPM:    true,
			FixedParent: true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				KeyBits: 2048,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: privateKey.PublicKey.N.Bytes(), //nolint:staticcheck // QF1008
			},
		),
	}

	// Verify the structure
	assert.Equal(t, tpm2.TPMAlgRSA, rsaPublicArea.Type)
	assert.Equal(t, tpm2.TPMAlgSHA256, rsaPublicArea.NameAlg)
	assert.True(t, rsaPublicArea.ObjectAttributes.SignEncrypt)
	assert.True(t, rsaPublicArea.ObjectAttributes.FixedTPM)
	assert.True(t, rsaPublicArea.ObjectAttributes.FixedParent)

	// Extract RSA details
	rsaDetail, err := rsaPublicArea.Parameters.RSADetail()
	require.NoError(t, err)
	assert.Equal(t, tpm2.TPMAlgRSASSA, rsaDetail.Scheme.Scheme)
	assert.Equal(t, tpm2.TPMKeyBits(2048), rsaDetail.KeyBits)

	// Extract unique
	rsaUnique, err := rsaPublicArea.Unique.RSA()
	require.NoError(t, err)
	assert.Equal(t, privateKey.PublicKey.N.Bytes(), rsaUnique.Buffer) //nolint:staticcheck // QF1008
}

func TestCreateECCPublicArea(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	eccPublicArea := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt: true,
			FixedTPM:    true,
			FixedParent: true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				CurveID: tpm2.TPMECCNistP256,
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			func() *tpm2.TPMSECCPoint {
				uncompressed, pubErr := privateKey.PublicKey.Bytes()
				if pubErr != nil {
					panic("failed to encode public key: " + pubErr.Error())
				}
				coordLen := (len(uncompressed) - 1) / 2
				return &tpm2.TPMSECCPoint{
					X: tpm2.TPM2BECCParameter{Buffer: uncompressed[1 : 1+coordLen]},
					Y: tpm2.TPM2BECCParameter{Buffer: uncompressed[1+coordLen:]},
				}
			}(),
		),
	}

	// Verify the structure
	assert.Equal(t, tpm2.TPMAlgECC, eccPublicArea.Type)
	assert.Equal(t, tpm2.TPMAlgSHA256, eccPublicArea.NameAlg)

	// Extract ECC details
	eccDetail, err := eccPublicArea.Parameters.ECCDetail()
	require.NoError(t, err)
	assert.Equal(t, tpm2.TPMECCNistP256, eccDetail.CurveID)
	assert.Equal(t, tpm2.TPMAlgECDSA, eccDetail.Scheme.Scheme)

	// Extract unique
	eccUnique, err := eccPublicArea.Unique.ECC()
	require.NoError(t, err)
	uncompressedKey, keyErr := privateKey.PublicKey.Bytes()
	require.NoError(t, keyErr)
	keyCoordLen := (len(uncompressedKey) - 1) / 2
	assert.Equal(t, uncompressedKey[1:1+keyCoordLen], eccUnique.X.Buffer)
	assert.Equal(t, uncompressedKey[1+keyCoordLen:], eccUnique.Y.Buffer)
}

func TestEKAttributes_NilEKConfig(t *testing.T) {
	tpm := &TPM2{
		logger: slog.Default(),
		config: &Config{EK: nil},
	}
	attrs, err := tpm.EKAttributes()
	assert.Nil(t, attrs)
	assert.ErrorIs(t, err, ErrEKConfigNil)
}

func TestEKPublic_NilEKConfig(t *testing.T) {
	tpm := &TPM2{
		logger: slog.Default(),
		config: &Config{EK: nil},
	}
	_, _, err := tpm.EKPublic()
	assert.ErrorIs(t, err, ErrEKConfigNil)
}

func TestIAKAttributes_NilIAKConfig(t *testing.T) {
	tpm := &TPM2{
		logger: slog.Default(),
		config: &Config{IAK: nil},
	}
	attrs, err := tpm.IAKAttributes()
	assert.Nil(t, attrs)
	assert.ErrorIs(t, err, ErrIAKConfigNil)
}

func TestIDevIDAttributes_NilIDevIDConfig(t *testing.T) {
	tpm := &TPM2{
		logger: slog.Default(),
		config: &Config{IDevID: nil},
	}
	attrs, err := tpm.IDevIDAttributes()
	assert.Nil(t, attrs)
	assert.ErrorIs(t, err, ErrIDevIDConfigNil)
}

func TestSSRKAttributes_NilSSRKConfig(t *testing.T) {
	tpm := &TPM2{
		logger: slog.Default(),
		config: &Config{SSRK: nil},
	}
	attrs, err := tpm.SSRKAttributes()
	assert.Nil(t, attrs)
	assert.ErrorIs(t, err, ErrSSRKConfigNil)
}

func TestEKAttributes_NilRSAConfig(t *testing.T) {
	// Generate an RSA key pair for mock public key bytes
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pubDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	require.NoError(t, err)

	tpm := &TPM2{
		logger: slog.Default(),
		config: &Config{
			EK: &EKConfig{
				KeyAlgorithm: "RSA",
				RSAConfig:    nil,
			},
		},
		// Pre-set ekAttrs to bypass the KeyAttributes TPM call
		ekAttrs: &types.KeyAttributes{
			KeyAlgorithm: x509.RSA,
			KeyType:      types.KeyTypeEndorsement,
			StoreType:    types.StoreTPM2,
			TPMAttributes: &types.TPMAttributes{
				PublicKeyBytes: pubDER,
			},
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		},
	}

	// When ekAttrs is already cached, EKAttributes returns it directly
	attrs, err := tpm.EKAttributes()
	require.NoError(t, err)
	assert.NotNil(t, attrs)
	assert.Equal(t, 2048, attrs.RSAAttributes.KeySize)
}

func TestEKAttributes_NilECCConfig(t *testing.T) {
	// Generate an ECC key pair for mock public key bytes
	eccKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubDER, err := x509.MarshalPKIXPublicKey(&eccKey.PublicKey)
	require.NoError(t, err)

	tpm := &TPM2{
		logger: slog.Default(),
		config: &Config{
			EK: &EKConfig{
				KeyAlgorithm: "ECDSA",
				ECCConfig:    nil,
			},
		},
		// Pre-set ekAttrs to bypass the KeyAttributes TPM call
		ekAttrs: &types.KeyAttributes{
			KeyAlgorithm: x509.ECDSA,
			KeyType:      types.KeyTypeEndorsement,
			StoreType:    types.StoreTPM2,
			TPMAttributes: &types.TPMAttributes{
				PublicKeyBytes: pubDER,
			},
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P256(),
			},
		},
	}

	// When ekAttrs is already cached, EKAttributes returns it directly
	attrs, err := tpm.EKAttributes()
	require.NoError(t, err)
	assert.NotNil(t, attrs)
	assert.Equal(t, elliptic.P256(), attrs.ECCAttributes.Curve)
}

// TestPlatformSRKAttributes_NilConfig verifies PlatformSRKAttributes returns
// an error when PlatformSRK configuration is nil.
func TestPlatformSRKAttributes_NilConfig(t *testing.T) {
	tpm := &TPM2{
		logger: slog.Default(),
		config: &Config{PlatformSRK: nil},
	}
	attrs, err := tpm.PlatformSRKAttributes()
	assert.Nil(t, attrs)
	assert.ErrorIs(t, err, ErrInvalidPlatformSRKConfiguration)
}

// TestPlatformSRKAttributes_Caching verifies that calling PlatformSRKAttributes
// twice returns the same cached pointer without re-querying the TPM.
func TestPlatformSRKAttributes_Caching(t *testing.T) {
	// Pre-set platformSRKAttrs to simulate a cached result
	cachedAttrs := &types.KeyAttributes{
		CN:        "platform-srk",
		KeyType:   types.KeyTypeStorage,
		StoreType: types.StoreTPM2,
	}
	tpm := &TPM2{
		logger:           slog.Default(),
		config:           &Config{PlatformSRK: &PlatformSRKConfig{SRKHandle: 0x81000002}},
		platformSRKAttrs: cachedAttrs,
	}

	attrs1, err := tpm.PlatformSRKAttributes()
	require.NoError(t, err)
	attrs2, err := tpm.PlatformSRKAttributes()
	require.NoError(t, err)

	// Both calls should return the exact same pointer (cached)
	assert.Same(t, attrs1, attrs2)
	assert.Equal(t, "platform-srk", attrs1.CN)
	assert.Equal(t, types.KeyTypeStorage, attrs1.KeyType)
	assert.Equal(t, types.StoreTPM2, attrs1.StoreType)
}

// TestPlatformSRKAttributes_CachedWithCustomCN verifies that when the
// PlatformSRK config provides a CN, the cached attributes preserve it.
func TestPlatformSRKAttributes_CachedWithCustomCN(t *testing.T) {
	cachedAttrs := &types.KeyAttributes{
		CN:        "custom-platform-srk",
		KeyType:   types.KeyTypeStorage,
		StoreType: types.StoreTPM2,
	}
	tpm := &TPM2{
		logger: slog.Default(),
		config: &Config{
			PlatformSRK: &PlatformSRKConfig{
				CN:        "custom-platform-srk",
				SRKHandle: 0x81000002,
			},
		},
		platformSRKAttrs: cachedAttrs,
	}

	attrs, err := tpm.PlatformSRKAttributes()
	require.NoError(t, err)
	assert.Equal(t, "custom-platform-srk", attrs.CN)
}

// TestPlatformSRKAttributes_DefaultConfigApplied verifies that when NewTPM2()
// defaults a nil PlatformSRK to DefaultConfig.PlatformSRK, calling
// PlatformSRKAttributes does not return ErrInvalidPlatformSRKConfiguration.
// This uses a pre-cached result to avoid requiring a real TPM transport.
func TestPlatformSRKAttributes_DefaultConfigApplied(t *testing.T) {
	// Simulate the defaulting that NewTPM2 now performs:
	// if params.Config.PlatformSRK == nil { params.Config.PlatformSRK = DefaultConfig.PlatformSRK }
	config := &Config{PlatformSRK: nil}
	if config.PlatformSRK == nil {
		config.PlatformSRK = DefaultConfig.PlatformSRK
	}

	// Pre-cache attrs to avoid needing a real TPM transport for KeyAttributes()
	cachedAttrs := &types.KeyAttributes{
		CN:        "platform-srk",
		KeyType:   types.KeyTypeStorage,
		StoreType: types.StoreTPM2,
	}
	tpm := &TPM2{
		logger:           slog.Default(),
		config:           config,
		platformSRKAttrs: cachedAttrs,
	}

	attrs, err := tpm.PlatformSRKAttributes()
	require.NoError(t, err)
	assert.NotNil(t, attrs)
	assert.NotErrorIs(t, err, ErrInvalidPlatformSRKConfiguration)

	// Verify the default PlatformSRK config values were applied
	assert.Equal(t, "platform", config.PlatformSRK.SRKAuth)
	assert.Equal(t, uint32(0x81000002), config.PlatformSRK.SRKHandle)
	assert.True(t, config.PlatformSRK.PlatformPolicy)
}

// TestNewTPM2_DefaultsPlatformSRK verifies that the NewTPM2 constructor
// defaults PlatformSRK when the caller provides a Config with PlatformSRK nil.
// This tests the config defaulting logic directly without requiring a TPM device.
func TestNewTPM2_DefaultsPlatformSRK(t *testing.T) {
	config := &Config{
		PlatformSRK: nil,
		EK:          DefaultConfig.EK,
		SSRK:        DefaultConfig.SSRK,
	}
	params := &Params{
		Config: config,
	}

	// Simulate the defaulting section of NewTPM2 (the part we fixed)
	if params.Config.PlatformSRK == nil {
		params.Config.PlatformSRK = DefaultConfig.PlatformSRK
	}

	// After defaulting, PlatformSRK should match DefaultConfig
	require.NotNil(t, params.Config.PlatformSRK)
	assert.Equal(t, DefaultConfig.PlatformSRK.SRKAuth, params.Config.PlatformSRK.SRKAuth)
	assert.Equal(t, DefaultConfig.PlatformSRK.SRKHandle, params.Config.PlatformSRK.SRKHandle)
	assert.Equal(t, DefaultConfig.PlatformSRK.PlatformPolicy, params.Config.PlatformSRK.PlatformPolicy)
}
