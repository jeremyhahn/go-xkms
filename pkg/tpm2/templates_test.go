package tpm2

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
)

func TestRSASSATemplateExtended(t *testing.T) {
	t.Run("has correct type", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgRSA, RSASSATemplate.Type)
	})

	t.Run("has correct name algorithm", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgSHA256, RSASSATemplate.NameAlg)
	})

	t.Run("has SignEncrypt attribute set", func(t *testing.T) {
		assert.True(t, RSASSATemplate.ObjectAttributes.SignEncrypt)
	})

	t.Run("has FixedTPM attribute set", func(t *testing.T) {
		assert.True(t, RSASSATemplate.ObjectAttributes.FixedTPM)
	})

	t.Run("has FixedParent attribute set", func(t *testing.T) {
		assert.True(t, RSASSATemplate.ObjectAttributes.FixedParent)
	})

	t.Run("has SensitiveDataOrigin attribute set", func(t *testing.T) {
		assert.True(t, RSASSATemplate.ObjectAttributes.SensitiveDataOrigin)
	})

	t.Run("has UserWithAuth attribute set", func(t *testing.T) {
		assert.True(t, RSASSATemplate.ObjectAttributes.UserWithAuth)
	})

	t.Run("is not restricted", func(t *testing.T) {
		assert.False(t, RSASSATemplate.ObjectAttributes.Restricted)
	})

	t.Run("has correct RSA parameters", func(t *testing.T) {
		rsaDetail, err := RSASSATemplate.Parameters.RSADetail()
		assert.NoError(t, err)
		assert.NotNil(t, rsaDetail)
		assert.Equal(t, tpm2.TPMKeyBits(2048), rsaDetail.KeyBits)
		assert.Equal(t, tpm2.TPMAlgRSASSA, rsaDetail.Scheme.Scheme)
	})

	t.Run("has empty auth policy by default", func(t *testing.T) {
		assert.Empty(t, RSASSATemplate.AuthPolicy.Buffer)
	})

	t.Run("unique buffer has correct size for RSA 2048", func(t *testing.T) {
		rsaUnique, err := RSASSATemplate.Unique.RSA()
		assert.NoError(t, err)
		assert.Equal(t, 256, len(rsaUnique.Buffer))
	})
}

func TestRSAPSSTemplateExtended(t *testing.T) {
	t.Run("has correct type", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgRSA, RSAPSSTemplate.Type)
	})

	t.Run("has correct name algorithm", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgSHA256, RSAPSSTemplate.NameAlg)
	})

	t.Run("has RSA-PSS scheme", func(t *testing.T) {
		rsaDetail, err := RSAPSSTemplate.Parameters.RSADetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgRSAPSS, rsaDetail.Scheme.Scheme)
	})

	t.Run("has SignEncrypt attribute set", func(t *testing.T) {
		assert.True(t, RSAPSSTemplate.ObjectAttributes.SignEncrypt)
	})

	t.Run("has FixedTPM attribute set", func(t *testing.T) {
		assert.True(t, RSAPSSTemplate.ObjectAttributes.FixedTPM)
	})

	t.Run("has UserWithAuth attribute set", func(t *testing.T) {
		assert.True(t, RSAPSSTemplate.ObjectAttributes.UserWithAuth)
	})

	t.Run("has correct key size", func(t *testing.T) {
		rsaDetail, err := RSAPSSTemplate.Parameters.RSADetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMKeyBits(2048), rsaDetail.KeyBits)
	})

	t.Run("unique buffer has correct size", func(t *testing.T) {
		rsaUnique, err := RSAPSSTemplate.Unique.RSA()
		assert.NoError(t, err)
		assert.Equal(t, 256, len(rsaUnique.Buffer))
	})
}

func TestECCP256TemplateExtended(t *testing.T) {
	t.Run("has correct type", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgECC, ECCP256Template.Type)
	})

	t.Run("has correct name algorithm", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgSHA256, ECCP256Template.NameAlg)
	})

	t.Run("has NIST P256 curve", func(t *testing.T) {
		eccDetail, err := ECCP256Template.Parameters.ECCDetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMECCNistP256, eccDetail.CurveID)
	})

	t.Run("has ECDSA scheme", func(t *testing.T) {
		eccDetail, err := ECCP256Template.Parameters.ECCDetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgECDSA, eccDetail.Scheme.Scheme)
	})

	t.Run("has SignEncrypt attribute set", func(t *testing.T) {
		assert.True(t, ECCP256Template.ObjectAttributes.SignEncrypt)
	})

	t.Run("has FixedTPM attribute set", func(t *testing.T) {
		assert.True(t, ECCP256Template.ObjectAttributes.FixedTPM)
	})

	t.Run("has UserWithAuth attribute set", func(t *testing.T) {
		assert.True(t, ECCP256Template.ObjectAttributes.UserWithAuth)
	})

	t.Run("is not restricted", func(t *testing.T) {
		assert.False(t, ECCP256Template.ObjectAttributes.Restricted)
	})

	t.Run("has empty auth policy by default", func(t *testing.T) {
		assert.Empty(t, ECCP256Template.AuthPolicy.Buffer)
	})
}

func TestECCP384TemplateExtended(t *testing.T) {
	t.Run("has correct type", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgECC, ECCP384Template.Type)
	})

	t.Run("has correct name algorithm for P384", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgSHA384, ECCP384Template.NameAlg)
	})

	t.Run("has NIST P384 curve", func(t *testing.T) {
		eccDetail, err := ECCP384Template.Parameters.ECCDetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMECCNistP384, eccDetail.CurveID)
	})

	t.Run("has ECDSA scheme", func(t *testing.T) {
		eccDetail, err := ECCP384Template.Parameters.ECCDetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgECDSA, eccDetail.Scheme.Scheme)
	})

	t.Run("has SHA384 hash algorithm in scheme", func(t *testing.T) {
		eccDetail, err := ECCP384Template.Parameters.ECCDetail()
		assert.NoError(t, err)
		schemeDetails := eccDetail.Scheme.Details
		ecdsaScheme, err := schemeDetails.ECDSA()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA384, ecdsaScheme.HashAlg)
	})

	t.Run("has SignEncrypt attribute set", func(t *testing.T) {
		assert.True(t, ECCP384Template.ObjectAttributes.SignEncrypt)
	})

	t.Run("has FixedTPM attribute set", func(t *testing.T) {
		assert.True(t, ECCP384Template.ObjectAttributes.FixedTPM)
	})
}

func TestECCP521TemplateExtended(t *testing.T) {
	t.Run("has correct type", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgECC, ECCP521Template.Type)
	})

	t.Run("has correct name algorithm for P521", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgSHA512, ECCP521Template.NameAlg)
	})

	t.Run("has NIST P521 curve", func(t *testing.T) {
		eccDetail, err := ECCP521Template.Parameters.ECCDetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMECCNistP521, eccDetail.CurveID)
	})

	t.Run("has ECDSA scheme", func(t *testing.T) {
		eccDetail, err := ECCP521Template.Parameters.ECCDetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgECDSA, eccDetail.Scheme.Scheme)
	})

	t.Run("has SHA512 hash algorithm in scheme", func(t *testing.T) {
		eccDetail, err := ECCP521Template.Parameters.ECCDetail()
		assert.NoError(t, err)
		schemeDetails := eccDetail.Scheme.Details
		ecdsaScheme, err := schemeDetails.ECDSA()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA512, ecdsaScheme.HashAlg)
	})

	t.Run("has SignEncrypt attribute set", func(t *testing.T) {
		assert.True(t, ECCP521Template.ObjectAttributes.SignEncrypt)
	})

	t.Run("has UserWithAuth attribute set", func(t *testing.T) {
		assert.True(t, ECCP521Template.ObjectAttributes.UserWithAuth)
	})
}

func TestRSASSAAKTemplateExtended(t *testing.T) {
	t.Run("has correct type", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgRSA, RSASSAAKTemplate.Type)
	})

	t.Run("is restricted", func(t *testing.T) {
		assert.True(t, RSASSAAKTemplate.ObjectAttributes.Restricted)
	})

	t.Run("has SignEncrypt attribute for signing", func(t *testing.T) {
		assert.True(t, RSASSAAKTemplate.ObjectAttributes.SignEncrypt)
	})

	t.Run("has FixedTPM attribute", func(t *testing.T) {
		assert.True(t, RSASSAAKTemplate.ObjectAttributes.FixedTPM)
	})

	t.Run("has FixedParent attribute", func(t *testing.T) {
		assert.True(t, RSASSAAKTemplate.ObjectAttributes.FixedParent)
	})

	t.Run("has SensitiveDataOrigin attribute", func(t *testing.T) {
		assert.True(t, RSASSAAKTemplate.ObjectAttributes.SensitiveDataOrigin)
	})

	t.Run("has UserWithAuth attribute", func(t *testing.T) {
		assert.True(t, RSASSAAKTemplate.ObjectAttributes.UserWithAuth)
	})

	t.Run("has RSASSA scheme", func(t *testing.T) {
		rsaDetail, err := RSASSAAKTemplate.Parameters.RSADetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgRSASSA, rsaDetail.Scheme.Scheme)
	})

	t.Run("has 2048-bit key size", func(t *testing.T) {
		rsaDetail, err := RSASSAAKTemplate.Parameters.RSADetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMKeyBits(2048), rsaDetail.KeyBits)
	})

	t.Run("unique buffer has correct size", func(t *testing.T) {
		rsaUnique, err := RSASSAAKTemplate.Unique.RSA()
		assert.NoError(t, err)
		assert.Equal(t, 256, len(rsaUnique.Buffer))
	})
}

func TestRSAPSSAKTemplateExtended(t *testing.T) {
	t.Run("has correct type", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgRSA, RSAPSSAKTemplate.Type)
	})

	t.Run("is restricted", func(t *testing.T) {
		assert.True(t, RSAPSSAKTemplate.ObjectAttributes.Restricted)
	})

	t.Run("has SignEncrypt attribute for signing", func(t *testing.T) {
		assert.True(t, RSAPSSAKTemplate.ObjectAttributes.SignEncrypt)
	})

	t.Run("has FixedTPM attribute", func(t *testing.T) {
		assert.True(t, RSAPSSAKTemplate.ObjectAttributes.FixedTPM)
	})

	t.Run("has RSAPSS scheme", func(t *testing.T) {
		rsaDetail, err := RSAPSSAKTemplate.Parameters.RSADetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgRSAPSS, rsaDetail.Scheme.Scheme)
	})

	t.Run("has 2048-bit key size", func(t *testing.T) {
		rsaDetail, err := RSAPSSAKTemplate.Parameters.RSADetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMKeyBits(2048), rsaDetail.KeyBits)
	})

	t.Run("has empty auth policy", func(t *testing.T) {
		assert.Empty(t, RSAPSSAKTemplate.AuthPolicy.Buffer)
	})
}

func TestECCAKP256TemplateExtended(t *testing.T) {
	t.Run("has correct type", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgECC, ECCAKP256Template.Type)
	})

	t.Run("is restricted", func(t *testing.T) {
		assert.True(t, ECCAKP256Template.ObjectAttributes.Restricted)
	})

	t.Run("has SignEncrypt attribute for signing", func(t *testing.T) {
		assert.True(t, ECCAKP256Template.ObjectAttributes.SignEncrypt)
	})

	t.Run("has FixedTPM attribute", func(t *testing.T) {
		assert.True(t, ECCAKP256Template.ObjectAttributes.FixedTPM)
	})

	t.Run("has FixedParent attribute", func(t *testing.T) {
		assert.True(t, ECCAKP256Template.ObjectAttributes.FixedParent)
	})

	t.Run("has SensitiveDataOrigin attribute", func(t *testing.T) {
		assert.True(t, ECCAKP256Template.ObjectAttributes.SensitiveDataOrigin)
	})

	t.Run("has UserWithAuth attribute", func(t *testing.T) {
		assert.True(t, ECCAKP256Template.ObjectAttributes.UserWithAuth)
	})

	t.Run("has NIST P256 curve", func(t *testing.T) {
		eccDetail, err := ECCAKP256Template.Parameters.ECCDetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMECCNistP256, eccDetail.CurveID)
	})

	t.Run("has ECDSA scheme", func(t *testing.T) {
		eccDetail, err := ECCAKP256Template.Parameters.ECCDetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgECDSA, eccDetail.Scheme.Scheme)
	})
}

func TestRSASSAIDevIDTemplateExtended(t *testing.T) {
	t.Run("has correct type", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgRSA, RSASSAIDevIDTemplate.Type)
	})

	t.Run("is NOT restricted", func(t *testing.T) {
		assert.False(t, RSASSAIDevIDTemplate.ObjectAttributes.Restricted)
	})

	t.Run("has SignEncrypt attribute for signing", func(t *testing.T) {
		assert.True(t, RSASSAIDevIDTemplate.ObjectAttributes.SignEncrypt)
	})

	t.Run("has FixedTPM attribute", func(t *testing.T) {
		assert.True(t, RSASSAIDevIDTemplate.ObjectAttributes.FixedTPM)
	})

	t.Run("has FixedParent attribute", func(t *testing.T) {
		assert.True(t, RSASSAIDevIDTemplate.ObjectAttributes.FixedParent)
	})

	t.Run("has SensitiveDataOrigin attribute", func(t *testing.T) {
		assert.True(t, RSASSAIDevIDTemplate.ObjectAttributes.SensitiveDataOrigin)
	})

	t.Run("has UserWithAuth attribute", func(t *testing.T) {
		assert.True(t, RSASSAIDevIDTemplate.ObjectAttributes.UserWithAuth)
	})

	t.Run("has RSASSA scheme", func(t *testing.T) {
		rsaDetail, err := RSASSAIDevIDTemplate.Parameters.RSADetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgRSASSA, rsaDetail.Scheme.Scheme)
	})

	t.Run("has 2048-bit key size", func(t *testing.T) {
		rsaDetail, err := RSASSAIDevIDTemplate.Parameters.RSADetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMKeyBits(2048), rsaDetail.KeyBits)
	})
}

func TestRSAPSSIDevIDTemplateExtended(t *testing.T) {
	t.Run("has correct type", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgRSA, RSAPSSIDevIDTemplate.Type)
	})

	t.Run("is NOT restricted", func(t *testing.T) {
		assert.False(t, RSAPSSIDevIDTemplate.ObjectAttributes.Restricted)
	})

	t.Run("has SignEncrypt attribute for signing", func(t *testing.T) {
		assert.True(t, RSAPSSIDevIDTemplate.ObjectAttributes.SignEncrypt)
	})

	t.Run("has FixedTPM attribute", func(t *testing.T) {
		assert.True(t, RSAPSSIDevIDTemplate.ObjectAttributes.FixedTPM)
	})

	t.Run("has RSAPSS scheme", func(t *testing.T) {
		rsaDetail, err := RSAPSSIDevIDTemplate.Parameters.RSADetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgRSAPSS, rsaDetail.Scheme.Scheme)
	})

	t.Run("has empty auth policy", func(t *testing.T) {
		assert.Empty(t, RSAPSSIDevIDTemplate.AuthPolicy.Buffer)
	})
}

func TestECCIDevIDP256TemplateExtended(t *testing.T) {
	t.Run("has correct type", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgECC, ECCIDevIDP256Template.Type)
	})

	t.Run("is NOT restricted", func(t *testing.T) {
		assert.False(t, ECCIDevIDP256Template.ObjectAttributes.Restricted)
	})

	t.Run("has SignEncrypt attribute for signing", func(t *testing.T) {
		assert.True(t, ECCIDevIDP256Template.ObjectAttributes.SignEncrypt)
	})

	t.Run("has FixedTPM attribute", func(t *testing.T) {
		assert.True(t, ECCIDevIDP256Template.ObjectAttributes.FixedTPM)
	})

	t.Run("has FixedParent attribute", func(t *testing.T) {
		assert.True(t, ECCIDevIDP256Template.ObjectAttributes.FixedParent)
	})

	t.Run("has NIST P256 curve", func(t *testing.T) {
		eccDetail, err := ECCIDevIDP256Template.Parameters.ECCDetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMECCNistP256, eccDetail.CurveID)
	})

	t.Run("has ECDSA scheme", func(t *testing.T) {
		eccDetail, err := ECCIDevIDP256Template.Parameters.ECCDetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgECDSA, eccDetail.Scheme.Scheme)
	})
}

func TestAES128CFBTemplateAttributes(t *testing.T) {
	t.Run("has correct type", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgSymCipher, AES128CFBTemplate.Type)
	})

	t.Run("has correct name algorithm", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgSHA256, AES128CFBTemplate.NameAlg)
	})

	t.Run("has FixedTPM attribute", func(t *testing.T) {
		assert.True(t, AES128CFBTemplate.ObjectAttributes.FixedTPM)
	})

	t.Run("has FixedParent attribute", func(t *testing.T) {
		assert.True(t, AES128CFBTemplate.ObjectAttributes.FixedParent)
	})

	t.Run("has NoDA attribute", func(t *testing.T) {
		assert.True(t, AES128CFBTemplate.ObjectAttributes.NoDA)
	})

	t.Run("has Decrypt attribute", func(t *testing.T) {
		assert.True(t, AES128CFBTemplate.ObjectAttributes.Decrypt)
	})

	t.Run("has SignEncrypt attribute", func(t *testing.T) {
		assert.True(t, AES128CFBTemplate.ObjectAttributes.SignEncrypt)
	})

	t.Run("is NOT restricted", func(t *testing.T) {
		assert.False(t, AES128CFBTemplate.ObjectAttributes.Restricted)
	})

	t.Run("has UserWithAuth attribute", func(t *testing.T) {
		assert.True(t, AES128CFBTemplate.ObjectAttributes.UserWithAuth)
	})

	t.Run("has AES algorithm in parameters", func(t *testing.T) {
		symParms, err := AES128CFBTemplate.Parameters.SymDetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgAES, symParms.Sym.Algorithm)
	})

	t.Run("has CFB mode in parameters", func(t *testing.T) {
		symParms, err := AES128CFBTemplate.Parameters.SymDetail()
		assert.NoError(t, err)
		mode, err := symParms.Sym.Mode.AES()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgCFB, *mode)
	})
}

func TestAES256CFBTemplateAttributes(t *testing.T) {
	t.Run("has correct type", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgSymCipher, AES256CFBTemplate.Type)
	})

	t.Run("has FixedTPM attribute", func(t *testing.T) {
		assert.True(t, AES256CFBTemplate.ObjectAttributes.FixedTPM)
	})

	t.Run("has NoDA attribute", func(t *testing.T) {
		assert.True(t, AES256CFBTemplate.ObjectAttributes.NoDA)
	})

	t.Run("has AES algorithm in parameters", func(t *testing.T) {
		symParms, err := AES256CFBTemplate.Parameters.SymDetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgAES, symParms.Sym.Algorithm)
	})

	t.Run("has CFB mode in parameters", func(t *testing.T) {
		symParms, err := AES256CFBTemplate.Parameters.SymDetail()
		assert.NoError(t, err)
		mode, err := symParms.Sym.Mode.AES()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgCFB, *mode)
	})
}

func TestKeyedHashTemplateAttributes(t *testing.T) {
	t.Run("has correct type", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgKeyedHash, KeyedHashTemplate.Type)
	})

	t.Run("has correct name algorithm", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgSHA256, KeyedHashTemplate.NameAlg)
	})

	t.Run("has FixedTPM attribute", func(t *testing.T) {
		assert.True(t, KeyedHashTemplate.ObjectAttributes.FixedTPM)
	})

	t.Run("has FixedParent attribute", func(t *testing.T) {
		assert.True(t, KeyedHashTemplate.ObjectAttributes.FixedParent)
	})

	t.Run("has UserWithAuth attribute", func(t *testing.T) {
		assert.True(t, KeyedHashTemplate.ObjectAttributes.UserWithAuth)
	})

	t.Run("has empty auth policy", func(t *testing.T) {
		assert.Empty(t, KeyedHashTemplate.AuthPolicy.Buffer)
	})
}

func TestTemplateAttributeModificationExtended(t *testing.T) {
	t.Run("can modify auth policy on RSA template", func(t *testing.T) {
		template := RSASSATemplate
		policyDigest := tpm2.TPM2BDigest{
			Buffer: []byte{0x01, 0x02, 0x03, 0x04},
		}
		template.AuthPolicy = policyDigest
		assert.Equal(t, policyDigest.Buffer, template.AuthPolicy.Buffer)
	})

	t.Run("can modify NoDA attribute", func(t *testing.T) {
		template := RSASSATemplate
		template.ObjectAttributes.NoDA = true
		assert.True(t, template.ObjectAttributes.NoDA)
	})

	t.Run("can set AdminWithPolicy attribute", func(t *testing.T) {
		template := RSASSAIDevIDTemplate
		template.ObjectAttributes.AdminWithPolicy = true
		assert.True(t, template.ObjectAttributes.AdminWithPolicy)
	})

	t.Run("can change name algorithm", func(t *testing.T) {
		template := RSASSATemplate
		template.NameAlg = tpm2.TPMAlgSHA384
		assert.Equal(t, tpm2.TPMAlgSHA384, template.NameAlg)
	})
}

func TestTemplateConsistencyChecks(t *testing.T) {
	t.Run("all AK templates are restricted", func(t *testing.T) {
		assert.True(t, RSASSAAKTemplate.ObjectAttributes.Restricted)
		assert.True(t, RSAPSSAKTemplate.ObjectAttributes.Restricted)
		assert.True(t, ECCAKP256Template.ObjectAttributes.Restricted)
	})

	t.Run("all IDevID templates are not restricted", func(t *testing.T) {
		assert.False(t, RSASSAIDevIDTemplate.ObjectAttributes.Restricted)
		assert.False(t, RSAPSSIDevIDTemplate.ObjectAttributes.Restricted)
		assert.False(t, ECCIDevIDP256Template.ObjectAttributes.Restricted)
	})

	t.Run("all signing templates have SignEncrypt set", func(t *testing.T) {
		assert.True(t, RSASSATemplate.ObjectAttributes.SignEncrypt)
		assert.True(t, RSAPSSTemplate.ObjectAttributes.SignEncrypt)
		assert.True(t, ECCP256Template.ObjectAttributes.SignEncrypt)
		assert.True(t, RSASSAAKTemplate.ObjectAttributes.SignEncrypt)
		assert.True(t, RSAPSSAKTemplate.ObjectAttributes.SignEncrypt)
		assert.True(t, ECCAKP256Template.ObjectAttributes.SignEncrypt)
		assert.True(t, RSASSAIDevIDTemplate.ObjectAttributes.SignEncrypt)
		assert.True(t, RSAPSSIDevIDTemplate.ObjectAttributes.SignEncrypt)
		assert.True(t, ECCIDevIDP256Template.ObjectAttributes.SignEncrypt)
	})

	t.Run("all templates have FixedTPM set", func(t *testing.T) {
		assert.True(t, RSASSATemplate.ObjectAttributes.FixedTPM)
		assert.True(t, RSAPSSTemplate.ObjectAttributes.FixedTPM)
		assert.True(t, ECCP256Template.ObjectAttributes.FixedTPM)
		assert.True(t, ECCP384Template.ObjectAttributes.FixedTPM)
		assert.True(t, ECCP521Template.ObjectAttributes.FixedTPM)
		assert.True(t, RSASSAAKTemplate.ObjectAttributes.FixedTPM)
		assert.True(t, RSAPSSAKTemplate.ObjectAttributes.FixedTPM)
		assert.True(t, ECCAKP256Template.ObjectAttributes.FixedTPM)
		assert.True(t, AES128CFBTemplate.ObjectAttributes.FixedTPM)
		assert.True(t, AES256CFBTemplate.ObjectAttributes.FixedTPM)
		assert.True(t, KeyedHashTemplate.ObjectAttributes.FixedTPM)
	})

	t.Run("all templates have UserWithAuth set", func(t *testing.T) {
		assert.True(t, RSASSATemplate.ObjectAttributes.UserWithAuth)
		assert.True(t, RSAPSSTemplate.ObjectAttributes.UserWithAuth)
		assert.True(t, ECCP256Template.ObjectAttributes.UserWithAuth)
		assert.True(t, ECCP384Template.ObjectAttributes.UserWithAuth)
		assert.True(t, ECCP521Template.ObjectAttributes.UserWithAuth)
		assert.True(t, RSASSAAKTemplate.ObjectAttributes.UserWithAuth)
		assert.True(t, RSAPSSAKTemplate.ObjectAttributes.UserWithAuth)
		assert.True(t, ECCAKP256Template.ObjectAttributes.UserWithAuth)
	})
}
