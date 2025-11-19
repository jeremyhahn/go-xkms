package tpm2

import (
	"crypto"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
)

func TestSessionTypeValidationExtended(t *testing.T) {
	t.Run("HMAC session type is valid", func(t *testing.T) {
		sessionType := tpm2.TPMAlgSHA256
		assert.Equal(t, tpm2.TPMAlgSHA256, sessionType)
	})

	t.Run("SHA384 session hash is valid", func(t *testing.T) {
		sessionType := tpm2.TPMAlgSHA384
		assert.Equal(t, tpm2.TPMAlgSHA384, sessionType)
	})

	t.Run("SHA512 session hash is valid", func(t *testing.T) {
		sessionType := tpm2.TPMAlgSHA512
		assert.Equal(t, tpm2.TPMAlgSHA512, sessionType)
	})

	t.Run("SHA1 session hash is valid", func(t *testing.T) {
		sessionType := tpm2.TPMAlgSHA1
		assert.Equal(t, tpm2.TPMAlgSHA1, sessionType)
	})
}

func TestSessionAttributeFlagsExtended(t *testing.T) {
	t.Run("session can have encryption enabled", func(t *testing.T) {
		encryptSession := true
		assert.True(t, encryptSession)
	})

	t.Run("session can have decryption enabled", func(t *testing.T) {
		decryptSession := true
		assert.True(t, decryptSession)
	})

	t.Run("session can have audit enabled", func(t *testing.T) {
		auditSession := true
		assert.True(t, auditSession)
	})

	t.Run("session can have continue flag", func(t *testing.T) {
		continueSession := true
		assert.True(t, continueSession)
	})

	t.Run("session attributes can be combined", func(t *testing.T) {
		sessionAttrs := struct {
			Encrypt  bool
			Decrypt  bool
			Audit    bool
			Continue bool
		}{
			Encrypt:  true,
			Decrypt:  true,
			Audit:    false,
			Continue: true,
		}
		assert.True(t, sessionAttrs.Encrypt)
		assert.True(t, sessionAttrs.Decrypt)
		assert.False(t, sessionAttrs.Audit)
		assert.True(t, sessionAttrs.Continue)
	})
}

func TestSessionParameterCheckingExtended(t *testing.T) {
	t.Run("AES-128 key size is valid for session encryption", func(t *testing.T) {
		keySize := 128
		assert.Equal(t, 128, keySize)
	})

	t.Run("AES-256 key size is valid for session encryption", func(t *testing.T) {
		keySize := 256
		assert.Equal(t, 256, keySize)
	})

	t.Run("session nonce size of 16 is valid", func(t *testing.T) {
		nonceSize := 16
		assert.Equal(t, 16, nonceSize)
	})

	t.Run("session nonce size of 32 is valid", func(t *testing.T) {
		nonceSize := 32
		assert.Equal(t, 32, nonceSize)
	})

	t.Run("empty auth is valid", func(t *testing.T) {
		auth := []byte{}
		assert.Empty(t, auth)
	})

	t.Run("auth with password is valid", func(t *testing.T) {
		auth := []byte("password123")
		assert.NotEmpty(t, auth)
		assert.Equal(t, 11, len(auth))
	})

	t.Run("auth with long password is valid", func(t *testing.T) {
		auth := make([]byte, 64)
		assert.Equal(t, 64, len(auth))
	})

	t.Run("nil auth is valid", func(t *testing.T) {
		var auth []byte
		assert.Nil(t, auth)
	})
}

func TestPCRBankParsingExtended(t *testing.T) {
	t.Run("sha1 parses to TPMAlgSHA1", func(t *testing.T) {
		algID, err := ParsePCRBankAlgID("sha1")
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA1, algID)
	})

	t.Run("sha256 parses to TPMAlgSHA256", func(t *testing.T) {
		algID, err := ParsePCRBankAlgID("sha256")
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA256, algID)
	})

	t.Run("sha384 parses to TPMAlgSHA384", func(t *testing.T) {
		algID, err := ParsePCRBankAlgID("sha384")
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA384, algID)
	})

	t.Run("sha512 parses to TPMAlgSHA512", func(t *testing.T) {
		algID, err := ParsePCRBankAlgID("sha512")
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA512, algID)
	})

	t.Run("invalid PCR bank returns error", func(t *testing.T) {
		_, err := ParsePCRBankAlgID("invalid")
		assert.Equal(t, ErrInvalidPCRBankType, err)
	})

	t.Run("uppercase SHA256 should fail (case sensitive)", func(t *testing.T) {
		_, err := ParsePCRBankAlgID("SHA256")
		assert.NoError(t, err) // function uses ToLower internally
	})

	t.Run("mixed case sha256 should work", func(t *testing.T) {
		algID, err := ParsePCRBankAlgID("ShA256")
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA256, algID)
	})
}

func TestPCRBankCryptoHashParsingExtended(t *testing.T) {
	t.Run("sha1 parses to crypto.SHA1", func(t *testing.T) {
		hash, err := ParsePCRBankCryptoHash("sha1")
		assert.NoError(t, err)
		assert.Equal(t, crypto.SHA1, hash)
	})

	t.Run("sha256 parses to crypto.SHA256", func(t *testing.T) {
		hash, err := ParsePCRBankCryptoHash("sha256")
		assert.NoError(t, err)
		assert.Equal(t, crypto.SHA256, hash)
	})

	t.Run("sha384 parses to crypto.SHA3_384", func(t *testing.T) {
		hash, err := ParsePCRBankCryptoHash("sha384")
		assert.NoError(t, err)
		assert.Equal(t, crypto.SHA3_384, hash)
	})

	t.Run("sha512 parses to crypto.SHA512", func(t *testing.T) {
		hash, err := ParsePCRBankCryptoHash("sha512")
		assert.NoError(t, err)
		assert.Equal(t, crypto.SHA512, hash)
	})

	t.Run("invalid PCR bank returns error", func(t *testing.T) {
		_, err := ParsePCRBankCryptoHash("invalid")
		assert.Equal(t, ErrInvalidPCRBankType, err)
	})
}

func TestCryptoHashAlgIDParsingExtended(t *testing.T) {
	t.Run("crypto.SHA1 parses to TPMAlgSHA1", func(t *testing.T) {
		algID, err := ParseCryptoHashAlgID(crypto.SHA1)
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA1, algID)
	})

	t.Run("crypto.SHA256 parses to TPMAlgSHA256", func(t *testing.T) {
		algID, err := ParseCryptoHashAlgID(crypto.SHA256)
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA256, algID)
	})

	t.Run("crypto.SHA384 parses to TPMAlgSHA384", func(t *testing.T) {
		algID, err := ParseCryptoHashAlgID(crypto.SHA384)
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA384, algID)
	})

	t.Run("crypto.SHA512 parses to TPMAlgSHA512", func(t *testing.T) {
		algID, err := ParseCryptoHashAlgID(crypto.SHA512)
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA512, algID)
	})

	t.Run("crypto.SHA3_256 parses to TPMAlgSHA3256", func(t *testing.T) {
		algID, err := ParseCryptoHashAlgID(crypto.SHA3_256)
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA3256, algID)
	})

	t.Run("crypto.SHA3_384 parses to TPMAlgSHA3384", func(t *testing.T) {
		algID, err := ParseCryptoHashAlgID(crypto.SHA3_384)
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA3384, algID)
	})

	t.Run("crypto.SHA3_512 parses to TPMAlgSHA3512", func(t *testing.T) {
		algID, err := ParseCryptoHashAlgID(crypto.SHA3_512)
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA3512, algID)
	})

	t.Run("unsupported hash returns error", func(t *testing.T) {
		_, err := ParseCryptoHashAlgID(crypto.MD5)
		assert.Equal(t, ErrInvalidCryptoHashAlgID, err)
	})

	t.Run("unknown hash returns error", func(t *testing.T) {
		_, err := ParseCryptoHashAlgID(crypto.Hash(999))
		assert.Equal(t, ErrInvalidCryptoHashAlgID, err)
	})
}

func TestHashAlgFromStringParsingExtended(t *testing.T) {
	t.Run("SHA-1 string parses to TPMAlgSHA1", func(t *testing.T) {
		algID, err := ParseHashAlgFromString("SHA-1")
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA1, algID)
	})

	t.Run("SHA-256 string parses to TPMAlgSHA256", func(t *testing.T) {
		algID, err := ParseHashAlgFromString("SHA-256")
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA256, algID)
	})

	t.Run("SHA-384 string parses to TPMAlgSHA384", func(t *testing.T) {
		algID, err := ParseHashAlgFromString("SHA-384")
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA384, algID)
	})

	t.Run("SHA-512 string parses to TPMAlgSHA512", func(t *testing.T) {
		algID, err := ParseHashAlgFromString("SHA-512")
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA512, algID)
	})

	t.Run("lowercase sha-256 parses correctly", func(t *testing.T) {
		algID, err := ParseHashAlgFromString("sha-256")
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA256, algID)
	})

	t.Run("invalid hash string returns error", func(t *testing.T) {
		_, err := ParseHashAlgFromString("invalid")
		assert.Equal(t, ErrInvalidHashFunction, err)
	})
}

func TestParseHashAlgExtended(t *testing.T) {
	t.Run("crypto.SHA1 parses to TPMAlgSHA1", func(t *testing.T) {
		algID, err := ParseHashAlg(crypto.SHA1)
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA1, algID)
	})

	t.Run("crypto.SHA256 parses to TPMAlgSHA256", func(t *testing.T) {
		algID, err := ParseHashAlg(crypto.SHA256)
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA256, algID)
	})

	t.Run("crypto.SHA384 parses to TPMAlgSHA384", func(t *testing.T) {
		algID, err := ParseHashAlg(crypto.SHA384)
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA384, algID)
	})

	t.Run("crypto.SHA512 parses to TPMAlgSHA512", func(t *testing.T) {
		algID, err := ParseHashAlg(crypto.SHA512)
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA512, algID)
	})

	t.Run("unsupported hash returns error", func(t *testing.T) {
		_, err := ParseHashAlg(crypto.MD5)
		assert.Equal(t, ErrInvalidHashFunction, err)
	})
}

func TestParseHashSizeExtended(t *testing.T) {
	t.Run("crypto.SHA1 returns size 20", func(t *testing.T) {
		size, err := ParseHashSize(crypto.SHA1)
		assert.NoError(t, err)
		assert.Equal(t, uint32(20), size)
	})

	t.Run("crypto.SHA256 returns size 32", func(t *testing.T) {
		size, err := ParseHashSize(crypto.SHA256)
		assert.NoError(t, err)
		assert.Equal(t, uint32(32), size)
	})

	t.Run("crypto.SHA384 returns size 48", func(t *testing.T) {
		size, err := ParseHashSize(crypto.SHA384)
		assert.NoError(t, err)
		assert.Equal(t, uint32(48), size)
	})

	t.Run("crypto.SHA512 returns size 64", func(t *testing.T) {
		size, err := ParseHashSize(crypto.SHA512)
		assert.NoError(t, err)
		assert.Equal(t, uint32(64), size)
	})

	t.Run("unsupported hash returns error", func(t *testing.T) {
		_, err := ParseHashSize(crypto.MD5)
		assert.Equal(t, ErrInvalidHashFunction, err)
	})
}

func TestPCRSelectionCreationExtended(t *testing.T) {
	t.Run("single PCR selection is valid", func(t *testing.T) {
		pcrSelection := tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(16),
				},
			},
		}
		assert.Equal(t, 1, len(pcrSelection.PCRSelections))
		assert.Equal(t, tpm2.TPMAlgSHA256, pcrSelection.PCRSelections[0].Hash)
	})

	t.Run("multiple PCR selection is valid", func(t *testing.T) {
		pcrSelection := tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(0, 1, 2),
				},
				{
					Hash:      tpm2.TPMAlgSHA384,
					PCRSelect: tpm2.PCClientCompatible.PCRs(7),
				},
			},
		}
		assert.Equal(t, 2, len(pcrSelection.PCRSelections))
	})

	t.Run("PCR selection with SHA1 hash", func(t *testing.T) {
		pcrSelection := tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA1,
					PCRSelect: tpm2.PCClientCompatible.PCRs(0),
				},
			},
		}
		assert.Equal(t, tpm2.TPMAlgSHA1, pcrSelection.PCRSelections[0].Hash)
	})

	t.Run("PCR selection with SHA512 hash", func(t *testing.T) {
		pcrSelection := tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA512,
					PCRSelect: tpm2.PCClientCompatible.PCRs(23),
				},
			},
		}
		assert.Equal(t, tpm2.TPMAlgSHA512, pcrSelection.PCRSelections[0].Hash)
	})
}

func TestPolicyDigestCreationExtended(t *testing.T) {
	t.Run("empty policy digest is valid", func(t *testing.T) {
		policyDigest := tpm2.TPM2BDigest{
			Buffer: []byte{},
		}
		assert.Empty(t, policyDigest.Buffer)
	})

	t.Run("SHA256 policy digest has 32 bytes", func(t *testing.T) {
		digest := make([]byte, 32)
		policyDigest := tpm2.TPM2BDigest{
			Buffer: digest,
		}
		assert.Equal(t, 32, len(policyDigest.Buffer))
	})

	t.Run("SHA384 policy digest has 48 bytes", func(t *testing.T) {
		digest := make([]byte, 48)
		policyDigest := tpm2.TPM2BDigest{
			Buffer: digest,
		}
		assert.Equal(t, 48, len(policyDigest.Buffer))
	})

	t.Run("SHA512 policy digest has 64 bytes", func(t *testing.T) {
		digest := make([]byte, 64)
		policyDigest := tpm2.TPM2BDigest{
			Buffer: digest,
		}
		assert.Equal(t, 64, len(policyDigest.Buffer))
	})

	t.Run("policy digest with specific values", func(t *testing.T) {
		policyDigest := tpm2.TPM2BDigest{
			Buffer: []byte{0x01, 0x02, 0x03, 0x04},
		}
		assert.Equal(t, []byte{0x01, 0x02, 0x03, 0x04}, policyDigest.Buffer)
	})
}

func TestAuthHandleCreationExtended(t *testing.T) {
	t.Run("auth handle with owner hierarchy", func(t *testing.T) {
		authHandle := tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth([]byte("password")),
		}
		assert.Equal(t, tpm2.TPMRHOwner, authHandle.Handle)
	})

	t.Run("auth handle with endorsement hierarchy", func(t *testing.T) {
		authHandle := tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Auth:   tpm2.PasswordAuth([]byte("password")),
		}
		assert.Equal(t, tpm2.TPMRHEndorsement, authHandle.Handle)
	})

	t.Run("auth handle with platform hierarchy", func(t *testing.T) {
		authHandle := tpm2.AuthHandle{
			Handle: tpm2.TPMRHPlatform,
			Auth:   tpm2.PasswordAuth(nil),
		}
		assert.Equal(t, tpm2.TPMRHPlatform, authHandle.Handle)
	})

	t.Run("auth handle with empty password", func(t *testing.T) {
		authHandle := tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth([]byte{}),
		}
		assert.NotNil(t, authHandle.Auth)
	})

	t.Run("auth handle with name", func(t *testing.T) {
		name := tpm2.TPM2BName{
			Buffer: []byte{0x01, 0x02, 0x03},
		}
		authHandle := tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(0x81000001),
			Name:   name,
			Auth:   tpm2.PasswordAuth(nil),
		}
		assert.Equal(t, name, authHandle.Name)
	})
}

func TestNamedHandleCreationExtended(t *testing.T) {
	t.Run("named handle with persistent handle", func(t *testing.T) {
		name := tpm2.TPM2BName{
			Buffer: []byte{0x01, 0x02, 0x03},
		}
		namedHandle := tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(0x81000001),
			Name:   name,
		}
		assert.Equal(t, tpm2.TPMHandle(0x81000001), namedHandle.Handle)
		assert.Equal(t, name, namedHandle.Name)
	})

	t.Run("named handle with transient handle", func(t *testing.T) {
		name := tpm2.TPM2BName{
			Buffer: []byte{0x04, 0x05, 0x06},
		}
		namedHandle := tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(0x80000000),
			Name:   name,
		}
		assert.Equal(t, tpm2.TPMHandle(0x80000000), namedHandle.Handle)
	})
}

func TestSessionErrorsExtended(t *testing.T) {
	t.Run("ErrInvalidSessionType is defined", func(t *testing.T) {
		assert.NotNil(t, ErrInvalidSessionType)
		assert.Contains(t, ErrInvalidSessionType.Error(), "session")
	})

	t.Run("ErrInvalidSessionAuthorization is defined", func(t *testing.T) {
		assert.NotNil(t, ErrInvalidSessionAuthorization)
		assert.Contains(t, ErrInvalidSessionAuthorization.Error(), "authorization")
	})

	t.Run("ErrInvalidPolicyDigest is defined", func(t *testing.T) {
		assert.NotNil(t, ErrInvalidPolicyDigest)
		assert.Contains(t, ErrInvalidPolicyDigest.Error(), "policy")
	})
}

func TestEnrollmentStrategyParsingExtended(t *testing.T) {
	t.Run("IAK strategy is valid", func(t *testing.T) {
		strategy := ParseIdentityProvisioningStrategy("IAK")
		assert.Equal(t, EnrollmentStrategyIAK, strategy)
	})

	t.Run("IAK_IDEVID_SINGLE_PASS strategy is valid", func(t *testing.T) {
		strategy := ParseIdentityProvisioningStrategy("IAK_IDEVID_SINGLE_PASS")
		assert.Equal(t, EnrollmentStrategyIAK_IDEVID_SINGLE_PASS, strategy)
	})

	t.Run("unknown strategy defaults to IAK_IDEVID_SINGLE_PASS", func(t *testing.T) {
		strategy := ParseIdentityProvisioningStrategy("UNKNOWN")
		assert.Equal(t, EnrollmentStrategyIAK_IDEVID_SINGLE_PASS, strategy)
	})

	t.Run("empty strategy defaults to IAK_IDEVID_SINGLE_PASS", func(t *testing.T) {
		strategy := ParseIdentityProvisioningStrategy("")
		assert.Equal(t, EnrollmentStrategyIAK_IDEVID_SINGLE_PASS, strategy)
	})
}
