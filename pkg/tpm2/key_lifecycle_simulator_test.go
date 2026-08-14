//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file covers the EK / SRK / IAK / IDevID key lifecycle against the
// in-process go-tpm-tools simulator. Every test builds its own harness, and the
// harness owns exactly one simulator at a time -- the go-tpm-tools simulator is
// a process-global, mutex-guarded singleton, so holding two live simultaneously
// deadlocks the process.

// TestEK_MatchesPersistedEndorsementKey proves the cached EK accessors all
// describe the same key that is actually persisted at the configured handle.
// Three independent paths must agree: the PKIX-encoded bytes cached in the key
// attributes, the RSA parameters read live from the TPM, and the public area at
// the persistent handle. A regression in any one of them (stale cache, wrong
// handle, mis-parsed RSA modulus) breaks the agreement.
func TestEK_MatchesPersistedEndorsementKey(t *testing.T) {
	h := newSimHarness(t, nil)

	ekAttrs, err := h.TPM.EKAttributes()
	require.NoError(t, err)
	require.NotNil(t, ekAttrs.TPMAttributes)
	assert.Equal(t, tpm2.TPMHandle(h.TPM.config.EK.Handle), ekAttrs.TPMAttributes.Handle,
		"the EK attributes must describe the configured persistent handle")

	ekAny, err := h.TPM.EK()
	require.NoError(t, err)
	ekPKIX, ok := ekAny.(*rsa.PublicKey)
	require.True(t, ok, "the configured EK is RSA, got %T", ekAny)

	ekRSA, err := h.TPM.EKRSA()
	require.NoError(t, err)
	assert.Equal(t, ekPKIX.N, ekRSA.N,
		"the PKIX-cached EK and the EK read live from the TPM must be the same key")
	assert.Equal(t, ekPKIX.E, ekRSA.E)
	assert.Equal(t, h.TPM.config.EK.RSAConfig.KeySize, ekRSA.N.BitLen(),
		"the EK must have the configured modulus size")

	// The public area at the persistent handle must carry the same modulus.
	name, pub, err := h.TPM.EKPublic()
	require.NoError(t, err)
	assert.NotEmpty(t, name.Buffer, "the EK must have a non-empty TPM name")
	rsaUnique, err := pub.Unique.RSA()
	require.NoError(t, err)
	assert.Equal(t, ekRSA.N.Bytes(), rsaUnique.Buffer,
		"the public area at the EK handle must hold the same modulus")
}

// TestEKRSA_CachesAcrossCalls proves the RSA public key is memoised rather than
// re-read from the TPM on every call, and that the cache returns the identical
// pointer. Re-deriving it per call would put an avoidable TPM round trip on
// every attestation.
func TestEKRSA_CachesAcrossCalls(t *testing.T) {
	h := newSimHarness(t, nil)

	first, err := h.TPM.EKRSA()
	require.NoError(t, err)
	second, err := h.TPM.EKRSA()
	require.NoError(t, err)
	assert.Same(t, first, second, "EKRSA must memoise the parsed public key")
}

// TestEKECC_RSAEndorsementKey_Rejected proves the ECC accessor refuses to
// misinterpret an RSA endorsement key. The harness provisions an RSA EK, so
// asking for ECC parameters must fail with the typed parse error rather than
// returning a zero-valued curve point that downstream code would treat as a
// real key.
func TestEKECC_RSAEndorsementKey_Rejected(t *testing.T) {
	h := newSimHarness(t, nil)

	eccPub, err := h.TPM.EKECC()
	require.Error(t, err, "an RSA EK has no ECC parameters")
	assert.Nil(t, eccPub)
	assert.ErrorIs(t, err, ErrEKECCParse)
}

// TestEK_NotInitialized_ReturnsTypedError covers the uninitialised contract of
// the cached public-key accessors. Callers distinguish "no EK provisioned yet"
// from "the TPM is broken" by these sentinels, so they must not collapse into a
// generic error.
func TestEK_NotInitialized_ReturnsTypedError(t *testing.T) {
	h := newSimHarness(t, nil)

	savedEK := h.TPM.ekAttrs
	h.TPM.ekAttrs = nil
	t.Cleanup(func() { h.TPM.ekAttrs = savedEK })

	pub, err := h.TPM.EK()
	assert.Nil(t, pub)
	assert.ErrorIs(t, err, ErrEKNotInitialized)

	savedIAK := h.TPM.iakAttrs
	h.TPM.iakAttrs = nil
	t.Cleanup(func() { h.TPM.iakAttrs = savedIAK })

	iak, err := h.TPM.IAK()
	assert.Nil(t, iak)
	assert.ErrorIs(t, err, ErrIAKNotInitialized)

	savedIDevID := h.TPM.idevidAttrs
	h.TPM.idevidAttrs = nil
	t.Cleanup(func() { h.TPM.idevidAttrs = savedIDevID })

	idevid, err := h.TPM.IDevID()
	assert.Nil(t, idevid)
	assert.ErrorIs(t, err, ErrIDevIDNotInitialized)
}

// TestEKPublic_NilEKConfig_ReturnsTypedError covers the misconfiguration path:
// a config with no EK section must be reported as such rather than reading
// handle 0.
func TestEKPublic_NilEKConfig_ReturnsTypedError(t *testing.T) {
	h := newSimHarness(t, nil)

	saved := h.TPM.config.EK
	h.TPM.config.EK = nil
	t.Cleanup(func() { h.TPM.config.EK = saved })

	_, _, err := h.TPM.EKPublic()
	assert.ErrorIs(t, err, ErrEKConfigNil)

	h.TPM.ekAttrs = nil
	t.Cleanup(func() { h.TPM.ekAttrs = nil })
	_, attrErr := h.TPM.EKAttributes()
	assert.ErrorIs(t, attrErr, ErrEKConfigNil)
}

// TestIAKAttributes_NilIAKConfig_ReturnsTypedError covers the same
// misconfiguration contract for the attestation key.
func TestIAKAttributes_NilIAKConfig_ReturnsTypedError(t *testing.T) {
	h := newSimHarness(t, nil)

	savedAttrs := h.TPM.iakAttrs
	savedCfg := h.TPM.config.IAK
	h.TPM.iakAttrs = nil
	h.TPM.config.IAK = nil
	t.Cleanup(func() {
		h.TPM.iakAttrs = savedAttrs
		h.TPM.config.IAK = savedCfg
	})

	attrs, err := h.TPM.IAKAttributes()
	assert.Nil(t, attrs)
	assert.ErrorIs(t, err, ErrIAKConfigNil)
}

// TestIDevIDAttributes_NilIDevIDConfig_ReturnsTypedError covers the IDevID
// misconfiguration contract. The harness enrols via the IAK strategy, so no
// IDevID is configured and the typed error is the correct answer.
func TestIDevIDAttributes_NilIDevIDConfig_ReturnsTypedError(t *testing.T) {
	h := newSimHarness(t, nil)

	require.Nil(t, h.TPM.config.IDevID,
		"precondition: the IAK enrollment strategy configures no IDevID")

	attrs, err := h.TPM.IDevIDAttributes()
	assert.Nil(t, attrs)
	assert.ErrorIs(t, err, ErrIDevIDConfigNil)
}

// TestSRKPublic_IsAliasOfSSRKPublic proves the interface-satisfying alias
// really forwards to the shared storage root key rather than reading a
// different handle. A divergence here would give the TrustedPlatformModule
// interface a different SRK than the concrete type uses internally.
func TestSRKPublic_IsAliasOfSSRKPublic(t *testing.T) {
	h := newSimHarness(t, nil)

	ssrkName, ssrkPub, err := h.TPM.SSRKPublic()
	require.NoError(t, err)
	srkName, srkPub, err := h.TPM.SRKPublic()
	require.NoError(t, err)

	assert.Equal(t, ssrkName.Buffer, srkName.Buffer,
		"SRKPublic must return the same key name as SSRKPublic")
	assert.Equal(t, ssrkPub.Type, srkPub.Type)

	ssrkUnique, err := ssrkPub.Unique.RSA()
	require.NoError(t, err)
	srkUnique, err := srkPub.Unique.RSA()
	require.NoError(t, err)
	assert.Equal(t, ssrkUnique.Buffer, srkUnique.Buffer,
		"SRKPublic must return the same public area as SSRKPublic")
}

// TestSSRKAttributes_DescribeConfiguredHandle proves the SRK attributes point
// at the configured persistent handle and carry a usable public area.
func TestSSRKAttributes_DescribeConfiguredHandle(t *testing.T) {
	h := newSimHarness(t, nil)

	srkAttrs, err := h.TPM.SSRKAttributes()
	require.NoError(t, err)
	require.NotNil(t, srkAttrs.TPMAttributes)

	assert.Equal(t, tpm2.TPMHandle(h.TPM.config.SSRK.Handle), srkAttrs.TPMAttributes.Handle,
		"the SRK attributes must describe the configured persistent handle")
	assert.NotEmpty(t, srkAttrs.TPMAttributes.Name.Buffer)

	// The handle must actually be readable on the TPM.
	name, _, err := h.TPM.ReadHandle(srkAttrs.TPMAttributes.Handle)
	require.NoError(t, err, "the configured SRK handle must be persistent on the TPM")
	assert.Equal(t, srkAttrs.TPMAttributes.Name.Buffer, name.Buffer)
}

// TestPlatformSRKAttributes_NotEnrolled_ReturnsError proves the platform SRK
// is NOT created by Provision(). It is enrolled separately, on first boot, by
// PlatformKeyStore.EnrollPlatformSRK. Asking for its attributes before that
// must fail rather than return attributes for an empty handle -- which would
// make a later seal silently target a non-existent parent.
func TestPlatformSRKAttributes_NotEnrolled_ReturnsError(t *testing.T) {
	h := newSimHarness(t, nil)

	require.NotNil(t, h.TPM.config.PlatformSRK,
		"precondition: the platform SRK is configured but not yet enrolled")

	_, _, readErr := h.TPM.ReadHandle(tpm2.TPMHandle(h.TPM.config.PlatformSRK.SRKHandle))
	require.Error(t, readErr,
		"precondition: Provision() must not have persisted the platform SRK")

	attrs, err := h.TPM.PlatformSRKAttributes()
	require.Error(t, err, "an un-enrolled platform SRK must not yield attributes")
	assert.Nil(t, attrs)
}

// TestPlatformSRKAttributes_NilConfig_ReturnsTypedError covers the
// misconfiguration contract for the platform SRK.
func TestPlatformSRKAttributes_NilConfig_ReturnsTypedError(t *testing.T) {
	h := newSimHarness(t, nil)

	saved := h.TPM.config.PlatformSRK
	h.TPM.config.PlatformSRK = nil
	h.TPM.platformSRKAttrs = nil
	t.Cleanup(func() { h.TPM.config.PlatformSRK = saved })

	attrs, err := h.TPM.PlatformSRKAttributes()
	assert.Nil(t, attrs)
	assert.ErrorIs(t, err, ErrInvalidPlatformSRKConfiguration)
}

// TestIAKAttributes_ParentIsEndorsementKey proves the attestation key is
// rooted under the EK, which is what lets a remote verifier tie an IAK
// attestation back to the endorsement hierarchy. A regression that left the
// parent unset would silently break credential activation.
func TestIAKAttributes_ParentIsEndorsementKey(t *testing.T) {
	h := newSimHarness(t, nil)

	iakAttrs, err := h.TPM.IAKAttributes()
	require.NoError(t, err)
	require.NotNil(t, iakAttrs.Parent, "the IAK must record its parent")

	ekAttrs, err := h.TPM.EKAttributes()
	require.NoError(t, err)
	assert.Equal(t, ekAttrs.TPMAttributes.Handle, iakAttrs.Parent.TPMAttributes.Handle,
		"the IAK's parent must be the endorsement key")
	assert.Equal(t, tpm2.TPMHandle(h.TPM.config.IAK.Handle), iakAttrs.TPMAttributes.Handle)

	// The signature algorithm must come from configuration, not a default.
	expected, err := types.ParseSignatureAlgorithm(h.TPM.config.IAK.SignatureAlgorithm)
	require.NoError(t, err)
	assert.Equal(t, expected, iakAttrs.SignatureAlgorithm)
}

// TestIAK_PublicKeyMatchesPersistedKey proves the cached IAK public key parses
// and matches the key actually persisted at the IAK handle.
func TestIAK_PublicKeyMatchesPersistedKey(t *testing.T) {
	h := newSimHarness(t, nil)

	iakAttrs, err := h.TPM.IAKAttributes()
	require.NoError(t, err)

	iakAny, err := h.TPM.IAK()
	require.NoError(t, err)
	iakRSA, ok := iakAny.(*rsa.PublicKey)
	require.True(t, ok, "the configured IAK is RSA, got %T", iakAny)

	_, pub, err := h.TPM.ReadHandle(iakAttrs.TPMAttributes.Handle)
	require.NoError(t, err)
	unique, err := pub.Unique.RSA()
	require.NoError(t, err)
	assert.Equal(t, iakRSA.N.Bytes(), unique.Buffer,
		"the cached IAK public key must match the key at the IAK handle")

	// It must also be a different key from the EK.
	ekRSA, err := h.TPM.EKRSA()
	require.NoError(t, err)
	assert.NotEqual(t, ekRSA.N, iakRSA.N, "the IAK must not be the EK")
}

// TestIAK_CorruptCachedPublicKeyBytes_ReturnsParseError proves a corrupted
// cache is reported rather than returned as a key. The accessor parses PKIX
// bytes on every call, so garbage in the cache must surface as the typed parse
// error.
func TestIAK_CorruptCachedPublicKeyBytes_ReturnsParseError(t *testing.T) {
	h := newSimHarness(t, nil)

	iakAttrs, err := h.TPM.IAKAttributes()
	require.NoError(t, err)

	saved := iakAttrs.TPMAttributes.PublicKeyBytes
	iakAttrs.TPMAttributes.PublicKeyBytes = []byte{0x30, 0x00, 0xFF, 0xFF}
	t.Cleanup(func() { iakAttrs.TPMAttributes.PublicKeyBytes = saved })

	pub, err := h.TPM.IAK()
	assert.Nil(t, pub)
	assert.ErrorIs(t, err, ErrIAKPublicParse)
}

// TestEK_CorruptCachedPublicKeyBytes_ReturnsParseError is the EK counterpart of
// the IAK corruption test.
func TestEK_CorruptCachedPublicKeyBytes_ReturnsParseError(t *testing.T) {
	h := newSimHarness(t, nil)

	ekAttrs, err := h.TPM.EKAttributes()
	require.NoError(t, err)

	saved := ekAttrs.TPMAttributes.PublicKeyBytes
	ekAttrs.TPMAttributes.PublicKeyBytes = []byte("not-a-pkix-public-key")
	t.Cleanup(func() { ekAttrs.TPMAttributes.PublicKeyBytes = saved })

	pub, err := h.TPM.EK()
	assert.Nil(t, pub)
	assert.ErrorIs(t, err, ErrEKNotInitialized)
}

// TestKeyAttributes_UnknownHandle_ReturnsError proves reading attributes for a
// handle that holds no object fails instead of returning zero-valued
// attributes that callers would treat as a real key.
func TestKeyAttributes_UnknownHandle_ReturnsError(t *testing.T) {
	h := newSimHarness(t, nil)

	// A persistent handle in the valid range that nothing was persisted at.
	attrs, err := h.TPM.KeyAttributes(tpm2.TPMHandle(0x81FF00FF))
	require.Error(t, err, "an empty persistent handle must not yield key attributes")
	assert.Nil(t, attrs)
}

// TestKeyAttributes_PersistedHandles_CarryPublicKeyBytes proves the generic
// attribute reader produces PKIX-parseable public key bytes for each key the
// provisioning flow persists. Downstream code (CSR generation, attestation,
// certificate issuance) depends on these bytes being valid PKIX.
func TestKeyAttributes_PersistedHandles_CarryPublicKeyBytes(t *testing.T) {
	h := newSimHarness(t, nil)

	// The platform SRK is deliberately absent: Provision() does not create it.
	// It is enrolled separately by PlatformKeyStore.EnrollPlatformSRK, covered
	// in platform_keystore_enroll_simulator_test.go.
	for name, handle := range map[string]uint32{
		"EK":   h.TPM.config.EK.Handle,
		"SSRK": h.TPM.config.SSRK.Handle,
		"IAK":  h.TPM.config.IAK.Handle,
	} {
		t.Run(name, func(t *testing.T) {
			attrs, err := h.TPM.KeyAttributes(tpm2.TPMHandle(handle))
			require.NoError(t, err, "%s must be persistent after provisioning", name)
			require.NotNil(t, attrs.TPMAttributes)

			require.NotEmpty(t, attrs.TPMAttributes.PublicKeyBytes,
				"%s must expose PKIX public key bytes", name)
			pub, err := x509.ParsePKIXPublicKey(attrs.TPMAttributes.PublicKeyBytes)
			require.NoError(t, err, "%s public key bytes must be valid PKIX", name)
			assert.NotNil(t, pub)

			assert.Equal(t, tpm2.TPMHandle(handle), attrs.TPMAttributes.Handle)
			assert.NotEmpty(t, attrs.TPMAttributes.Name.Buffer)
		})
	}
}

// TestSSRK_ReturnsConfiguredStorageRootKeyConfig proves the SSRK config
// accessor reports the configuration actually in force, and reports nil for a
// TPM with no configuration rather than panicking.
func TestSSRK_ReturnsConfiguredStorageRootKeyConfig(t *testing.T) {
	h := newSimHarness(t, nil)

	cfg := h.TPM.SSRK()
	require.NotNil(t, cfg)
	assert.Equal(t, h.TPM.config.SSRK.Handle, cfg.Handle,
		"SSRK must report the handle the SRK was actually persisted at")

	// The reported handle must be the one that is live on the TPM.
	_, _, err := h.TPM.ReadHandle(tpm2.TPMHandle(cfg.Handle))
	require.NoError(t, err)

	saved := h.TPM.config
	h.TPM.config = nil
	t.Cleanup(func() { h.TPM.config = saved })
	assert.Nil(t, h.TPM.SSRK(), "a TPM with no configuration must report no SRK config")
}
