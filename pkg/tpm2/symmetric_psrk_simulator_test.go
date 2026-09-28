//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"crypto/x509"
	"encoding/binary"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

// psrkSymmetricAttrs returns the attributes of an AES-256-GCM key named cn
// sealed under parent.
func psrkSymmetricAttrs(cn string, parent *types.KeyAttributes) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:                 cn,
		KeyAlgorithm:       x509.PublicKeyAlgorithm(0),
		Parent:             parent,
		StoreType:          types.StoreTPM2,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
}

// withParent returns a copy of attrs whose parent is a copy of parent
// presenting password (nil for none).
func withParent(attrs, parent *types.KeyAttributes, password []byte) *types.KeyAttributes {
	p := *parent
	p.Password = nil
	if password != nil {
		p.Password = mustPassword(password)
	}
	a := *attrs
	a.Parent = &p
	return &a
}

// requireSymmetricRoundTrip encrypts and decrypts through the key attrs
// names, proving the sealed key loads and unseals under attrs.Parent.
func requireSymmetricRoundTrip(t *testing.T, h *simHarness, attrs *types.KeyAttributes) {
	t.Helper()
	encrypter, err := h.TPM.SymmetricEncrypter(attrs)
	require.NoError(t, err)
	plaintext := []byte("symmetric key sealed under the Platform SRK")
	encrypted, err := encrypter.Encrypt(plaintext, nil)
	require.NoError(t, err)
	decrypted, err := encrypter.Decrypt(encrypted, nil)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

// requireSymmetricLoadFails proves the key attrs names cannot be used: the
// encrypter is handed out (it only reads the public blob), but its first
// Encrypt must be refused by the TPM with want.
func requireSymmetricLoadFails(t *testing.T, h *simHarness, attrs *types.KeyAttributes, want tpm2.TPMRC) {
	t.Helper()
	encrypter, err := h.TPM.SymmetricEncrypter(attrs)
	require.NoError(t, err)
	_, err = encrypter.Encrypt([]byte("must not encrypt"), nil)
	require.ErrorIs(t, err, want)
	resetDALockout(t, h)
}

// resetDALockout clears the dictionary-attack failure count a refused
// authorization adds. Neither the Platform SRK nor the key object is NoDA, so
// every refusal counts, and the simulator locks out after a few; each refusal
// here must be refused for its own reason, not for an earlier one's lockout.
func resetDALockout(t *testing.T, h *simHarness) {
	t.Helper()
	require.NoError(t, h.TPM.DictionaryAttackLockoutReset(nil))
}

// requireParentHandle fails unless every command with code cc names want as
// its first (parent) handle.
func (c *busCapture) requireParentHandle(t *testing.T, cc tpm2.TPMCC, want tpm2.TPMHandle) {
	t.Helper()
	cmds := c.commands(cc)
	require.NotEmptyf(t, cmds, "expected at least one command 0x%x", uint32(cc))
	for _, cmd := range cmds {
		require.Equalf(t, uint32(want), binary.BigEndian.Uint32(cmd[10:14]),
			"command 0x%x is parented on 0x%x, want the Platform SRK 0x%x",
			uint32(cc), binary.BigEndian.Uint32(cmd[10:14]), uint32(want))
	}
}

// TestSymmetricKeyPSRK_UserPIN seals a symmetric key under a Platform SRK
// authorized by its USER PIN alone and proves that the key is created and
// loaded under the Platform SRK, that it round-trips with the PIN, that it
// cannot be used without the PIN or with a wrong one, and that neither the
// AES key nor the PIN ever crosses the TPM bus in plaintext.
func TestSymmetricKeyPSRK_UserPIN(t *testing.T) {
	h := newSimHarness(t, func(c *Config) { c.PlatformSRK.PlatformPolicy = false })
	userPIN := []byte("user-pin-9e4b17c2d0")
	psrk := createPSRK(t, h, []byte("so-pin-41f7a0c3e9"), userPIN)
	attrs := psrkSymmetricAttrs("psrk-symmetric-user-pin", psrk)

	bus := capture(h)
	_, err := h.TPM.GenerateSymmetricKey(attrs)
	require.NoError(t, err)
	requireSymmetricRoundTrip(t, h, attrs)
	material, err := (&tpm2AESEncrypter{tpm: h.TPM, attrs: attrs}).loadKeyMaterial()
	require.NoError(t, err)
	require.Len(t, material, 32)

	bus.requireAbsent(t, "the AES key", material)
	bus.requireAbsent(t, "the USER PIN", userPIN)
	bus.requireParentHandle(t, tpm2.TPMCCCreate, platformSRKHandle(h.TPM.config))
	bus.requireParentHandle(t, tpm2.TPMCCLoad, platformSRKHandle(h.TPM.config))
	bus.requireSessionAttr(t, tpm2.TPMCCCreate, sessionAttrDecrypt)
	bus.requireSessionAttr(t, tpm2.TPMCCUnseal, sessionAttrEncrypt)
	bus.requireSaltedAuthorization(t, tpm2.TPMCCCreate)
	bus.requireSaltedAuthorization(t, tpm2.TPMCCLoad)
	bus.requireAllSessionsSalted(t)

	t.Run("the key object has DA protection", func(t *testing.T) {
		pubBlob, err := h.Backend.Get(attrs, store.FSEXT_PUBLIC_BLOB)
		require.NoError(t, err)
		pub2B := tpm2.BytesAs2B[tpm2.TPMTPublic](pubBlob)
		pub, err := pub2B.Contents()
		require.NoError(t, err)
		require.False(t, pub.ObjectAttributes.NoDA)
	})

	t.Run("without the PIN the key cannot be used", func(t *testing.T) {
		requireSymmetricLoadFails(t, h, withParent(attrs, psrk, nil), tpm2.TPMRCAuthFail)
	})

	t.Run("with a wrong PIN the key cannot be used", func(t *testing.T) {
		requireSymmetricLoadFails(t, h, withParent(attrs, psrk, []byte("user-pin-WRONG")), tpm2.TPMRCAuthFail)
	})

	t.Run("without the PIN no key can be created", func(t *testing.T) {
		noPIN := withParent(psrkSymmetricAttrs("psrk-symmetric-no-pin", psrk), psrk, nil)
		_, err := h.TPM.GenerateSymmetricKey(noPIN)
		require.ErrorIs(t, err, tpm2.TPMRCAuthFail)
		resetDALockout(t, h)
		_, err = h.Backend.Get(noPIN, store.FSEXT_PUBLIC_BLOB)
		require.Error(t, err, "a refused creation must not leave a blob behind")
	})

	t.Run("the key's own password authorizes its unseal", func(t *testing.T) {
		ownPIN := []byte("object-pin-2b6e0d9f1a")
		keyAttrs := psrkSymmetricAttrs("psrk-symmetric-object-pin", psrk)
		keyAttrs.Password = mustPassword(ownPIN)
		_, err := h.TPM.GenerateSymmetricKey(keyAttrs)
		require.NoError(t, err)
		requireSymmetricRoundTrip(t, h, keyAttrs)

		wrong := *keyAttrs
		wrong.Password = mustPassword([]byte("object-pin-WRONG"))
		requireSymmetricLoadFails(t, h, &wrong, tpm2.TPMRCAuthFail)
	})
}

// TestSymmetricKeyPSRK_PlatformPolicy seals a symmetric key under a Platform
// SRK carrying the platform policy and proves both of its branches: the PCR
// branch unlocks it with no PIN while the platform state is unchanged and
// refuses it once the platform PCR moves, and the USER PIN branch still
// unlocks it after that.
func TestSymmetricKeyPSRK_PlatformPolicy(t *testing.T) {
	h := newSimHarness(t, nil)
	userPIN := []byte("user-pin-6a0c3f82b5")
	psrk := createPSRK(t, h, []byte("so-pin-d93e1b07c4"), userPIN)
	pcrBranch := withParent(psrkSymmetricAttrs("psrk-symmetric-pcr", psrk), psrk, nil)

	bus := capture(h)
	_, err := h.TPM.GenerateSymmetricKey(pcrBranch)
	require.NoError(t, err)
	requireSymmetricRoundTrip(t, h, pcrBranch)
	material, err := (&tpm2AESEncrypter{tpm: h.TPM, attrs: pcrBranch}).loadKeyMaterial()
	require.NoError(t, err)

	bus.requireAbsent(t, "the AES key", material)
	bus.requireParentHandle(t, tpm2.TPMCCCreate, platformSRKHandle(h.TPM.config))
	bus.requireParentHandle(t, tpm2.TPMCCLoad, platformSRKHandle(h.TPM.config))
	bus.requireSessionAttr(t, tpm2.TPMCCUnseal, sessionAttrEncrypt)

	h.extendPlatformPCR(t, []byte("different boot measurement"))

	t.Run("the PCR branch refuses a changed platform", func(t *testing.T) {
		requireSymmetricLoadFails(t, h, pcrBranch, tpm2.TPMRCPolicyFail)
	})

	t.Run("the USER PIN branch survives a changed platform", func(t *testing.T) {
		requireSymmetricRoundTrip(t, h, withParent(pcrBranch, psrk, userPIN))
	})
}

// TestSymmetricKeyPSRK_RejectsSSRKParent proves a symmetric key cannot be
// parented on the Shared SRK: the TCG-default SSRK is never used for
// go-xkms's own secrets.
func TestSymmetricKeyPSRK_RejectsSSRKParent(t *testing.T) {
	h := newSimHarness(t, nil)
	ssrk, err := h.TPM.SSRKAttributes()
	require.NoError(t, err)
	attrs := psrkSymmetricAttrs("ssrk-symmetric", ssrk)

	_, err = h.TPM.GenerateSymmetricKey(attrs)
	require.ErrorIs(t, err, ErrSymmetricKeyParent)
	_, err = h.Backend.Get(attrs, store.FSEXT_PUBLIC_BLOB)
	require.Error(t, err, "a refused key must not be stored")

	_, err = (&tpm2AESEncrypter{tpm: h.TPM, attrs: attrs}).loadKeyMaterial()
	require.ErrorIs(t, err, ErrSymmetricKeyParent)
}

// writeLegacySymmetricBlob writes attrs to h's backend exactly as releases
// before the Platform SRK change (go-xkms#1148) did: a keyed-hash object
// created under the Shared SRK with no authorization and NoDA set, its
// private area saved to the pre-#1148 FSEXT_LEGACY_PRIVATE_BLOB (".priv")
// extension instead of FSEXT_PRIVATE_BLOB (".blob").
func writeLegacySymmetricBlob(t *testing.T, h *simHarness, attrs *types.KeyAttributes) {
	t.Helper()

	ssrkHandle := tpm2.TPMHandle(h.TPM.config.SSRK.Handle)
	ssrkName, _, err := h.TPM.ReadHandle(ssrkHandle)
	require.NoError(t, err)

	legacyTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:     true,
			FixedParent:  true,
			UserWithAuth: true,
			NoDA:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash,
			&tpm2.TPMSKeyedHashParms{Scheme: tpm2.TPMTKeyedHashScheme{Scheme: tpm2.TPMAlgNull}}),
	}
	created, err := tpm2.Create{
		ParentHandle: &tpm2.NamedHandle{Handle: ssrkHandle, Name: ssrkName},
		InPublic:     tpm2.New2B(legacyTemplate),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: make([]byte, 32)}),
			},
		},
	}.Execute(h.TPM.transport)
	require.NoError(t, err)

	require.NoError(t, h.Backend.Save(attrs, tpm2.Marshal(created.OutPrivate), store.FSEXT_LEGACY_PRIVATE_BLOB, false))
	require.NoError(t, h.Backend.Save(attrs, tpm2.Marshal(created.OutPublic), store.FSEXT_PUBLIC_BLOB, false))
}

// TestSymmetricKeyPSRK_RefusesUnprotectedBlob writes a key exactly as
// releases before the Platform SRK change did -- under the Shared SRK, with
// no authorization and NoDA -- and proves it is refused by name rather than
// loaded, and that the refusal names the on-disk file an operator must
// delete by hand (go-xkms#1168).
func TestSymmetricKeyPSRK_RefusesUnprotectedBlob(t *testing.T) {
	h := newSimHarness(t, nil)
	attrs := psrkSymmetricAttrs("pre-psrk-symmetric", nil)
	writeLegacySymmetricBlob(t, h, attrs)

	legacyFile := attrs.CN + string(store.FSEXT_LEGACY_PRIVATE_BLOB)

	_, err := h.TPM.GetSymmetricKey(attrs)
	require.ErrorIs(t, err, ErrUnprotectedSymmetricKey)
	require.ErrorContains(t, err, legacyFile)

	_, err = h.TPM.SymmetricEncrypter(attrs)
	require.ErrorIs(t, err, ErrUnprotectedSymmetricKey)
	require.ErrorContains(t, err, legacyFile)
}

// TestFileBackendDelete_RemovesLegacySymmetricPrivateBlob proves that
// deleting a pre-#1148 symmetric key removes its legacy ".priv" private
// blob along with the current-format files, rather than leaving the
// unprotected key material behind on disk (go-xkms#1168).
func TestFileBackendDelete_RemovesLegacySymmetricPrivateBlob(t *testing.T) {
	h := newSimHarness(t, nil)
	attrs := psrkSymmetricAttrs("pre-psrk-symmetric-delete", nil)
	writeLegacySymmetricBlob(t, h, attrs)

	// Both legacy files are present before deletion.
	_, err := h.Backend.Get(attrs, store.FSEXT_LEGACY_PRIVATE_BLOB)
	require.NoError(t, err)
	_, err = h.Backend.Get(attrs, store.FSEXT_PUBLIC_BLOB)
	require.NoError(t, err)

	require.NoError(t, h.TPM.DeleteKeyPair(attrs, h.Backend))

	_, err = h.Backend.Get(attrs, store.FSEXT_LEGACY_PRIVATE_BLOB)
	require.ErrorIs(t, err, storage.ErrNotFound, "the legacy .priv blob must be removed")
	_, err = h.Backend.Get(attrs, store.FSEXT_PUBLIC_BLOB)
	require.ErrorIs(t, err, storage.ErrNotFound, "the .pub file must be removed")
}

// TestFileBackendDelete_RemovesCurrentFormatSymmetricKey proves that
// deleting a symmetric key written in the current (post-#1148) format still
// works: adding FSEXT_LEGACY_PRIVATE_BLOB to the deletion list must not
// regress the normal delete path (go-xkms#1168).
func TestFileBackendDelete_RemovesCurrentFormatSymmetricKey(t *testing.T) {
	h := newSimHarness(t, nil)
	userPIN := []byte("user-pin-delete-normal")
	psrk := createPSRK(t, h, []byte("so-pin-delete-normal"), userPIN)
	attrs := psrkSymmetricAttrs("current-format-symmetric", psrk)

	_, err := h.TPM.GenerateSymmetricKey(attrs)
	require.NoError(t, err)

	_, err = h.Backend.Get(attrs, store.FSEXT_PRIVATE_BLOB)
	require.NoError(t, err)
	_, err = h.Backend.Get(attrs, store.FSEXT_PUBLIC_BLOB)
	require.NoError(t, err)

	require.NoError(t, h.TPM.DeleteKey(attrs, h.Backend))

	_, err = h.Backend.Get(attrs, store.FSEXT_PRIVATE_BLOB)
	require.ErrorIs(t, err, storage.ErrNotFound)
	_, err = h.Backend.Get(attrs, store.FSEXT_PUBLIC_BLOB)
	require.ErrorIs(t, err, storage.ErrNotFound)
}
