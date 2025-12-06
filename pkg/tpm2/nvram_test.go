package tpm2

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestNVWithAuthNoPolicy(t *testing.T) {

	encryptOpts := map[string]bool{
		"withEncryption":    true,
		"withoutEncryption": false,
	}

	policyOpts := map[string]bool{
		"withPolicy":    true,
		"withoutPolicy": false,
	}

	for _, encryptOpt := range encryptOpts {

		for _, policyOpt := range policyOpts {

			_, tpm := createSim(encryptOpt, false)

			userPIN := store.NewClearPassword([]byte("user-pin"))
			secret := []byte("secret")

			ekAttrs, err := tpm.EKAttributes()
			assert.Nil(t, err)

			oldHierarchyAuth := ekAttrs.TPMAttributes.HierarchyAuth

			// Change the hierarchy authorization passwords to user-pin
			err = tpm.SetHierarchyAuth(oldHierarchyAuth, userPIN, nil)
			assert.Nil(t, err)

			ekAttrs.TPMAttributes.HierarchyAuth = userPIN

			keyAttrs := &types.KeyAttributes{
				Parent:         ekAttrs,
				Password:       store.NewClearPassword([]byte("test")),
				PlatformPolicy: policyOpt,
				SealData:       types.NewSealData(secret),
				TPMAttributes: &types.TPMAttributes{
					Handle:        tpm2.TPMHandle(nvramOwnerIndex),
					HashAlg:       tpm2.TPMAlgSHA256,
					Hierarchy:     tpm2.TPMRHOwner,
					HierarchyAuth: userPIN,
				},
			}

			// providing valid auth - should work
			err = tpm.NVWrite(keyAttrs)
			assert.Nil(t, err)

			// correct auth, no PCR policy - should work
			dataSize := uint16(len(secret))
			nvSecret, err := tpm.NVRead(keyAttrs, dataSize)
			assert.Nil(t, err)
			assert.NotNil(t, nvSecret)
			assert.Equal(t, secret, nvSecret)

			// providing invalid hierarchy auth - should fail
			keyAttrs.Parent.TPMAttributes.HierarchyAuth = store.NewClearPassword([]byte("test"))
			err = tpm.NVWrite(keyAttrs)
			assert.NotNil(t, err)

			// // providing invalid key auth - should fail
			// keyAttrs.Password = store.NewClearPassword([]byte{})
			// err = tpm.NVWrite(keyAttrs)
			// assert.NotNil(t, err)

			keyAttrs.Parent.TPMAttributes.HierarchyAuth = userPIN
			keyAttrs.Password = store.NewClearPassword([]byte{})
			if policyOpt {

				// invalid key auth with platform policy - should succeed
				nvSecret, err = tpm.NVRead(keyAttrs, dataSize)
				assert.Nil(t, err)
				assert.NotNil(t, nvSecret)
			}

			_ = tpm.Close()
		}
	}
}
