//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestSealUnseal(t *testing.T) {

	encryptOpts := map[string]bool{
		"withEncryption":    true,
		"withoutEncryption": false,
	}

	policyOpts := map[string]bool{
		"withPolicy":    true,
		"withoutPolicy": false,
	}

	passwdOpts := map[string]bool{
		"withPassword":    true,
		"withoutPassword": false,
	}

	for _, encryptOpt := range encryptOpts {

		for _, policyOpt := range policyOpts {

			if policyOpt == false {

				for _, passwdOpt := range passwdOpts {

					logger, tpm := createSim(encryptOpt, policyOpt)

					ekAttrs, err := tpm.EKAttributes()
					assert.Nil(t, err)

					hierarchyAuth := ekAttrs.TPMAttributes.HierarchyAuth

					srkTemplate := tpm2.RSASRKTemplate
					srkTemplate.ObjectAttributes.NoDA = false

					var srkAuth types.Password
					var keyAuth types.Password
					if passwdOpt {
						srkAuth = mustPassword([]byte("srk-password"))
						keyAuth = mustPassword([]byte("key-password"))
					}

					srkAttrs := &types.KeyAttributes{
						CN:             "srk-with-policy",
						KeyAlgorithm:   x509.RSA,
						KeyType:        types.KeyTypeStorage,
						Password:       srkAuth,
						PlatformPolicy: policyOpt,
						StoreType:      types.StoreTPM2,
						TPMAttributes: &types.TPMAttributes{
							Handle:        keyStoreHandle,
							HandleType:    tpm2.TPMHTPersistent,
							Hierarchy:     tpm2.TPMRHOwner,
							HierarchyAuth: hierarchyAuth,
							Template:      srkTemplate,
						}}

					err = tpm.CreateSRK(srkAttrs)
					assert.Nil(t, err)

					keyAttrs := &types.KeyAttributes{
						CN:             "test",
						KeyAlgorithm:   x509.RSA,
						KeyType:        types.KeyTypeCA,
						Parent:         srkAttrs,
						Password:       keyAuth,
						PlatformPolicy: policyOpt,
						StoreType:      types.StoreTPM2,
						TPMAttributes: &types.TPMAttributes{
							Hierarchy: tpm2.TPMRHOwner,
						}}

					_, err = tpm.SealKey(keyAttrs, nil, false)
					assert.Nil(t, err)

					// Retrieve the AES-256 key protected
					// by the platform PCR session policy
					secret, err := tpm.UnsealKey(keyAttrs, nil)
					assert.Nil(t, err)
					assert.NotNil(t, secret)
					assert.Equal(t, 32, len(secret))

					// Print the secret and TPM handles
					logger.Debug(string(secret))

					if policyOpt {
						// Extend the PCR and read again - policy check should fail
						extendRandomBytes(tpm.Transport())
						secret2, err := tpm.UnsealKey(keyAttrs, nil)
						assert.NotNil(t, err)
						assert.Nil(t, secret2)
						assert.Equal(t, ErrPolicyCheckFailed, err)
					}

					// Close / reset the simulator between tests
					_ = tpm.Close()
				}
			}
		}
	}
}

func TestCreateKeyWithPolicy(t *testing.T) {

	encryptOpts := map[string]bool{
		"withEncryption":    true,
		"withoutEncryption": false,
	}

	passwdOpts := map[string]bool{
		"withPassword":    true,
		"withoutPassword": false,
	}

	for _, encryptOpt := range encryptOpts {

		for _, passwdOpt := range passwdOpts {

			_, tpm := createSim(encryptOpt, false)

			ekAttrs, err := tpm.EKAttributes()
			assert.Nil(t, err)

			hierarchyAuth := ekAttrs.TPMAttributes.HierarchyAuth

			srkTemplate := tpm2.RSASRKTemplate
			srkTemplate.ObjectAttributes.NoDA = false

			var srkAuth types.Password
			var keyAuth types.Password
			if passwdOpt {
				srkAuth = mustPassword([]byte("srk-password"))
				keyAuth = mustPassword([]byte("key-password"))
			}

			srkAttrs := &types.KeyAttributes{
				CN:             "srk-with-policy",
				KeyAlgorithm:   x509.RSA,
				KeyType:        types.KeyTypeStorage,
				Password:       srkAuth,
				PlatformPolicy: true,
				StoreType:      types.StoreTPM2,
				TPMAttributes: &types.TPMAttributes{
					Handle:        keyStoreHandle,
					HandleType:    tpm2.TPMHTPersistent,
					Hierarchy:     tpm2.TPMRHOwner,
					HierarchyAuth: hierarchyAuth,
					Template:      srkTemplate,
				}}

			err = tpm.CreateSRK(srkAttrs)
			assert.Nil(t, err)

			keyAttrs := &types.KeyAttributes{
				CN:             "test",
				KeyAlgorithm:   x509.RSA,
				KeyType:        types.KeyTypeCA,
				Parent:         srkAttrs,
				Password:       keyAuth,
				PlatformPolicy: true,
				StoreType:      types.StoreTPM2,
				TPMAttributes: &types.TPMAttributes{
					Hierarchy: tpm2.TPMRHOwner,
				}}
			rsaPub, err := tpm.CreateRSA(keyAttrs, nil, false)
			assert.Nil(t, err)
			assert.NotNil(t, rsaPub)

			// Flush the handle after successful creation
			if keyAttrs.TPMAttributes != nil && keyAttrs.TPMAttributes.Handle != 0 {
				tpm.Flush(keyAttrs.TPMAttributes.Handle)
			}

			// nil password with policy auth - should succeed
			keyAttrs.Parent.Password = nil
			keyAttrs.CN = "test4"
			rsaPub4, err4 := tpm.CreateRSA(keyAttrs, nil, false)
			assert.Nil(t, err4)
			assert.NotNil(t, rsaPub4)

			// Flush the handle after successful creation
			if keyAttrs.TPMAttributes != nil && keyAttrs.TPMAttributes.Handle != 0 {
				tpm.Flush(keyAttrs.TPMAttributes.Handle)
			}

			// incorrect password with policy auth - should fail. The
			// PlatformPolicy password branch binds the supplied auth value
			// into the session HMAC (TPM 2.0 Part 1, Section 19.6), so the
			// TPM rejects a session built with the wrong password with
			// TPM_RC_AUTH_FAIL - the PolicyOR construction lets a caller
			// authorize with the correct password OR the correct PCR
			// state, never with an arbitrary/incorrect password.
			keyAttrs.Parent.Password = mustPassword([]byte("foo"))
			keyAttrs.CN = "test5"
			rsaPub5, err5 := tpm.CreateRSA(keyAttrs, nil, false)
			assert.NotNil(t, err5)
			assert.Nil(t, rsaPub5)

			// correct password with policy auth - should work
			keyAttrs.Parent.Password = srkAuth
			keyAttrs.CN = "test6"
			rsaPub6, err6 := tpm.CreateRSA(keyAttrs, nil, false)
			assert.Nil(t, err6)
			assert.NotNil(t, rsaPub6)

			// Flush the handle after successful creation
			if keyAttrs.TPMAttributes != nil && keyAttrs.TPMAttributes.Handle != 0 {
				tpm.Flush(keyAttrs.TPMAttributes.Handle)
			}

			// Extend the PCR and read again - the PCR branch must stop
			// authorizing.
			//
			// This probes the PCR branch specifically, by presenting no
			// password on either the key or its parent. The password branch
			// deliberately survives a PCR change now: the SRK and the key each
			// record the platform policy pin they were created with, so a
			// caller holding the PINs can still authorize them. That is the
			// recovery path, and it is covered in
			// seal_pcr_policy_simulator_test.go.
			//
			// Probing the password branch here would not report a policy
			// failure in any case: once authorization succeeds, TPM2_Unseal of
			// an RSA key answers TPM_RC_TYPE, because an asymmetric key is not
			// a sealed data object.
			extendRandomBytes(tpm.Transport())

			pcrBranchParent := *keyAttrs.Parent
			pcrBranchParent.Password = nil
			pcrBranchAttrs := *keyAttrs
			pcrBranchAttrs.Parent = &pcrBranchParent
			pcrBranchAttrs.Password = nil

			secret2, err := tpm.UnsealKey(&pcrBranchAttrs, nil)
			assert.NotNil(t, err)
			assert.Nil(t, secret2)
			assert.Equal(t, ErrPolicyCheckFailed, err)

			// Close / reset the simulator between tests
			_ = tpm.Close()
		}
	}
}

func TestCreateKeyWithoutPolicy(t *testing.T) {

	encryptOpts := map[string]bool{
		"withEncryption":    true,
		"withoutEncryption": false,
	}

	passwdOpts := map[string]bool{
		"withPassword":    true,
		"withoutPassword": false,
	}

	for _, encryptOpt := range encryptOpts {

		for _, passwdOpt := range passwdOpts {

			_, tpm := createSim(encryptOpt, false)

			ekAttrs, err := tpm.EKAttributes()
			assert.Nil(t, err)

			hierarchyAuth := ekAttrs.TPMAttributes.HierarchyAuth

			srkTemplate := tpm2.RSASRKTemplate
			srkTemplate.ObjectAttributes.NoDA = false

			var srkAuth types.Password
			var keyAuth types.Password
			if passwdOpt {
				srkAuth = mustPassword([]byte("srk-password"))
				keyAuth = mustPassword([]byte("key-password"))
			}

			srkAttrs := &types.KeyAttributes{
				CN:           "srk-with-policy",
				KeyAlgorithm: x509.RSA,
				KeyType:      types.KeyTypeStorage,
				Password:     srkAuth,
				StoreType:    types.StoreTPM2,
				TPMAttributes: &types.TPMAttributes{
					Handle:        keyStoreHandle,
					HandleType:    tpm2.TPMHTPersistent,
					Hierarchy:     tpm2.TPMRHOwner,
					HierarchyAuth: hierarchyAuth,
					Template:      srkTemplate,
				}}

			err = tpm.CreateSRK(srkAttrs)
			assert.Nil(t, err)

			keyAttrs := &types.KeyAttributes{
				CN:           "test",
				KeyAlgorithm: x509.RSA,
				KeyType:      types.KeyTypeCA,
				Parent:       srkAttrs,
				Password:     keyAuth,
				StoreType:    types.StoreTPM2,
				TPMAttributes: &types.TPMAttributes{
					Hierarchy: tpm2.TPMRHOwner,
				}}
			rsaPub, err := tpm.CreateRSA(keyAttrs, nil, false)
			assert.Nil(t, err)
			assert.NotNil(t, rsaPub)

			// Flush the handle after successful creation
			if keyAttrs.TPMAttributes != nil && keyAttrs.TPMAttributes.Handle != 0 {
				tpm.Flush(keyAttrs.TPMAttributes.Handle)
			}

			if passwdOpt {
				// nil password without policy auth - should fail
				keyAttrs.Parent.Password = nil
				keyAttrs.CN = "test4"
				rsaPub2, err2 := tpm.CreateRSA(keyAttrs, nil, false)
				assert.NotNil(t, err2)
				assert.Nil(t, rsaPub2)
				assert.Equal(t, ErrAuthFailWithDA, err2)
			} else {
				// nil password without policy auth - should work
				keyAttrs.Parent.Password = nil
				keyAttrs.CN = "test4"
				rsaPub2, err2 := tpm.CreateRSA(keyAttrs, nil, false)
				assert.Nil(t, err2)
				assert.NotNil(t, rsaPub2)

				// Flush the handle after successful creation
				if keyAttrs.TPMAttributes != nil && keyAttrs.TPMAttributes.Handle != 0 {
					tpm.Flush(keyAttrs.TPMAttributes.Handle)
				}
			}

			// incorrect password without policy auth - should fail
			keyAttrs.Parent.Password = mustPassword([]byte("foo"))
			keyAttrs.CN = "test5"
			rsaPub3, err3 := tpm.CreateRSA(keyAttrs, nil, false)
			assert.NotNil(t, err3)
			assert.Nil(t, rsaPub3)
			assert.Equal(t, ErrAuthFailWithDA, err3)

			// correct password without policy auth - should work
			keyAttrs.Parent.Password = srkAuth
			keyAttrs.CN = "test6"
			rsaPub6, err6 := tpm.CreateRSA(keyAttrs, nil, false)
			assert.Nil(t, err6)
			assert.NotNil(t, rsaPub6)

			// Close / reset the simulator between tests
			_ = tpm.Close()
		}
	}

}
