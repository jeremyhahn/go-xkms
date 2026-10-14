//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNVWithAuthNoPolicy(t *testing.T) {

	policyOpts := map[string]bool{
		"withPolicy":    true,
		"withoutPolicy": false,
	}

	for _, policyOpt := range policyOpts {

		_, tpm := createSim(t, false)

		userPIN := mustPassword(t, []byte("user-pin"))
		secret := []byte("secret")

		ekAttrs, err := tpm.EKAttributes()
		assert.Nil(t, err)

		oldHierarchyAuth := ekAttrs.TPMAttributes.HierarchyAuth

		// Change the hierarchy authorization passwords to user-pin
		err = tpm.SetHierarchyAuth(oldHierarchyAuth, userPIN, nil)
		assert.Nil(t, err)

		ekAttrs.TPMAttributes.HierarchyAuth = userPIN

		keyAttrs := &types.KeyAttributes{
			Parent:    ekAttrs,
			Password:  mustPassword(t, []byte("test")),
			TPMPolicy: platformPolicyName(policyOpt),
			SealData:  types.NewSealData(secret),
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
		keyAttrs.Parent.TPMAttributes.HierarchyAuth = mustPassword(t, []byte("test"))
		err = tpm.NVWrite(keyAttrs)
		assert.NotNil(t, err)

		// // providing invalid key auth - should fail
		// keyAttrs.Password = mustPassword(t, []byte{})
		// err = tpm.NVWrite(keyAttrs)
		// assert.NotNil(t, err)

		keyAttrs.Parent.TPMAttributes.HierarchyAuth = userPIN
		keyAttrs.Password = mustPassword(t, []byte{})
		if policyOpt {

			// invalid key auth with platform policy - should succeed
			nvSecret, err = tpm.NVRead(keyAttrs, dataSize)
			assert.Nil(t, err)
			assert.NotNil(t, nvSecret)
		}

		_ = tpm.Close()
	}
}

// TestNVDefineCounter tests the NVDefineCounter function
func TestNVDefineCounter(t *testing.T) {

	tests := []struct {
		name    string
		setup   func(*TPM2) (*types.KeyAttributes, error)
		wantErr bool
		errType error
	}{
		{
			name: "success_define_counter",
			setup: func(tpm *TPM2) (*types.KeyAttributes, error) {
				ekAttrs, err := tpm.EKAttributes()
				if err != nil {
					return nil, err
				}

				return &types.KeyAttributes{
					Parent: ekAttrs,
					TPMAttributes: &types.TPMAttributes{
						Handle:    tpm2.TPMHandle(nvramCounterIndex),
						HashAlg:   tpm2.TPMAlgSHA256,
						Hierarchy: tpm2.TPMRHOwner,
					},
				}, nil
			},
			wantErr: false,
		},
		{
			name: "error_nil_tpm_attributes",
			setup: func(tpm *TPM2) (*types.KeyAttributes, error) {
				ekAttrs, err := tpm.EKAttributes()
				if err != nil {
					return nil, err
				}

				return &types.KeyAttributes{
					Parent:        ekAttrs,
					TPMAttributes: nil,
				}, nil
			},
			wantErr: true,
			errType: store.ErrInvalidKeyAttributes,
		},
		{
			name: "error_nil_parent",
			setup: func(tpm *TPM2) (*types.KeyAttributes, error) {
				return &types.KeyAttributes{
					Parent: nil,
					TPMAttributes: &types.TPMAttributes{
						Handle:    tpm2.TPMHandle(nvramCounterIndex),
						HashAlg:   tpm2.TPMAlgSHA256,
						Hierarchy: tpm2.TPMRHOwner,
					},
				}, nil
			},
			wantErr: true,
			errType: store.ErrInvalidParentAttributes,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, tpmIface := createSim(t, false)
			defer func() { _ = tpmIface.Close() }()

			tpm := tpmIface.(*TPM2)
			keyAttrs, err := tt.setup(tpm)
			require.NoError(t, err)

			err = tpm.NVDefineCounter(keyAttrs)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errType != nil {
					assert.ErrorIs(t, err, tt.errType)
				}
			} else {
				assert.NoError(t, err)
				// Verify the handle and name were set
				assert.Equal(t, tpm2.TPMHandle(nvramCounterIndex), keyAttrs.TPMAttributes.Handle)
				assert.NotEmpty(t, keyAttrs.TPMAttributes.Name.Buffer)

				// Clean up
				err = tpm.NVUndefine(keyAttrs)
				assert.NoError(t, err)
			}
		})
	}
}

// TestNVDefineExtend tests the NVDefineExtend function
func TestNVDefineExtend(t *testing.T) {

	tests := []struct {
		name    string
		hashAlg tpm2.TPMIAlgHash
		setup   func(*TPM2, tpm2.TPMIAlgHash) (*types.KeyAttributes, error)
		wantErr bool
		errType error
	}{
		{
			name:    "success_define_extend_sha256",
			hashAlg: tpm2.TPMAlgSHA256,
			setup: func(tpm *TPM2, hashAlg tpm2.TPMIAlgHash) (*types.KeyAttributes, error) {
				ekAttrs, err := tpm.EKAttributes()
				if err != nil {
					return nil, err
				}

				return &types.KeyAttributes{
					Parent: ekAttrs,
					TPMAttributes: &types.TPMAttributes{
						Handle:    tpm2.TPMHandle(nvramExtendIndex),
						HashAlg:   hashAlg,
						Hierarchy: tpm2.TPMRHOwner,
					},
				}, nil
			},
			wantErr: false,
		},
		{
			name:    "success_define_extend_sha384",
			hashAlg: tpm2.TPMAlgSHA384,
			setup: func(tpm *TPM2, hashAlg tpm2.TPMIAlgHash) (*types.KeyAttributes, error) {
				ekAttrs, err := tpm.EKAttributes()
				if err != nil {
					return nil, err
				}

				return &types.KeyAttributes{
					Parent: ekAttrs,
					TPMAttributes: &types.TPMAttributes{
						Handle:    tpm2.TPMHandle(nvramExtendIndex),
						HashAlg:   hashAlg,
						Hierarchy: tpm2.TPMRHOwner,
					},
				}, nil
			},
			wantErr: false,
		},
		{
			name:    "error_nil_tpm_attributes",
			hashAlg: tpm2.TPMAlgSHA256,
			setup: func(tpm *TPM2, hashAlg tpm2.TPMIAlgHash) (*types.KeyAttributes, error) {
				ekAttrs, err := tpm.EKAttributes()
				if err != nil {
					return nil, err
				}

				return &types.KeyAttributes{
					Parent:        ekAttrs,
					TPMAttributes: nil,
				}, nil
			},
			wantErr: true,
			errType: store.ErrInvalidKeyAttributes,
		},
		{
			name:    "error_nil_parent",
			hashAlg: tpm2.TPMAlgSHA256,
			setup: func(tpm *TPM2, hashAlg tpm2.TPMIAlgHash) (*types.KeyAttributes, error) {
				return &types.KeyAttributes{
					Parent: nil,
					TPMAttributes: &types.TPMAttributes{
						Handle:    tpm2.TPMHandle(nvramExtendIndex),
						HashAlg:   hashAlg,
						Hierarchy: tpm2.TPMRHOwner,
					},
				}, nil
			},
			wantErr: true,
			errType: store.ErrInvalidParentAttributes,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, tpmIface := createSim(t, false)
			defer func() { _ = tpmIface.Close() }()

			tpm := tpmIface.(*TPM2)
			keyAttrs, err := tt.setup(tpm, tt.hashAlg)
			require.NoError(t, err)

			err = tpm.NVDefineExtend(keyAttrs)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errType != nil {
					assert.ErrorIs(t, err, tt.errType)
				}
			} else {
				assert.NoError(t, err)
				// Verify the handle and name were set
				assert.Equal(t, tpm2.TPMHandle(nvramExtendIndex), keyAttrs.TPMAttributes.Handle)
				assert.NotEmpty(t, keyAttrs.TPMAttributes.Name.Buffer)

				// Clean up
				err = tpm.NVUndefine(keyAttrs)
				assert.NoError(t, err)
			}
		})
	}
}

// TestNVIncrement tests the NVIncrement function
func TestNVIncrement(t *testing.T) {

	t.Run("success_increment_counter", func(t *testing.T) {
		_, tpm := createSim(t, false)
		defer func() { _ = tpm.Close() }()

		ekAttrs, err := tpm.EKAttributes()
		require.NoError(t, err)

		keyAttrs := &types.KeyAttributes{
			Parent: ekAttrs,
			TPMAttributes: &types.TPMAttributes{
				Handle:    tpm2.TPMHandle(nvramCounterIndex),
				HashAlg:   tpm2.TPMAlgSHA256,
				Hierarchy: tpm2.TPMRHOwner,
			},
		}

		// Define the counter
		err = tpm.NVDefineCounter(keyAttrs)
		require.NoError(t, err)

		// Increment the counter
		value1, err := tpm.NVIncrement(keyAttrs)
		assert.NoError(t, err)
		assert.Greater(t, value1, uint64(0))

		// Increment again
		value2, err := tpm.NVIncrement(keyAttrs)
		assert.NoError(t, err)
		assert.Equal(t, value1+1, value2)

		// Increment a third time
		value3, err := tpm.NVIncrement(keyAttrs)
		assert.NoError(t, err)
		assert.Equal(t, value2+1, value3)

		// Clean up
		err = tpm.NVUndefine(keyAttrs)
		assert.NoError(t, err)
	})

	t.Run("error_nil_tpm_attributes", func(t *testing.T) {
		_, tpm := createSim(t, false)
		defer func() { _ = tpm.Close() }()

		ekAttrs, err := tpm.EKAttributes()
		require.NoError(t, err)

		keyAttrs := &types.KeyAttributes{
			Parent:        ekAttrs,
			TPMAttributes: nil,
		}

		_, err = tpm.NVIncrement(keyAttrs)
		assert.ErrorIs(t, err, store.ErrInvalidKeyAttributes)
	})

	t.Run("error_nil_parent", func(t *testing.T) {
		_, tpm := createSim(t, false)
		defer func() { _ = tpm.Close() }()

		keyAttrs := &types.KeyAttributes{
			Parent: nil,
			TPMAttributes: &types.TPMAttributes{
				Handle:    tpm2.TPMHandle(nvramCounterIndex),
				HashAlg:   tpm2.TPMAlgSHA256,
				Hierarchy: tpm2.TPMRHOwner,
			},
		}

		_, err := tpm.NVIncrement(keyAttrs)
		assert.ErrorIs(t, err, store.ErrInvalidParentAttributes)
	})
}

// TestNVExtend tests the NVExtend function
func TestNVExtend(t *testing.T) {

	t.Run("success_extend_data", func(t *testing.T) {
		_, tpm := createSim(t, false)
		defer func() { _ = tpm.Close() }()

		ekAttrs, err := tpm.EKAttributes()
		require.NoError(t, err)

		keyAttrs := &types.KeyAttributes{
			Parent: ekAttrs,
			TPMAttributes: &types.TPMAttributes{
				Handle:    tpm2.TPMHandle(nvramExtendIndex),
				HashAlg:   tpm2.TPMAlgSHA256,
				Hierarchy: tpm2.TPMRHOwner,
			},
		}

		// Define the extend index
		err = tpm.NVDefineExtend(keyAttrs)
		require.NoError(t, err)

		// Extend data into the index
		data := []byte("test data to extend")
		err = tpm.NVExtend(keyAttrs, data)
		assert.NoError(t, err)

		// Read back the digest
		digest, err := tpm.NVReadExtend(keyAttrs)
		assert.NoError(t, err)
		assert.Len(t, digest, 32) // SHA-256 digest size

		// Extend more data
		data2 := []byte("more test data")
		err = tpm.NVExtend(keyAttrs, data2)
		assert.NoError(t, err)

		// Read back the updated digest
		digest2, err := tpm.NVReadExtend(keyAttrs)
		assert.NoError(t, err)
		assert.Len(t, digest2, 32)

		// Digests should be different after extending more data
		assert.NotEqual(t, digest, digest2)

		// Clean up
		err = tpm.NVUndefine(keyAttrs)
		assert.NoError(t, err)
	})

	t.Run("error_nil_data", func(t *testing.T) {
		_, tpm := createSim(t, false)
		defer func() { _ = tpm.Close() }()

		ekAttrs, err := tpm.EKAttributes()
		require.NoError(t, err)

		keyAttrs := &types.KeyAttributes{
			Parent: ekAttrs,
			TPMAttributes: &types.TPMAttributes{
				Handle:    tpm2.TPMHandle(nvramExtendIndex),
				HashAlg:   tpm2.TPMAlgSHA256,
				Hierarchy: tpm2.TPMRHOwner,
			},
		}

		err = tpm.NVExtend(keyAttrs, nil)
		assert.ErrorIs(t, err, ErrInvalidNVExtendData)
	})

	t.Run("error_empty_data", func(t *testing.T) {
		_, tpm := createSim(t, false)
		defer func() { _ = tpm.Close() }()

		ekAttrs, err := tpm.EKAttributes()
		require.NoError(t, err)

		keyAttrs := &types.KeyAttributes{
			Parent: ekAttrs,
			TPMAttributes: &types.TPMAttributes{
				Handle:    tpm2.TPMHandle(nvramExtendIndex),
				HashAlg:   tpm2.TPMAlgSHA256,
				Hierarchy: tpm2.TPMRHOwner,
			},
		}

		err = tpm.NVExtend(keyAttrs, []byte{})
		assert.ErrorIs(t, err, ErrInvalidNVExtendData)
	})

	t.Run("error_nil_tpm_attributes", func(t *testing.T) {
		_, tpm := createSim(t, false)
		defer func() { _ = tpm.Close() }()

		ekAttrs, err := tpm.EKAttributes()
		require.NoError(t, err)

		keyAttrs := &types.KeyAttributes{
			Parent:        ekAttrs,
			TPMAttributes: nil,
		}

		err = tpm.NVExtend(keyAttrs, []byte("test"))
		assert.ErrorIs(t, err, store.ErrInvalidKeyAttributes)
	})

	t.Run("error_nil_parent", func(t *testing.T) {
		_, tpm := createSim(t, false)
		defer func() { _ = tpm.Close() }()

		keyAttrs := &types.KeyAttributes{
			Parent: nil,
			TPMAttributes: &types.TPMAttributes{
				Handle:    tpm2.TPMHandle(nvramExtendIndex),
				HashAlg:   tpm2.TPMAlgSHA256,
				Hierarchy: tpm2.TPMRHOwner,
			},
		}

		err := tpm.NVExtend(keyAttrs, []byte("test"))
		assert.ErrorIs(t, err, store.ErrInvalidParentAttributes)
	})
}

// TestNVReadCounter tests the NVReadCounter function
func TestNVReadCounter(t *testing.T) {

	t.Run("success_read_counter", func(t *testing.T) {
		_, tpm := createSim(t, false)
		defer func() { _ = tpm.Close() }()

		ekAttrs, err := tpm.EKAttributes()
		require.NoError(t, err)

		keyAttrs := &types.KeyAttributes{
			Parent: ekAttrs,
			TPMAttributes: &types.TPMAttributes{
				Handle:    tpm2.TPMHandle(nvramCounterIndex),
				HashAlg:   tpm2.TPMAlgSHA256,
				Hierarchy: tpm2.TPMRHOwner,
			},
		}

		// Define the counter
		err = tpm.NVDefineCounter(keyAttrs)
		require.NoError(t, err)

		// Increment to initialize
		_, err = tpm.NVIncrement(keyAttrs)
		require.NoError(t, err)

		// Read the counter
		value, err := tpm.NVReadCounter(keyAttrs)
		assert.NoError(t, err)
		assert.Greater(t, value, uint64(0))

		// Increment
		_, err = tpm.NVIncrement(keyAttrs)
		require.NoError(t, err)

		// Read again - should be incremented
		value2, err := tpm.NVReadCounter(keyAttrs)
		assert.NoError(t, err)
		assert.Equal(t, value+1, value2)

		// Clean up
		err = tpm.NVUndefine(keyAttrs)
		assert.NoError(t, err)
	})

	t.Run("error_nil_tpm_attributes", func(t *testing.T) {
		_, tpm := createSim(t, false)
		defer func() { _ = tpm.Close() }()

		ekAttrs, err := tpm.EKAttributes()
		require.NoError(t, err)

		keyAttrs := &types.KeyAttributes{
			Parent:        ekAttrs,
			TPMAttributes: nil,
		}

		_, err = tpm.NVReadCounter(keyAttrs)
		assert.ErrorIs(t, err, store.ErrInvalidKeyAttributes)
	})

	t.Run("error_nil_parent", func(t *testing.T) {
		_, tpm := createSim(t, false)
		defer func() { _ = tpm.Close() }()

		keyAttrs := &types.KeyAttributes{
			Parent: nil,
			TPMAttributes: &types.TPMAttributes{
				Handle:    tpm2.TPMHandle(nvramCounterIndex),
				HashAlg:   tpm2.TPMAlgSHA256,
				Hierarchy: tpm2.TPMRHOwner,
			},
		}

		_, err := tpm.NVReadCounter(keyAttrs)
		assert.ErrorIs(t, err, store.ErrInvalidParentAttributes)
	})
}

// TestNVReadExtend tests the NVReadExtend function
func TestNVReadExtend(t *testing.T) {

	hashAlgTests := []struct {
		name        string
		hashAlg     tpm2.TPMIAlgHash
		expectedLen int
	}{
		{"sha256", tpm2.TPMAlgSHA256, 32},
		{"sha384", tpm2.TPMAlgSHA384, 48},
		{"sha512", tpm2.TPMAlgSHA512, 64},
	}

	for _, tt := range hashAlgTests {
		t.Run("success_read_"+tt.name, func(t *testing.T) {
			_, tpm := createSim(t, false)
			defer func() { _ = tpm.Close() }()

			ekAttrs, err := tpm.EKAttributes()
			require.NoError(t, err)

			keyAttrs := &types.KeyAttributes{
				Parent: ekAttrs,
				TPMAttributes: &types.TPMAttributes{
					Handle:    tpm2.TPMHandle(nvramExtendIndex),
					HashAlg:   tt.hashAlg,
					Hierarchy: tpm2.TPMRHOwner,
				},
			}

			// Define the extend index
			err = tpm.NVDefineExtend(keyAttrs)
			require.NoError(t, err)

			// Extend some data
			err = tpm.NVExtend(keyAttrs, []byte("test data"))
			require.NoError(t, err)

			// Read the digest
			digest, err := tpm.NVReadExtend(keyAttrs)
			assert.NoError(t, err)
			assert.Len(t, digest, tt.expectedLen)

			// Clean up
			err = tpm.NVUndefine(keyAttrs)
			assert.NoError(t, err)
		})
	}

	t.Run("error_nil_tpm_attributes", func(t *testing.T) {
		_, tpm := createSim(t, false)
		defer func() { _ = tpm.Close() }()

		ekAttrs, err := tpm.EKAttributes()
		require.NoError(t, err)

		keyAttrs := &types.KeyAttributes{
			Parent:        ekAttrs,
			TPMAttributes: nil,
		}

		_, err = tpm.NVReadExtend(keyAttrs)
		assert.ErrorIs(t, err, store.ErrInvalidKeyAttributes)
	})

	t.Run("error_nil_parent", func(t *testing.T) {
		_, tpm := createSim(t, false)
		defer func() { _ = tpm.Close() }()

		keyAttrs := &types.KeyAttributes{
			Parent: nil,
			TPMAttributes: &types.TPMAttributes{
				Handle:    tpm2.TPMHandle(nvramExtendIndex),
				HashAlg:   tpm2.TPMAlgSHA256,
				Hierarchy: tpm2.TPMRHOwner,
			},
		}

		_, err := tpm.NVReadExtend(keyAttrs)
		assert.ErrorIs(t, err, store.ErrInvalidParentAttributes)
	})
}

// TestNVUndefine tests the NVUndefine function
func TestNVUndefine(t *testing.T) {

	t.Run("success_undefine_counter", func(t *testing.T) {
		_, tpm := createSim(t, false)
		defer func() { _ = tpm.Close() }()

		ekAttrs, err := tpm.EKAttributes()
		require.NoError(t, err)

		keyAttrs := &types.KeyAttributes{
			Parent: ekAttrs,
			TPMAttributes: &types.TPMAttributes{
				Handle:    tpm2.TPMHandle(nvramCounterIndex),
				HashAlg:   tpm2.TPMAlgSHA256,
				Hierarchy: tpm2.TPMRHOwner,
			},
		}

		// Define the counter
		err = tpm.NVDefineCounter(keyAttrs)
		require.NoError(t, err)

		// Undefine it
		err = tpm.NVUndefine(keyAttrs)
		assert.NoError(t, err)

		// Try to increment - should fail because it's undefined
		_, err = tpm.NVIncrement(keyAttrs)
		assert.Error(t, err)
	})

	t.Run("success_undefine_extend", func(t *testing.T) {
		_, tpm := createSim(t, false)
		defer func() { _ = tpm.Close() }()

		ekAttrs, err := tpm.EKAttributes()
		require.NoError(t, err)

		keyAttrs := &types.KeyAttributes{
			Parent: ekAttrs,
			TPMAttributes: &types.TPMAttributes{
				Handle:    tpm2.TPMHandle(nvramExtendIndex),
				HashAlg:   tpm2.TPMAlgSHA256,
				Hierarchy: tpm2.TPMRHOwner,
			},
		}

		// Define the extend index
		err = tpm.NVDefineExtend(keyAttrs)
		require.NoError(t, err)

		// Undefine it
		err = tpm.NVUndefine(keyAttrs)
		assert.NoError(t, err)

		// Try to extend - should fail because it's undefined
		err = tpm.NVExtend(keyAttrs, []byte("test"))
		assert.Error(t, err)
	})

	t.Run("error_nil_tpm_attributes", func(t *testing.T) {
		_, tpm := createSim(t, false)
		defer func() { _ = tpm.Close() }()

		ekAttrs, err := tpm.EKAttributes()
		require.NoError(t, err)

		keyAttrs := &types.KeyAttributes{
			Parent:        ekAttrs,
			TPMAttributes: nil,
		}

		err = tpm.NVUndefine(keyAttrs)
		assert.ErrorIs(t, err, store.ErrInvalidKeyAttributes)
	})

	t.Run("error_nil_parent", func(t *testing.T) {
		_, tpm := createSim(t, false)
		defer func() { _ = tpm.Close() }()

		keyAttrs := &types.KeyAttributes{
			Parent: nil,
			TPMAttributes: &types.TPMAttributes{
				Handle:    tpm2.TPMHandle(nvramCounterIndex),
				HashAlg:   tpm2.TPMAlgSHA256,
				Hierarchy: tpm2.TPMRHOwner,
			},
		}

		err := tpm.NVUndefine(keyAttrs)
		assert.ErrorIs(t, err, store.ErrInvalidParentAttributes)
	})
}

// TestHashAlgDigestSize tests the hashAlgDigestSize helper function
func TestHashAlgDigestSize(t *testing.T) {
	tests := []struct {
		name        string
		hashAlg     tpm2.TPMIAlgHash
		expectedLen uint16
		wantErr     bool
	}{
		{"sha1", tpm2.TPMAlgSHA1, 20, false},
		{"sha256", tpm2.TPMAlgSHA256, 32, false},
		{"sha384", tpm2.TPMAlgSHA384, 48, false},
		{"sha512", tpm2.TPMAlgSHA512, 64, false},
		{"unsupported", tpm2.TPMIAlgHash(0xFFFF), 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			size, err := hashAlgDigestSize(tt.hashAlg)

			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorIs(t, err, ErrHashAlgorithmNotSupported)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedLen, size)
			}
		})
	}
}

// TestNVCounterWithHierarchyAuth tests counter operations with hierarchy authentication
func TestNVCounterWithHierarchyAuth(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	userPIN := mustPassword(t, []byte("user-pin"))

	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)

	oldHierarchyAuth := ekAttrs.TPMAttributes.HierarchyAuth

	// Change the hierarchy authorization passwords to user-pin
	err = tpm.SetHierarchyAuth(oldHierarchyAuth, userPIN, nil)
	require.NoError(t, err)

	ekAttrs.TPMAttributes.HierarchyAuth = userPIN

	keyAttrs := &types.KeyAttributes{
		Parent: ekAttrs,
		TPMAttributes: &types.TPMAttributes{
			Handle:        tpm2.TPMHandle(nvramCounterIndex),
			HashAlg:       tpm2.TPMAlgSHA256,
			Hierarchy:     tpm2.TPMRHOwner,
			HierarchyAuth: userPIN,
		},
	}

	// Define the counter with auth
	err = tpm.NVDefineCounter(keyAttrs)
	require.NoError(t, err)

	// Increment with correct auth
	value1, err := tpm.NVIncrement(keyAttrs)
	assert.NoError(t, err)
	assert.Greater(t, value1, uint64(0))

	// Read with correct auth
	value2, err := tpm.NVReadCounter(keyAttrs)
	assert.NoError(t, err)
	assert.Equal(t, value1, value2)

	// Try with wrong auth - should fail
	keyAttrs.Parent.TPMAttributes.HierarchyAuth = mustPassword(t, []byte("wrong-pin"))
	_, err = tpm.NVIncrement(keyAttrs)
	assert.Error(t, err)

	// Restore correct auth and clean up
	keyAttrs.Parent.TPMAttributes.HierarchyAuth = userPIN
	err = tpm.NVUndefine(keyAttrs)
	assert.NoError(t, err)
}

// TestNVExtendWithHierarchyAuth tests extend operations with hierarchy authentication
func TestNVExtendWithHierarchyAuth(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	userPIN := mustPassword(t, []byte("user-pin"))

	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)

	oldHierarchyAuth := ekAttrs.TPMAttributes.HierarchyAuth

	// Change the hierarchy authorization passwords to user-pin
	err = tpm.SetHierarchyAuth(oldHierarchyAuth, userPIN, nil)
	require.NoError(t, err)

	ekAttrs.TPMAttributes.HierarchyAuth = userPIN

	keyAttrs := &types.KeyAttributes{
		Parent: ekAttrs,
		TPMAttributes: &types.TPMAttributes{
			Handle:        tpm2.TPMHandle(nvramExtendIndex),
			HashAlg:       tpm2.TPMAlgSHA256,
			Hierarchy:     tpm2.TPMRHOwner,
			HierarchyAuth: userPIN,
		},
	}

	// Define the extend index with auth
	err = tpm.NVDefineExtend(keyAttrs)
	require.NoError(t, err)

	// Extend with correct auth
	err = tpm.NVExtend(keyAttrs, []byte("test data"))
	assert.NoError(t, err)

	// Read with correct auth
	digest, err := tpm.NVReadExtend(keyAttrs)
	assert.NoError(t, err)
	assert.Len(t, digest, 32)

	// Try with wrong auth - should fail
	keyAttrs.Parent.TPMAttributes.HierarchyAuth = mustPassword(t, []byte("wrong-pin"))
	err = tpm.NVExtend(keyAttrs, []byte("more data"))
	assert.Error(t, err)

	// Restore correct auth and clean up
	keyAttrs.Parent.TPMAttributes.HierarchyAuth = userPIN
	err = tpm.NVUndefine(keyAttrs)
	assert.NoError(t, err)
}

// TestCertificateNVRAMOperations tests NVRAM certificate operations
func TestCertificateNVRAMOperations(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl, ok := tpm.(*TPM2)
	require.True(t, ok)

	// The round trip is the assertion that was missing when the NV index was
	// defined as TPM_NT_COUNTER: a counter index is fixed at 8 octets, so
	// NVDefineSpace at certificate size is rejected with TPM_RC_SIZE and the
	// certificate was never stored. The subtest this replaced called
	// writeCertToNVRAM, discarded the error, and passed regardless.
	t.Run("writeCertToNVRAM round trips a certificate through readCertFromNVRAM", func(t *testing.T) {
		cert := nvramTestCert(t)
		nvIndex := tpm2.TPMHandle(0x01C90100)

		require.NoError(t, tpmImpl.writeCertToNVRAM(nvIndex, cert.Raw))
		defer func() { _ = tpmImpl.deleteCertFromNVRAM(nvIndex) }()

		got, err := tpmImpl.readCertFromNVRAM(nvIndex)
		require.NoError(t, err)
		require.Equal(t, cert.Raw, got, "NVRAM must return the certificate DER verbatim")

		parsed, err := x509.ParseCertificate(got)
		require.NoError(t, err, "the bytes read back must still be a certificate")
		require.Equal(t, cert.Subject.CommonName, parsed.Subject.CommonName)
	})

	// Pins the index type itself, so a regression to a counter, bit field or
	// extend index is caught at the definition rather than only at the write.
	t.Run("writeCertToNVRAM defines an ordinary index", func(t *testing.T) {
		cert := nvramTestCert(t)
		nvIndex := tpm2.TPMHandle(0x01C90101)

		require.NoError(t, tpmImpl.writeCertToNVRAM(nvIndex, cert.Raw))
		defer func() { _ = tpmImpl.deleteCertFromNVRAM(nvIndex) }()

		rsp, err := tpm2.NVReadPublic{NVIndex: nvIndex}.Execute(tpmImpl.transport)
		require.NoError(t, err)
		pub, err := rsp.NVPublic.Contents()
		require.NoError(t, err)

		assert.Equal(t, tpm2.TPMNTOrdinary, pub.Attributes.NT,
			"certificate storage requires TPM_NT_ORDINARY, not a counter")
		assert.Equal(t, uint16(len(cert.Raw)), pub.DataSize)
	})

	// Chunking is bounded by TPM_PT_NV_BUFFER_MAX, which is a different limit
	// from the per-index maximum. A certificate that spans more than one
	// NV_Write keeps both loops honest.
	t.Run("writeCertToNVRAM round trips a certificate larger than TPM_PT_NV_BUFFER_MAX", func(t *testing.T) {
		bufMax := nvBufferMaxUint16(tpmImpl.transport)
		cert := nvramTestCertLargerThan(t, int(bufMax))
		require.Greater(t, len(cert.Raw), int(bufMax),
			"the test certificate must span more than one NV_Write")

		nvIndex := tpm2.TPMHandle(0x01C90102)
		require.NoError(t, tpmImpl.writeCertToNVRAM(nvIndex, cert.Raw))
		defer func() { _ = tpmImpl.deleteCertFromNVRAM(nvIndex) }()

		got, err := tpmImpl.readCertFromNVRAM(nvIndex)
		require.NoError(t, err)
		require.Equal(t, cert.Raw, got)
	})

	t.Run("writeCertToNVRAM rejects a certificate larger than TPM_PT_NV_INDEX_MAX", func(t *testing.T) {
		indexMax, err := nvIndexMaxSize(tpmImpl.transport)
		require.NoError(t, err)

		oversized := make([]byte, int(indexMax)+1)
		err = tpmImpl.writeCertToNVRAM(tpm2.TPMHandle(0x01C90103), oversized)
		require.ErrorIs(t, err, ErrNVCertTooLarge,
			"the size limit must be reported as a typed error, not a bare TPM_RC_SIZE")
	})

	t.Run("writeCertToNVRAM rejects empty certificate DER", func(t *testing.T) {
		err := tpmImpl.writeCertToNVRAM(tpm2.TPMHandle(0x01C90104), nil)
		require.ErrorIs(t, err, ErrNVCertEmpty)
	})

	t.Run("readCertFromNVRAM returns error for undefined index", func(t *testing.T) {
		nvIndex := tpm2.TPMHandle(0x01C90999)

		_, err := tpmImpl.readCertFromNVRAM(nvIndex)
		assert.Error(t, err)
	})

	t.Run("deleteCertFromNVRAM returns error for undefined index", func(t *testing.T) {
		nvIndex := tpm2.TPMHandle(0x01C90998)

		err := tpmImpl.deleteCertFromNVRAM(nvIndex)
		assert.Error(t, err)
	})
}

// TestNVReadAuthReadWithNonEmptyOwnerAuth proves that NVRead uses the
// index-self auth path (TPMA_NV_AUTHREAD, TCG Part 3 §31.13) when the
// NV index was defined with AuthRead=true and empty index authValue, even
// when the simulator owner hierarchy auth has been changed to a non-empty
// value.  Without the fix, the function would send the owner handle with
// the wrong (empty) password and receive TPM_RC_BAD_AUTH.
func TestNVReadAuthReadWithNonEmptyOwnerAuth(t *testing.T) {
	_, tpmIface := createSim(t, false)
	defer func() { _ = tpmIface.Close() }()

	tpm := tpmIface.(*TPM2)

	ownerPIN := mustPassword(t, []byte("owner-secret"))

	// Set owner hierarchy auth to a non-empty value on the SIMULATOR ONLY.
	ownerHandle := tpm2.TPMHandle(tpm2.TPMRHOwner)
	ekAttrs, err := tpmIface.EKAttributes()
	require.NoError(t, err)

	err = tpm.SetHierarchyAuth(ekAttrs.TPMAttributes.HierarchyAuth, ownerPIN, &ownerHandle)
	require.NoError(t, err)

	secret := []byte("authread-secret")
	nvHandle := tpm2.TPMHandle(0x01800030)

	// Define NV space with AuthRead=true but OwnerRead=false, so the only
	// valid read path is the index-self auth.  Use owner auth for defining
	// and writing (OwnerWrite=true) so we can set up the index, but we
	// intentionally leave AuthRead as the sole readable attribute.
	defs := tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(ownerPIN.Bytes()),
		},
		PublicInfo: tpm2.New2B(
			tpm2.TPMSNVPublic{
				NVIndex:  nvHandle,
				NameAlg:  tpm2.TPMAlgSHA256,
				DataSize: uint16(len(secret)),
				Attributes: tpm2.TPMANV{
					AuthRead:   true,
					AuthWrite:  true,
					OwnerWrite: true,
					NT:         tpm2.TPMNTOrdinary,
					NoDA:       true,
					// OwnerRead intentionally NOT set.
				},
			}),
	}
	_, err = defs.Execute(tpm.transport)
	require.NoError(t, err)

	nvPubRsp, err := tpm2.NVReadPublic{NVIndex: nvHandle}.Execute(tpm.transport)
	require.NoError(t, err)

	// Write via owner auth.
	_, err = tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(ownerPIN.Bytes()),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: nvHandle,
			Name:   nvPubRsp.NVName,
		},
		Data:   tpm2.TPM2BMaxNVBuffer{Buffer: secret},
		Offset: 0,
	}.Execute(tpm.transport)
	require.NoError(t, err)

	// Construct keyAttrs with NO hierarchy auth — caller doesn't know owner
	// password, simulating an EK cert index with empty index auth.
	keyAttrs := &types.KeyAttributes{
		Parent: &types.KeyAttributes{
			TPMAttributes: &types.TPMAttributes{
				HierarchyAuth: mustPassword(t, nil), // empty — no owner auth
			},
		},
		TPMAttributes: &types.TPMAttributes{
			Handle:    nvHandle,
			HashAlg:   tpm2.TPMAlgSHA256,
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	// NVRead must succeed via AuthRead (index-self auth), bypassing the
	// non-empty owner auth that would otherwise fail.
	data, err := tpm.NVRead(keyAttrs, uint16(len(secret)))
	require.NoError(t, err)
	assert.Equal(t, secret, data)

	// Clean up — requires the owner auth we set.
	_, err = tpm2.NVUndefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(ownerPIN.Bytes()),
		},
		NVIndex: tpm2.NamedHandle{Handle: nvHandle, Name: nvPubRsp.NVName},
	}.Execute(tpm.transport)
	assert.NoError(t, err)
}

// TestNVReadOwnerReadWithOwnerAuth proves that an OWNERREAD-only NV index
// (no AUTHREAD) is still readable via NVRead when the caller supplies the
// correct owner hierarchy auth.
func TestNVReadOwnerReadWithOwnerAuth(t *testing.T) {
	_, tpmIface := createSim(t, false)
	defer func() { _ = tpmIface.Close() }()

	tpm := tpmIface.(*TPM2)

	ownerPIN := mustPassword(t, []byte("owner-read-test"))

	ownerHandle := tpm2.TPMHandle(tpm2.TPMRHOwner)
	ekAttrs, err := tpmIface.EKAttributes()
	require.NoError(t, err)

	err = tpm.SetHierarchyAuth(ekAttrs.TPMAttributes.HierarchyAuth, ownerPIN, &ownerHandle)
	require.NoError(t, err)

	secret := []byte("ownerread-secret")
	nvHandle := tpm2.TPMHandle(0x01800040)

	// Define with OwnerRead=true and OwnerWrite=true; AuthRead is NOT set so
	// only the owner-hierarchy path is valid for reads.
	defs := tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(ownerPIN.Bytes()),
		},
		PublicInfo: tpm2.New2B(
			tpm2.TPMSNVPublic{
				NVIndex:  nvHandle,
				NameAlg:  tpm2.TPMAlgSHA256,
				DataSize: uint16(len(secret)),
				Attributes: tpm2.TPMANV{
					OwnerRead:  true,
					OwnerWrite: true,
					AuthWrite:  true,
					NT:         tpm2.TPMNTOrdinary,
					NoDA:       true,
					// AuthRead intentionally NOT set.
				},
			}),
	}
	_, err = defs.Execute(tpm.transport)
	require.NoError(t, err)

	nvPubRsp, err := tpm2.NVReadPublic{NVIndex: nvHandle}.Execute(tpm.transport)
	require.NoError(t, err)

	_, err = tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(ownerPIN.Bytes()),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: nvHandle,
			Name:   nvPubRsp.NVName,
		},
		Data:   tpm2.TPM2BMaxNVBuffer{Buffer: secret},
		Offset: 0,
	}.Execute(tpm.transport)
	require.NoError(t, err)

	// Supply owner auth via Parent.TPMAttributes.HierarchyAuth.
	keyAttrs := &types.KeyAttributes{
		Parent: &types.KeyAttributes{
			TPMAttributes: &types.TPMAttributes{
				HierarchyAuth: ownerPIN,
			},
		},
		TPMAttributes: &types.TPMAttributes{
			Handle:    nvHandle,
			HashAlg:   tpm2.TPMAlgSHA256,
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	data, err := tpm.NVRead(keyAttrs, uint16(len(secret)))
	require.NoError(t, err)
	assert.Equal(t, secret, data)

	// Clean up.
	_, err = tpm2.NVUndefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(ownerPIN.Bytes()),
		},
		NVIndex: tpm2.NamedHandle{Handle: nvHandle, Name: nvPubRsp.NVName},
	}.Execute(tpm.transport)
	assert.NoError(t, err)
}

// TestNVReadNotAuthorizedError proves that NVRead returns ErrNVReadNotAuthorized
// when the NV index attributes have neither AuthRead nor OwnerRead set.
// We simulate this by defining an index with only PPRead (platform hierarchy
// read, bit 16) and no owner- or auth-value-based read attribute, then
// calling NVRead which must return the typed error without panicking.
func TestNVReadNotAuthorizedError(t *testing.T) {
	_, tpmIface := createSim(t, false)
	defer func() { _ = tpmIface.Close() }()

	tpm := tpmIface.(*TPM2)

	ekAttrs, err := tpmIface.EKAttributes()
	require.NoError(t, err)

	var hierarchyAuth []byte
	if ekAttrs.TPMAttributes.HierarchyAuth != nil {
		hierarchyAuth = ekAttrs.TPMAttributes.HierarchyAuth.Bytes()
	}

	secret := []byte("ppread-only")
	nvHandle := tpm2.TPMHandle(0x01800050)

	// Define an NV index with PPRead only — neither AuthRead nor OwnerRead
	// is set.  NVRead cannot satisfy this without a platform session, so it
	// must return ErrNVReadNotAuthorized via the default branch.
	defs := tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		PublicInfo: tpm2.New2B(
			tpm2.TPMSNVPublic{
				NVIndex:  nvHandle,
				NameAlg:  tpm2.TPMAlgSHA256,
				DataSize: uint16(len(secret)),
				Attributes: tpm2.TPMANV{
					PPRead:     true,
					OwnerWrite: true,
					AuthWrite:  true,
					NT:         tpm2.TPMNTOrdinary,
					NoDA:       true,
					// AuthRead and OwnerRead both NOT set.
				},
			}),
	}
	_, err = defs.Execute(tpm.transport)
	require.NoError(t, err)

	nvPubRsp, err := tpm2.NVReadPublic{NVIndex: nvHandle}.Execute(tpm.transport)
	require.NoError(t, err)

	// Write so the index is WRITTEN (not uninitialized) — avoids a different
	// TPM error if the TPM refuses to read an unwritten index.
	_, err = tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: nvHandle,
			Name:   nvPubRsp.NVName,
		},
		Data:   tpm2.TPM2BMaxNVBuffer{Buffer: secret},
		Offset: 0,
	}.Execute(tpm.transport)
	require.NoError(t, err)

	keyAttrs := &types.KeyAttributes{
		Parent: &types.KeyAttributes{
			TPMAttributes: &types.TPMAttributes{
				HierarchyAuth: mustPassword(t, nil),
			},
		},
		TPMAttributes: &types.TPMAttributes{
			Handle:    nvHandle,
			HashAlg:   tpm2.TPMAlgSHA256,
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	_, err = tpm.NVRead(keyAttrs, uint16(len(secret)))
	assert.ErrorIs(t, err, ErrNVReadNotAuthorized)

	// Clean up.
	_, err = tpm2.NVUndefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		NVIndex: tpm2.NamedHandle{Handle: nvHandle, Name: nvPubRsp.NVName},
	}.Execute(tpm.transport)
	assert.NoError(t, err)
}

// TestNVReadWriteChunked proves that NVRead and NVWrite correctly handle NV
// indices whose DataSize exceeds the TPM's TPM_PT_NV_BUFFER_MAX.
//
// The test:
//  1. Queries the simulator's NV buffer maximum via the same capability call
//     that production code uses (nvBufferMaxUint16 wrapping nvBufferMax).
//  2. Defines an NV index of bufMax+33 bytes — one chunk longer than a single
//     NV_Write or NV_Read can transfer — then writes known data and reads it
//     back, asserting byte-exact round-trip equality.
//  3. Verifies the error path: attempting an NVRead with a dataSize that
//     would exceed the index's actual DataSize is clamped and succeeds (the
//     clamping semantics guarantee the API is robust to over-sized requests).
func TestNVReadWriteChunked(t *testing.T) {
	_, tpmIface := createSim(t, false)
	defer func() { _ = tpmIface.Close() }()

	tpm := tpmIface.(*TPM2)

	// Query the simulator's NV buffer maximum.
	bufMax := nvBufferMaxUint16(tpm.transport)
	require.NotZero(t, bufMax, "TPM_PT_NV_BUFFER_MAX must be non-zero")

	// Size the payload to bufMax+33 so at least two chunks are required.
	payloadSize := int(bufMax) + 33
	require.LessOrEqual(t, payloadSize, math.MaxUint16,
		"payload size must fit in uint16")

	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i % 251) // deterministic, non-trivial pattern
	}

	ekAttrs, err := tpmIface.EKAttributes()
	require.NoError(t, err)

	nvHandle := tpm2.TPMHandle(nvramChunkIndex)

	keyAttrs := &types.KeyAttributes{
		Parent:   ekAttrs,
		SealData: types.NewSealData(payload),
		TPMAttributes: &types.TPMAttributes{
			Handle:    nvHandle,
			HashAlg:   tpm2.TPMAlgSHA256,
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	t.Run("write_and_read_larger_than_buffer_max", func(t *testing.T) {
		// NVWrite must succeed even though payloadSize > bufMax.
		err := tpm.NVWrite(keyAttrs)
		require.NoError(t, err, "NVWrite must succeed for payload > TPM_PT_NV_BUFFER_MAX")

		// NVRead with the exact payload size must succeed and return all bytes.
		got, err := tpm.NVRead(keyAttrs, uint16(payloadSize)) // #nosec G115 -- checked above
		require.NoError(t, err, "NVRead must succeed for payload > TPM_PT_NV_BUFFER_MAX")
		assert.Equal(t, payload, got, "round-trip data must match exactly")

		// NVRead with dataSize==0 must also return the full index contents.
		got0, err := tpm.NVRead(keyAttrs, 0)
		require.NoError(t, err, "NVRead with dataSize==0 must return full contents")
		assert.Equal(t, payload, got0, "round-trip data (dataSize=0) must match exactly")

		// Clean up.
		err = tpm.NVUndefine(keyAttrs)
		assert.NoError(t, err)
	})

	t.Run("read_oversized_request_is_clamped", func(t *testing.T) {
		// Re-define with a small payload so we can request a larger size.
		smallPayload := payload[:bufMax/2]
		keyAttrs2 := &types.KeyAttributes{
			Parent:   ekAttrs,
			SealData: types.NewSealData(smallPayload),
			TPMAttributes: &types.TPMAttributes{
				Handle:    tpm2.TPMHandle(nvramChunkIndex + 1),
				HashAlg:   tpm2.TPMAlgSHA256,
				Hierarchy: tpm2.TPMRHOwner,
			},
		}

		err := tpm.NVWrite(keyAttrs2)
		require.NoError(t, err)

		// Request more bytes than the index contains — the implementation
		// must clamp to nvPub.DataSize and succeed.
		overSize := uint16(len(smallPayload)) + 100
		got, err := tpm.NVRead(keyAttrs2, overSize)
		require.NoError(t, err, "NVRead with oversized request must be clamped and succeed")
		assert.Equal(t, smallPayload, got, "clamped read must return full index contents")

		err = tpm.NVUndefine(keyAttrs2)
		assert.NoError(t, err)
	})
}

// nvramTestCertLargerThan creates a self-signed certificate whose DER encoding
// exceeds minSize bytes, by padding it with an opaque extension. Real IDevID
// certificates reach this size through TCG subject-alternative-name and
// hardware-module extensions; the padding stands in for that bulk without
// depending on a particular profile.
func nvramTestCertLargerThan(t *testing.T, minSize int) *x509.Certificate {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// The base certificate is ~725 bytes; pad past minSize with room to spare
	// for the DER framing the extension itself adds.
	padding := make([]byte, minSize)
	_, err = rand.Read(padding)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "Large Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		ExtraExtensions: []pkix.Extension{
			{
				// Private enterprise arc; the value is opaque filler.
				Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 138},
				Value: padding,
			},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)
	require.Greater(t, len(certDER), minSize)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

// nvramTestCert creates a self-signed test certificate for NVRAM tests
func nvramTestCert(t *testing.T) *x509.Certificate {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

// TestNVIndexMaxSize_TransportFailure proves nvIndexMaxSize propagates a
// transport fault from its own TPM_PT_NV_INDEX_MAX query rather than
// returning a zero size that writeCertToNVRAM's size check would silently
// trust.
func TestNVIndexMaxSize_TransportFailure(t *testing.T) {
	_, err := nvIndexMaxSize(failingTransport{})
	require.Error(t, err)
}

// TestNvExtendExecute_TransportFailure proves the hand-rolled TPM2_NV_Extend
// command sender surfaces a transport fault (wrapped, never a bare error)
// rather than silently treating a dead transport as an extend that never
// happened.
func TestNvExtendExecute_TransportFailure(t *testing.T) {
	err := nvExtendExecute(
		failingTransport{},
		tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(0x01500040),
			Name:   tpm2.TPM2BName{Buffer: []byte("nv-index-name")},
		},
		[]byte("extend-data"),
	)
	require.Error(t, err)
}

// TestNVBufferMaxUint16_TransportFailureFallsBackToConservativeDefault
// proves nvBufferMaxUint16 degrades to nvChunkSizeFallback rather than
// returning zero (which would make every NV read/write loop spin forever)
// when the device cannot answer TPM_PT_NV_BUFFER_MAX.
func TestNVBufferMaxUint16_TransportFailureFallsBackToConservativeDefault(t *testing.T) {
	assert.Equal(t, nvChunkSizeFallback, nvBufferMaxUint16(failingTransport{}))
}
