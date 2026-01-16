package tpm2

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			_, tpmIface := createSim(false, false)
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
			_, tpmIface := createSim(false, false)
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
		_, tpm := createSim(false, false)
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
		_, tpm := createSim(false, false)
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
		_, tpm := createSim(false, false)
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
		_, tpm := createSim(false, false)
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
		_, tpm := createSim(false, false)
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
		_, tpm := createSim(false, false)
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
		_, tpm := createSim(false, false)
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
		_, tpm := createSim(false, false)
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
		_, tpm := createSim(false, false)
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
		_, tpm := createSim(false, false)
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
		_, tpm := createSim(false, false)
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
			_, tpm := createSim(false, false)
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
		_, tpm := createSim(false, false)
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
		_, tpm := createSim(false, false)
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
		_, tpm := createSim(false, false)
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
		_, tpm := createSim(false, false)
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
		_, tpm := createSim(false, false)
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
		_, tpm := createSim(false, false)
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
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	userPIN := store.NewClearPassword([]byte("user-pin"))

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
	keyAttrs.Parent.TPMAttributes.HierarchyAuth = store.NewClearPassword([]byte("wrong-pin"))
	_, err = tpm.NVIncrement(keyAttrs)
	assert.Error(t, err)

	// Restore correct auth and clean up
	keyAttrs.Parent.TPMAttributes.HierarchyAuth = userPIN
	err = tpm.NVUndefine(keyAttrs)
	assert.NoError(t, err)
}

// TestNVExtendWithHierarchyAuth tests extend operations with hierarchy authentication
func TestNVExtendWithHierarchyAuth(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	userPIN := store.NewClearPassword([]byte("user-pin"))

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
	keyAttrs.Parent.TPMAttributes.HierarchyAuth = store.NewClearPassword([]byte("wrong-pin"))
	err = tpm.NVExtend(keyAttrs, []byte("more data"))
	assert.Error(t, err)

	// Restore correct auth and clean up
	keyAttrs.Parent.TPMAttributes.HierarchyAuth = userPIN
	err = tpm.NVUndefine(keyAttrs)
	assert.NoError(t, err)
}
