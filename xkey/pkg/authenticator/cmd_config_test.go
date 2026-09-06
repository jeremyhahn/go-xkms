// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package authenticator

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// TestDecodeConfigRequest tests the decodeConfigRequest function.
func TestDecodeConfigRequest(t *testing.T) {
	t.Run("empty data returns error", func(t *testing.T) {
		_, err := decodeConfigRequest(nil)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrConfigMissingSubCommand)

		_, err = decodeConfigRequest([]byte{})
		require.Error(t, err)
		require.ErrorIs(t, err, ErrConfigMissingSubCommand)
	})

	t.Run("invalid CBOR returns error", func(t *testing.T) {
		_, err := decodeConfigRequest([]byte{0xFF, 0xFF, 0xFF})
		require.Error(t, err)
		require.ErrorIs(t, err, ErrCBORDecodingFailed)
	})

	t.Run("missing subCommand returns error", func(t *testing.T) {
		data, err := cbor.Marshal(map[int]interface{}{
			configKeyPinUvAuthProtocol: PINProtocol1,
		})
		require.NoError(t, err)

		_, err = decodeConfigRequest(data)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrConfigMissingSubCommand)
	})

	t.Run("invalid subCommand type returns error", func(t *testing.T) {
		data, err := cbor.Marshal(map[int]interface{}{
			configKeySubCommand: "invalid", // should be integer
		})
		require.NoError(t, err)

		_, err = decodeConfigRequest(data)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidParameter)
	})

	t.Run("invalid subCommandParams type returns error", func(t *testing.T) {
		data, err := cbor.Marshal(map[int]interface{}{
			configKeySubCommand:       AuthConfigCmdEnableEnterpriseAttestation,
			configKeySubCommandParams: "invalid", // should be map
		})
		require.NoError(t, err)

		_, err = decodeConfigRequest(data)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidParameter)
	})

	t.Run("invalid pinUvAuthProtocol type returns error", func(t *testing.T) {
		data, err := cbor.Marshal(map[int]interface{}{
			configKeySubCommand:        AuthConfigCmdEnableEnterpriseAttestation,
			configKeyPinUvAuthProtocol: "invalid",
		})
		require.NoError(t, err)

		_, err = decodeConfigRequest(data)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidParameter)
	})

	t.Run("invalid pinUvAuthParam type returns error", func(t *testing.T) {
		data, err := cbor.Marshal(map[int]interface{}{
			configKeySubCommand:     AuthConfigCmdEnableEnterpriseAttestation,
			configKeyPinUvAuthParam: 12345, // should be bytes
		})
		require.NoError(t, err)

		_, err = decodeConfigRequest(data)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidParameter)
	})

	t.Run("valid request decodes successfully", func(t *testing.T) {
		params := map[interface{}]interface{}{
			"test": "value",
		}
		authParam := []byte{0x01, 0x02, 0x03}

		data, err := cbor.Marshal(map[int]interface{}{
			configKeySubCommand:        AuthConfigCmdToggleAlwaysUv,
			configKeySubCommandParams:  params,
			configKeyPinUvAuthProtocol: PINProtocol1,
			configKeyPinUvAuthParam:    authParam,
		})
		require.NoError(t, err)

		req, err := decodeConfigRequest(data)
		require.NoError(t, err)
		require.Equal(t, uint8(AuthConfigCmdToggleAlwaysUv), req.subCommand)
		require.Equal(t, uint8(PINProtocol1), req.pinUvAuthProtocol)
		require.Equal(t, authParam, req.pinUvAuthParam)
		require.NotNil(t, req.subCommandParams)
	})
}

// TestHandleConfig tests the main config dispatcher.
func TestHandleConfig(t *testing.T) {
	t.Run("invalid subCommand returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticator(t)
		defer func() { _ = auth.Close() }()

		data, err := cbor.Marshal(map[int]interface{}{
			configKeySubCommand: uint8(0x50), // invalid, not in valid range
		})
		require.NoError(t, err)

		_, err = auth.handleConfig(data)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidSubcommand)
	})

	t.Run("vendor prototype with valid subCommand", func(t *testing.T) {
		auth := createTestConfigAuthenticator(t)
		defer func() { _ = auth.Close() }()

		// Vendor command without vendorCmd parameter should fail
		data, err := cbor.Marshal(map[int]interface{}{
			configKeySubCommand: uint8(AuthConfigCmdVendorPrototype),
		})
		require.NoError(t, err)

		_, err = auth.handleConfig(data)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidParameter)
	})
}

// TestHandleConfigEnableEnterpriseAttestation tests the enterprise attestation subcommand.
func TestHandleConfigEnableEnterpriseAttestation(t *testing.T) {
	t.Run("success without PIN", func(t *testing.T) {
		auth := createTestConfigAuthenticatorNoPIN(t)
		defer func() { _ = auth.Close() }()

		data, err := cbor.Marshal(map[int]interface{}{
			configKeySubCommand: AuthConfigCmdEnableEnterpriseAttestation,
		})
		require.NoError(t, err)

		resp, err := auth.handleConfig(data)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp[0])
	})

	t.Run("requires PIN auth when PIN is set", func(t *testing.T) {
		auth := createTestConfigAuthenticator(t)
		defer func() { _ = auth.Close() }()

		err := auth.SetInitialPIN("123456")
		require.NoError(t, err)

		data, err := cbor.Marshal(map[int]interface{}{
			configKeySubCommand: AuthConfigCmdEnableEnterpriseAttestation,
		})
		require.NoError(t, err)

		_, err = auth.handleConfig(data)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrPINAuthInvalid)
	})

	t.Run("success with valid PIN auth", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithPINToken(t)
		defer func() { _ = auth.Close() }()

		authParam := createConfigAuthParam(t, auth, AuthConfigCmdEnableEnterpriseAttestation, nil)

		data, err := cbor.Marshal(map[int]interface{}{
			configKeySubCommand:        AuthConfigCmdEnableEnterpriseAttestation,
			configKeyPinUvAuthProtocol: PINProtocol1,
			configKeyPinUvAuthParam:    authParam,
		})
		require.NoError(t, err)

		resp, err := auth.handleConfig(data)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp[0])
	})
}

// TestHandleConfigToggleAlwaysUv tests the toggle always UV subcommand.
func TestHandleConfigToggleAlwaysUv(t *testing.T) {
	t.Run("success without PIN", func(t *testing.T) {
		auth := createTestConfigAuthenticatorNoPIN(t)
		defer func() { _ = auth.Close() }()

		initialValue := auth.config.AlwaysUV

		data, err := cbor.Marshal(map[int]interface{}{
			configKeySubCommand: AuthConfigCmdToggleAlwaysUv,
		})
		require.NoError(t, err)

		resp, err := auth.handleConfig(data)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp[0])
		require.NotEqual(t, initialValue, auth.config.AlwaysUV)
	})

	t.Run("requires PIN auth when PIN is set", func(t *testing.T) {
		auth := createTestConfigAuthenticator(t)
		defer func() { _ = auth.Close() }()

		err := auth.SetInitialPIN("123456")
		require.NoError(t, err)

		data, err := cbor.Marshal(map[int]interface{}{
			configKeySubCommand: AuthConfigCmdToggleAlwaysUv,
		})
		require.NoError(t, err)

		_, err = auth.handleConfig(data)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrPINAuthInvalid)
	})

	t.Run("success with valid PIN auth toggles value", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithPINToken(t)
		defer func() { _ = auth.Close() }()

		initialValue := auth.config.AlwaysUV

		authParam := createConfigAuthParam(t, auth, AuthConfigCmdToggleAlwaysUv, nil)

		data, err := cbor.Marshal(map[int]interface{}{
			configKeySubCommand:        AuthConfigCmdToggleAlwaysUv,
			configKeyPinUvAuthProtocol: PINProtocol1,
			configKeyPinUvAuthParam:    authParam,
		})
		require.NoError(t, err)

		resp, err := auth.handleConfig(data)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp[0])
		require.NotEqual(t, initialValue, auth.config.AlwaysUV)

		// Toggle again
		authParam2 := createConfigAuthParam(t, auth, AuthConfigCmdToggleAlwaysUv, nil)
		data2, err := cbor.Marshal(map[int]interface{}{
			configKeySubCommand:        AuthConfigCmdToggleAlwaysUv,
			configKeyPinUvAuthProtocol: PINProtocol1,
			configKeyPinUvAuthParam:    authParam2,
		})
		require.NoError(t, err)

		resp2, err := auth.handleConfig(data2)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp2[0])
		require.Equal(t, initialValue, auth.config.AlwaysUV)
	})
}

// TestHandleConfigSetMinPINLength tests the set minimum PIN length subcommand.
func TestHandleConfigSetMinPINLength(t *testing.T) {
	t.Run("missing params returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticatorNoPIN(t)
		defer func() { _ = auth.Close() }()

		data, err := cbor.Marshal(map[int]interface{}{
			configKeySubCommand: AuthConfigCmdSetMinPINLength,
		})
		require.NoError(t, err)

		_, err = auth.handleConfig(data)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidParameter)
	})

	t.Run("missing newMinPINLength returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticatorNoPIN(t)
		defer func() { _ = auth.Close() }()

		data, err := cbor.Marshal(map[int]interface{}{
			configKeySubCommand: AuthConfigCmdSetMinPINLength,
			configKeySubCommandParams: map[interface{}]interface{}{
				"other": "param",
			},
		})
		require.NoError(t, err)

		_, err = auth.handleConfig(data)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidParameter)
	})

	t.Run("newMinPINLength below default fails", func(t *testing.T) {
		auth := createTestConfigAuthenticatorNoPIN(t)
		defer func() { _ = auth.Close() }()

		data, err := cbor.Marshal(map[int]interface{}{
			configKeySubCommand: AuthConfigCmdSetMinPINLength,
			configKeySubCommandParams: map[interface{}]interface{}{
				"newMinPINLength": uint8(2), // below minimum
			},
		})
		require.NoError(t, err)

		_, err = auth.handleConfig(data)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrPINPolicyViolation)
	})

	t.Run("success with valid newMinPINLength", func(t *testing.T) {
		auth := createTestConfigAuthenticatorNoPIN(t)
		defer func() { _ = auth.Close() }()

		newLength := uint8(8)

		data, err := cbor.Marshal(map[int]interface{}{
			configKeySubCommand: AuthConfigCmdSetMinPINLength,
			configKeySubCommandParams: map[interface{}]interface{}{
				"newMinPINLength": newLength,
			},
		})
		require.NoError(t, err)

		resp, err := auth.handleConfig(data)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp[0])
		require.Equal(t, int(newLength), auth.config.PINMinLength)
	})

	t.Run("success using string key for newMinPINLength", func(t *testing.T) {
		auth := createTestConfigAuthenticatorNoPIN(t)
		defer func() { _ = auth.Close() }()

		newLength := uint8(6)

		data, err := cbor.Marshal(map[int]interface{}{
			configKeySubCommand: AuthConfigCmdSetMinPINLength,
			configKeySubCommandParams: map[interface{}]interface{}{
				"newMinPINLength": newLength,
			},
		})
		require.NoError(t, err)

		resp, err := auth.handleConfig(data)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp[0])
		require.Equal(t, int(newLength), auth.config.PINMinLength)
	})
}

// TestHandleConfigVendorPrototype tests the vendor prototype dispatcher.
func TestHandleConfigVendorPrototype(t *testing.T) {
	t.Run("nil params returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticator(t)
		defer func() { _ = auth.Close() }()

		data, err := cbor.Marshal(map[int]interface{}{
			configKeySubCommand: AuthConfigCmdVendorPrototype,
		})
		require.NoError(t, err)

		_, err = auth.handleConfig(data)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidParameter)
	})

	t.Run("missing vendorCmd returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticator(t)
		defer func() { _ = auth.Close() }()

		data, err := cbor.Marshal(map[int]interface{}{
			configKeySubCommand: AuthConfigCmdVendorPrototype,
			configKeySubCommandParams: map[interface{}]interface{}{
				"other": "param",
			},
		})
		require.NoError(t, err)

		_, err = auth.handleConfig(data)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrConfigInvalidVendorCmd)
	})

	t.Run("invalid vendorCmd type returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticator(t)
		defer func() { _ = auth.Close() }()

		data, err := cbor.Marshal(map[int]interface{}{
			configKeySubCommand: AuthConfigCmdVendorPrototype,
			configKeySubCommandParams: map[interface{}]interface{}{
				vendorParamKeyVendorCmd: "invalid",
			},
		})
		require.NoError(t, err)

		_, err = auth.handleConfig(data)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrConfigInvalidVendorCmd)
	})

	t.Run("unknown vendorCmd returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticator(t)
		defer func() { _ = auth.Close() }()

		data, err := cbor.Marshal(map[int]interface{}{
			configKeySubCommand: AuthConfigCmdVendorPrototype,
			configKeySubCommandParams: map[interface{}]interface{}{
				vendorParamKeyVendorCmd: uint8(0xFF), // unknown
			},
		})
		require.NoError(t, err)

		_, err = auth.handleConfig(data)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrConfigInvalidVendorCmd)
	})

	t.Run("vendorCmd using integer key works", func(t *testing.T) {
		auth := createTestConfigAuthenticator(t)
		defer func() { _ = auth.Close() }()

		// Use VendorCmdGetTokenInfo since it doesn't require auth. On an
		// uninitialized token it succeeds and reports the uninitialized state.
		data, err := cbor.Marshal(map[int]interface{}{
			configKeySubCommand: AuthConfigCmdVendorPrototype,
			configKeySubCommandParams: map[interface{}]interface{}{
				vendorParamKeyVendorCmd: uint8(VendorCmdGetTokenInfo),
			},
		})
		require.NoError(t, err)

		resp, err := auth.handleConfig(data)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp[0])
	})
}

// TestHandleVendorSetSOPIN tests the SO PIN initialization subcommand.
func TestHandleVendorSetSOPIN(t *testing.T) {
	t.Run("missing pin parameter returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticator(t)
		defer func() { _ = auth.Close() }()

		params := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdSetSOPIN),
		}

		_, err := handleVendorSetSOPIN(auth, params)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrConfigMissingPin)
	})

	t.Run("nil key manager returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticator(t)
		defer func() { _ = auth.Close() }()
		auth.keyManager = nil

		params := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdSetSOPIN),
			vendorParamKeyPin:       "securepin123",
		}

		_, err := handleVendorSetSOPIN(auth, params)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrKeyManagerNoSOPIN)
	})

	t.Run("success initializes SO PIN", func(t *testing.T) {
		auth := createTestConfigAuthenticator(t)
		defer func() { _ = auth.Close() }()

		params := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdSetSOPIN),
			vendorParamKeyPin:       "securepin123",
		}

		resp, err := handleVendorSetSOPIN(auth, params)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp[0])
		require.True(t, auth.keyManager.IsSOPINConfigured())
	})

	t.Run("already initialized returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticator(t)
		defer func() { _ = auth.Close() }()

		// First initialization
		params := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdSetSOPIN),
			vendorParamKeyPin:       "securepin123",
		}
		_, err := handleVendorSetSOPIN(auth, params)
		require.NoError(t, err)

		// Second initialization should fail
		_, err = handleVendorSetSOPIN(auth, params)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrKeyManagerAlreadyInitialized)
	})

	t.Run("pin as bytes works", func(t *testing.T) {
		auth := createTestConfigAuthenticator(t)
		defer func() { _ = auth.Close() }()

		params := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdSetSOPIN),
			vendorParamKeyPin:       []byte("securepin123"),
		}

		resp, err := handleVendorSetSOPIN(auth, params)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp[0])
	})
}

// TestHandleVendorChangeSOPIN tests the SO PIN change subcommand.
func TestHandleVendorChangeSOPIN(t *testing.T) {
	t.Run("missing pin parameter returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithSOPIN(t)
		defer func() { _ = auth.Close() }()

		params := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdChangeSOPIN),
			vendorParamKeyNewPin:    "newsecurepin",
		}

		_, err := handleVendorChangeSOPIN(auth, params)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrConfigMissingPin)
	})

	t.Run("missing newPin parameter returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithSOPIN(t)
		defer func() { _ = auth.Close() }()

		params := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdChangeSOPIN),
			vendorParamKeyPin:       "securepin123",
		}

		_, err := handleVendorChangeSOPIN(auth, params)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrConfigMissingNewPin)
	})

	t.Run("nil key manager returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticator(t)
		defer func() { _ = auth.Close() }()
		auth.keyManager = nil

		params := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdChangeSOPIN),
			vendorParamKeyPin:       "securepin123",
			vendorParamKeyNewPin:    "newsecurepin",
		}

		_, err := handleVendorChangeSOPIN(auth, params)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrKeyManagerNoSOPIN)
	})

	t.Run("SO PIN not set returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticator(t)
		defer func() { _ = auth.Close() }()

		params := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdChangeSOPIN),
			vendorParamKeyPin:       "securepin123",
			vendorParamKeyNewPin:    "newsecurepin",
		}

		_, err := handleVendorChangeSOPIN(auth, params)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrTokenUninitialized)
	})

	t.Run("wrong current PIN returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithSOPIN(t)
		defer func() { _ = auth.Close() }()

		params := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdChangeSOPIN),
			vendorParamKeyPin:       "wrongpin1234",
			vendorParamKeyNewPin:    "newsecurepin",
		}

		_, err := handleVendorChangeSOPIN(auth, params)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrSOPINInvalid)
	})

	t.Run("success changes SO PIN", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithSOPIN(t)
		defer func() { _ = auth.Close() }()

		params := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdChangeSOPIN),
			vendorParamKeyPin:       "securepin123",
			vendorParamKeyNewPin:    "newsecurepin",
		}

		resp, err := handleVendorChangeSOPIN(auth, params)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp[0])

		// Verify the new PIN works. Unlocking is the real check: it proves the
		// Admin Key was re-wrapped under the new SO PIN, not merely that a key
		// can be derived from it.
		auth.keyManager.Lock()
		require.NoError(t, auth.keyManager.UnlockWithSOPIN("newsecurepin"))
	})
}

// TestHandleVendorUnlockWithSOPIN tests the SO unlock subcommand.
func TestHandleVendorUnlockWithSOPIN(t *testing.T) {
	t.Run("missing pin parameter returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithSOPIN(t)
		defer func() { _ = auth.Close() }()

		params := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdUnlockWithSOPIN),
		}

		_, err := handleVendorUnlockWithSOPIN(auth, params)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrConfigMissingPin)
	})

	t.Run("nil key manager returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticator(t)
		defer func() { _ = auth.Close() }()
		auth.keyManager = nil

		params := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdUnlockWithSOPIN),
			vendorParamKeyPin:       "securepin123",
		}

		_, err := handleVendorUnlockWithSOPIN(auth, params)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrKeyManagerNoSOPIN)
	})

	t.Run("wrong PIN returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithSOPIN(t)
		defer func() { _ = auth.Close() }()

		// Lock the manager first
		auth.keyManager.Lock()

		params := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdUnlockWithSOPIN),
			vendorParamKeyPin:       "wrongpin1234",
		}

		_, err := handleVendorUnlockWithSOPIN(auth, params)
		require.Error(t, err)
	})

	t.Run("success unlocks key manager", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithSOPIN(t)
		defer func() { _ = auth.Close() }()

		// Lock the manager first
		auth.keyManager.Lock()
		require.False(t, auth.keyManager.IsSOUnlocked())

		params := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdUnlockWithSOPIN),
			vendorParamKeyPin:       "securepin123",
		}

		resp, err := handleVendorUnlockWithSOPIN(auth, params)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp[0])
		require.True(t, auth.keyManager.IsSOUnlocked())
	})
}

// TestHandleVendorResetUserPIN tests the user PIN reset subcommand.
func TestHandleVendorResetUserPIN(t *testing.T) {
	t.Run("nil key manager returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticator(t)
		defer func() { _ = auth.Close() }()
		auth.keyManager = nil

		params := map[interface{}]interface{}{
			vendorParamKeyVendorCmd:  uint8(VendorCmdResetUserPIN),
			vendorParamKeyNewPinHash: make([]byte, PINHashSize),
		}

		_, err := handleVendorResetUserPIN(auth, params)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrTokenUninitialized)
	})

	t.Run("not SO unlocked returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithSOPIN(t)
		defer func() { _ = auth.Close() }()

		// Lock the manager
		auth.keyManager.Lock()

		params := map[interface{}]interface{}{
			vendorParamKeyVendorCmd:  uint8(VendorCmdResetUserPIN),
			vendorParamKeyNewPinHash: make([]byte, PINHashSize),
		}

		_, err := handleVendorResetUserPIN(auth, params)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrKeyManagerLocked)
	})

	t.Run("missing newPinHash returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithSOPIN(t)
		defer func() { _ = auth.Close() }()

		params := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdResetUserPIN),
		}

		_, err := handleVendorResetUserPIN(auth, params)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrConfigMissingNewPinHash)
	})

	t.Run("invalid newPinHash length returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithSOPIN(t)
		defer func() { _ = auth.Close() }()

		params := map[interface{}]interface{}{
			vendorParamKeyVendorCmd:  uint8(VendorCmdResetUserPIN),
			vendorParamKeyNewPinHash: make([]byte, 8), // wrong size
		}

		_, err := handleVendorResetUserPIN(auth, params)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrConfigInvalidPinHash)
	})

	t.Run("success resets user PIN", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithSOPIN(t)
		defer func() { _ = auth.Close() }()

		newPIN := "newuserpin12"
		pinHash := sha256.Sum256([]byte(newPIN))

		params := map[interface{}]interface{}{
			vendorParamKeyVendorCmd:  uint8(VendorCmdResetUserPIN),
			vendorParamKeyNewPinHash: pinHash[:PINHashSize],
		}

		resp, err := handleVendorResetUserPIN(auth, params)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp[0])
		require.True(t, auth.state.PINSet)
		require.Equal(t, pinHash[:PINHashSize], auth.state.PINHash)
	})

	t.Run("newPinHash as string works", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithSOPIN(t)
		defer func() { _ = auth.Close() }()

		newPIN := "newuserpin12"
		pinHash := sha256.Sum256([]byte(newPIN))

		params := map[interface{}]interface{}{
			vendorParamKeyVendorCmd:  uint8(VendorCmdResetUserPIN),
			vendorParamKeyNewPinHash: string(pinHash[:PINHashSize]),
		}

		resp, err := handleVendorResetUserPIN(auth, params)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp[0])
	})
}

// TestHandleVendorReplaceAttestKey tests the attestation key replacement subcommand.
func TestHandleVendorReplaceAttestKey(t *testing.T) {
	t.Run("nil key manager returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticator(t)
		defer func() { _ = auth.Close() }()
		auth.keyManager = nil

		params := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdReplaceAttestKey),
		}

		_, err := handleVendorReplaceAttestKey(auth, params)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrTokenUninitialized)
	})

	t.Run("not SO unlocked returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithSOPIN(t)
		defer func() { _ = auth.Close() }()

		// Lock the manager
		auth.keyManager.Lock()

		params := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdReplaceAttestKey),
		}

		_, err := handleVendorReplaceAttestKey(auth, params)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrKeyManagerLocked)
	})

	// The command returns a certificate signing request rather than accepting a
	// certificate inline: a certificate can only be issued for a public key the
	// device has already generated, so an inline certificate could never
	// certify the key this command creates.
	t.Run("success replaces attestation key and returns a CSR", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithSOPIN(t)
		defer func() { _ = auth.Close() }()

		params := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdReplaceAttestKey),
		}

		resp, err := handleVendorReplaceAttestKey(auth, params)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp[0])
		require.NotEmpty(t, auth.state.WrappedAttestSO)

		var decoded map[int]interface{}
		require.NoError(t, decodeCBOR(resp[1:], &decoded))

		csrDER, ok := decoded[configResponseKeyAttestCSR].([]byte)
		require.True(t, ok, "response must carry the attestation CSR")

		csr, err := x509.ParseCertificateRequest(csrDER)
		require.NoError(t, err)
		require.NoError(t, csr.CheckSignature())
		signer, err := auth.keyManager.AttestationSigner()
		require.NoError(t, err)
		require.True(t, csr.PublicKey.(*ecdsa.PublicKey).Equal(signer.Public()))
	})
}

// TestConfigResponseKeysAreDistinct pins the authenticatorConfig response-key
// wire values and proves no two of them collide.
//
// This exists because the collision it guards against is invisible without it.
// Every other test in this file decodes by CONSTANT — `decoded[configResponseKeyAttestCSR]`
// — so two constants sharing a value compile, pass, and stay wrong until a
// client decodes the wrong field. That is exactly what happened between this
// branch and #306, which claims 0x04 and 0x05: each side was correct alone and
// each side's tests passed.
//
// Add a key here when you add one to the block. The map is written out by hand
// rather than derived, so the assertion is against an intended contract rather
// than against whatever the code currently says.
func TestConfigResponseKeysAreDistinct(t *testing.T) {
	wire := map[string]int{
		"configResponseKeyRetries":   configResponseKeyRetries,
		"configResponseKeyPolicy":    configResponseKeyPolicy,
		"configResponseKeyPolicies":  configResponseKeyPolicies,
		"configResponseKeyAttestCSR": configResponseKeyAttestCSR,
	}

	// The pinned values. A change here is a wire-contract change and has to be
	// a deliberate edit to this test, not a silent consequence of a rebase.
	require.Equal(t, 0x01, wire["configResponseKeyRetries"])
	require.Equal(t, 0x02, wire["configResponseKeyPolicy"])
	require.Equal(t, 0x03, wire["configResponseKeyPolicies"])
	require.Equal(t, 0x06, wire["configResponseKeyAttestCSR"],
		"0x04 and 0x05 belong to #306's tokenFlags and powerCycleState")

	seen := make(map[int]string, len(wire))
	for name, value := range wire {
		if other, collides := seen[value]; collides {
			t.Fatalf("response keys %s and %s both use wire value %#x", name, other, value)
		}
		seen[value] = name
	}
}

// TestHandleVendorSetAttestCert tests installing the certificate chain an
// operator's attestation CA issued for the device attestation key.
func TestHandleVendorSetAttestCert(t *testing.T) {
	// ErrTokenUninitialized, not ErrKeyManagerNoSOPIN: this gate is
	// requireSOUnlocked, the same one every other SO-gated vendor command uses.
	// An uninitialized token and an absent key manager are the same condition
	// to a caller, and it must be distinguishable from "SO unlock expired".
	t.Run("uninitialized token returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticator(t)
		defer func() { _ = auth.Close() }()
		auth.keyManager = nil

		_, err := handleVendorSetAttestCert(auth, map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdSetAttestCert),
		})

		require.ErrorIs(t, err, ErrTokenUninitialized)
	})

	t.Run("not SO unlocked returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithSOPIN(t)
		defer func() { _ = auth.Close() }()
		auth.keyManager.Lock()

		_, err := handleVendorSetAttestCert(auth, map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdSetAttestCert),
		})

		require.ErrorIs(t, err, ErrKeyManagerLocked)
	})

	t.Run("missing certificate returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithSOPIN(t)
		defer func() { _ = auth.Close() }()

		_, err := handleVendorSetAttestCert(auth, map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdSetAttestCert),
		})

		require.ErrorIs(t, err, ErrInvalidParameter)
	})

	t.Run("non-array chain parameter returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithSOPIN(t)
		defer func() { _ = auth.Close() }()

		_, err := handleVendorSetAttestCert(auth, map[interface{}]interface{}{
			vendorParamKeyVendorCmd:   uint8(VendorCmdSetAttestCert),
			vendorParamKeyAttestCert:  []byte{0x30, 0x00},
			vendorParamKeyAttestChain: "not-an-array",
		})

		require.ErrorIs(t, err, ErrInvalidParameter)
	})

	t.Run("invalid certificate returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithSOPIN(t)
		defer func() { _ = auth.Close() }()

		_, err := handleVendorSetAttestCert(auth, map[interface{}]interface{}{
			vendorParamKeyVendorCmd:  uint8(VendorCmdSetAttestCert),
			vendorParamKeyAttestCert: []byte{0x01, 0x02, 0x03},
		})

		require.ErrorIs(t, err, ErrAttestationChainInvalid)
	})

	t.Run("installs a chain issued through an intermediate", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithSOPIN(t)
		defer func() { _ = auth.Close() }()

		ca := newTestAttestationCA(t, true)
		signer, err := auth.attestation.GenerateAttestationKey()
		require.NoError(t, err)
		leafDER := ca.issueAttestationCert(t, signer.Public(), auth.state.AAGUID[:])

		intermediates := make([]interface{}, 0, 1)
		for _, der := range ca.intermediates() {
			intermediates = append(intermediates, der)
		}

		resp, err := handleVendorSetAttestCert(auth, map[interface{}]interface{}{
			vendorParamKeyVendorCmd:   uint8(VendorCmdSetAttestCert),
			vendorParamKeyAttestCert:  leafDER,
			vendorParamKeyAttestChain: intermediates,
		})

		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp[0])
		require.Equal(t, leafDER, auth.state.AttestationCert)
		require.Len(t, auth.state.AttestationCertChain, 1)
	})
}

// TestHandleVendorGetTokenInfo tests the token lifecycle reporting subcommand.
func TestHandleVendorGetTokenInfo(t *testing.T) {
	t.Run("uninitialized token reports uninitialized rather than failing", func(t *testing.T) {
		auth := createTestConfigAuthenticator(t)
		defer func() { _ = auth.Close() }()

		params := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdGetTokenInfo),
		}

		resp, err := handleVendorGetTokenInfo(auth, params)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp[0])

		respMap := decodeTokenInfo(t, resp)

		flags, ok := respMap[configResponseKeyTokenFlags]
		require.True(t, ok, "token flags must always be reported")
		require.Equal(t, uint64(0), flags)
		require.Equal(t, "uninitialized", TokenFlags(0).String())

		// A retry count on a token with no Security Officer would read as
		// "there are attempts left", so it is absent.
		_, ok = respMap[configResponseKeyRetries]
		require.False(t, ok, "an uninitialized token must not report SO retries")
	})

	t.Run("SOPINManager nil reports uninitialized", func(t *testing.T) {
		auth := createTestConfigAuthenticator(t)
		defer func() { _ = auth.Close() }()
		auth.state.SOPINManager = nil

		params := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdGetTokenInfo),
		}

		resp, err := handleVendorGetTokenInfo(auth, params)
		require.NoError(t, err)

		respMap := decodeTokenInfo(t, resp)
		require.Equal(t, uint64(0), respMap[configResponseKeyTokenFlags])
	})

	t.Run("initialized token reports flags, retries and power cycle state", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithSOPIN(t)
		defer func() { _ = auth.Close() }()

		params := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdGetTokenInfo),
		}

		resp, err := handleVendorGetTokenInfo(auth, params)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp[0])

		respMap := decodeTokenInfo(t, resp)

		require.Equal(t, uint64(TokenFlagInitialized), respMap[configResponseKeyTokenFlags])

		retries, err := toUint8(respMap[configResponseKeyRetries])
		require.NoError(t, err)
		require.Equal(t, uint8(DefaultSOPINMaxRetries), retries)

		require.Equal(t, false, respMap[configResponseKeyPowerCycleState])
	})

	t.Run("failures surface as PKCS#11 count-low and power cycle state", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithSOPIN(t)
		defer func() { _ = auth.Close() }()

		for i := 0; i < SOPINMaxConsecutiveFailures; i++ {
			auth.keyManager.Lock()
			require.Error(t, auth.keyManager.UnlockWithSOPIN("wrongpin999"))
		}

		params := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdGetTokenInfo),
		}
		resp, err := handleVendorGetTokenInfo(auth, params)
		require.NoError(t, err)

		respMap := decodeTokenInfo(t, resp)
		flags := TokenFlags(respMap[configResponseKeyTokenFlags].(uint64))
		require.NotZero(t, flags&TokenFlagInitialized)
		require.NotZero(t, flags&TokenFlagSOPINCountLow, "flags: %s", flags)
		require.Equal(t, true, respMap[configResponseKeyPowerCycleState])
	})
}

// decodeTokenInfo decodes a token-info response body.
func decodeTokenInfo(t *testing.T, resp []byte) map[int]interface{} {
	t.Helper()

	var respMap map[int]interface{}
	require.NoError(t, cbor.Unmarshal(resp[1:], &respMap))
	return respMap
}

// TestVerifyConfigPinUvAuth tests the PIN auth verification for config operations.
func TestVerifyConfigPinUvAuth(t *testing.T) {
	t.Run("PIN not enabled passes without auth", func(t *testing.T) {
		auth := createTestConfigAuthenticatorNoPIN(t)
		defer func() { _ = auth.Close() }()

		req := &configRequest{
			subCommand: AuthConfigCmdToggleAlwaysUv,
		}

		err := auth.verifyConfigPinUvAuth(req, AuthConfigCmdToggleAlwaysUv)
		require.NoError(t, err)
	})

	t.Run("PIN enabled but not set passes", func(t *testing.T) {
		auth := createTestConfigAuthenticator(t)
		defer func() { _ = auth.Close() }()

		req := &configRequest{
			subCommand: AuthConfigCmdToggleAlwaysUv,
		}

		err := auth.verifyConfigPinUvAuth(req, AuthConfigCmdToggleAlwaysUv)
		require.NoError(t, err)
	})

	t.Run("PIN set but no auth param fails", func(t *testing.T) {
		auth := createTestConfigAuthenticator(t)
		defer func() { _ = auth.Close() }()

		err := auth.SetInitialPIN("123456")
		require.NoError(t, err)

		req := &configRequest{
			subCommand: AuthConfigCmdToggleAlwaysUv,
		}

		err = auth.verifyConfigPinUvAuth(req, AuthConfigCmdToggleAlwaysUv)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrPINAuthInvalid)
	})

	t.Run("wrong PIN protocol fails", func(t *testing.T) {
		auth := createTestConfigAuthenticator(t)
		defer func() { _ = auth.Close() }()

		err := auth.SetInitialPIN("123456")
		require.NoError(t, err)

		req := &configRequest{
			subCommand:        AuthConfigCmdToggleAlwaysUv,
			pinUvAuthProtocol: 3, // unsupported
			pinUvAuthParam:    make([]byte, 16),
		}

		err = auth.verifyConfigPinUvAuth(req, AuthConfigCmdToggleAlwaysUv)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrUnsupportedPINProtocol)
	})

	t.Run("invalid auth param fails", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithPINToken(t)
		defer func() { _ = auth.Close() }()

		req := &configRequest{
			subCommand:        AuthConfigCmdToggleAlwaysUv,
			pinUvAuthProtocol: PINProtocol1,
			pinUvAuthParam:    make([]byte, 16), // invalid
		}

		err := auth.verifyConfigPinUvAuth(req, AuthConfigCmdToggleAlwaysUv)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrPINAuthInvalid)
	})

	t.Run("valid auth param passes", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithPINToken(t)
		defer func() { _ = auth.Close() }()

		authParam := createConfigAuthParam(t, auth, AuthConfigCmdToggleAlwaysUv, nil)

		req := &configRequest{
			subCommand:        AuthConfigCmdToggleAlwaysUv,
			pinUvAuthProtocol: PINProtocol1,
			pinUvAuthParam:    authParam,
		}

		err := auth.verifyConfigPinUvAuth(req, AuthConfigCmdToggleAlwaysUv)
		require.NoError(t, err)
	})

	t.Run("missing config permission fails", func(t *testing.T) {
		auth := createTestConfigAuthenticator(t)
		defer func() { _ = auth.Close() }()

		err := auth.SetInitialPIN("123456")
		require.NoError(t, err)

		// Initialize PIN protocol without config permission
		initKeyAgreement(t, auth)

		// Generate platform key agreement ONCE - reuse for both encryption and request
		auth.mu.Lock()
		platformCOSE, sharedSecret, _ := auth.generatePlatformKeyAgreement()
		auth.mu.Unlock()

		pinHashEnc, err := encryptPINHash(sharedSecret, "123456")
		require.NoError(t, err)

		tokenReq := map[int]interface{}{
			clientPINKeyPinUvAuthProtocol: PINProtocol1,
			clientPINKeySubCommand:        ClientPINSubCmdGetPinUvAuthTokenUsingPinWithPermissions,
			clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
			clientPINKeyPinHashEnc:        pinHashEnc,
			clientPINKeyPermissions:       PINPermissionMakeCredential, // No config permission
		}

		tokenReqBytes, err := cbor.Marshal(tokenReq)
		require.NoError(t, err)

		_, err = auth.ProcessCBOR(CmdClientPIN, tokenReqBytes)
		require.NoError(t, err)

		// Now try config operation
		token := auth.GetPinUvAuthToken()
		require.NotNil(t, token)

		// Build auth message
		msg := make([]byte, 0, 34)
		for i := 0; i < 32; i++ {
			msg = append(msg, 0xFF)
		}
		msg = append(msg, CmdConfig)
		msg = append(msg, AuthConfigCmdToggleAlwaysUv)

		mac := hmac.New(sha256.New, token)
		mac.Write(msg)
		authParam := mac.Sum(nil)[:16]

		req := &configRequest{
			subCommand:        AuthConfigCmdToggleAlwaysUv,
			pinUvAuthProtocol: PINProtocol1,
			pinUvAuthParam:    authParam,
		}

		err = auth.verifyConfigPinUvAuth(req, AuthConfigCmdToggleAlwaysUv)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrOperationDenied)
	})
}

// TestVerifyConfigHMAC tests the HMAC verification for config operations.
func TestVerifyConfigHMAC(t *testing.T) {
	t.Run("nil protocol returns false", func(t *testing.T) {
		auth := createTestConfigAuthenticator(t)
		defer func() { _ = auth.Close() }()

		result := auth.verifyConfigHMAC([]byte("test"), []byte{0x01, 0x02})
		require.False(t, result)
	})

	t.Run("nil token returns false", func(t *testing.T) {
		auth := createTestConfigAuthenticator(t)
		defer func() { _ = auth.Close() }()

		auth.pinState.protocol = &pinProtocolState{}

		result := auth.verifyConfigHMAC([]byte("test"), []byte{0x01, 0x02})
		require.False(t, result)
	})

	t.Run("wrong MAC returns false", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithPINToken(t)
		defer func() { _ = auth.Close() }()

		result := auth.verifyConfigHMAC([]byte("test"), make([]byte, 16))
		require.False(t, result)
	})

	t.Run("valid MAC returns true", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithPINToken(t)
		defer func() { _ = auth.Close() }()

		token := auth.GetPinUvAuthToken()
		require.NotNil(t, token)

		message := []byte("test message")
		mac := hmac.New(sha256.New, token)
		mac.Write(message)
		validMac := mac.Sum(nil)[:16]

		result := auth.verifyConfigHMAC(message, validMac)
		require.True(t, result)
	})

	// The CTAP 2.1 §6.5.2.1 usage timers apply to every command a token
	// authorizes. Enforcing them only on makeCredential and getAssertion would
	// leave a stale token able to reconfigure the authenticator.
	t.Run("expired token returns false even with a valid MAC", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithPINToken(t)
		defer func() { _ = auth.Close() }()

		token := auth.GetPinUvAuthToken()
		require.NotNil(t, token)

		message := []byte("test message")
		mac := hmac.New(sha256.New, token)
		mac.Write(message)
		validMac := mac.Sum(nil)[:16]

		auth.pinState.protocol.tokenLastUsed = time.Now().Add(-pinUvAuthTokenInactivityLimit - time.Second)

		require.False(t, auth.verifyConfigHMAC(message, validMac),
			"an expired token must not authorize authenticatorConfig")
	})
}

// TestExtractStringParam tests the extractStringParam helper.
func TestExtractStringParam(t *testing.T) {
	t.Run("nil params returns error", func(t *testing.T) {
		_, err := extractStringParam(nil, "key")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidParameter)
	})

	t.Run("missing key returns error", func(t *testing.T) {
		params := map[interface{}]interface{}{
			"other": "value",
		}
		_, err := extractStringParam(params, "key")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidParameter)
	})

	t.Run("wrong type returns error", func(t *testing.T) {
		params := map[interface{}]interface{}{
			"key": 12345,
		}
		_, err := extractStringParam(params, "key")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidParameter)
	})

	t.Run("string value works", func(t *testing.T) {
		params := map[interface{}]interface{}{
			"key": "value",
		}
		val, err := extractStringParam(params, "key")
		require.NoError(t, err)
		require.Equal(t, "value", val)
	})

	t.Run("bytes value converted to string", func(t *testing.T) {
		params := map[interface{}]interface{}{
			"key": []byte("value"),
		}
		val, err := extractStringParam(params, "key")
		require.NoError(t, err)
		require.Equal(t, "value", val)
	})
}

// TestExtractBytesParam tests the extractBytesParam helper.
func TestExtractBytesParam(t *testing.T) {
	t.Run("nil params returns error", func(t *testing.T) {
		_, err := extractBytesParam(nil, "key")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidParameter)
	})

	t.Run("missing key returns error", func(t *testing.T) {
		params := map[interface{}]interface{}{
			"other": []byte{0x01},
		}
		_, err := extractBytesParam(params, "key")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidParameter)
	})

	t.Run("wrong type returns error", func(t *testing.T) {
		params := map[interface{}]interface{}{
			"key": 12345,
		}
		_, err := extractBytesParam(params, "key")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidParameter)
	})

	t.Run("bytes value works", func(t *testing.T) {
		expected := []byte{0x01, 0x02, 0x03}
		params := map[interface{}]interface{}{
			"key": expected,
		}
		val, err := extractBytesParam(params, "key")
		require.NoError(t, err)
		require.Equal(t, expected, val)
	})

	t.Run("string value converted to bytes", func(t *testing.T) {
		params := map[interface{}]interface{}{
			"key": "value",
		}
		val, err := extractBytesParam(params, "key")
		require.NoError(t, err)
		require.Equal(t, []byte("value"), val)
	})
}

// TestToUint8 tests the toUint8 helper function.
func TestToUint8(t *testing.T) {
	tests := []struct {
		name    string
		input   interface{}
		want    uint8
		wantErr bool
	}{
		{"int valid", int(100), 100, false},
		{"int negative", int(-1), 0, true},
		{"int too large", int(256), 0, true},
		{"int8 valid", int8(100), 100, false},
		{"int8 negative", int8(-1), 0, true},
		{"int16 valid", int16(100), 100, false},
		{"int16 negative", int16(-1), 0, true},
		{"int16 too large", int16(256), 0, true},
		{"int32 valid", int32(100), 100, false},
		{"int32 negative", int32(-1), 0, true},
		{"int32 too large", int32(256), 0, true},
		{"int64 valid", int64(100), 100, false},
		{"int64 negative", int64(-1), 0, true},
		{"int64 too large", int64(256), 0, true},
		{"uint valid", uint(100), 100, false},
		{"uint too large", uint(256), 0, true},
		{"uint8 valid", uint8(100), 100, false},
		{"uint16 valid", uint16(100), 100, false},
		{"uint16 too large", uint16(256), 0, true},
		{"uint32 valid", uint32(100), 100, false},
		{"uint32 too large", uint32(256), 0, true},
		{"uint64 valid", uint64(100), 100, false},
		{"uint64 too large", uint64(256), 0, true},
		{"string invalid", "100", 0, true},
		{"nil invalid", nil, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := toUint8(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

// TestProcessCBORConfig tests the config command via ProcessCBOR.
func TestProcessCBORConfig(t *testing.T) {
	t.Run("config command routed correctly", func(t *testing.T) {
		auth := createTestConfigAuthenticatorNoPIN(t)
		defer func() { _ = auth.Close() }()

		data, err := cbor.Marshal(map[int]interface{}{
			configKeySubCommand: AuthConfigCmdToggleAlwaysUv,
		})
		require.NoError(t, err)

		resp, err := auth.ProcessCBOR(CmdConfig, data)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp[0])
	})

	t.Run("invalid config returns error response", func(t *testing.T) {
		auth := createTestConfigAuthenticator(t)
		defer func() { _ = auth.Close() }()

		data, err := cbor.Marshal(map[int]interface{}{
			configKeySubCommand: uint8(0x50), // invalid
		})
		require.NoError(t, err)

		resp, err := auth.ProcessCBOR(CmdConfig, data)
		require.Error(t, err)
		require.Equal(t, uint8(StatusInvalidSubcommand), resp[0])
	})
}

// Helper functions for tests.

// createTestConfigAuthenticator creates an authenticator for config tests.
func createTestConfigAuthenticator(t *testing.T) *Authenticator {
	t.Helper()

	storage := NewMemoryStorage()
	config := &Config{
		UserPresenceHandler: NewAutoGrantHandler(),
		Storage:             storage,
		EnablePIN:           true,
		PINMinLength:        4,
		PINMaxRetries:       8,
		SupportedAlgorithms: []int{COSEAlgES256},
	}

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)

	return auth
}

// createTestConfigAuthenticatorNoPIN creates an authenticator without PIN support.
func createTestConfigAuthenticatorNoPIN(t *testing.T) *Authenticator {
	t.Helper()

	storage := NewMemoryStorage()
	config := &Config{
		UserPresenceHandler: NewAutoGrantHandler(),
		Storage:             storage,
		EnablePIN:           false,
		SupportedAlgorithms: []int{COSEAlgES256},
	}

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)

	return auth
}

// createTestConfigAuthenticatorWithPINToken creates an authenticator with PIN set and token obtained.
func createTestConfigAuthenticatorWithPINToken(t *testing.T) *Authenticator {
	t.Helper()

	auth := createTestConfigAuthenticator(t)

	// Set PIN
	err := auth.SetInitialPIN("123456")
	require.NoError(t, err)

	// Get key agreement
	err = initKeyAgreement(t, auth)
	require.NoError(t, err)

	// Generate platform key and get shared secret
	auth.mu.Lock()
	platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	require.NoError(t, err)

	// Encrypt PIN hash
	pinHashEnc, err := encryptPINHash(sharedSecret, "123456")
	require.NoError(t, err)

	// Get PIN token with config permission
	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdGetPinUvAuthTokenUsingPinWithPermissions,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinHashEnc:        pinHashEnc,
		clientPINKeyPermissions:       PINPermissionAuthenticatorCfg | PINPermissionMakeCredential,
	}

	reqBytes, err := cbor.Marshal(req)
	require.NoError(t, err)

	_, err = auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.NoError(t, err)

	return auth
}

// createTestConfigAuthenticatorWithSOPIN creates an authenticator with SO PIN initialized.
func createTestConfigAuthenticatorWithSOPIN(t *testing.T) *Authenticator {
	t.Helper()

	auth := createTestConfigAuthenticator(t)

	// Initialize SO PIN
	err := auth.keyManager.InitializeSOPIN("securepin123")
	require.NoError(t, err)

	return auth
}

// createConfigAuthParam creates a valid pinUvAuthParam for config operations.
func createConfigAuthParam(t *testing.T, auth *Authenticator, subCmd uint8, params map[interface{}]interface{}) []byte {
	t.Helper()

	token := auth.GetPinUvAuthToken()
	require.NotNil(t, token)

	// Build message: 0xFF{32} || CmdConfig || subCommand || subCommandParams
	msg := make([]byte, 0, 64)
	for i := 0; i < 32; i++ {
		msg = append(msg, 0xFF)
	}
	msg = append(msg, CmdConfig)
	msg = append(msg, subCmd)

	if params != nil {
		paramsData, err := encodeCBOR(params)
		require.NoError(t, err)
		msg = append(msg, paramsData...)
	}

	mac := hmac.New(sha256.New, token)
	mac.Write(msg)
	return mac.Sum(nil)[:16]
}

// createTestConfigAuthenticatorWithPINTokenV2 creates an authenticator with PIN set
// and token obtained using PINProtocol2 (V2 key derivation, full 32-byte HMAC).
func createTestConfigAuthenticatorWithPINTokenV2(t *testing.T) *Authenticator {
	t.Helper()

	auth := createTestConfigAuthenticator(t)

	// Set PIN
	err := auth.SetInitialPIN("123456")
	require.NoError(t, err)

	// Get key agreement
	err = initKeyAgreement(t, auth)
	require.NoError(t, err)

	// Generate platform key and get V2 shared secret (HKDF-derived hmacKey + aesKey)
	auth.mu.Lock()
	platformCOSE, _, aesKey, err := auth.generatePlatformKeyAgreementV2()
	auth.mu.Unlock()
	require.NoError(t, err)

	// Encrypt PIN hash using V2 (random IV prepended)
	pinHashEnc, err := encryptPINHashV2(aesKey, "123456")
	require.NoError(t, err)

	// Get PIN token with config permission using V2
	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol2,
		clientPINKeySubCommand:        ClientPINSubCmdGetPinUvAuthTokenUsingPinWithPermissions,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinHashEnc:        pinHashEnc,
		clientPINKeyPermissions:       PINPermissionAuthenticatorCfg | PINPermissionMakeCredential,
	}

	reqBytes, err := cbor.Marshal(req)
	require.NoError(t, err)

	_, err = auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.NoError(t, err)

	return auth
}

// createConfigAuthParamV2 creates a valid pinUvAuthParam for config operations using PINProtocol2.
// Returns the full 32-byte HMAC (no truncation).
func createConfigAuthParamV2(t *testing.T, auth *Authenticator, subCmd uint8, params map[interface{}]interface{}) []byte {
	t.Helper()

	token := auth.GetPinUvAuthToken()
	require.NotNil(t, token)

	// Build message: 0xFF{32} || CmdConfig || subCommand || subCommandParams
	msg := make([]byte, 0, 64)
	for i := 0; i < 32; i++ {
		msg = append(msg, 0xFF)
	}
	msg = append(msg, CmdConfig)
	msg = append(msg, subCmd)

	if params != nil {
		paramsData, err := encodeCBOR(params)
		require.NoError(t, err)
		msg = append(msg, paramsData...)
	}

	mac := hmac.New(sha256.New, token)
	mac.Write(msg)
	return mac.Sum(nil) // Full 32 bytes for V2
}

// TestHandleConfigEnableEnterpriseAttestationV2 tests enterprise attestation with V2 PIN auth.
func TestHandleConfigEnableEnterpriseAttestationV2(t *testing.T) {
	auth := createTestConfigAuthenticatorWithPINTokenV2(t)
	defer func() { _ = auth.Close() }()

	authParam := createConfigAuthParamV2(t, auth, AuthConfigCmdEnableEnterpriseAttestation, nil)

	data, err := cbor.Marshal(map[int]interface{}{
		configKeySubCommand:        AuthConfigCmdEnableEnterpriseAttestation,
		configKeyPinUvAuthProtocol: PINProtocol2,
		configKeyPinUvAuthParam:    authParam,
	})
	require.NoError(t, err)

	resp, err := auth.handleConfig(data)
	require.NoError(t, err)
	require.Equal(t, uint8(StatusOK), resp[0])
}

// TestHandleConfigToggleAlwaysUvV2 tests toggle always UV with V2 PIN auth.
func TestHandleConfigToggleAlwaysUvV2(t *testing.T) {
	auth := createTestConfigAuthenticatorWithPINTokenV2(t)
	defer func() { _ = auth.Close() }()

	initialValue := auth.config.AlwaysUV

	authParam := createConfigAuthParamV2(t, auth, AuthConfigCmdToggleAlwaysUv, nil)

	data, err := cbor.Marshal(map[int]interface{}{
		configKeySubCommand:        AuthConfigCmdToggleAlwaysUv,
		configKeyPinUvAuthProtocol: PINProtocol2,
		configKeyPinUvAuthParam:    authParam,
	})
	require.NoError(t, err)

	resp, err := auth.handleConfig(data)
	require.NoError(t, err)
	require.Equal(t, uint8(StatusOK), resp[0])
	require.NotEqual(t, initialValue, auth.config.AlwaysUV)
}

// TestVerifyConfigHMACWithV2 tests HMAC verification using PINProtocol2 (full 32-byte HMAC).
func TestVerifyConfigHMACWithV2(t *testing.T) {
	t.Run("V2 full 32-byte HMAC accepted", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithPINTokenV2(t)
		defer func() { _ = auth.Close() }()

		token := auth.GetPinUvAuthToken()
		require.NotNil(t, token)

		message := []byte("test message for V2")
		mac := hmac.New(sha256.New, token)
		mac.Write(message)
		fullMAC := mac.Sum(nil) // Full 32 bytes

		result := auth.verifyConfigHMAC(message, fullMAC)
		require.True(t, result)
	})

	t.Run("V2 rejects V1-style truncated HMAC", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithPINTokenV2(t)
		defer func() { _ = auth.Close() }()

		token := auth.GetPinUvAuthToken()
		require.NotNil(t, token)

		message := []byte("test message for V2")
		mac := hmac.New(sha256.New, token)
		mac.Write(message)
		truncatedMAC := mac.Sum(nil)[:16] // V1-style truncation

		result := auth.verifyConfigHMAC(message, truncatedMAC)
		require.False(t, result)
	})
}
