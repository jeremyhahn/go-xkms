// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

//go:build ble

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	pkgxkms "github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// errShareTestRadio stands in for a phone link that drops mid-share.
var errShareTestRadio = errors.New("radio link lost")

// shareXKMSdFixture pairs a test phone and points the xkmsd bridge at a real
// in-process xkmsd, returning a client to that daemon so a test can create
// the key it then shares.
func shareXKMSdFixture(t *testing.T) transport.Client {
	t.Helper()
	deviceInfoTestHome(t)
	isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")

	swBackend, err := software.NewBackend(&software.Config{KeyStorage: storage.NewMemory()})
	require.NoError(t, err)
	backend, err := pkgxkms.New(&pkgxkms.BackendConfig{Backend: swBackend, CertStorage: storage.NewMemory()})
	require.NoError(t, err)
	svc, err := pkgxkms.NewService(&pkgxkms.ServiceConfig{Backends: map[string]pkgxkms.Backend{"software": backend}})
	require.NoError(t, err)

	address, _ := startTestXKMSdService(t, svc)
	c704dEnableXKMSd(t, address)

	client, err := dialXKMSd(loadXKMSdBridgeConfig(), discardLogger())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	return client
}

func generateShareTestKey(t *testing.T, client transport.Client, req *transport.GenerateKeyRequest) {
	t.Helper()
	req.Backend = "software"
	_, err := client.GenerateKey(context.Background(), req)
	require.NoError(t, err)
}

func setShareTestPolicy(t *testing.T, policy *pairing.SharingPolicy) {
	t.Helper()
	store, err := loadSharingPolicyStore()
	require.NoError(t, err)
	require.NoError(t, store.SetPolicy(policy))
}

func runShareAgainstXKMSd(t *testing.T, keyID string, phone *fakeDeviceTransport) (string, error) {
	t.Helper()
	useFakeTransport(t, phone)

	var out bytes.Buffer
	cmd := deviceShareTestCmd()
	cmd.SetOut(&out)
	require.NoError(t, cmd.Flags().Set("label", "laptop key"))
	err := runDeviceShare(cmd, []string{"software", keyID})
	return out.String(), err
}

func TestRunDeviceShare_SendsTheXKMSdPublicKeyToThePhone(t *testing.T) {
	client := shareXKMSdFixture(t)
	generateShareTestKey(t, client, &transport.GenerateKeyRequest{
		KeyID: "signing-key", KeyType: "ECDSA", Algorithm: "ECDSA", Curve: "P-256",
	})
	setShareTestPolicy(t, &pairing.SharingPolicy{
		Backend: "software", KeyID: "signing-key", AllowShare: true, SharePublic: true,
	})
	key, err := client.GetKey(context.Background(), "software", "signing-key")
	require.NoError(t, err)

	phone := &fakeDeviceTransport{results: map[string]any{
		pairingproto.MethodLocalSharePublicKey: &pairingproto.LocalSharePublicKeyResult{Accepted: true, ImportID: "import-7"},
	}}
	out, err := runShareAgainstXKMSd(t, "signing-key", phone)
	require.NoError(t, err)

	assert.Contains(t, out, "Public key accepted (import ID: import-7)")
	assert.Contains(t, out, "Key sharing completed successfully.")
	assert.True(t, phone.connected)
	assert.True(t, phone.closed)
	require.Len(t, phone.wire, 1, "a public-only policy must send exactly one request")

	var sent pairingproto.LocalSharePublicKeyParams
	require.NoError(t, json.Unmarshal(phone.wire[0], &sent))
	assert.Equal(t, key.PublicKeyPEM, string(sent.PublicKeyPEM), "the phone must receive xkmsd's public key")
	assert.Equal(t, "laptop key", sent.Label)
	assert.Equal(t, "signing-key", sent.KeyID)
}

func TestRunDeviceShare_SendsExportedSymmetricMaterialToThePhone(t *testing.T) {
	client := shareXKMSdFixture(t)
	generateShareTestKey(t, client, &transport.GenerateKeyRequest{
		KeyID: "wrap-key", KeyType: "symmetric", Algorithm: "aes256-gcm", KeySize: 256, Exportable: true,
	})
	setShareTestPolicy(t, &pairing.SharingPolicy{
		Backend: "software", KeyID: "wrap-key", AllowShare: true, ShareSymmetric: true,
	})
	export, err := client.ExportKeyMaterial(context.Background(), &transport.ExportKeyMaterialRequest{Backend: "software", KeyID: "wrap-key"})
	require.NoError(t, err)

	phone := &fakeDeviceTransport{results: map[string]any{
		pairingproto.MethodLocalShareSymmetric: &pairingproto.LocalShareSymmetricResult{Accepted: false},
	}}
	out, err := runShareAgainstXKMSd(t, "wrap-key", phone)
	require.NoError(t, err)

	assert.Contains(t, out, "Symmetric key rejected by phone.")
	require.Len(t, phone.wire, 1, "a symmetric-only policy must send exactly one request")

	var sent pairingproto.LocalShareSymmetricParams
	require.NoError(t, json.Unmarshal(phone.wire[0], &sent))
	assert.Equal(t, export.KeyMaterial, sent.WrappedKey, "the phone must receive the exported key bytes")
	assert.Equal(t, export.KeySize, sent.KeySize)
	assert.NotEmpty(t, sent.Algorithm)
}

func TestRunDeviceShare_PhoneFailuresAreShareErrors(t *testing.T) {
	tests := []struct {
		name  string
		phone *fakeDeviceTransport
		want  error
	}{
		{"connect fails", &fakeDeviceTransport{connectErr: errShareTestRadio}, ErrShareConnectFailed},
		{"send fails", &fakeDeviceTransport{sendErr: errShareTestRadio}, ErrShareRequestFailed},
		{"phone answers with an error", &fakeDeviceTransport{rpcErrors: map[string]*pairingproto.RPCError{
			pairingproto.MethodLocalSharePublicKey: {Code: -32000, Message: "storage full"},
		}}, ErrShareRequestFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := shareXKMSdFixture(t)
			generateShareTestKey(t, client, &transport.GenerateKeyRequest{
				KeyID: "signing-key", KeyType: "ECDSA", Algorithm: "ECDSA", Curve: "P-256",
			})
			setShareTestPolicy(t, &pairing.SharingPolicy{
				Backend: "software", KeyID: "signing-key", AllowShare: true, SharePublic: true,
			})

			out, err := runShareAgainstXKMSd(t, "signing-key", tt.phone)
			require.ErrorIs(t, err, tt.want)
			assert.NotContains(t, out, "completed successfully")
			assert.True(t, tt.phone.closed, "the phone link must be closed on failure")
		})
	}
}

func TestRunDeviceShare_SymmetricSendFailureIsAShareError(t *testing.T) {
	client := shareXKMSdFixture(t)
	generateShareTestKey(t, client, &transport.GenerateKeyRequest{
		KeyID: "wrap-key", KeyType: "symmetric", Algorithm: "aes256-gcm", KeySize: 256, Exportable: true,
	})
	setShareTestPolicy(t, &pairing.SharingPolicy{
		Backend: "software", KeyID: "wrap-key", AllowShare: true, ShareSymmetric: true,
	})

	_, err := runShareAgainstXKMSd(t, "wrap-key", &fakeDeviceTransport{sendErr: errShareTestRadio})
	require.ErrorIs(t, err, ErrShareRequestFailed)
	require.ErrorIs(t, err, errShareTestRadio)
}

func TestRunDeviceShare_UnexportableKeyFailsBeforeThePhone(t *testing.T) {
	client := shareXKMSdFixture(t)
	generateShareTestKey(t, client, &transport.GenerateKeyRequest{
		KeyID: "wrap-key", KeyType: "symmetric", Algorithm: "aes256-gcm", KeySize: 256, Sensitive: true,
	})
	setShareTestPolicy(t, &pairing.SharingPolicy{
		Backend: "software", KeyID: "wrap-key", AllowShare: true, ShareSymmetric: true,
	})

	phone := &fakeDeviceTransport{}
	_, err := runShareAgainstXKMSd(t, "wrap-key", phone)
	require.ErrorIs(t, err, ErrShareKeyLoadFailed)
	assert.False(t, phone.connected, "nothing may reach the phone when the key cannot be read")
}

func TestLoadSharedKeyMaterial_ReadsPublicKeyWithoutSecret(t *testing.T) {
	client := shareXKMSdFixture(t)
	generateShareTestKey(t, client, &transport.GenerateKeyRequest{
		KeyID: "signing-key", KeyType: "ECDSA", Algorithm: "ECDSA", Curve: "P-256", Exportable: true,
	})

	material, err := loadSharedKeyMaterial("software", "signing-key", false, discardLogger())
	require.NoError(t, err)
	defer material.KeyMaterial.Destroy()

	assert.Contains(t, string(material.PublicKeyPEM), "PUBLIC KEY")
	assert.Zero(t, material.KeyMaterial.Size(), "secret material must not be fetched unless asked for")
}

func TestLoadSharedKeyMaterial_UnknownKeyFails(t *testing.T) {
	shareXKMSdFixture(t)

	_, err := loadSharedKeyMaterial("software", "missing-key", true, discardLogger())
	require.ErrorIs(t, err, ErrShareKeyLoadFailed)
}
