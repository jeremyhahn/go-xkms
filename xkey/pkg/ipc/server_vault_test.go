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

package ipc

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockVaultHandler struct {
	mockHandler
	err          error
	origin       string
	fingerprints []string
}

func (h *mockVaultHandler) HandleVaultUnlockKeyFactor(origin string, fingerprints []string) (*VaultResult, error) {
	h.origin, h.fingerprints = origin, fingerprints
	if h.err != nil {
		return nil, h.err
	}
	return &VaultResult{Unlocked: true}, nil
}

func TestServer_Vault_UnlockReachesTheHandler(t *testing.T) {
	handler := &mockVaultHandler{}
	client := serveUnlockHandler(t, handler)

	resp, err := client.VaultUnlockKeyFactor("https://kms.example.com", []string{"ab12"})
	require.NoError(t, err)
	assert.Equal(t, StatusOK, resp.Status)
	require.NotNil(t, resp.Vault)
	assert.True(t, resp.Vault.Unlocked)
	assert.Equal(t, "https://kms.example.com", handler.origin)
	assert.Equal(t, []string{"ab12"}, handler.fingerprints)
}

func TestServer_Vault_RefusalsAndUnsupported(t *testing.T) {
	handler := &mockVaultHandler{err: errors.New("denied in xKey")}
	client := serveUnlockHandler(t, handler)
	resp, err := client.VaultUnlockKeyFactor("https://kms.example.com", []string{"ab12"})
	require.NoError(t, err)
	assert.Equal(t, StatusError, resp.Status)
	assert.Contains(t, resp.Error, "denied in xKey")

	// A daemon with no app to approve in answers unsupported, structurally.
	headless := serveUnlockHandler(t, &mockHandler{})
	resp, err = headless.VaultUnlockKeyFactor("https://kms.example.com", []string{"ab12"})
	require.NoError(t, err)
	assert.Equal(t, StatusError, resp.Status)
	assert.Equal(t, ActionUnsupported, resp.Action)
}

func TestVaultPayload_Validate(t *testing.T) {
	ok := VaultPayload{Action: ActionVaultUnlockKeyFactor, Origin: "https://kms.example.com", Fingerprints: []string{"ab"}}
	require.NoError(t, ok.Validate())
	for name, p := range map[string]VaultPayload{
		"action":       {Action: "export_dek", Origin: ok.Origin, Fingerprints: ok.Fingerprints},
		"origin":       {Action: ok.Action, Fingerprints: ok.Fingerprints},
		"fingerprints": {Action: ok.Action, Origin: ok.Origin},
	} {
		assert.ErrorIs(t, p.Validate(), ErrInvalidMessage, name)
	}
	assert.Error(t, (&Message{Type: MessageTypeVault}).Validate(), "a vault message needs its payload")
}
