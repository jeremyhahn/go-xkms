package cmd

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

func TestWriteVaultStatus_ListsFactorsAndKeyReference(t *testing.T) {
	const fingerprint = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	resp := &transport.PasswordVaultStatusResponse{
		Initialized: true,
		Unlocked:    false,
		Factors: []transport.PasswordVaultFactor{
			{ID: "f-passphrase", Factor: "passphrase", Label: "daily", CreatedAt: "2026-10-01T00:00:00Z"},
			{
				ID: "f-key", Factor: "key", Label: "tpm", CreatedAt: "2026-10-02T00:00:00Z",
				KeyFingerprint: fingerprint,
				KeyRef:         transport.PasswordVaultKeyRef{Backend: "tpm2", KeyID: "vault-key", TPMPolicy: "boot"},
			},
		},
		PasskeyRPID: "kms.example.com",
	}

	var out bytes.Buffer
	require.NoError(t, writeVaultStatus(&out, resp))

	got := out.String()
	assert.Contains(t, got, "Initialized:  Yes")
	assert.Contains(t, got, "Unlocked:     No")
	assert.Contains(t, got, "f-passphrase")
	assert.Contains(t, got, "key tpm2/vault-key  fingerprint "+fingerprint[:16]+"  policy boot")
	assert.NotContains(t, got, fingerprint, "status shows the short fingerprint only")
	assert.Contains(t, got, "Passkeys for: kms.example.com")
	assert.NotContains(t, got, "Factors:      none")
}

func TestWriteVaultStatus_NoFactorsPointsAtEnroll(t *testing.T) {
	var out bytes.Buffer
	require.NoError(t, writeVaultStatus(&out, &transport.PasswordVaultStatusResponse{}))

	got := out.String()
	assert.Contains(t, got, "Initialized:  No")
	assert.Contains(t, got, "Factors:      none (enroll one with 'xkey password vault enroll')")
	assert.NotContains(t, got, "Passkeys for:")
}

func TestWriteVaultStatus_ShortFingerprintIsShownWhole(t *testing.T) {
	// The fingerprint is a server-supplied string; one shorter than the
	// display width must be printed as is, not crash the CLI.
	resp := &transport.PasswordVaultStatusResponse{
		Initialized: true,
		Factors: []transport.PasswordVaultFactor{{
			ID: "f-key", Factor: "key", KeyFingerprint: "abc123",
			KeyRef: transport.PasswordVaultKeyRef{Backend: "pkcs11", KeyID: "k"},
		}},
	}

	var out bytes.Buffer
	require.NoError(t, writeVaultStatus(&out, resp))
	assert.Contains(t, out.String(), "key pkcs11/k  fingerprint abc123\n")
}

func TestWriteVaultEnrollResult_RecoveryCodeShownOnce(t *testing.T) {
	resp := &transport.PasswordVaultEnrollResponse{
		Factor: transport.PasswordVaultFactor{
			ID: "f-key", Factor: "key", Label: "yubikey", CreatedAt: "2026-10-02T00:00:00Z",
			KeyFingerprint: "feedface",
			KeyRef:         transport.PasswordVaultKeyRef{Backend: "pkcs11", KeyID: "slot-9d"},
		},
		RecoveryCode: "AAAA-BBBB-CCCC",
	}

	var out bytes.Buffer
	require.NoError(t, writeVaultEnrollResult(&out, "Enrolled", resp))

	got := out.String()
	assert.True(t, strings.HasPrefix(got, "Enrolled:\n"))
	assert.Contains(t, got, "Label:    yubikey")
	assert.Contains(t, got, "Key:      pkcs11/slot-9d (fingerprint feedface)")
	assert.Contains(t, got, "RECOVERY CODE")
	assert.Contains(t, got, "  AAAA-BBBB-CCCC\n")
}

func TestWritePasswordValue(t *testing.T) {
	ctx := context.Background()

	t.Run("writes the secret's bytes", func(t *testing.T) {
		secret, err := secure.NewSecret(ctx, []byte("hunter2"))
		require.NoError(t, err)
		t.Cleanup(secret.Destroy)

		var out bytes.Buffer
		writePasswordValue(ctx, &out, secret)
		assert.Equal(t, "hunter2", out.String())
	})

	t.Run("nil secret writes nothing", func(t *testing.T) {
		var out bytes.Buffer
		writePasswordValue(ctx, &out, nil)
		assert.Empty(t, out.String())
	})

	t.Run("destroyed secret reports the error inline", func(t *testing.T) {
		secret, err := secure.NewSecret(ctx, []byte("hunter2"))
		require.NoError(t, err)
		secret.Destroy()

		var out bytes.Buffer
		writePasswordValue(ctx, &out, secret)
		assert.True(t, strings.HasPrefix(out.String(), "<error: "), "got %q", out.String())
		assert.NotContains(t, out.String(), "hunter2")
	})
}
