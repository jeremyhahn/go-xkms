package cmd

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/secretservice"
)

// newSecretServiceRun returns a command carrying the secret-service password
// flags, writing to the returned buffer.
func newSecretServiceRun(t *testing.T) (*bytes.Buffer, func() error) {
	t.Helper()

	cmd := newSecretServicePasswordTestCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetContext(t.Context())
	return &buf, func() error { return runSecretService(cmd, nil) }
}

func TestRunSecretService_RequiresInitializedBarrier(t *testing.T) {
	isolateBarrier(t)
	_, run := newSecretServiceRun(t)

	err := run()
	var barrierErr *BarrierError
	require.ErrorAs(t, err, &barrierErr)
	assert.Equal(t, "check_initialized", barrierErr.Operation)
}

func TestRunSecretService_NoBusReportsStartFailure(t *testing.T) {
	tests := []struct {
		name     string
		password string
	}{
		{name: "startup password unseals", password: "correct-horse"},
		{name: "wrong startup password starts sealed", password: "wrong-horse"},
		{name: "no startup password", password: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := isolateBarrier(t)
			pipeBarrier(t, "correct-horse", "correct-horse")
			_, err := runBarrierCmd(t, runBarrierInit)
			require.NoError(t, err)

			t.Setenv("XKEY_BARRIER_PASSWORD", tt.password)
			t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+filepath.Join(dir, "no-bus"))
			buf, run := newSecretServiceRun(t)

			err = run()
			assert.ErrorIs(t, err, ErrSecretServiceStartFailed)
			assert.ErrorIs(t, err, secretservice.ErrDBusUnavailable)
			assert.NotContains(t, buf.String(), "Secret Service daemon started")
		})
	}
}

func TestSecretServiceUnlockFunc_PromptsWithoutPresetPassword(t *testing.T) {
	t.Setenv("XKEY_BARRIER_PASSWORD", "")
	pipeBarrier(t, "typed-password")
	cmd := newSecretServicePasswordTestCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	creds, err := secretServiceUnlockFunc(cmd)(context.Background())
	require.NoError(t, err)
	require.NotNil(t, creds.Secret)
	require.NoError(t, creds.Secret.Destroy())
}

func TestSecretServiceUnlockFunc_EmptyPromptIsRefused(t *testing.T) {
	t.Setenv("XKEY_BARRIER_PASSWORD", "")
	pipeBarrier(t, "")
	cmd := newSecretServicePasswordTestCmd()

	_, err := secretServiceUnlockFunc(cmd)(context.Background())
	assert.ErrorIs(t, err, ErrBarrierPasswordEmpty)
}
