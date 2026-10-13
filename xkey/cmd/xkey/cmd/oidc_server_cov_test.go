package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newOIDCImportFlagsCmd returns a command carrying the token import flags.
func newOIDCImportFlagsCmd(t *testing.T, flags map[string]string) *cobra.Command {
	t.Helper()

	cmd := &cobra.Command{}
	cmd.Flags().String("codex-auth", "", "")
	cmd.Flags().String("access-token", "", "")
	cmd.Flags().String("refresh-token", "", "")
	for name, value := range flags {
		require.NoError(t, cmd.Flags().Set(name, value))
	}
	return cmd
}

func TestReadSecretFlag_LiteralValuePassesThrough(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetIn(iotest.ErrReader(errors.New("stdin must not be read")))

	got, err := readSecretFlag(cmd, "sk-literal")
	require.NoError(t, err)
	assert.Equal(t, "sk-literal", got)
}

func TestReadSecretFlag_DashReadsStdinAndTrimsLineEnding(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetIn(strings.NewReader("sk-from-stdin\r\n"))

	got, err := readSecretFlag(cmd, "-")
	require.NoError(t, err)
	assert.Equal(t, "sk-from-stdin", got)
}

func TestReadSecretFlag_UnreadableStdin(t *testing.T) {
	cause := errors.New("stdin closed")
	cmd := &cobra.Command{}
	cmd.SetIn(iotest.ErrReader(cause))

	_, err := readSecretFlag(cmd, "-")
	assert.ErrorIs(t, err, ErrOIDCTokenStoreFailed)
	assert.ErrorIs(t, err, cause)
}

func TestOIDCImportedTokens_AccessAndRefreshTokens(t *testing.T) {
	cmd := newOIDCImportFlagsCmd(t, map[string]string{"access-token": "-", "refresh-token": "rt-literal"})
	cmd.SetIn(strings.NewReader("at-from-stdin\n"))

	tokens, err := oidcImportedTokens(cmd)
	require.NoError(t, err)
	assert.Equal(t, "at-from-stdin", tokens.AccessToken)
	assert.Equal(t, "rt-literal", tokens.RefreshToken)
}

func TestOIDCImportedTokens_Errors(t *testing.T) {
	dir := t.TempDir()
	corrupt := filepath.Join(dir, "auth.json")
	require.NoError(t, os.WriteFile(corrupt, []byte("not json"), 0o600))

	tests := []struct {
		name   string
		flags  map[string]string
		stdin  error
		wantIs error
	}{
		{name: "no source", wantIs: ErrOIDCImportSource},
		{
			name:   "both sources",
			flags:  map[string]string{"codex-auth": corrupt, "access-token": "at"},
			wantIs: ErrOIDCImportSource,
		},
		{
			name:   "codex file missing",
			flags:  map[string]string{"codex-auth": filepath.Join(dir, "missing.json")},
			wantIs: ErrOIDCTokenStoreFailed,
		},
		{
			name:   "access token stdin unreadable",
			flags:  map[string]string{"access-token": "-"},
			stdin:  errors.New("stdin closed"),
			wantIs: ErrOIDCTokenStoreFailed,
		},
		{
			name:   "refresh token stdin unreadable",
			flags:  map[string]string{"access-token": "at", "refresh-token": "-"},
			stdin:  errors.New("stdin closed"),
			wantIs: ErrOIDCTokenStoreFailed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newOIDCImportFlagsCmd(t, tt.flags)
			if tt.stdin != nil {
				cmd.SetIn(iotest.ErrReader(tt.stdin))
			}

			tokens, err := oidcImportedTokens(cmd)
			assert.ErrorIs(t, err, tt.wantIs)
			assert.Nil(t, tokens)
		})
	}
}

func TestOIDCImportedTokens_CorruptCodexAuth(t *testing.T) {
	corrupt := filepath.Join(t.TempDir(), "auth.json")
	require.NoError(t, os.WriteFile(corrupt, []byte("not json"), 0o600))
	cmd := newOIDCImportFlagsCmd(t, map[string]string{"codex-auth": corrupt})

	tokens, err := oidcImportedTokens(cmd)
	assert.Error(t, err)
	assert.Nil(t, tokens)
}
