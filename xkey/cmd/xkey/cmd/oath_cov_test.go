package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/qrscan"
)

const (
	scanTOTPURI = "otpauth://totp/Example:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA256&issuer=Example"
	scanHOTPURI = "otpauth://hotp/Bank?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA256&counter=3"
)

// withScreen replaces the host display capture with displays screens
// showing the given scan results.
func withScreen(t *testing.T, displays int, results []*qrscan.ScanResult, scanErr error) {
	t.Helper()

	origNum, origScan := oathNumDisplays, oathScanScreen
	oathNumDisplays = func() int { return displays }
	oathScanScreen = func(int) ([]*qrscan.ScanResult, error) { return results, scanErr }
	t.Cleanup(func() { oathNumDisplays, oathScanScreen = origNum, origScan })
}

func TestRunOATHScan_ListsEveryDisplay(t *testing.T) {
	withScreen(t, 2, nil, nil)
	cmd, buf := newOATHCmd(t, oathScanCmd, oathStorePath(t))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "list-displays", "true"))

	require.NoError(t, runOATHScan(cmd, nil))
	assert.Contains(t, buf.String(), "Found 2 display(s):\n  Display 0\n  Display 1\n")
}

func TestRunOATHScan_ScreenErrors(t *testing.T) {
	cause := errors.New("capture denied")
	tests := []struct {
		name     string
		displays int
		scanErr  error
		wantIs   error
		wantOut  string
	}{
		{name: "no displays", displays: 0, wantIs: ErrOATHScanFailed},
		{name: "no QR code", displays: 1, scanErr: qrscan.ErrNoQRCodeFound, wantIs: ErrOATHNoQRFound},
		{
			name: "QR without otpauth URI", displays: 1, scanErr: qrscan.ErrInvalidQRContent,
			wantIs: ErrOATHNoQRFound, wantOut: "none contain valid otpauth:// URIs",
		},
		{name: "capture failure", displays: 1, scanErr: cause, wantIs: cause},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withScreen(t, tt.displays, nil, tt.scanErr)
			cmd, buf := newOATHCmd(t, oathScanCmd, oathStorePath(t))

			err := runOATHScan(cmd, nil)
			assert.ErrorIs(t, err, tt.wantIs)
			assert.Contains(t, buf.String(), tt.wantOut)
		})
	}
}

func TestRunOATHScan_MultipleCodesRequireIndex(t *testing.T) {
	withScreen(t, 1, []*qrscan.ScanResult{
		{URI: scanTOTPURI}, {URI: "otpauth://bogus"}, {URI: scanHOTPURI},
	}, nil)
	store := oathStorePath(t)
	cmd, buf := newOATHCmd(t, oathScanCmd, store)

	err := runOATHScan(cmd, nil)
	assert.ErrorIs(t, err, ErrOATHMultipleQRFound)
	out := buf.String()
	assert.Contains(t, out, "Found 3 QR codes")
	assert.Contains(t, out, "[0] Example (alice@example.com) (Example) - TOTP 6-digit")
	assert.Contains(t, out, "[1] (parse error:")
	assert.Contains(t, out, "[2] Bank - HOTP 6-digit")
	assert.Contains(t, out, "Use --index <N>")
	_, statErr := os.Stat(store)
	assert.True(t, os.IsNotExist(statErr), "nothing is stored until a code is chosen")
}

func TestRunOATHScan_IndexSelectsAndNameOverrides(t *testing.T) {
	withScreen(t, 1, []*qrscan.ScanResult{{URI: scanTOTPURI}, {URI: scanHOTPURI}}, nil)
	store := oathStorePath(t)
	cmd, buf := newOATHCmd(t, oathScanCmd, store)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "index", "1"))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "name", "Savings"))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "yes", "true"))

	require.NoError(t, runOATHScan(cmd, nil))
	out := buf.String()
	assert.Contains(t, out, "Name:      Savings")
	assert.Contains(t, out, "Type:      HOTP")
	assert.NotContains(t, out, "Period:")
	assert.Contains(t, out, "Added OATH credential: Savings")
	assert.Equal(t, []string{"Savings"}, oathStoreNames(t, store))
}

func TestRunOATHScan_ConfirmationDefaultsToYes(t *testing.T) {
	withScreen(t, 1, []*qrscan.ScanResult{{URI: scanTOTPURI}}, nil)
	store := oathStorePath(t)
	pipeStdin(t, "\n")
	cmd, buf := newOATHCmd(t, oathScanCmd, store)

	require.NoError(t, runOATHScan(cmd, nil))
	out := buf.String()
	assert.Contains(t, out, "Issuer:    Example")
	assert.Contains(t, out, "Period:    30s")
	assert.Contains(t, out, "Add this credential? [Y/n]: ")
	assert.Equal(t, []string{"Example (alice@example.com)"}, oathStoreNames(t, store))
}

func TestRunOATHScan_ConfirmationDeclined(t *testing.T) {
	withScreen(t, 1, []*qrscan.ScanResult{{URI: scanTOTPURI}}, nil)
	store := oathStorePath(t)
	pipeStdin(t, "n\n")
	cmd, buf := newOATHCmd(t, oathScanCmd, store)

	require.NoError(t, runOATHScan(cmd, nil))
	assert.Contains(t, buf.String(), "Cancelled.")
	_, statErr := os.Stat(store)
	assert.True(t, os.IsNotExist(statErr), "a declined credential is never stored")
}

func TestRunOATHScan_ConfirmationUnreadable(t *testing.T) {
	withScreen(t, 1, []*qrscan.ScanResult{{URI: scanTOTPURI}}, nil)
	pipeStdin(t, "")
	cmd, _ := newOATHCmd(t, oathScanCmd, oathStorePath(t))

	err := runOATHScan(cmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read input")
}

func TestRunOATHScan_InvalidURI(t *testing.T) {
	withScreen(t, 1, []*qrscan.ScanResult{{URI: "otpauth://bogus"}}, nil)
	cmd, _ := newOATHCmd(t, oathScanCmd, oathStorePath(t))

	assert.ErrorIs(t, runOATHScan(cmd, nil), ErrOATHInvalidURI)
}

func TestRunOATHScan_StoreFailures(t *testing.T) {
	withScreen(t, 1, []*qrscan.ScanResult{{URI: scanTOTPURI}}, nil)

	t.Run("store cannot open", func(t *testing.T) {
		blocker := filepath.Join(t.TempDir(), "file")
		require.NoError(t, os.WriteFile(blocker, nil, 0o600))
		cmd, _ := newOATHCmd(t, oathScanCmd, filepath.Join(blocker, "oath.json"))
		require.NoError(t, setFlagForTest(t, cmd.Flags(), "yes", "true"))

		assert.ErrorIs(t, runOATHScan(cmd, nil), ErrOATHStoreOpenFailed)
	})

	t.Run("credential already stored", func(t *testing.T) {
		store := oathStorePath(t)
		cmd, _ := newOATHCmd(t, oathScanCmd, store)
		require.NoError(t, setFlagForTest(t, cmd.Flags(), "yes", "true"))
		require.NoError(t, runOATHScan(cmd, nil))

		cmd, _ = newOATHCmd(t, oathScanCmd, store)
		require.NoError(t, setFlagForTest(t, cmd.Flags(), "yes", "true"))
		assert.ErrorIs(t, runOATHScan(cmd, nil), ErrOATHAddFailed)
	})
}

func TestOATHCommands_StoreOpenFailure(t *testing.T) {
	tests := []struct {
		name string
		cmd  *cobra.Command
		run  func(*cobra.Command, []string) error
		args []string
	}{
		{name: "list", cmd: oathListCmd, run: runOATHList},
		{name: "generate", cmd: oathGenerateCmd, run: runOATHGenerate, args: []string{"github"}},
		{name: "remove", cmd: oathRemoveCmd, run: runOATHRemove, args: []string{"github"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocker := filepath.Join(t.TempDir(), "file")
			require.NoError(t, os.WriteFile(blocker, nil, 0o600))
			cmd, _ := newOATHCmd(t, tt.cmd, filepath.Join(blocker, "oath.json"))

			assert.ErrorIs(t, tt.run(cmd, tt.args), ErrOATHStoreOpenFailed)
		})
	}
}
