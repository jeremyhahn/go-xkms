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

//go:build integration && passwordvault

package password

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/test/integration/xkmsdtest"
)

// The personal password vault, end to end: a real xkmsd (xkmsdtest) and
// the real xkmsctl and xkey binaries, with every vault factor on its real
// token -- passphrase, passkey on xkey's virtual FIDO2 authenticator,
// certificate key, TPM key on the swtpm fixture under "platform" and under
// a named policy, and PIV slot 9d on a SoftHSM token -- plus the recovery
// code, the isolation of one user's personal entries from another's, and
// the xKey browser bridge through the real native-messaging host.
//
// It runs in the devcontainer as root (the virtual authenticator needs
// /dev/uhid): make integration-test-password-vault. The binaries come from
// XKMSD_BIN, XKMSCTL_BIN and XKEY_CLI_BIN, which the target builds.

// vault is the running server and the binaries driven against it.
var vault struct {
	server  *xkmsdtest.Server
	xkmsctl string
	xkey    string
}

func TestMain(m *testing.M) {
	code, err := runVaultSuite(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, "password vault integration:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

// runVaultSuite starts the server, runs the suite and stops the server.
func runVaultSuite(m *testing.M) (int, error) {
	bins := map[string]string{}
	for _, name := range []string{"XKMSD_BIN", "XKMSCTL_BIN", "XKEY_CLI_BIN"} {
		path := os.Getenv(name)
		if path == "" {
			return 0, &missingBinaryError{env: name}
		}
		bins[name] = path
	}
	vault.xkmsctl, vault.xkey = bins["XKMSCTL_BIN"], bins["XKEY_CLI_BIN"]
	// The local-store suite in this package runs the same xkey.
	binaryOnce.Do(func() { binaryPath = vault.xkey })

	work, err := os.MkdirTemp("", "password-vault-it-")
	if err != nil {
		return 0, err
	}
	server, err := xkmsdtest.Start(bins["XKMSD_BIN"], filepath.Join(work, "xkmsd"))
	if err != nil {
		return 0, err
	}
	vault.server = server
	code := m.Run()
	if code != 0 {
		fmt.Fprintln(os.Stderr, "xkmsd log tail:\n"+server.LogTail(60))
	}
	return code, errors.Join(server.Close(), os.RemoveAll(work))
}

// missingBinaryError reports a binary the target did not provide.
type missingBinaryError struct{ env string }

func (e *missingBinaryError) Error() string {
	return e.env + " is not set: run the suite with make integration-test-password-vault"
}
