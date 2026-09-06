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

//go:build integration && logins

package logins

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/spki"
)

// This leg drives the real xkey CLI (auth register / auth login) through a
// headless CTAP2 ceremony against the server's WebAuthn relying party,
// exactly as an operator running "xkey auth login" would, minus the touch:
// a standalone "xkey fido2 --require-touch=false --pin=false" daemon (see
// VirtualAuthenticatorArgv in argv.go) stands in for the attached security
// key, and startTouchPump supplies the presence a human would.
//
// The public-route-vs-client_auth coupling that once broke this leg is
// resolved: since go-qrdb v0.5.7-alpha, module-declared PUBLIC routes
// (HandlePublic -> RESTRoutePublic) short-circuit BEFORE authentication, so
// the anonymous WebAuthn ceremony works even with tls.client_auth "verify"
// enabled for the mTLS/PIV legs.
//
// Note: xkmsd's WebAuthn ceremony mints a
// single opaque access token with no refresh
// (pkg/api/transport/types.go FinishAuthenticationResponse.Token), unlike
// the PIV session login-plane's TokenPair, so this leg only ever asserts a
// token is minted and that it authenticates - it does not assert
// refresh/logout rotation for FIDO2 sessions.

var (
	xkeyBinOnce sync.Once
	xkeyBinPath string
	xkeyBinErr  error
)

// xkeyBinary returns the path to the xkey CLI binary, building it from the
// sibling xkey module when XKEY_CLI_BIN is not set. Mirrors
// test/integration/api's xkeyBinary helper.
func xkeyBinary(t *testing.T) string {
	t.Helper()
	xkeyBinOnce.Do(func() {
		if p := strings.TrimSpace(os.Getenv("XKEY_CLI_BIN")); p != "" {
			xkeyBinPath = p
			return
		}
		moduleDir, err := filepath.Abs(filepath.Join("..", "..", "..", "xkey"))
		if err != nil {
			xkeyBinErr = err
			return
		}
		dir, mkErr := os.MkdirTemp("", "xkey-cli-")
		if mkErr != nil {
			xkeyBinErr = mkErr
			return
		}
		out := filepath.Join(dir, "xkey")
		cmd := exec.Command("go", "build", "-tags", "codec_json", "-o", out, "./cmd/xkey")
		cmd.Dir = moduleDir
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if berr := cmd.Run(); berr != nil {
			xkeyBinErr = fmt.Errorf("build xkey CLI: %w: %s", berr, stderr.String())
			return
		}
		xkeyBinPath = out
	})
	require.NoError(t, xkeyBinErr, "xkey binary unavailable")
	return xkeyBinPath
}

// hostPort strips the scheme from a base URL, e.g.
// "https://xkms-server:8443" -> "xkms-server:8443".
func hostPort(t *testing.T, baseURL string) string {
	t.Helper()
	u, err := url.Parse(baseURL)
	require.NoError(t, err)
	require.NotEmpty(t, u.Host)
	return u.Host
}

// runXkey runs the xkey binary with args against home, returning combined
// stdout+stderr. It fails the test on a non-zero exit so callers only need
// to assert on the returned output when they expect success.
func runXkey(t *testing.T, ctx context.Context, bin, home string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(ctx, bin, args...)
	// xkey's default storage paths (auth data, password store, ...) are
	// relative to the process cwd, not $HOME; without pinning Dir here a
	// sudo'd test run leaves root-owned directories inside the repo.
	cmd.Dir = home
	cmd.Env = append(os.Environ(), "HOME="+home)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	require.NoError(t, err, "xkey %s failed:\n%s", strings.Join(args, " "), out.String())
	return out.String()
}

// startVirtualAuthenticator starts the xkey binary with
// VirtualAuthenticatorArgv in the background, standing in for an attached
// CTAP2 security key, and registers a cleanup that stops it. It uses
// in-memory credential storage (the default), so credentials live only for
// the daemon's lifetime - exactly one register+login exchange.
func startVirtualAuthenticator(t *testing.T, bin, home string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())

	cmd := exec.CommandContext(ctx, bin, VirtualAuthenticatorArgv...)
	// See runXkey: pin Dir so the daemon's relative storage paths
	// (./data/staticpw by default) land under the per-test tmp dir instead
	// of the repo working tree.
	cmd.Dir = home
	cmd.Env = append(os.Environ(), "HOME="+home)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	require.NoError(t, cmd.Start(), "start xkey fido2 virtual authenticator")

	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("xkey fido2 output:\n%s", out.String())
		}
	})

	// The daemon opens a uhid device and starts serving CTAP2 requests
	// almost immediately, but the CTAP client in "auth register" reaches it
	// through /dev/hidrawX, and the devcontainer runs no udev to create
	// that node when the kernel registers the virtual device. The suite
	// runs as root (the same sudo the uhid open needs), so poll sysfs for
	// the new hidraw entry and mknod its device node ourselves; on a host
	// with udev the node already exists and the mknod is skipped.
	require.Eventually(t, func() bool {
		return ensureHidrawNodes(t)
	}, 10*time.Second, 200*time.Millisecond,
		"virtual FIDO2 authenticator never surfaced an openable hidraw device")

	startTouchPump(t, bin)
}

// startTouchPump approves the daemon's user-presence requests for the
// test's lifetime by invoking "xkey touch" against the daemon's IPC socket
// in a loop. CTAP2 semantics require user presence on MakeCredential /
// GetAssertion whenever no PIN auth proves user interaction, so a headless
// run must supply the "touch" the way an operator's approval dialog would.
// A touch with no pending request is a cheap no-op, so pumping is safe.
func startTouchPump(t *testing.T, bin string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		<-done
	})

	go func() {
		defer close(done)
		ticker := time.NewTicker(300 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				socks, _ := filepath.Glob("/tmp/xkey-*/xkey.sock")
				for _, sock := range socks {
					cmd := exec.CommandContext(ctx, bin, "touch", "--socket", sock)
					_ = cmd.Run()
				}
			}
		}
	}()
}

// ensureHidrawNodes creates /dev/hidrawX character nodes for every
// /sys/class/hidraw entry that lacks one, returning true once at least one
// FIDO-vendor (0xF1D0) hidraw node exists and opens. The vendor gate
// matters: the daemon also registers a virtual keyboard, and the host can
// carry unrelated HID devices (a VM's QEMU USB tablet), so "some hidraw
// node opened" is not "the authenticator is ready". sysfs publishes the
// device numbers in each entry's "dev" file as "major:minor".
func ensureHidrawNodes(t *testing.T) bool {
	t.Helper()
	entries, err := os.ReadDir("/sys/class/hidraw")
	if err != nil || len(entries) == 0 {
		return false
	}
	ready := false
	for _, entry := range entries {
		devPath := filepath.Join("/dev", entry.Name())
		raw, err := os.ReadFile(filepath.Join("/sys/class/hidraw", entry.Name(), "dev"))
		if err != nil {
			continue
		}
		var major, minor uint32
		if _, err := fmt.Sscanf(strings.TrimSpace(string(raw)), "%d:%d", &major, &minor); err != nil {
			continue
		}
		rdev := unix.Mkdev(major, minor)

		// A node left behind by an earlier run can carry a stale device
		// number; recreate it whenever it disagrees with sysfs.
		var st unix.Stat_t
		switch err := unix.Stat(devPath, &st); {
		case err == nil && st.Rdev == rdev:
			// Node exists and matches.
		case err == nil:
			if err := os.Remove(devPath); err != nil {
				t.Logf("remove stale %s: %v", devPath, err)
				continue
			}
			fallthrough
		default:
			if err := unix.Mknod(devPath, unix.S_IFCHR|0o600, int(rdev)); err != nil {
				t.Logf("mknod %s: %v", devPath, err)
				continue
			}
		}
		if !isFIDOVendorHidraw(entry.Name()) {
			continue
		}
		if f, err := os.OpenFile(devPath, os.O_RDWR, 0); err == nil {
			_ = f.Close()
			ready = true
		}
	}
	return ready
}

// isFIDOVendorHidraw reports whether the hidraw sysfs entry is the virtual
// CTAP2 authenticator (vendor 0xF1D0, product 0x0001), read from the HID_ID
// line of the device uevent ("bus:vendor:product" in hex). The product
// check matters too: the daemon's virtual keyboard shares the 0xF1D0
// vendor (product 0x0004), and readiness on the keyboard alone would race
// the authenticator's registration.
func isFIDOVendorHidraw(name string) bool {
	raw, err := os.ReadFile(filepath.Join("/sys/class/hidraw", name, "device", "uevent"))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		id, ok := strings.CutPrefix(line, "HID_ID=")
		if !ok {
			continue
		}
		parts := strings.Split(strings.TrimSpace(id), ":")
		if len(parts) != 3 {
			return false
		}
		var vendor, product uint32
		if _, err := fmt.Sscanf(parts[1], "%X", &vendor); err != nil {
			return false
		}
		if _, err := fmt.Sscanf(parts[2], "%X", &product); err != nil {
			return false
		}
		return vendor == 0xF1D0 && product == 0x0001
	}
	return false
}

// TestFIDO2Login_RegisterAndLogin drives a full WebAuthn register+login
// ceremony through the real xkey CLI against a headless virtual
// authenticator, and asserts the issued token authenticates a
// session-gated REST route.
func TestFIDO2Login_RegisterAndLogin(t *testing.T) {
	for _, tgt := range targets() {
		t.Run(tgt.Name, func(t *testing.T) {
			bin := xkeyBinary(t)
			home := t.TempDir()

			pin, _, err := spki.FetchServerPinWithCA(hostPort(t, tgt.BaseURL), loadCAPool(t, tgt))
			require.NoError(t, err, "compute the server's SPKI pin for trust-on-first-use registration")

			startVirtualAuthenticator(t, bin, home)

			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			username := "logins-fido2-test"
			runXkey(t, ctx, bin, home,
				"auth", "register",
				"--server", tgt.WebAuthnURL,
				"--spki-pin", pin,
				"--username", username,
			)

			runXkey(t, ctx, bin, home,
				"auth", "login",
				"--server", tgt.WebAuthnURL,
				"--username", username,
			)

			token := strings.TrimSpace(runXkey(t, ctx, bin, home, "auth", "token", "--server", tgt.WebAuthnURL))
			require.NotEmpty(t, token, "auth login must store a token auth token can print")

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, tgt.BaseURL+"/api/v1/auth/me", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+token)

			resp, err := httpClient(t, tgt, nil).Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()
			require.Equal(t, http.StatusOK, resp.StatusCode, "the FIDO2-issued token must authenticate /api/v1/auth/me")
		})
	}
}
