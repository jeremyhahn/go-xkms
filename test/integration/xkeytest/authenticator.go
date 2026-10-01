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

// Package xkeytest runs xkey's headless CTAP2 virtual authenticator for an
// integration suite, standing in for an attached FIDO2 security key: the
// "xkey fido2" daemon over /dev/uhid, its hidraw node, and the user
// presence a human would give. It needs root (uhid, mknod), so the suites
// that use it run under sudo in the devcontainer.
package xkeytest

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// hidrawClass is the kernel's hidraw device class in sysfs.
const hidrawClass = "/sys/class/hidraw"

// readyTimeout bounds the wait for the authenticator's hidraw node.
const readyTimeout = 10 * time.Second

// Authenticator is a running virtual authenticator.
type Authenticator struct {
	t      testing.TB
	device string
	cancel context.CancelFunc
	cmd    *exec.Cmd
	out    bytes.Buffer
	pump   chan struct{}
	once   sync.Once
}

// StartAuthenticator starts bin (the xkey binary) with args -- an "xkey
// fido2" invocation -- in home, feeding it stdin, waits until its hidraw
// node opens, and approves its user-presence requests until it is stopped.
// It is stopped when the test ends; Stop stops it earlier.
func StartAuthenticator(t testing.TB, bin, home string, args []string, stdin string) *Authenticator {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	a := &Authenticator{t: t, cancel: cancel, pump: make(chan struct{})}
	// Other virtual authenticators may run on the host (the hidraw class is
	// the kernel's, not the container's): ours is the one that appears.
	before := authenticatorNodes()
	a.cmd = exec.CommandContext(ctx, bin, args...)
	// xkey's default storage paths are relative to the working directory
	// and its home: pin both to the test's home so a run as root leaves
	// nothing in the repository and reaches no other xkey instance (under
	// sudo, xkey otherwise resolves the invoking user's home).
	a.cmd.Dir = home
	a.cmd.Env = homeEnv(home)
	a.cmd.Stdin = strings.NewReader(stdin)
	a.cmd.Stdout = &a.out
	a.cmd.Stderr = &a.out
	if err := a.cmd.Start(); err != nil {
		cancel()
		t.Fatalf("xkeytest: start the virtual authenticator: %v", err)
	}
	go a.touchPump(ctx, bin, home)
	t.Cleanup(a.Stop)

	// The daemon reaches clients through /dev/hidrawX, and the devcontainer
	// runs no udev to create that node, so create it from sysfs.
	deadline := time.Now().Add(readyTimeout)
	for a.device = newAuthenticatorNode(t, before); a.device == ""; a.device = newAuthenticatorNode(t, before) {
		if time.Now().After(deadline) {
			a.Stop()
			t.Fatalf("xkeytest: the virtual authenticator never surfaced an openable hidraw device:\n%s", a.out.String())
		}
		timer := time.NewTimer(200 * time.Millisecond)
		<-timer.C
	}
	return a
}

// Device returns the authenticator's hidraw device path, the --device a
// FIDO2 client names it by.
func (a *Authenticator) Device() string { return a.device }

// Stop stops the authenticator: afterwards no security key is attached.
func (a *Authenticator) Stop() {
	a.once.Do(func() {
		a.cancel()
		<-a.pump
		_ = a.cmd.Wait()
		if a.t.Failed() {
			a.t.Logf("xkey fido2 output:\n%s", a.out.String())
		}
	})
}

// touchPump approves the daemon's user-presence requests by running "xkey
// touch" against its IPC socket -- the one its home derives -- until ctx
// ends. A touch with no pending request is a no-op.
func (a *Authenticator) touchPump(ctx context.Context, bin, home string) {
	defer close(a.pump)
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			touch := exec.CommandContext(ctx, bin, "touch")
			touch.Dir = home
			touch.Env = homeEnv(home)
			_ = touch.Run()
		}
	}
}

// homeEnv is the environment that makes home an xkey process's whole home.
func homeEnv(home string) []string {
	return append(os.Environ(), "HOME="+home, "XKEY_HOME="+home, "XKEY_DATA_DIR="+filepath.Join(home, "data"))
}

// authenticatorNodes returns the hidraw entries of virtual CTAP2
// authenticators.
func authenticatorNodes() map[string]bool {
	nodes := map[string]bool{}
	entries, err := os.ReadDir(hidrawClass)
	if err != nil {
		return nodes
	}
	for _, entry := range entries {
		if isAuthenticatorHidraw(entry.Name()) {
			nodes[entry.Name()] = true
		}
	}
	return nodes
}

// newAuthenticatorNode creates the /dev node of the authenticator entry
// that is not in before and returns its path once it opens, or "" while
// there is none.
func newAuthenticatorNode(t testing.TB, before map[string]bool) string {
	for name := range authenticatorNodes() {
		if before[name] {
			continue
		}
		devPath := "/dev/" + name
		if err := ensureNode(name, devPath); err != nil {
			t.Logf("xkeytest: %v", err)
			continue
		}
		if f, err := os.OpenFile(devPath, os.O_RDWR, 0); err == nil {
			_ = f.Close()
			return devPath
		}
	}
	return ""
}

// ensureNode creates devPath, the character node of hidraw entry name, from
// the device numbers sysfs publishes ("major:minor"); a node left by an
// earlier run with stale numbers is recreated.
func ensureNode(name, devPath string) error {
	raw, err := os.ReadFile(hidrawClass + "/" + name + "/dev")
	if err != nil {
		return err
	}
	var major, minor uint32
	if _, err := fmt.Sscanf(strings.TrimSpace(string(raw)), "%d:%d", &major, &minor); err != nil {
		return err
	}
	rdev := unix.Mkdev(major, minor)
	var st unix.Stat_t
	switch err := unix.Stat(devPath, &st); {
	case err == nil && st.Rdev == rdev:
		return nil
	case err == nil:
		if err := os.Remove(devPath); err != nil {
			return err
		}
	}
	return unix.Mknod(devPath, unix.S_IFCHR|0o600, int(rdev))
}

// isAuthenticatorHidraw reports whether the hidraw entry is the virtual
// CTAP2 authenticator, from the HID_ID line of its uevent
// ("bus:vendor:product"): vendor 0xF1D0, product 0x0001. The daemon's
// virtual keyboard shares the vendor (product 0x0004).
func isAuthenticatorHidraw(name string) bool {
	raw, err := os.ReadFile(hidrawClass + "/" + name + "/device/uevent")
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
