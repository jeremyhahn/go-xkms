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

//go:build integration && swtpm

// Package keybackend — swtpm backend integration tests.
//
// Registers a tpm2 BackendType entry in the TestAllBackends_* matrix that runs
// against a REAL ephemeral swtpm exposed as a unix-socket device (the
// fido2-hardware docker-compose starts swtpm with --create-ek-cert on a unix
// socket; the test opens it via TPM_DEVICE, default /tmp/swtpm/swtpm.sock, the
// same way real hardware is opened). It NEVER opens the host /dev/tpmrm0 and
// NEVER uses the in-process MS simulator.
//
// The swtpm is provisioned exactly ONCE per test binary (provisioning RSA EK/
// SSRK/PlatformSRK/IAK is expensive — tens of seconds — so doing it per subtest
// would blow the test timeout) and a SINGLE backend connection is shared across
// every subtest. The initial connect/provision is retried to absorb the brief
// window after swtpm start where it returns TPM_RC_RETRY/TPM_RC_INITIALIZE.
package keybackend

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/require"
)

func init() {
	registerBackend(backendEntry{
		name:     "tpm2",
		skip:     requireSwtpm,
		adapter:  newSwtpmAdapter,
		hardware: true,
	})
}

// swtpmDevice returns the swtpm unix-socket device path the integration
// container exposes (set by fido2-hardware-entrypoint.sh). xkms opens this
// exactly like a real hardware TPM device (a ".sock" device is served via
// linuxudstpm) — no TCP, no in-process simulator.
func swtpmDevice() string {
	if d := os.Getenv("TPM_DEVICE"); d != "" {
		return d
	}
	return "/tmp/swtpm/swtpm.sock"
}

// requireSwtpm fails the tpm2 entry when no swtpm device socket is present.
// swtpm is a software TPM started by the integration container entrypoint, so
// a missing socket is an environment fault that must be reported rather than
// silently dropping the whole TPM2 matrix.
func requireSwtpm(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(swtpmDevice()); err != nil {
		t.Fatalf("swtpm device %s not present: %v; start swtpm or run this suite "+
			"via the devcontainer (make integration-test)", swtpmDevice(), err)
	}
}

// Shared, provisioned swtpm-backed TPM2 backend. The swtpm is a single stateful
// instance; provisioning is expensive and must happen once. All matrix subtests
// reuse swtpmBackend via NewBackendAdapter, and the underlying socket connection
// stays open for the lifetime of the test binary (reclaimed on exit).
var (
	swtpmOnce    sync.Once
	swtpmBackend xkms.KeyProvider
	swtpmErr     error
)

// provisionSwtpmOnce opens the swtpm via its unix-socket device, provisions it
// (retrying the transient TPM_RC_RETRY window right after swtpm start), and
// builds one shared TPM2 backend over the provisioned TPM instance.
func provisionSwtpmOnce() {
	logger := slog.Default()
	device := swtpmDevice()

	// Dedicated blob directory so the backend's ListKeys can enumerate the
	// FIDO2 child-key blobs it writes (see TPM2 backend keyDir handling).
	keyDir, err := os.MkdirTemp("", "fido2-swtpm-*")
	if err != nil {
		swtpmErr = &WrappedError{Msg: "temp key dir", Err: err}
		return
	}
	factory, err := xkms.NewTPMStorageFactory(logger, keyDir)
	if err != nil {
		swtpmErr = &WrappedError{Msg: "tpm storage factory", Err: err}
		return
	}
	keyBackend := factory.KeyBackend()

	// Open the swtpm via its unix-socket device, exactly like real hardware.
	cfg := xkms.DefaultTPMConfig
	cfg.UseSimulator = false
	cfg.Device = device

	// Retry the initial open + provision: swtpm can return TPM_RC_RETRY for a
	// short window after startup before it is ready to service commands.
	const maxAttempts = 40
	var tpm xkms.TrustedPlatformModule
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		params := &xkms.TPMParams{Logger: logger, Config: &cfg}
		tpm, err = xkms.NewTPM2(params)
		// NewTPM2 returns a usable TPM both when fully provisioned (err == nil)
		// and when the EK exists but other keys are missing (ErrTPMNotInitialized).
		// Because swtpm_setup --create-ek-cert pre-creates the EK, NewTPM2 may
		// succeed yet the SRK is absent, so always run Provision (idempotent: it
		// creates only the keys that don't exist) to guarantee EK+SRK+IAK.
		if err == nil || errors.Is(err, xkms.ErrTPMNotInitialized) {
			provErr := tpm.Provision(nil)
			if provErr == nil {
				// Provision is TCG-only (EK + Shared SRK + IAK).
				// xkms.NewTPM2BackendWithTPM below resolves its storage
				// parent exclusively off the Platform SRK -- never the
				// Shared SRK -- so it must be enrolled here too.
				if psrkErr := xkms.EnrollSimulatorPlatformSRK(tpm, &cfg); psrkErr != nil {
					_ = tpm.Close()
					swtpmErr = &WrappedError{Msg: "swtpm Platform SRK enrollment", Err: psrkErr}
					return
				}
				err = nil
				break
			}
			_ = tpm.Close()
			if isTransientTPMError(provErr) {
				time.Sleep(500 * time.Millisecond)
				continue
			}
			swtpmErr = &WrappedError{Msg: "swtpm Provision", Err: provErr}
			return
		}
		if isTransientTPMError(err) {
			if tpm != nil {
				_ = tpm.Close()
			}
			time.Sleep(500 * time.Millisecond)
			continue
		}
		swtpmErr = &WrappedError{Msg: "swtpm NewTPM2", Err: err}
		return
	}
	if err != nil || tpm == nil {
		swtpmErr = &MessageError{Msg: fmt.Sprintf("swtpm not ready after %d attempts: %v", maxAttempts, err)}
		return
	}

	backend, err := xkms.NewTPM2BackendWithTPM(&xkms.TPM2BackendExternalConfig{
		TPM:        tpm,
		KeyBackend: keyBackend,
		KeyDir:     keyDir,
		Logger:     logger,
	})
	if err != nil {
		_ = tpm.Close()
		swtpmErr = &WrappedError{Msg: "tpm2 backend over swtpm", Err: err}
		return
	}
	swtpmBackend = backend
}

// isTransientTPMError reports whether the error is a retryable swtpm-not-ready
// condition (TPM_RC_RETRY / TPM_RC_INITIALIZE during the startup window).
func isTransientTPMError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "TPM_RC_RETRY") || strings.Contains(msg, "TPM_RC_INITIALIZE")
}

// newSwtpmAdapter returns a FIDO2 BackendAdapter over the shared, provisioned
// swtpm-backed TPM2 backend.
func newSwtpmAdapter(t *testing.T) *BackendAdapter {
	t.Helper()
	requireSwtpm(t)
	swtpmOnce.Do(provisionSwtpmOnce)
	require.NoError(t, swtpmErr, "swtpm provisioning failed")
	require.NotNil(t, swtpmBackend, "swtpm backend not provisioned")
	return NewBackendAdapter(swtpmBackend, xkms.BackendTypeTPM2)
}
