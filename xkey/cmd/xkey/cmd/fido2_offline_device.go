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

package cmd

import (
	"errors"
	"io"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
)

// Offline device access.
//
// Some operator verbs — provisioning the attestation identity, initializing the
// token — change persisted device state rather than driving a live ceremony.
// They cannot go through the IPC socket: `pkg/ipc` carries no CTAP passthrough,
// and the running daemon holds the authenticator state in memory and writes it
// back on its next change, which would discard whatever was written underneath
// it. So they open the same storage the daemon would, with the daemon stopped.
//
// This file holds what every such verb repeats: the daemon-liveness refusal and
// the authenticator construction. The volatile-storage refusal stays with each
// command file, because what a memory store loses — an attestation identity, a
// Security Officer credential — is a different sentence for each.

// Offline device errors.
var (
	// ErrFIDO2DaemonRunning indicates the FIDO2 daemon holds the authenticator
	// state, so a change written offline would be overwritten.
	ErrFIDO2DaemonRunning = errors.New("fido2: the FIDO2 daemon is running and owns the device state; stop it first")

	// ErrFIDO2DaemonCheckFailed indicates the daemon liveness probe itself
	// failed, so it is not known whether the daemon holds the state.
	ErrFIDO2DaemonCheckFailed = errors.New("fido2: could not determine whether the FIDO2 daemon is running")
)

// fido2DaemonRunning reports whether the FIDO2 daemon is listening.
//
// Only "the socket is not there" and "nothing is listening on it" mean the
// daemon is absent. Any other failure leaves the question unanswered, and
// writing device state past an unanswered question is how a device ends up with
// state the daemon then overwrites, so it is an error.
func fido2DaemonRunning(socketPath string) (bool, error) {
	if socketPath == "" {
		socketPath = ipc.DefaultSocketPath()
	}

	client := ipc.NewClient(socketPath)
	defer func() { _ = client.Close() }()

	if _, err := client.Status(); err != nil {
		if errors.Is(err, ipc.ErrDaemonNotRunning) {
			return false, nil
		}
		return false, &SentinelCauseError{Sentinel: ErrFIDO2DaemonCheckFailed, Cause: err}
	}
	return true, nil
}

// newOfflineAuthenticator constructs an authenticator over already-open device
// storage for an offline operator verb.
//
// The presence handler is a required, explicit obligation: NewAuthenticator
// refuses a nil handler rather than auto-granting, and a nil-defaults-to-
// permissive field is exactly how a check that never fires comes to read like
// one that did. It is interactive, on the command's own streams, so a verb that
// does consult it — token initialization does — asks the operator at the
// terminal they are already sitting at.
func newOfflineAuthenticator(
	in io.Reader,
	out io.Writer,
	storage authenticator.StatefulCredentialStorage,
) (*authenticator.Authenticator, error) {
	return authenticator.NewAuthenticator(&authenticator.Config{
		AAGUID:              authenticator.DefaultAAGUID,
		Storage:             storage,
		UserPresenceHandler: authenticator.NewInteractiveHandlerWithIO(in, out, -1),
	})
}
