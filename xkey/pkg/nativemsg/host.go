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

package nativemsg

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
)

// repairable errors trigger a re-pairing ceremony instead of outright
// rejection. These indicate the extension was likely reinstalled (new
// identity key) or its origin changed, not an attack.
var repairableErrors = map[error]struct{}{
	ErrIdentityMismatch:       {},
	ErrIdentityOriginMismatch: {},
}

const (
	// ipcDialTimeout is the timeout for connecting to the IPC socket.
	ipcDialTimeout = 5 * time.Second

	// ipcReadWriteTimeout is the deadline for IPC read/write operations.
	// Must exceed the CTAP2 user presence timeout (30s) because autofill
	// "get" requests can block on authenticator touch approval.
	ipcReadWriteTimeout = 45 * time.Second
)

// Host bridges the browser extension (via stdin/stdout native messaging) to the
// xkey IPC server (via Unix domain socket). It handles X25519 ECDH handshake,
// Ed25519 identity verification, encrypted message relay, and clean shutdown.
type Host struct {
	ipcSocketPath   string
	logger          *slog.Logger
	crypto          *SessionCrypto
	pairing         *PairingVerifier
	extensionOrigin string // set during handshake, used for session invalidation
	stdin           io.Reader
	stdout          io.Writer
	auditLog        atomic.Pointer[audit.Logger]
}

// NewHost creates a new native messaging host using os.Stdin and os.Stdout.
// If pairing is nil, identity verification is skipped (--no-pairing mode).
func NewHost(ipcSocketPath string, logger *slog.Logger, pairing *PairingVerifier) *Host {
	return &Host{
		ipcSocketPath: ipcSocketPath,
		logger:        logger,
		pairing:       pairing,
		stdin:         os.Stdin,
		stdout:        os.Stdout,
	}
}

// NewHostWithIO creates a new host with custom I/O (for testing).
// If pairing is nil, identity verification is skipped (--no-pairing mode).
func NewHostWithIO(ipcSocketPath string, logger *slog.Logger, stdin io.Reader, stdout io.Writer, pairing *PairingVerifier) *Host {
	return &Host{
		ipcSocketPath: ipcSocketPath,
		logger:        logger,
		pairing:       pairing,
		stdin:         stdin,
		stdout:        stdout,
	}
}

// Run performs the handshake and then enters the message relay loop.
// It blocks until stdin is closed (browser closes extension), context is
// cancelled, or an error occurs.
func (h *Host) Run(ctx context.Context) error {
	if err := h.handshake(); err != nil {
		h.logHostEvent(audit.OpExtensionHandshake, false, err, nil)
		return err
	}

	h.logHostEvent(audit.OpExtensionHandshake, true, nil, nil)
	h.logger.Info("native messaging handshake completed")
	return h.relayLoop(ctx)
}

// handshake reads the initial handshake message from the browser extension,
// performs the X25519 ECDH key exchange, verifies identity if a pairing
// verifier is configured, and sends the response.
func (h *Host) handshake() error {
	msg, err := ReadMessage(h.stdin)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrHandshakeFailed, err)
	}

	if msg.Type != MsgTypeHandshake {
		return fmt.Errorf("%w: expected handshake message, got %q", ErrHandshakeFailed, msg.Type)
	}

	if msg.PubKey == "" {
		return fmt.Errorf("%w: missing public key in handshake", ErrHandshakeFailed)
	}

	peerPubKey, err := base64.StdEncoding.DecodeString(msg.PubKey)
	if err != nil {
		return fmt.Errorf("%w: invalid base64 public key: %v", ErrInvalidPublicKey, err)
	}

	sc, ourPubKey, err := NewSessionCrypto()
	if err != nil {
		return err
	}

	if err := sc.CompleteHandshake(peerPubKey); err != nil {
		return err
	}

	h.crypto = sc

	// If no pairing verifier is configured, skip identity verification
	// (--no-pairing mode for development/testing).
	if h.pairing == nil {
		return h.sendHandshakeOK(ourPubKey)
	}

	return h.handshakeWithIdentity(msg, ourPubKey)
}

// handshakeWithIdentity performs identity verification or initiates pairing
// as part of the handshake flow.
func (h *Host) handshakeWithIdentity(msg *NativeMessage, ourPubKey []byte) error {
	// Extension must include identity key and origin in handshake.
	if msg.IdentityKey == "" || msg.Origin == "" {
		// No identity provided - initiate pairing if not yet paired.
		if !h.pairing.IsPaired() {
			return h.initiatePairing(ourPubKey, nil, msg.Origin)
		}
		// Paired but no identity sent - reject.
		return h.sendHandshakeRejected(ourPubKey, "identity key required")
	}

	identityKey, err := base64.StdEncoding.DecodeString(msg.IdentityKey)
	if err != nil {
		return h.sendHandshakeRejected(ourPubKey, "invalid identity key encoding")
	}

	// Not yet paired - initiate pairing ceremony.
	if !h.pairing.IsPaired() {
		return h.initiatePairing(ourPubKey, identityKey, msg.Origin)
	}

	// Already paired - verify identity signature.
	if msg.IdentitySig == "" {
		return h.sendHandshakeRejected(ourPubKey, "identity signature required")
	}

	signature, err := base64.StdEncoding.DecodeString(msg.IdentitySig)
	if err != nil {
		return h.sendHandshakeRejected(ourPubKey, "invalid signature encoding")
	}

	// The extension signs SHA-256(ephemeralPubKey || origin || context) where
	// ephemeralPubKey is the extension's X25519 key from msg.PubKey.
	peerPubKey, err := base64.StdEncoding.DecodeString(msg.PubKey)
	if err != nil {
		return h.sendHandshakeRejected(ourPubKey, "invalid public key encoding")
	}

	if verifyErr := h.pairing.VerifyIdentity(identityKey, signature, peerPubKey, msg.Origin); verifyErr != nil {
		h.logger.Warn("identity verification failed", "error", verifyErr, "origin", msg.Origin)

		// Identity or origin mismatch means the extension was likely reinstalled
		// (generating a new Ed25519 keypair). Initiate re-pairing so the user can
		// confirm the new extension via the 6-digit code ceremony.
		for target := range repairableErrors {
			if errors.Is(verifyErr, target) {
				h.logger.Info("identity changed, initiating re-pairing", "origin", msg.Origin)
				return h.initiatePairing(ourPubKey, identityKey, msg.Origin)
			}
		}

		h.logHostEvent(audit.OpExtensionRejected, false, verifyErr, map[string]any{"origin": msg.Origin, "reason": verifyErr.Error()})
		return h.sendHandshakeRejected(ourPubKey, verifyErr.Error())
	}

	h.logger.Info("identity verified", "origin", msg.Origin)
	h.logHostEvent(audit.OpExtensionIdentityOK, true, nil, map[string]any{"origin": msg.Origin})
	h.extensionOrigin = msg.Origin
	return h.sendHandshakeOK(ourPubKey)
}

// initiatePairing starts the pairing ceremony, notifies the IPC server to
// display the code, waits for the extension to submit the code, verifies it,
// and completes the handshake if successful.
func (h *Host) initiatePairing(ourPubKey, identityKey []byte, origin string) error {
	code, pairingErr := h.pairing.StartPairing(identityKey, origin)
	if pairingErr != nil {
		h.logger.Error("failed to start pairing", "error", pairingErr)
		return h.sendHandshakeRejected(ourPubKey, pairingErr.Error())
	}

	h.logger.Info("pairing ceremony started",
		"origin", origin,
		"code", code,
		"ipc_socket", h.ipcSocketPath,
	)

	// Notify the IPC server (GUI or headless) to display the code.
	// If notification fails, the user will never see the code, so abort
	// the ceremony rather than leaving the extension waiting indefinitely.
	if notifyErr := h.notifyPairingCode(code, identityKey, origin); notifyErr != nil {
		h.logger.Error("pairing IPC failed: user cannot see pairing code",
			"error", notifyErr,
			"socket_path", h.ipcSocketPath,
		)
		if writeErr := h.sendPairingFailed("pairing code could not be displayed"); writeErr != nil {
			h.logger.Error("failed to write pairing_failed", "error", writeErr)
		}
		return fmt.Errorf("%w: %v", ErrIPCConnection, notifyErr)
	}
	h.logger.Info("pairing code sent to GUI via IPC")

	// Tell the extension that pairing is required.
	if err := h.sendPairingRequired(ourPubKey); err != nil {
		return err
	}

	// Wait for the extension to submit the pairing code.
	return h.awaitPairingConfirmation(ourPubKey, origin)
}

// notifyPairingCode sends the pairing code to the IPC server so it can be
// displayed to the user in the GUI or terminal.
func (h *Host) notifyPairingCode(code string, identityKey []byte, origin string) error {
	msg := &ipc.Message{
		Type: ipc.MessageTypePairing,
		Pairing: &ipc.PairingPayload{
			Action:      ipc.ActionPairingNotifyCode,
			Code:        code,
			IdentityKey: base64.StdEncoding.EncodeToString(identityKey),
			Origin:      origin,
		},
	}

	resp, err := h.forwardToIPC(msg)
	if err != nil {
		return err
	}
	if resp.Status != ipc.StatusOK {
		return fmt.Errorf("%w: IPC pairing notify: %s", ErrIPCConnection, resp.Error)
	}
	return nil
}

// notifyPairingCompleted sends a completion notification to the IPC server so
// the GUI can close the pairing dialog and show a success indicator.
func (h *Host) notifyPairingCompleted(origin string) error {
	msg := &ipc.Message{
		Type: ipc.MessageTypePairing,
		Pairing: &ipc.PairingPayload{
			Action: ipc.ActionPairingCompleted,
			Origin: origin,
		},
	}

	resp, err := h.forwardToIPC(msg)
	if err != nil {
		return err
	}
	if resp.Status != ipc.StatusOK {
		return fmt.Errorf("%w: IPC pairing completed: %s", ErrIPCConnection, resp.Error)
	}
	return nil
}

// awaitPairingConfirmation reads the next message from the extension, expecting
// a pairing_confirm message with a 6-digit code. It verifies the code and sends
// either pairing_ok or pairing_failed. On success, it sends handshake_ok.
func (h *Host) awaitPairingConfirmation(ourPubKey []byte, origin string) error {
	msg, err := ReadMessage(h.stdin)
	if err != nil {
		if isEOF(err) {
			return fmt.Errorf("%w: extension disconnected during pairing", ErrPairingRejected)
		}
		return fmt.Errorf("%w: %v", ErrPairingRejected, err)
	}

	if msg.Type != MsgTypePairingConfirm {
		h.logger.Warn("unexpected message during pairing", "type", msg.Type)
		if writeErr := h.sendPairingFailed("expected pairing_confirm message"); writeErr != nil {
			h.logger.Error("failed to write pairing_failed", "error", writeErr)
		}
		return ErrPairingRejected
	}

	if msg.Code == "" {
		if writeErr := h.sendPairingFailed("pairing code is required"); writeErr != nil {
			h.logger.Error("failed to write pairing_failed", "error", writeErr)
		}
		return ErrPairingInvalidCode
	}

	// Decode the identity key from the confirmation (must match the pending key).
	var confirmIdentityKey []byte
	if msg.IdentityKey != "" {
		confirmIdentityKey, err = base64.StdEncoding.DecodeString(msg.IdentityKey)
		if err != nil {
			if writeErr := h.sendPairingFailed("invalid identity key encoding"); writeErr != nil {
				h.logger.Error("failed to write pairing_failed", "error", writeErr)
			}
			return ErrPairingRejected
		}
	}

	// Verify the pairing code against the pending state.
	if completeErr := h.pairing.CompletePairing(confirmIdentityKey, origin, msg.Code); completeErr != nil {
		h.logger.Warn("pairing verification failed", "error", completeErr)
		if writeErr := h.sendPairingFailed(completeErr.Error()); writeErr != nil {
			h.logger.Error("failed to write pairing_failed", "error", writeErr)
		}
		return completeErr
	}

	h.logger.Info("pairing completed successfully", "origin", origin)
	h.extensionOrigin = origin

	// Notify the IPC server (GUI or headless) that pairing is complete.
	if notifyErr := h.notifyPairingCompleted(origin); notifyErr != nil {
		h.logger.Warn("failed to notify IPC server of pairing completion", "error", notifyErr)
	}

	// Tell the extension pairing succeeded. The extension already received
	// our X25519 public key in the handshake_pair message, so a second
	// handshake_ok is not needed — sending it would leave a stale message
	// in the native port queue that would corrupt the next encrypted request.
	return h.sendPairingOK()
}

// sendHandshakeOK writes a successful handshake response.
func (h *Host) sendHandshakeOK(ourPubKey []byte) error {
	resp := &NativeMessage{
		Type:   MsgTypeHandshakeOK,
		PubKey: base64.StdEncoding.EncodeToString(ourPubKey),
	}
	if err := WriteMessage(h.stdout, resp); err != nil {
		return fmt.Errorf("%w: %v", ErrHandshakeFailed, err)
	}
	return nil
}

// sendPairingRequired writes a response indicating the extension must complete
// pairing before the session can proceed. The host stays alive to receive the
// pairing confirmation.
func (h *Host) sendPairingRequired(ourPubKey []byte) error {
	resp := &NativeMessage{
		Type:            MsgTypeHandshakePair,
		PubKey:          base64.StdEncoding.EncodeToString(ourPubKey),
		PairingRequired: true,
	}
	if err := WriteMessage(h.stdout, resp); err != nil {
		return fmt.Errorf("%w: %v", ErrHandshakeFailed, err)
	}
	return nil
}

// sendPairingOK writes a pairing success message to the extension.
func (h *Host) sendPairingOK() error {
	return WriteMessage(h.stdout, &NativeMessage{Type: MsgTypePairingOK})
}

// sendPairingFailed writes a pairing failure message to the extension.
func (h *Host) sendPairingFailed(reason string) error {
	return WriteMessage(h.stdout, &NativeMessage{
		Type:  MsgTypePairingFailed,
		Error: reason,
	})
}

// sendHandshakeRejected writes a response indicating the identity was rejected.
func (h *Host) sendHandshakeRejected(ourPubKey []byte, reason string) error {
	resp := &NativeMessage{
		Type:   MsgTypeHandshakeRejected,
		PubKey: base64.StdEncoding.EncodeToString(ourPubKey),
		Error:  reason,
	}
	if err := WriteMessage(h.stdout, resp); err != nil {
		return fmt.Errorf("%w: %v", ErrHandshakeFailed, err)
	}
	return ErrIdentityMismatch
}

// relayLoop reads encrypted messages from stdin, decrypts them, forwards to
// the IPC server, encrypts the response, and writes back to stdout.
func (h *Host) relayLoop(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		msg, err := ReadMessage(h.stdin)
		if err != nil {
			// EOF means the browser closed the extension. This is a clean exit.
			if isEOF(err) {
				h.logger.Info("browser extension disconnected")
				h.logHostEvent(audit.OpExtensionDisconnected, true, nil, map[string]any{"origin": h.extensionOrigin})
				return nil
			}
			h.logger.Error("failed to read message", "error", err)
			return err
		}

		// Check if pairing was revoked while we were waiting for a message.
		// This allows the GUI to unpair an extension and have the native host
		// exit cleanly on the next request, without polling or timers.
		if h.pairing != nil && h.extensionOrigin != "" {
			if reloadErr := h.pairing.Reload(); reloadErr != nil {
				h.logger.Warn("failed to reload pairing state", "error", reloadErr)
			}
			if !h.pairing.IsPairedForOrigin(h.extensionOrigin) {
				h.logger.Info("pairing revoked, disconnecting", "origin", h.extensionOrigin)
				return ErrPairingRevoked
			}
		}

		if msg.Type != MsgTypeEncrypted {
			h.logger.Warn("unexpected message type in relay loop", "type", msg.Type)
			if writeErr := WriteError(h.stdout, "expected encrypted message"); writeErr != nil {
				h.logger.Error("failed to write error response", "error", writeErr)
			}
			continue
		}

		if err := h.handleEncryptedMessage(msg); err != nil {
			h.logger.Error("failed to handle encrypted message", "error", err)
			h.logHostEvent(audit.OpExtensionRelay, false, err, nil)
			if writeErr := WriteError(h.stdout, err.Error()); writeErr != nil {
				h.logger.Error("failed to write error response", "error", writeErr)
			}
		}
	}
}

// handleEncryptedMessage decrypts an incoming message, sends it to the IPC
// server, and writes the encrypted response back to stdout.
func (h *Host) handleEncryptedMessage(msg *NativeMessage) error {
	ciphertext, err := base64.StdEncoding.DecodeString(msg.Ciphertext)
	if err != nil {
		return fmt.Errorf("%w: invalid base64 ciphertext: %v", ErrDecryptionFailed, err)
	}

	plaintext, err := h.crypto.Decrypt(msg.Nonce, ciphertext)
	if err != nil {
		return err
	}

	// Parse the decrypted plaintext as an IPC Message.
	var ipcMsg ipc.Message
	if err := json.Unmarshal(plaintext, &ipcMsg); err != nil {
		return fmt.Errorf("%w: invalid IPC message: %v", ErrReadFailed, err)
	}

	// Forward to the IPC server and get the response.
	ipcResp, err := h.forwardToIPC(&ipcMsg)
	if err != nil {
		return err
	}

	// Serialize the IPC response.
	respJSON, err := json.Marshal(ipcResp)
	if err != nil {
		return fmt.Errorf("%w: cannot serialize IPC response: %v", ErrWriteFailed, err)
	}

	// Encrypt the response.
	nonce, ct, err := h.crypto.Encrypt(respJSON)
	if err != nil {
		return err
	}

	// Write the encrypted response to stdout.
	outMsg := &NativeMessage{
		Type:       MsgTypeEncrypted,
		Nonce:      nonce,
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}

	return WriteMessage(h.stdout, outMsg)
}

// forwardToIPC opens a connection to the IPC socket, sends the message, reads
// the response, and closes the connection.
func (h *Host) forwardToIPC(msg *ipc.Message) (*ipc.Response, error) {
	conn, err := net.DialTimeout("unix", h.ipcSocketPath, ipcDialTimeout)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIPCConnection, err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(ipcReadWriteTimeout)); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIPCConnection, err)
	}

	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(msg); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIPCConnection, err)
	}

	var resp ipc.Response
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&resp); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIPCConnection, err)
	}

	return &resp, nil
}

// isEOF returns true if the error wraps io.EOF or io.ErrUnexpectedEOF,
// indicating the reader has been closed.
func isEOF(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

// SetAuditLogger sets the audit logger for the native messaging host.
func (h *Host) SetAuditLogger(l audit.Logger) {
	h.auditLog.Store(&l)
}

// logHostEvent logs an audit event for native messaging operations.
func (h *Host) logHostEvent(op audit.OperationType, success bool, err error, details map[string]any) {
	if p := h.auditLog.Load(); p != nil {
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		(*p).Log(audit.Entry{
			Timestamp: time.Now(),
			Operation: op,
			Success:   success,
			Error:     errStr,
			Details:   details,
		})
	}
}
