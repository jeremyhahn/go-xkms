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

package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
)

const (
	// readDeadline is the maximum time to wait for a client message.
	readDeadline = 5 * time.Second

	// socketFileMode is the permission mode for the socket file.
	socketFileMode = 0600

	// socketDirMode is the permission mode for the socket directory.
	socketDirMode = 0700
)

// Handler defines the interface for processing IPC messages.
type Handler interface {
	HandleTouch() (*Response, error)
	HandleTypePassword(name string) (*Response, error)
	HandleStatus() (*Response, error)
}

// PKCS11Handler processes PKCS#11 IPC requests. Implementations provide
// access to barrier-protected keys and certificates via the running xkey
// GUI instance.
type PKCS11Handler interface {
	HandlePKCS11Sign(params *SignParams) (*SignResult, error)
	HandlePKCS11GetPIVCertificate(params *PIVCertParams) (*PIVCertResult, error)
	HandlePKCS11ListPIVSlots(params *PIVSlotsParams) (*PIVSlotsResult, error)
	HandlePKCS11BarrierStatus() (*BarrierStatusResult, error)
}

// AutofillHandler processes autofill IPC requests. Implementations provide
// credential lookup, TOTP generation, credential saving, and policy access
// for the browser extension native messaging host.
type AutofillHandler interface {
	HandleAutofillSearch(domain string) (*AutofillResult, error)
	HandleAutofillGet(id, challenge string) (*AutofillResult, error)
	HandleAutofillTOTP(domain string) (*AutofillResult, error)
	HandleAutofillTOTPByID(id string) (*AutofillResult, error)
	HandleAutofillStatus() (*AutofillResult, error)
	HandleAutofillPolicy() (*AutofillResult, error)
	HandleAutofillSave(domain, username, password, title string) (*AutofillResult, error)
	HandleAutofillIgnoreDomain(domain string) (*AutofillResult, error)
	HandleAutofillFocus() (*AutofillResult, error)
}

// PairingHandler processes extension pairing IPC requests. The native
// messaging host forwards pairing codes and completion notifications
// here so the GUI or headless server can react to pairing state changes.
type PairingHandler interface {
	HandlePairingNotifyCode(code, identityKey, origin string) error
	HandlePairingCompleted(origin string) error
}

// StateHandler answers read-only questions about the daemon's live device
// state: PIN configuration, barrier seal state, and the static password
// store. A daemon that owns the unsealed state implements this so the CLI
// can report what is true right now instead of what the sealed on-disk data
// directory happens to say.
//
// Implementations must not return PINs, password values, or key material:
// see state_types.go for why.
type StateHandler interface {
	HandleStatePIN() (*PINStateResult, error)
	HandleStateBarrier() (*BarrierStatusResult, error)
	HandleStatePasswordStore() (*PasswordStoreStateResult, error)
	HandleStatePasswordList() (*PasswordListResult, error)
}

// UnlockHandler processes app unlock IPC requests. Implementations
// verify the user PIN and transition the app to the unlocked state.
type UnlockHandler interface {
	HandleUnlock(pin string) (*UnlockResult, error)
}

// dispatchFunc is the function signature for message dispatch handlers.
type dispatchFunc func(Handler, *Message) (*Response, error)

// handlers maps message types to their dispatch functions for O(1) lookup.
var handlers = map[string]dispatchFunc{
	MessageTypeTouch: func(h Handler, _ *Message) (*Response, error) {
		return h.HandleTouch()
	},
	MessageTypeTypePassword: func(h Handler, m *Message) (*Response, error) {
		return h.HandleTypePassword(m.Name)
	},
	MessageTypeStatus: func(h Handler, _ *Message) (*Response, error) {
		return h.HandleStatus()
	},
	MessageTypePKCS11: func(h Handler, m *Message) (*Response, error) {
		pkcs11Handler, ok := h.(PKCS11Handler)
		if !ok {
			return nil, &DetailError{Err: ErrHandlerFailed, Detail: ": handler does not implement PKCS11Handler"}
		}
		if m.PKCS11 == nil {
			return nil, &DetailError{Err: ErrInvalidMessage, Detail: ": pkcs11 payload is required"}
		}
		if err := m.PKCS11.Validate(); err != nil {
			return nil, err
		}
		return dispatchPKCS11(pkcs11Handler, m.PKCS11)
	},
	MessageTypeAutofill: func(h Handler, m *Message) (*Response, error) {
		afHandler, ok := h.(AutofillHandler)
		if !ok {
			return nil, &DetailError{Err: ErrHandlerFailed, Detail: ": handler does not implement AutofillHandler"}
		}
		if m.Autofill == nil {
			return nil, &DetailError{Err: ErrInvalidMessage, Detail: ": autofill payload is required"}
		}
		if err := m.Autofill.Validate(); err != nil {
			return nil, err
		}
		return dispatchAutofill(afHandler, m.Autofill)
	},
	MessageTypePairing: func(h Handler, m *Message) (*Response, error) {
		pairingHandler, ok := h.(PairingHandler)
		if !ok {
			return nil, &DetailError{Err: ErrHandlerFailed, Detail: ": handler does not implement PairingHandler"}
		}
		if m.Pairing == nil {
			return nil, &DetailError{Err: ErrInvalidMessage, Detail: ": pairing payload is required"}
		}
		if err := m.Pairing.Validate(); err != nil {
			return nil, err
		}
		return dispatchPairing(pairingHandler, m.Pairing)
	},
	MessageTypeState: func(h Handler, m *Message) (*Response, error) {
		stateHandler, ok := h.(StateHandler)
		if !ok {
			// Not an error the caller should abort on: the daemon is alive,
			// it just does not own this state. Answer structurally so the
			// client can fall back to disk and label the fallback.
			return &Response{
				Status: StatusError,
				Action: ActionUnsupported,
				Error:  ErrStateUnsupported.Error(),
			}, nil
		}
		if m.State == nil {
			return nil, &DetailError{Err: ErrInvalidMessage, Detail: ": state payload is required"}
		}
		if err := m.State.Validate(); err != nil {
			return nil, err
		}
		return dispatchState(stateHandler, m.State)
	},
	MessageTypeUnlock: func(h Handler, m *Message) (*Response, error) {
		unlockHandler, ok := h.(UnlockHandler)
		if !ok {
			return nil, &DetailError{Err: ErrHandlerFailed, Detail: ": handler does not implement UnlockHandler"}
		}
		if m.Unlock == nil {
			return nil, &DetailError{Err: ErrInvalidMessage, Detail: ": unlock payload is required"}
		}
		if err := m.Unlock.Validate(); err != nil {
			return nil, err
		}
		result, err := unlockHandler.HandleUnlock(m.Unlock.PIN)
		if err != nil {
			return nil, err
		}
		// Handlers report a refused unlock in band — UnlockResult.Success
		// false with a nil Go error — so the transport status has to follow
		// the result. Stamping StatusOK on every nil-error return made a
		// refused unlock indistinguishable from a granted one on the wire.
		if result == nil {
			return &Response{
				Status: StatusError,
				Error:  ErrUnlockNoResult.Error(),
			}, nil
		}
		if !result.Success {
			reason := result.Error
			if reason == "" {
				reason = ErrUnlockRefused.Error()
			}
			return &Response{
				Status: StatusError,
				Error:  reason,
				Unlock: result,
			}, nil
		}
		return &Response{
			Status: StatusOK,
			Unlock: result,
		}, nil
	},
}

// stateDispatchFunc is the function signature for state action dispatch handlers.
type stateDispatchFunc func(StateHandler) (*Response, error)

// stateHandlers maps state actions to their dispatch functions for O(1) lookup.
var stateHandlers = map[string]stateDispatchFunc{
	ActionStatePIN: func(h StateHandler) (*Response, error) {
		result, err := h.HandleStatePIN()
		if err != nil {
			return nil, err
		}
		return stateOKResponse(&StateResult{PIN: result}), nil
	},
	ActionStateBarrier: func(h StateHandler) (*Response, error) {
		result, err := h.HandleStateBarrier()
		if err != nil {
			return nil, err
		}
		return stateOKResponse(&StateResult{Barrier: result}), nil
	},
	ActionStatePasswordStore: func(h StateHandler) (*Response, error) {
		result, err := h.HandleStatePasswordStore()
		if err != nil {
			return nil, err
		}
		return stateOKResponse(&StateResult{PasswordStore: result}), nil
	},
	ActionStatePasswordList: func(h StateHandler) (*Response, error) {
		result, err := h.HandleStatePasswordList()
		if err != nil {
			return nil, err
		}
		return stateOKResponse(&StateResult{PasswordList: result}), nil
	},
}

// dispatchState routes a state payload to the appropriate handler using
// map-based O(1) dispatch.
func dispatchState(h StateHandler, p *StatePayload) (*Response, error) {
	fn, ok := stateHandlers[p.Action]
	if !ok {
		return nil, &DetailError{Err: ErrInvalidMessage, Detail: fmt.Sprintf(": unknown state action %q", p.Action)}
	}
	return fn(h)
}

// stateOKResponse creates a success response with the given state result.
func stateOKResponse(result *StateResult) *Response {
	return &Response{
		Status: StatusOK,
		State:  result,
	}
}

// pkcs11DispatchFunc is the function signature for PKCS#11 action dispatch handlers.
type pkcs11DispatchFunc func(PKCS11Handler, *PKCS11Payload) (*Response, error)

// pkcs11Handlers maps PKCS#11 actions to their dispatch functions for O(1) lookup.
var pkcs11Handlers = map[string]pkcs11DispatchFunc{
	ActionSign: func(h PKCS11Handler, p *PKCS11Payload) (*Response, error) {
		result, err := h.HandlePKCS11Sign(p.Sign)
		if err != nil {
			return nil, err
		}
		return pkcs11OKResponse(&PKCS11Result{Sign: result}), nil
	},
	ActionGetPIVCertificate: func(h PKCS11Handler, p *PKCS11Payload) (*Response, error) {
		result, err := h.HandlePKCS11GetPIVCertificate(p.PIVCert)
		if err != nil {
			return nil, err
		}
		return pkcs11OKResponse(&PKCS11Result{PIVCert: result}), nil
	},
	ActionListPIVSlots: func(h PKCS11Handler, p *PKCS11Payload) (*Response, error) {
		params := p.PIVSlots
		if params == nil {
			params = &PIVSlotsParams{}
		}
		result, err := h.HandlePKCS11ListPIVSlots(params)
		if err != nil {
			return nil, err
		}
		return pkcs11OKResponse(&PKCS11Result{PIVSlots: result}), nil
	},
	ActionBarrierStatus: func(h PKCS11Handler, _ *PKCS11Payload) (*Response, error) {
		result, err := h.HandlePKCS11BarrierStatus()
		if err != nil {
			return nil, err
		}
		return pkcs11OKResponse(&PKCS11Result{BarrierStatus: result}), nil
	},
}

// dispatchPKCS11 routes a PKCS#11 payload to the appropriate handler using
// map-based O(1) dispatch.
func dispatchPKCS11(h PKCS11Handler, p *PKCS11Payload) (*Response, error) {
	fn, ok := pkcs11Handlers[p.Action]
	if !ok {
		return nil, &DetailError{Err: ErrInvalidMessage, Detail: fmt.Sprintf(": unknown pkcs11 action %q", p.Action)}
	}
	return fn(h, p)
}

// pkcs11OKResponse creates a success response with the given PKCS#11 result.
func pkcs11OKResponse(result *PKCS11Result) *Response {
	return &Response{
		Status: StatusOK,
		PKCS11: result,
	}
}

// autofillDispatchFunc is the function signature for autofill action dispatch handlers.
type autofillDispatchFunc func(AutofillHandler, *AutofillPayload) (*Response, error)

// autofillHandlers maps autofill actions to their dispatch functions for O(1) lookup.
var autofillHandlers = map[string]autofillDispatchFunc{
	ActionAutofillSearch: func(h AutofillHandler, p *AutofillPayload) (*Response, error) {
		result, err := h.HandleAutofillSearch(p.Domain)
		if err != nil {
			return nil, err
		}
		return autofillOKResponse(result), nil
	},
	ActionAutofillGet: func(h AutofillHandler, p *AutofillPayload) (*Response, error) {
		result, err := h.HandleAutofillGet(p.ID, p.Challenge)
		if err != nil {
			return nil, err
		}
		return autofillOKResponse(result), nil
	},
	ActionAutofillTOTP: func(h AutofillHandler, p *AutofillPayload) (*Response, error) {
		result, err := h.HandleAutofillTOTP(p.Domain)
		if err != nil {
			return nil, err
		}
		return autofillOKResponse(result), nil
	},
	ActionAutofillTOTPByID: func(h AutofillHandler, p *AutofillPayload) (*Response, error) {
		result, err := h.HandleAutofillTOTPByID(p.ID)
		if err != nil {
			return nil, err
		}
		return autofillOKResponse(result), nil
	},
	ActionAutofillStatus: func(h AutofillHandler, _ *AutofillPayload) (*Response, error) {
		result, err := h.HandleAutofillStatus()
		if err != nil {
			return nil, err
		}
		return autofillOKResponse(result), nil
	},
	ActionAutofillPolicy: func(h AutofillHandler, _ *AutofillPayload) (*Response, error) {
		result, err := h.HandleAutofillPolicy()
		if err != nil {
			return nil, err
		}
		return autofillOKResponse(result), nil
	},
	ActionAutofillSave: func(h AutofillHandler, p *AutofillPayload) (*Response, error) {
		result, err := h.HandleAutofillSave(p.Domain, p.Username, p.Password, p.Title)
		if err != nil {
			return nil, err
		}
		return autofillOKResponse(result), nil
	},
	ActionAutofillIgnoreDomain: func(h AutofillHandler, p *AutofillPayload) (*Response, error) {
		result, err := h.HandleAutofillIgnoreDomain(p.Domain)
		if err != nil {
			return nil, err
		}
		return autofillOKResponse(result), nil
	},
	ActionAutofillFocus: func(h AutofillHandler, _ *AutofillPayload) (*Response, error) {
		result, err := h.HandleAutofillFocus()
		if err != nil {
			return nil, err
		}
		return autofillOKResponse(result), nil
	},
}

// dispatchAutofill routes an autofill payload to the appropriate handler using
// map-based O(1) dispatch.
func dispatchAutofill(h AutofillHandler, p *AutofillPayload) (*Response, error) {
	fn, ok := autofillHandlers[p.Action]
	if !ok {
		return nil, &DetailError{Err: ErrInvalidMessage, Detail: fmt.Sprintf(": unknown autofill action %q", p.Action)}
	}
	return fn(h, p)
}

// autofillOKResponse creates a success response with the given autofill result.
func autofillOKResponse(result *AutofillResult) *Response {
	return &Response{
		Status:   StatusOK,
		Autofill: result,
	}
}

// pairingDispatchFunc is the function signature for pairing action dispatch handlers.
type pairingDispatchFunc func(PairingHandler, *PairingPayload) (*Response, error)

// pairingHandlers maps pairing actions to their dispatch functions for O(1) lookup.
var pairingHandlers = map[string]pairingDispatchFunc{
	ActionPairingNotifyCode: func(h PairingHandler, p *PairingPayload) (*Response, error) {
		if err := h.HandlePairingNotifyCode(p.Code, p.IdentityKey, p.Origin); err != nil {
			return nil, err
		}
		return pairingOKResponse(&PairingResult{Acknowledged: true}), nil
	},
	ActionPairingCompleted: func(h PairingHandler, p *PairingPayload) (*Response, error) {
		if err := h.HandlePairingCompleted(p.Origin); err != nil {
			return nil, err
		}
		return pairingOKResponse(&PairingResult{Acknowledged: true}), nil
	},
}

// dispatchPairing routes a pairing payload to the appropriate handler using
// map-based O(1) dispatch.
func dispatchPairing(h PairingHandler, p *PairingPayload) (*Response, error) {
	fn, ok := pairingHandlers[p.Action]
	if !ok {
		return nil, &DetailError{Err: ErrInvalidMessage, Detail: fmt.Sprintf(": unknown pairing action %q", p.Action)}
	}
	return fn(h, p)
}

// pairingOKResponse creates a success response with the given pairing result.
func pairingOKResponse(result *PairingResult) *Response {
	return &Response{
		Status:  StatusOK,
		Pairing: result,
	}
}

// Server listens on a Unix domain socket and dispatches messages to a Handler.
type Server struct {
	listener   net.Listener
	handler    Handler
	logger     *slog.Logger
	socketPath string
	// trusted is the set of uids whose processes may use the server (see
	// trustedUIDs); every other peer is dropped before anything is read. It
	// is a field so tests can exclude the test process's own uid.
	trusted []int
	closed  atomic.Bool
	// shutdownMu serializes each accept loop iteration's "register with wg"
	// decision against Close's shutdown sequence. Without it, wg.Add (in
	// Serve) and wg.Wait (in Close) can transition the WaitGroup's counter
	// away from zero with no happens-before edge between them, which is a
	// data race by sync.WaitGroup's own documented contract even though the
	// counter itself is manipulated atomically.
	shutdownMu sync.Mutex
	wg         sync.WaitGroup
	auditLog   atomic.Pointer[audit.Logger]
}

// NewServer creates a new IPC server bound to the given socketPath.
//
// It creates the socket directory, and any missing parents, with mode 0700
// and refuses to start if the directory already exists and is a symbolic
// link, is owned by another user, or has any group or other permission bits
// (ErrSocketDirInsecure); see ensureSocketDir. It then removes a stale socket
// file left by a previous run — only a socket this user owns, see
// ReclaimSocket — refuses to replace a live one (ErrSocketInUse), and binds
// the socket file with mode 0600.
//
// When running as root via sudo, the directories it creates and the socket
// are handed to the original user (from SUDO_UID/SUDO_GID) so that client
// commands running as that user can connect.
//
// The socket's file mode is not the only gate: Serve checks the kernel-
// reported uid of every client against trustedUIDs and drops any other user
// before reading a byte (see handleConnection).
func NewServer(socketPath string, handler Handler, logger *slog.Logger) (*Server, error) {
	if socketPath == "" {
		return nil, ErrSocketPathUnresolved
	}
	trusted := trustedUIDs()
	if err := ensureSocketDir(filepath.Dir(socketPath), trusted); err != nil {
		return nil, err
	}

	// Check whether an existing socket is live before removing it.
	// If a listener is active, refuse to steal the socket; if stale, remove it.
	if _, statErr := os.Lstat(socketPath); statErr == nil {
		probe, dialErr := net.DialTimeout("unix", socketPath, 500*time.Millisecond)
		if dialErr == nil {
			if closeErr := probe.Close(); closeErr != nil {
				logger.Warn("probe socket close failed", "error", closeErr)
			}
			return nil, &SentinelCauseError{Sentinel: ErrSocketCreateFailed, Cause: &DetailError{Err: ErrSocketInUse, Detail: " on " + socketPath}}
		}
		// Socket file exists but nobody is listening — stale. Remove it only
		// if it is a socket this user owns.
		if err := reclaimSocket(socketPath, trusted); err != nil {
			return nil, err
		}
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrSocketCreateFailed, Cause: err}
	}

	if err := os.Chmod(socketPath, socketFileMode); err != nil {
		closeErr := listener.Close()
		return nil, &SentinelCauseError{Sentinel: ErrSocketPermission, Cause: errors.Join(err, closeErr)}
	}

	// When running as root via sudo, chown the socket to the original user.
	if uid, gid, ok := sudoOwnership(); ok {
		if err := os.Chown(socketPath, uid, gid); err != nil {
			closeErr := listener.Close()
			return nil, &DetailError{Err: ErrSocketPermission, Detail: fmt.Sprintf(": chown socket: %v", errors.Join(err, closeErr))}
		}
	}

	return &Server{
		listener:   listener,
		handler:    handler,
		logger:     logger,
		socketPath: socketPath,
		trusted:    trusted,
	}, nil
}

// sudoOwnership returns the UID and GID of the original user when running as
// root via sudo. It returns false if not running as root via sudo or if the
// environment variables are invalid.
func sudoOwnership() (uid, gid int, ok bool) {
	if os.Getuid() != 0 {
		return 0, 0, false
	}

	sudoUID := os.Getenv("SUDO_UID")
	sudoGID := os.Getenv("SUDO_GID")
	if sudoUID == "" || sudoGID == "" {
		return 0, 0, false
	}

	uid, uidErr := strconv.Atoi(sudoUID)
	gid, gidErr := strconv.Atoi(sudoGID)
	if uidErr != nil || gidErr != nil {
		return 0, 0, false
	}

	return uid, gid, true
}

// Serve runs the accept loop, dispatching each incoming connection to a
// goroutine. It blocks until the context is cancelled or Close is called.
func (s *Server) Serve(ctx context.Context) error {
	// Watch for context cancellation to close the listener.
	go func() {
		<-ctx.Done()
		if err := s.Close(); err != nil {
			s.logger.Error("close on context cancellation failed", "error", err)
		}
	}()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.closed.Load() {
				return ErrServerClosed
			}
			s.logger.Error("accept failed", "error", err)
			continue
		}

		// Register the connection under shutdownMu so Close cannot observe
		// wg reach zero and return from Wait while this Add is in flight (or
		// begin waiting concurrently with it): Close acquires the same lock
		// after closing the listener, so any Add that wins the race to
		// acquire the lock first is guaranteed to finish before Close's Wait
		// runs, and any Add that loses the race sees closed already true.
		s.shutdownMu.Lock()
		if s.closed.Load() {
			s.shutdownMu.Unlock()
			if closeErr := conn.Close(); closeErr != nil {
				s.logger.Error("close rejected connection failed", "error", closeErr)
			}
			continue
		}
		s.wg.Add(1)
		s.shutdownMu.Unlock()

		go func() {
			defer s.wg.Done()
			s.handleConnection(conn)
		}()
	}
}

// SocketPath returns the path of the Unix domain socket.
func (s *Server) SocketPath() string {
	return s.socketPath
}

// IsRunning returns true if the server is accepting connections.
func (s *Server) IsRunning() bool {
	return !s.closed.Load()
}

// Close shuts down the server by closing the listener and waiting for all
// in-flight connections to finish. It removes the socket file on shutdown.
func (s *Server) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}

	err := s.listener.Close()

	// Acquire and release shutdownMu as a barrier: any accept-loop iteration
	// that started registering a connection (see Serve) before closed was
	// observed true is guaranteed to finish its wg.Add before this unlocks,
	// and every iteration after this point sees closed true and skips wg.Add
	// entirely. This establishes the happens-before edge sync.WaitGroup
	// requires between the last Add and Wait.
	s.shutdownMu.Lock()
	s.shutdownMu.Unlock() //nolint:staticcheck,gocritic // SA2001/badLock: intentional empty critical section used as a happens-before barrier, see comment above

	s.wg.Wait()

	// Best-effort removal of the socket file; fold any failure into the
	// returned error rather than dropping it.
	if removeErr := os.Remove(s.socketPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		err = errors.Join(err, removeErr)
	}

	return err
}

// handleConnection processes a single client connection: verifies the
// client's uid, reads one JSON message, dispatches to the appropriate
// handler, and writes the JSON response.
func (s *Server) handleConnection(conn net.Conn) {
	defer func() {
		if err := conn.Close(); err != nil {
			s.logger.Error("close connection failed", "error", err)
		}
	}()

	if !s.admitPeer(conn) {
		return
	}

	if err := conn.SetReadDeadline(time.Now().Add(readDeadline)); err != nil {
		s.logger.Error("set read deadline failed", "error", err)
		return
	}

	// OpIPCMessageFailed/OpIPCMessageDispatched are SeverityInformational:
	// logIPCEvent returns nil for them today. auditLogFailure below is
	// defensive in case that classification ever changes; handleConnection
	// has no caller to propagate a failure to (it runs per accepted
	// connection in its own goroutine), so the strongest response available
	// here is to log loudly rather than silently drop the failure.
	auditLogFailure := func(auditErr error) {
		if auditErr != nil {
			s.logger.Error("audit log failed", "error", auditErr)
		}
	}

	var msg Message
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&msg); err != nil {
		s.logger.Debug("decode failed", "error", err)
		auditLogFailure(s.logIPCEvent(audit.OpIPCMessageFailed, false, err, nil))
		s.writeResponse(conn, ErrorResponse(fmt.Sprintf("%v: %v", ErrProtocolError, err)))
		return
	}

	if err := msg.Validate(); err != nil {
		auditLogFailure(s.logIPCEvent(audit.OpIPCMessageFailed, false, err, map[string]any{"message_type": msg.Type}))
		s.writeResponse(conn, ErrorResponse(err.Error()))
		return
	}

	fn, ok := handlers[msg.Type]
	if !ok {
		auditLogFailure(s.logIPCEvent(audit.OpIPCMessageFailed, false, ErrInvalidMessage, map[string]any{"message_type": msg.Type}))
		s.writeResponse(conn, ErrorResponse(
			fmt.Sprintf("%v: unknown message type %q", ErrInvalidMessage, msg.Type)))
		return
	}

	resp, err := fn(s.handler, &msg)
	if err != nil {
		s.logger.Error("handler failed", "type", msg.Type, "error", err)
		auditLogFailure(s.logIPCEvent(audit.OpIPCMessageFailed, false, err, map[string]any{"message_type": msg.Type}))
		s.writeResponse(conn, ErrorResponse(clientErrorMessage(err)))
		return
	}

	auditLogFailure(s.logIPCEvent(audit.OpIPCMessageDispatched, true, nil, map[string]any{"message_type": msg.Type}))
	s.writeResponse(conn, resp)
}

// admitPeer reports whether the process at the other end of conn runs as a
// trusted user (see verifyPeer). Any other peer, and any peer whose
// credentials cannot be read, is refused with a warning and gets no
// response: the socket's 0600 mode and 0700 directory keep other users out
// only while nothing loosens them, and this check does not depend on them.
func (s *Server) admitPeer(conn net.Conn) bool {
	uid, err := verifyPeer(conn, s.trusted)
	if err == nil {
		return true
	}
	if errors.Is(err, ErrPeerUntrusted) {
		s.logger.Warn("ipc: dropped connection from untrusted peer", "peer_uid", uid, "error", err)
		return false
	}
	s.logger.Warn("ipc: dropped connection with unverifiable peer", "error", err)
	return false
}

// publicErrors are the handler error classes whose fixed sentinel text is
// safe and useful to show a client: they describe the request or a state the
// user can act on, never internal detail.
var publicErrors = []error{
	ErrInvalidMessage,
	ErrBarrierSealed,
	ErrAutofillDisabled,
}

// clientErrorMessage returns the text sent to a client for a handler error.
// The wrapped detail of a handler error can carry file paths, backend
// messages or key identifiers, so it is logged (see handleConnection) and
// never echoed: the client receives the sentinel text of a public error
// class, or the fixed ErrHandlerFailed text for everything else.
func clientErrorMessage(err error) string {
	for _, public := range publicErrors {
		if errors.Is(err, public) {
			return public.Error()
		}
	}
	return ErrHandlerFailed.Error()
}

// writeResponse encodes a JSON response to the connection.
func (s *Server) writeResponse(conn net.Conn, resp *Response) {
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(resp); err != nil {
		s.logger.Error("encode response failed", "error", err)
	}
}

// SetAuditLogger sets the audit logger for the IPC server.
func (s *Server) SetAuditLogger(l audit.Logger) {
	s.auditLog.Store(&l)
}

// logIPCEvent logs an audit event for IPC message processing. Callers must
// propagate a non-nil return: op.Severity() (audit package) decides
// whether that failure is required to fail the caller.
func (s *Server) logIPCEvent(op audit.OperationType, success bool, err error, details map[string]any) error {
	p := s.auditLog.Load()
	if p == nil {
		return nil
	}
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	return (*p).Log(audit.Entry{
		Timestamp: time.Now(),
		Operation: op,
		Success:   success,
		Error:     errStr,
		Details:   details,
	})
}
