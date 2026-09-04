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
	"encoding/json"
	"errors"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"time"
)

// DefaultTimeout is the default timeout for client operations.
const DefaultTimeout = 5 * time.Second

// Client connects to the xkey daemon IPC socket. Each method opens a new
// connection, sends one message, reads the response, and closes.
type Client struct {
	socketPath string
	timeout    time.Duration
	closed     atomic.Bool
}

// NewClient creates a new IPC client targeting the given socket path.
func NewClient(socketPath string) *Client {
	return &Client{
		socketPath: socketPath,
		timeout:    DefaultTimeout,
	}
}

// Touch sends a touch message to the daemon and returns the response.
func (c *Client) Touch() (*Response, error) {
	return c.send(&Message{Type: MessageTypeTouch})
}

// TypePassword sends a type_password message to the daemon and returns the
// response.
func (c *Client) TypePassword(name string) (*Response, error) {
	return c.send(&Message{Type: MessageTypeTypePassword, Name: name})
}

// Status sends a status message to the daemon and returns the response.
func (c *Client) Status() (*Response, error) {
	return c.send(&Message{Type: MessageTypeStatus})
}

// AutofillSearch searches for credentials matching a domain.
func (c *Client) AutofillSearch(domain string) (*Response, error) {
	return c.send(&Message{
		Type: MessageTypeAutofill,
		Autofill: &AutofillPayload{
			Action: ActionAutofillSearch,
			Domain: domain,
		},
	})
}

// AutofillGet retrieves a credential by ID for form filling.
func (c *Client) AutofillGet(id, challenge string) (*Response, error) {
	return c.send(&Message{
		Type: MessageTypeAutofill,
		Autofill: &AutofillPayload{
			Action:    ActionAutofillGet,
			ID:        id,
			Challenge: challenge,
		},
	})
}

// AutofillTOTP gets a TOTP code for a domain.
func (c *Client) AutofillTOTP(domain string) (*Response, error) {
	return c.send(&Message{
		Type: MessageTypeAutofill,
		Autofill: &AutofillPayload{
			Action: ActionAutofillTOTP,
			Domain: domain,
		},
	})
}

// AutofillTOTPByID gets a TOTP code for a specific OATH account ID.
func (c *Client) AutofillTOTPByID(id string) (*Response, error) {
	return c.send(&Message{
		Type: MessageTypeAutofill,
		Autofill: &AutofillPayload{
			Action: ActionAutofillTOTPByID,
			ID:     id,
		},
	})
}

// AutofillStatus gets the current autofill system status.
func (c *Client) AutofillStatus() (*Response, error) {
	return c.send(&Message{
		Type: MessageTypeAutofill,
		Autofill: &AutofillPayload{
			Action: ActionAutofillStatus,
		},
	})
}

// AutofillPolicy gets the current autofill policy.
func (c *Client) AutofillPolicy() (*Response, error) {
	return c.send(&Message{
		Type: MessageTypeAutofill,
		Autofill: &AutofillPayload{
			Action: ActionAutofillPolicy,
		},
	})
}

// Unlock sends an unlock message with the provided PIN.
func (c *Client) Unlock(pin string) (*Response, error) {
	return c.send(&Message{
		Type:   MessageTypeUnlock,
		Unlock: &UnlockPayload{PIN: pin},
	})
}

// StatePIN asks the daemon for its live PIN configuration and lockout state.
func (c *Client) StatePIN() (*PINStateResult, error) {
	result, err := c.state(ActionStatePIN)
	if err != nil {
		return nil, err
	}
	if result.PIN == nil {
		return nil, &DetailError{Err: ErrProtocolError, Detail: ": state response carried no pin result"}
	}
	return result.PIN, nil
}

// StateBarrier asks the daemon for its live barrier seal state.
func (c *Client) StateBarrier() (*BarrierStatusResult, error) {
	result, err := c.state(ActionStateBarrier)
	if err != nil {
		return nil, err
	}
	if result.Barrier == nil {
		return nil, &DetailError{Err: ErrProtocolError, Detail: ": state response carried no barrier result"}
	}
	return result.Barrier, nil
}

// StatePasswordStore asks the daemon for the state of its static password
// store: availability, lock state, backend, and entry count.
func (c *Client) StatePasswordStore() (*PasswordStoreStateResult, error) {
	result, err := c.state(ActionStatePasswordStore)
	if err != nil {
		return nil, err
	}
	if result.PasswordStore == nil {
		return nil, &DetailError{Err: ErrProtocolError, Detail: ": state response carried no password_store result"}
	}
	return result.PasswordStore, nil
}

// StatePasswordList asks the daemon for the metadata of every stored
// password. Password values are never returned over IPC.
func (c *Client) StatePasswordList() (*PasswordListResult, error) {
	result, err := c.state(ActionStatePasswordList)
	if err != nil {
		return nil, err
	}
	if result.PasswordList == nil {
		return nil, &DetailError{Err: ErrProtocolError, Detail: ": state response carried no password_list result"}
	}
	return result.PasswordList, nil
}

// state sends one live-state query and unpacks the result. It maps a daemon
// that is alive but does not serve live state onto ErrStateUnsupported, so
// callers can tell "nobody is home" (ErrDaemonNotRunning) from "this daemon
// does not know" and label their fallback accordingly.
func (c *Client) state(action string) (*StateResult, error) {
	resp, err := c.send(&Message{
		Type:  MessageTypeState,
		State: &StatePayload{Action: action},
	})
	if err != nil {
		return nil, err
	}
	if resp.Action == ActionUnsupported {
		return nil, ErrStateUnsupported
	}
	if resp.Status == StatusError {
		return nil, &DetailError{Err: ErrStateOperation, Detail: ": " + resp.Error}
	}
	if resp.State == nil {
		return nil, &DetailError{Err: ErrProtocolError, Detail: ": state response carried no result"}
	}
	return resp.State, nil
}

// Close marks the client as closed. Subsequent calls to any method will return
// ErrClientClosed.
func (c *Client) Close() error {
	c.closed.Store(true)
	return nil
}

// send opens a connection to the daemon, writes the message, reads the
// response, and closes the connection. If the socket does not exist or the
// connection is refused, ErrDaemonNotRunning is returned.
func (c *Client) send(msg *Message) (*Response, error) {
	if c.closed.Load() {
		return nil, ErrClientClosed
	}

	conn, err := net.DialTimeout("unix", c.socketPath, c.timeout)
	if err != nil {
		if isDaemonNotRunning(err) {
			return nil, ErrDaemonNotRunning
		}
		return nil, &SentinelCauseError{Sentinel: ErrConnectionFailed, Cause: err}
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrConnectionFailed, Cause: err}
	}

	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(msg); err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrProtocolError, Cause: err}
	}

	var resp Response
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&resp); err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrProtocolError, Cause: err}
	}

	return &resp, nil
}

// isDaemonNotRunning returns true if the error indicates that the daemon is not
// running (socket file missing or connection refused). It checks the full error
// chain for os.ErrNotExist (which also matches syscall.ENOENT) and
// ECONNREFUSED (connection refused).
func isDaemonNotRunning(err error) bool {
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	return false
}
