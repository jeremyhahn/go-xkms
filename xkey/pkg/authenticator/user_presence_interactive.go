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

package authenticator

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// DefaultUserPresenceTimeout is the default timeout for user presence requests
// when no timeout is specified in the request.
const DefaultUserPresenceTimeout = 30 * time.Second

// InteractiveHandler prompts the user via terminal for presence and verification.
// It supports touch simulation (press ENTER) and PIN entry.
// All methods are safe for concurrent use.
type InteractiveHandler struct {
	mu     sync.Mutex
	reader io.Reader
	writer io.Writer
	fd     int // File descriptor for terminal operations
}

// NewInteractiveHandler creates a new InteractiveHandler using stdin/stdout.
// Returns ErrTerminalUnavailable if stdin is not a terminal.
func NewInteractiveHandler() (*InteractiveHandler, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, ErrTerminalUnavailable
	}
	return &InteractiveHandler{
		reader: os.Stdin,
		writer: os.Stdout,
		fd:     int(os.Stdin.Fd()),
	}, nil
}

// NewInteractiveHandlerWithIO creates an InteractiveHandler with custom I/O.
// This is primarily useful for testing scenarios where terminal I/O must be mocked.
// The fd parameter should be the file descriptor for terminal operations,
// or -1 if terminal operations should fall back to line-based reading.
func NewInteractiveHandlerWithIO(reader io.Reader, writer io.Writer, fd int) *InteractiveHandler {
	return &InteractiveHandler{
		reader: reader,
		writer: writer,
		fd:     fd,
	}
}

// RequestUserPresence prompts the user to press ENTER to confirm presence.
// It displays information about the operation and waits for user input.
func (h *InteractiveHandler) RequestUserPresence(ctx context.Context, req *UserPresenceRequest) (*UserPresenceResult, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	timeout := req.Timeout
	if timeout == 0 {
		timeout = DefaultUserPresenceTimeout
	}

	// Create context with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Drain any pending input from stdin to prevent buffered ENTER from previous operations
	h.drainPendingInput()

	// Display prompt
	h.displayPresencePrompt(req)

	// Wait for user input or timeout
	// Require "y" + ENTER to prevent buffered newlines from auto-approving
	resultCh := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(h.reader)
		if scanner.Scan() {
			resultCh <- strings.TrimSpace(scanner.Text())
		} else {
			resultCh <- ""
		}
	}()

	select {
	case <-timeoutCtx.Done():
		if timeoutCtx.Err() == context.DeadlineExceeded {
			_, _ = fmt.Fprintf(h.writer, "\n   Timeout - user presence not confirmed\n")
			return nil, ErrUserPresenceTimeout
		}
		return nil, timeoutCtx.Err()
	case input := <-resultCh:
		if input == "y" || input == "Y" || input == "yes" || input == "YES" {
			_, _ = fmt.Fprintf(h.writer, "   User presence confirmed\n")
			return &UserPresenceResult{Approved: true}, nil
		}
		_, _ = fmt.Fprintf(h.writer, "   User presence denied (expected 'y')\n")
		return nil, ErrUserPresenceDenied
	}
}

// displayPresencePrompt writes the user presence prompt to the output.
func (h *InteractiveHandler) displayPresencePrompt(req *UserPresenceRequest) {
	operation := req.Operation
	if operation == "" {
		operation = "operation"
	}
	rpDisplay := req.RPID
	if req.RPName != "" {
		rpDisplay = req.RPName
	}

	_, _ = fmt.Fprintf(h.writer, "\nUser presence required for %s\n", operation)
	if rpDisplay != "" {
		_, _ = fmt.Fprintf(h.writer, "   Relying Party: %s\n", rpDisplay)
	}
	if req.UserName != "" {
		_, _ = fmt.Fprintf(h.writer, "   User: %s\n", req.UserName)
	}
	_, _ = fmt.Fprintf(h.writer, "\n   Type 'y' and press ENTER to approve, or Ctrl+C to cancel: ")
	h.syncOutput()
}

// RequestUserVerification prompts for PIN entry when required.
// If PINRequired is false, it prompts for ENTER key confirmation.
func (h *InteractiveHandler) RequestUserVerification(ctx context.Context, req *UserVerificationRequest) (*UserVerificationResult, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	timeout := req.Timeout
	if timeout == 0 {
		timeout = DefaultUserPresenceTimeout
	}

	// Create context with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Display verification prompt
	h.displayVerificationPrompt(req)

	var pin string
	var err error

	if req.PINRequired {
		pin, err = h.readPIN(timeoutCtx)
		if err != nil {
			return nil, err
		}
	} else {
		err = h.waitForConfirmation(timeoutCtx)
		if err != nil {
			return nil, err
		}
	}

	_, _ = fmt.Fprintf(h.writer, "   User verified\n")
	return &UserVerificationResult{
		Verified: true,
		PIN:      pin,
	}, nil
}

// displayVerificationPrompt writes the user verification prompt to the output.
func (h *InteractiveHandler) displayVerificationPrompt(req *UserVerificationRequest) {
	operation := req.Operation
	if operation == "" {
		operation = "operation"
	}
	rpDisplay := req.RPID
	if req.RPName != "" {
		rpDisplay = req.RPName
	}

	_, _ = fmt.Fprintf(h.writer, "\nUser verification required for %s\n", operation)
	if rpDisplay != "" {
		_, _ = fmt.Fprintf(h.writer, "   Relying Party: %s\n", rpDisplay)
	}
	if req.UserName != "" {
		_, _ = fmt.Fprintf(h.writer, "   User: %s\n", req.UserName)
	}
	h.syncOutput()
}

// pinReadResult holds the result of a PIN read operation.
type pinReadResult struct {
	pin []byte
	err error
}

// readPIN reads a PIN from the terminal with hidden input.
func (h *InteractiveHandler) readPIN(ctx context.Context) (string, error) {
	_, _ = fmt.Fprintf(h.writer, "\n   Enter PIN: ")
	h.syncOutput()

	pinCh := make(chan pinReadResult, 1)

	go func() {
		// Check if we have a real terminal
		if term.IsTerminal(h.fd) {
			pinBytes, err := term.ReadPassword(h.fd)
			pinCh <- pinReadResult{pin: pinBytes, err: err}
		} else {
			// Fallback for testing - read line normally
			scanner := bufio.NewScanner(h.reader)
			if scanner.Scan() {
				pinCh <- pinReadResult{pin: []byte(scanner.Text()), err: nil}
			} else {
				pinCh <- pinReadResult{pin: nil, err: scanner.Err()}
			}
		}
	}()

	select {
	case <-ctx.Done():
		if ctx.Err() == context.DeadlineExceeded {
			_, _ = fmt.Fprintf(h.writer, "\n   Timeout - verification failed\n")
			return "", ErrUserPresenceTimeout
		}
		return "", ctx.Err()
	case result := <-pinCh:
		_, _ = fmt.Fprintf(h.writer, "\n") // New line after hidden input
		if result.err != nil {
			return "", ErrUserVerificationDenied
		}
		pin := strings.TrimSpace(string(result.pin))
		if pin == "" {
			_, _ = fmt.Fprintf(h.writer, "   Verification failed - empty PIN\n")
			return "", ErrUserVerificationDenied
		}
		return pin, nil
	}
}

// waitForConfirmation waits for the user to type 'y' and press ENTER.
func (h *InteractiveHandler) waitForConfirmation(ctx context.Context) error {
	_, _ = fmt.Fprintf(h.writer, "\n   Type 'y' and press ENTER to verify: ")
	h.syncOutput()

	resultCh := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(h.reader)
		if scanner.Scan() {
			resultCh <- strings.TrimSpace(scanner.Text())
		} else {
			resultCh <- ""
		}
	}()

	select {
	case <-ctx.Done():
		if ctx.Err() == context.DeadlineExceeded {
			_, _ = fmt.Fprintf(h.writer, "\n   Timeout - verification failed\n")
			return ErrUserPresenceTimeout
		}
		return ctx.Err()
	case input := <-resultCh:
		if input == "y" || input == "Y" || input == "yes" || input == "YES" {
			return nil
		}
		_, _ = fmt.Fprintf(h.writer, "   Verification denied (expected 'y')\n")
		return ErrUserVerificationDenied
	}
}

// drainPendingInput discards any buffered input to prevent stale ENTER presses
// from automatically approving new user presence requests.
func (h *InteractiveHandler) drainPendingInput() {
	// For stdin, we can use non-blocking read to drain pending data
	if f, ok := h.reader.(*os.File); ok {
		// Set non-blocking temporarily
		fd := int(f.Fd())
		if err := setNonBlocking(fd, true); err != nil {
			return
		}
		// Read and discard any pending data
		buf := make([]byte, 1024)
		for {
			n, err := f.Read(buf)
			if n == 0 || err != nil {
				break
			}
		}
		// Restore blocking mode
		_ = setNonBlocking(fd, false)
	}
}

// setNonBlocking sets or clears the O_NONBLOCK flag on a file descriptor.
func setNonBlocking(fd int, nonBlocking bool) error {
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return err
	}
	if nonBlocking {
		flags |= unix.O_NONBLOCK
	} else {
		flags &^= unix.O_NONBLOCK
	}
	_, err = unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags)
	return err
}

// Close releases resources held by the InteractiveHandler.
// This is a no-op for stdin/stdout but provided for interface consistency.
func (h *InteractiveHandler) Close() error {
	return nil
}

// syncOutput ensures all output is flushed to the terminal immediately.
func (h *InteractiveHandler) syncOutput() {
	if f, ok := h.writer.(*os.File); ok {
		_ = f.Sync()
	}
}

// Ensure InteractiveHandler implements UserPresenceHandler at compile time.
var _ UserPresenceHandler = (*InteractiveHandler)(nil)
