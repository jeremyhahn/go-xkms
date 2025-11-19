package tpm2

import (
	"errors"
	"sync"
)

var (
	ErrMockNoMoreResponses = errors.New("mock: no more responses available")
	ErrMockTransportClosed = errors.New("mock: transport closed")
	ErrMockResponseError   = errors.New("mock: simulated error response")
)

// MockTPMTransport implements transport.TPM interface for unit testing
// without requiring a real TPM or simulator
type MockTPMTransport struct {
	mu        sync.Mutex
	responses [][]byte
	errors    []error
	idx       int
	commands  [][]byte
	closed    bool
}

// NewMockTPMTransport creates a new mock transport with predefined responses
func NewMockTPMTransport(responses [][]byte) *MockTPMTransport {
	return &MockTPMTransport{
		responses: responses,
		commands:  make([][]byte, 0),
		errors:    make([]error, len(responses)),
	}
}

// NewMockTPMTransportWithErrors creates a mock transport that can return errors
func NewMockTPMTransportWithErrors(responses [][]byte, errs []error) *MockTPMTransport {
	if len(errs) != len(responses) {
		panic("responses and errors must have same length")
	}
	return &MockTPMTransport{
		responses: responses,
		errors:    errs,
		commands:  make([][]byte, 0),
	}
}

// Send implements transport.TPM interface
func (m *MockTPMTransport) Send(cmd []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, ErrMockTransportClosed
	}

	cmdCopy := make([]byte, len(cmd))
	copy(cmdCopy, cmd)
	m.commands = append(m.commands, cmdCopy)

	if m.idx >= len(m.responses) {
		return nil, ErrMockNoMoreResponses
	}

	resp := m.responses[m.idx]
	err := m.errors[m.idx]
	m.idx++

	if err != nil {
		return nil, err
	}

	if resp == nil {
		return nil, ErrMockResponseError
	}

	return resp, nil
}

// Close closes the mock transport
func (m *MockTPMTransport) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

// GetCommands returns all commands that were sent
func (m *MockTPMTransport) GetCommands() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.commands
}

// Reset resets the mock transport to its initial state
func (m *MockTPMTransport) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.idx = 0
	m.commands = make([][]byte, 0)
	m.closed = false
}

// AddResponse adds a response to the queue
func (m *MockTPMTransport) AddResponse(resp []byte, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.responses = append(m.responses, resp)
	m.errors = append(m.errors, err)
}

// IsClosed returns whether the transport is closed
func (m *MockTPMTransport) IsClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

// CommandCount returns the number of commands sent
func (m *MockTPMTransport) CommandCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.commands)
}

// MockErrorTransport always returns errors
type MockErrorTransport struct {
	err error
}

func NewMockErrorTransport(err error) *MockErrorTransport {
	return &MockErrorTransport{err: err}
}

func (m *MockErrorTransport) Send(cmd []byte) ([]byte, error) {
	return nil, m.err
}
