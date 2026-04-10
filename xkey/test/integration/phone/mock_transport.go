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

package phone

import (
	"context"
	"sync"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

// MockTransport simulates BLE transport for integration testing.
// It connects directly to a MockPhone instance in-process.
type MockTransport struct {
	mu            sync.Mutex
	mockPhone     *MockPhone
	noiseSession  *phone.NoiseSession
	fragmenter    *phone.Fragmenter
	reassembler   *phone.Reassembler
	mtu           int
	connected     bool
	handshakeDone bool
}

// NewMockTransport creates a mock transport connected to a mock phone.
func NewMockTransport(mockPhone *MockPhone, mtu int) *MockTransport {
	if mtu < phone.MinMTU {
		mtu = phone.DefaultMTU
	}
	return &MockTransport{
		mockPhone:   mockPhone,
		mtu:         mtu,
		fragmenter:  phone.NewFragmenter(mtu),
		reassembler: phone.NewReassembler(),
	}
}

// Connect simulates BLE connection and performs Noise handshake.
func (t *MockTransport) Connect(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.connected {
		return nil
	}

	// Initialize mock phone's Noise session
	if err := t.mockPhone.InitNoiseSession(); err != nil {
		return err
	}

	// Initialize initiator's Noise session
	session, err := phone.NewNoiseSession(&phone.NoiseSessionConfig{
		IsInitiator: true,
	})
	if err != nil {
		return err
	}

	if err := session.InitHandshake(); err != nil {
		return err
	}

	t.noiseSession = session

	// Perform Noise XX handshake
	if err := t.performHandshake(); err != nil {
		return err
	}

	t.connected = true
	t.handshakeDone = true
	return nil
}

func (t *MockTransport) performHandshake() error {
	// Message 1: Initiator -> Responder (e)
	msg1, complete, err := t.noiseSession.HandshakeMessage(nil)
	if err != nil {
		return err
	}
	if complete {
		return phone.ErrNoiseHandshakeFailed
	}

	// Message 2: Responder -> Initiator (e, ee, s, es)
	msg2, complete, err := t.mockPhone.ProcessHandshakeMessage(msg1)
	if err != nil {
		return err
	}
	if complete {
		return phone.ErrNoiseHandshakeFailed
	}

	// Message 3: Initiator -> Responder (s, se)
	msg3, complete, err := t.noiseSession.HandshakeMessage(msg2)
	if err != nil {
		return err
	}
	if !complete {
		return phone.ErrNoiseHandshakeFailed
	}

	// Final: Responder processes message 3
	_, complete, err = t.mockPhone.ProcessHandshakeMessage(msg3)
	if err != nil {
		return err
	}
	if !complete {
		return phone.ErrNoiseHandshakeFailed
	}

	return nil
}

// SendRequest sends a request and receives a response.
func (t *MockTransport) SendRequest(req *phone.Request) (*phone.Response, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.connected || !t.handshakeDone {
		return nil, phone.ErrNotConnected
	}

	// Encode request
	reqBytes, err := phone.EncodeRequest(req)
	if err != nil {
		return nil, err
	}

	// Encrypt request
	encrypted, err := t.noiseSession.Encrypt(reqBytes)
	if err != nil {
		return nil, err
	}

	// Fragment (simulates BLE MTU constraint)
	fragments, err := t.fragmenter.Fragment(encrypted)
	if err != nil {
		return nil, err
	}

	// Reassemble on "phone side" (simulates receiving fragments)
	t.reassembler.Reset()
	for _, fragData := range fragments {
		frag, err := phone.DecodeFragment(fragData)
		if err != nil {
			return nil, err
		}
		complete, err := t.reassembler.AddFragment(frag)
		if err != nil {
			return nil, err
		}
		if complete {
			break
		}
	}

	reassembled, err := t.reassembler.Assemble()
	if err != nil {
		return nil, err
	}

	// Process on mock phone
	encryptedResp, err := t.mockPhone.ProcessRequest(reassembled)
	if err != nil {
		return nil, err
	}

	// Fragment response (simulates BLE MTU constraint on response)
	respFragments, err := t.fragmenter.Fragment(encryptedResp)
	if err != nil {
		return nil, err
	}

	// Reassemble response on "desktop side"
	t.reassembler.Reset()
	for _, fragData := range respFragments {
		frag, err := phone.DecodeFragment(fragData)
		if err != nil {
			return nil, err
		}
		complete, err := t.reassembler.AddFragment(frag)
		if err != nil {
			return nil, err
		}
		if complete {
			break
		}
	}

	reassembledResp, err := t.reassembler.Assemble()
	if err != nil {
		return nil, err
	}

	// Decrypt response
	decrypted, err := t.noiseSession.Decrypt(reassembledResp)
	if err != nil {
		return nil, err
	}

	// Decode response
	return phone.DecodeResponse(decrypted)
}

// Disconnect simulates BLE disconnection.
func (t *MockTransport) Disconnect() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.connected = false
	t.handshakeDone = false
	t.noiseSession = nil
	return nil
}

// IsConnected returns whether the transport is connected.
func (t *MockTransport) IsConnected() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.connected && t.handshakeDone
}

// MTU returns the configured MTU.
func (t *MockTransport) MTU() int {
	return t.mtu
}
