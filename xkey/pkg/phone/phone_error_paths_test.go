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
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
	"github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errResponder is returned by a responder handler to force a JSON-RPC error.
var errResponder = errors.New("phone rejected the request")

// sendRawResponse encrypts and delivers an arbitrary response body, letting a
// test inject payloads a well-behaved peer would never produce.
func (r *mockPhoneResponder) sendRawResponse(plaintext []byte) {
	ctx := context.Background()

	if _, err := r.transport.Receive(ctx); err != nil {
		r.t.Errorf("responder: receive: %v", err)
		return
	}
	ciphertext, err := r.session.Encrypt(plaintext)
	if err != nil {
		r.t.Errorf("responder: encrypt: %v", err)
		return
	}
	if err := r.transport.Send(ctx, ciphertext); err != nil {
		r.t.Errorf("responder: send: %v", err)
	}
}

// sendUndecryptable delivers a frame the initiator's cipher state cannot open.
func (r *mockPhoneResponder) sendUndecryptable() {
	ctx := context.Background()

	if _, err := r.transport.Receive(ctx); err != nil {
		r.t.Errorf("responder: receive: %v", err)
		return
	}
	if err := r.transport.Send(ctx, []byte("this is not a valid noise frame")); err != nil {
		r.t.Errorf("responder: send: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Constructor validation
// ---------------------------------------------------------------------------

func TestNewPhoneKeyBackendWithTransport_NilTransport(t *testing.T) {
	t.Parallel()

	backend, err := NewPhoneKeyBackendWithTransport(nil, nil)
	assert.ErrorIs(t, err, ErrNotConnected)
	assert.Nil(t, backend)
}

func TestNewPhoneKeyBackendWithTransport_UntrustedDeviceClosesTransport(t *testing.T) {
	t.Parallel()

	transport, _ := newPipeTransports()

	// Neither an expected remote key nor TrustNewDevices: the backend must
	// refuse to be built and must not leave the transport open.
	backend, err := NewPhoneKeyBackendWithTransport(&PhoneKeyBackendConfig{}, transport)
	assert.ErrorIs(t, err, ErrUntrustedDevice)
	assert.Nil(t, backend)
	assert.False(t, transport.IsConnected(), "the rejected transport must be closed")
}

func TestNewPhoneKeyBackendWithTransport_NilConfigDefaultsToUntrusted(t *testing.T) {
	t.Parallel()

	transport, _ := newPipeTransports()

	// The default config has TrustNewDevices=false, so a nil config must be
	// treated as the secure default rather than trusting any peer.
	backend, err := NewPhoneKeyBackendWithTransport(nil, transport)
	assert.ErrorIs(t, err, ErrUntrustedDevice)
	assert.Nil(t, backend)
}

func TestNewPhoneKeyBackendWithTransport_ExpectedRemoteStaticIsTrusted(t *testing.T) {
	t.Parallel()

	transport, _ := newPipeTransports()
	key, err := bootstrap.GenerateNoiseStaticKey()
	require.NoError(t, err)

	backend, err := NewPhoneKeyBackendWithTransport(&PhoneKeyBackendConfig{
		ExpectedRemoteStatic: key.PublicBytes(),
		Logger:               nil, // exercises the default-logger path
	}, transport)
	require.NoError(t, err)
	require.NotNil(t, backend)
	defer func() { _ = backend.Close() }()

	assert.NotEmpty(t, backend.LocalStaticPublicKey())
	assert.Equal(t, key.PublicBytes(), backend.RemoteStaticPublicKey(),
		"the pinned peer key must be reported before the handshake runs")
}

// ---------------------------------------------------------------------------
// Static descriptors
// ---------------------------------------------------------------------------

func TestPhoneKeyBackend_TypeAndCapabilities(t *testing.T) {
	t.Parallel()

	transport, _ := newPipeTransports()
	backend, err := NewPhoneKeyBackendWithTransport(testPhoneKeyBackendConfig(), transport)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	assert.Equal(t, BackendTypePhone, backend.Type())

	caps := backend.Capabilities()
	assert.Equal(t, []int{pairingproto.COSEAlgES256, pairingproto.COSEAlgES384, pairingproto.COSEAlgES512}, caps.SupportedAlgorithms)
	assert.False(t, caps.SupportsExport, "phone keys must never leave the secure element")
	assert.False(t, caps.SupportsImport)
	assert.False(t, caps.SupportsAttestation)
	assert.True(t, caps.HardwareBacked)
	assert.True(t, caps.HandlesUserPresence)
	assert.True(t, caps.HandlesUserVerification)

	handle := &phoneKeyHandle{credentialID: []byte("id"), algorithm: pairingproto.COSEAlgES256}
	assert.Equal(t, BackendTypePhone, handle.BackendID())

	// #1162: the phone vouches for its own credentials only.
	assert.True(t, backend.HandlesUserVerificationFor(handle.BackendID()))
	assert.False(t, backend.HandlesUserVerificationFor(xkms.BackendTypeSoftware))
	assert.False(t, backend.HandlesUserVerificationFor(""))
	assert.True(t, backend.HandlesUserPresenceFor(handle.BackendID()))
	assert.False(t, backend.HandlesUserPresenceFor(xkms.BackendTypeSoftware))
	assert.False(t, backend.HandlesUserPresenceFor(""))
}

// ---------------------------------------------------------------------------
// Closed / disconnected guards
// ---------------------------------------------------------------------------

func TestPhoneKeyBackend_ClosedBackendRejectsEveryOperation(t *testing.T) {
	t.Parallel()

	transport, _ := newPipeTransports()
	backend, err := NewPhoneKeyBackendWithTransport(testPhoneKeyBackendConfig(), transport)
	require.NoError(t, err)

	require.NoError(t, backend.Close())
	require.NoError(t, backend.Close(), "Close must be idempotent")
	assert.False(t, transport.IsConnected(), "Close must release the transport")

	handle := &phoneKeyHandle{credentialID: []byte("credential"), algorithm: pairingproto.COSEAlgES256}
	ctx := context.Background()

	tests := []struct {
		name string
		call func() error
	}{
		{"GenerateCredentialKey", func() error {
			_, _, err := backend.GenerateCredentialKey(pairingproto.COSEAlgES256, []byte("credential"))
			return err
		}},
		{"Sign", func() error {
			_, err := backend.Sign(handle, pairingproto.COSEAlgES256, []byte("digest"))
			return err
		}},
		{"LoadKey", func() error {
			_, err := backend.LoadKey([]byte("credential"), pairingproto.COSEAlgES256)
			return err
		}},
		{"DeleteKey", func() error { return backend.DeleteKey(handle) }},
		{"GetDeviceInfo", func() error {
			_, err := backend.GetDeviceInfo(ctx)
			return err
		}},
		{"Ping", func() error { return backend.Ping(ctx) }},
		{"SendPairingConfirm", func() error {
			_, err := backend.SendPairingConfirm(ctx, "laptop")
			return err
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorIs(t, tt.call(), ErrBackendClosed)
		})
	}
}

func TestPhoneKeyBackend_DisconnectedGuards(t *testing.T) {
	t.Parallel()

	transport, _ := newPipeTransports()
	backend, err := NewPhoneKeyBackendWithTransport(testPhoneKeyBackendConfig(), transport)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	ctx := context.Background()

	// Ping and SendPairingConfirm must not silently connect: they require an
	// already-established session.
	assert.ErrorIs(t, backend.Ping(ctx), ErrNotConnected)

	_, err = backend.SendPairingConfirm(ctx, "laptop")
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = backend.SendRequest(ctx, pairingproto.NewRequest(pairingproto.MethodPing, nil))
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPhoneKeyBackend_InvalidArguments(t *testing.T) {
	t.Parallel()

	transport, _ := newPipeTransports()
	backend, err := NewPhoneKeyBackendWithTransport(testPhoneKeyBackendConfig(), transport)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	t.Run("GenerateCredentialKey empty credential ID", func(t *testing.T) {
		_, _, err := backend.GenerateCredentialKey(pairingproto.COSEAlgES256, nil)
		assert.ErrorIs(t, err, ErrInvalidCredentialID)
	})

	t.Run("GenerateCredentialKey unsupported algorithm", func(t *testing.T) {
		_, _, err := backend.GenerateCredentialKey(-999, []byte("credential"))
		assert.ErrorIs(t, err, ErrUnsupportedAlgorithm)
	})

	t.Run("LoadKey empty credential ID", func(t *testing.T) {
		_, err := backend.LoadKey(nil, pairingproto.COSEAlgES256)
		assert.ErrorIs(t, err, ErrInvalidCredentialID)
	})

	t.Run("Sign foreign key handle", func(t *testing.T) {
		_, err := backend.Sign(foreignHandle{}, pairingproto.COSEAlgES256, []byte("digest"))
		assert.ErrorIs(t, err, ErrInvalidKeyHandle)
	})

	t.Run("DeleteKey foreign key handle", func(t *testing.T) {
		assert.ErrorIs(t, backend.DeleteKey(foreignHandle{}), ErrInvalidKeyHandle)
	})
}

// foreignHandle is a KeyHandle from another backend.
type foreignHandle struct{}

func (foreignHandle) CredentialID() []byte        { return []byte("foreign") }
func (foreignHandle) Algorithm() int              { return pairingproto.COSEAlgES256 }
func (foreignHandle) BackendID() xkms.BackendType { return xkms.BackendTypeSoftware }

// ---------------------------------------------------------------------------
// Wire-level failure handling
// ---------------------------------------------------------------------------

func TestPhoneKeyBackend_UndecryptableResponse(t *testing.T) {
	t.Parallel()

	backend, responder := setupNoiseSessionPair(t)
	defer func() { _ = backend.Close() }()

	go responder.sendUndecryptable()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := backend.Ping(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDecryptionFailed)
}

func TestPhoneKeyBackend_MalformedResponseJSON(t *testing.T) {
	t.Parallel()

	backend, responder := setupNoiseSessionPair(t)
	defer func() { _ = backend.Close() }()

	go responder.sendRawResponse([]byte("{not json"))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := backend.Ping(ctx)
	assert.ErrorIs(t, err, ErrInvalidResponse)
}

func TestPhoneKeyBackend_ResultTypeMismatchIsInvalidResponse(t *testing.T) {
	t.Parallel()

	// A well-formed JSON-RPC envelope whose result is not the expected object.
	badResult := []byte(`{"jsonrpc":"2.0","id":1,"result":"unexpected-string"}`)

	tests := []struct {
		name string
		call func(b *PhoneKeyBackend) error
	}{
		{"Ping", func(b *PhoneKeyBackend) error { return b.Ping(context.Background()) }},

		{"GenerateCredentialKey", func(b *PhoneKeyBackend) error {
			_, _, err := b.GenerateCredentialKey(pairingproto.COSEAlgES256, []byte("credential"))
			return err
		}},
		{"Sign", func(b *PhoneKeyBackend) error {
			_, err := b.Sign(&phoneKeyHandle{credentialID: []byte("credential"), algorithm: pairingproto.COSEAlgES256}, pairingproto.COSEAlgES256, []byte("digest"))
			return err
		}},
		{"LoadKey", func(b *PhoneKeyBackend) error {
			_, err := b.LoadKey([]byte("credential"), pairingproto.COSEAlgES256)
			return err
		}},
		{"SendPairingConfirm", func(b *PhoneKeyBackend) error {
			_, err := b.SendPairingConfirm(context.Background(), "laptop")
			return err
		}},
		{"ListFido2Credentials", func(b *PhoneKeyBackend) error {
			_, err := b.ListFido2Credentials(context.Background(), "example.com")
			return err
		}},
		{"SignFido2Assertion", func(b *PhoneKeyBackend) error {
			_, err := b.SignFido2Assertion(context.Background(), &pairingproto.LocalSignFido2AssertionParams{
				CredentialID:   []byte("credential"),
				ClientDataHash: []byte("hash"),
				RpID:           "example.com",
			})
			return err
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			backend, responder := setupNoiseSessionPair(t)
			defer func() { _ = backend.Close() }()

			go responder.sendRawResponse(badResult)

			assert.ErrorIs(t, tt.call(backend), ErrInvalidResponse)
		})
	}
}

func TestPhoneKeyBackend_PhoneErrorsAreMappedPerOperation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string
		call   func(b *PhoneKeyBackend) error
	}{
		{"DeleteKey", pairingproto.MethodDeleteKey, func(b *PhoneKeyBackend) error {
			return b.DeleteKey(&phoneKeyHandle{credentialID: []byte("credential"), algorithm: pairingproto.COSEAlgES256})
		}},
		{"LoadKey", pairingproto.MethodLoadKey, func(b *PhoneKeyBackend) error {
			_, err := b.LoadKey([]byte("credential"), pairingproto.COSEAlgES256)
			return err
		}},
		{"ListFido2Credentials", pairingproto.MethodLocalListFido2Credentials, func(b *PhoneKeyBackend) error {
			_, err := b.ListFido2Credentials(context.Background(), "example.com")
			return err
		}},
		{"SignFido2Assertion", pairingproto.MethodLocalSignFido2Assertion, func(b *PhoneKeyBackend) error {
			_, err := b.SignFido2Assertion(context.Background(), &pairingproto.LocalSignFido2AssertionParams{
				CredentialID:   []byte("credential"),
				ClientDataHash: []byte("hash"),
				RpID:           "example.com",
			})
			return err
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			backend, responder := setupNoiseSessionPair(t)
			defer func() { _ = backend.Close() }()

			// The mock responder reports handler failures with RPC code
			// -32000, which the client must map to ErrKeyNotFound.
			responder.handlers[tt.method] = func(json.RawMessage) (interface{}, error) {
				return nil, errResponder
			}
			go responder.handleOne()

			err := tt.call(backend)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrKeyNotFound,
				"a JSON-RPC error code must be mapped to its typed error")
		})
	}
}

// TestPhoneKeyBackend_GetDeviceInfoResultTypeMismatch documents that
// GetDeviceInfo returns the raw decode error rather than ErrInvalidResponse,
// unlike the other operations. It must still fail rather than return a
// zero-valued device description.
func TestPhoneKeyBackend_GetDeviceInfoResultTypeMismatch(t *testing.T) {
	t.Parallel()

	backend, responder := setupNoiseSessionPair(t)
	defer func() { _ = backend.Close() }()

	go responder.sendRawResponse([]byte(`{"jsonrpc":"2.0","id":1,"result":"unexpected-string"}`))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	info, err := backend.GetDeviceInfo(ctx)
	require.Error(t, err)
	assert.Nil(t, info)
}

func TestPhoneKeyBackend_TransportSendFailurePropagates(t *testing.T) {
	t.Parallel()

	backend, _ := setupNoiseSessionPair(t)
	defer func() { _ = backend.Close() }()

	// Break the transport underneath an established session.
	transport := backend.transport.(*mockPipeTransport)
	transport.sendErr = errMockRecv

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	assert.ErrorIs(t, backend.Ping(ctx), errMockRecv)

	_, err := backend.GetDeviceInfo(ctx)
	assert.ErrorIs(t, err, errMockRecv)
}

// TestPhoneKeyBackend_SignShortCredentialID is a regression test: Sign used to
// slice the hex-encoded credential ID at a fixed offset for logging and
// panicked for credential IDs shorter than 8 bytes.
func TestPhoneKeyBackend_SignShortCredentialID(t *testing.T) {
	t.Parallel()

	backend, responder := setupNoiseSessionPair(t)
	defer func() { _ = backend.Close() }()

	go responder.handleOne()

	handle := &phoneKeyHandle{credentialID: []byte{0x01, 0x02}, algorithm: pairingproto.COSEAlgES256}
	sig, err := backend.Sign(handle, pairingproto.COSEAlgES256, []byte("digest"))
	require.NoError(t, err)
	assert.Equal(t, []byte{0x30, 0x44}, sig)
}

// TestPhoneKeyBackend_LoadKeyShortCredentialID covers the same fixed-offset
// slicing hazard on the LoadKey path.
func TestPhoneKeyBackend_LoadKeyShortCredentialID(t *testing.T) {
	t.Parallel()

	backend, responder := setupNoiseSessionPair(t)
	defer func() { _ = backend.Close() }()

	go responder.handleOne()

	handle, err := backend.LoadKey([]byte{0xff}, pairingproto.COSEAlgES256)
	require.NoError(t, err)
	assert.Equal(t, []byte{0xff}, handle.CredentialID())
}

func TestShortCredID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"shorter than prefix", "aabb", "aabb"},
		{"exactly prefix", "0123456789abcdef", "0123456789abcdef"},
		{"longer than prefix", "0123456789abcdef00", "0123456789abcdef"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, shortCredID(tt.in))
		})
	}
}

func TestPhoneKeyBackend_LoadKeyCacheAlgorithmMismatch(t *testing.T) {
	t.Parallel()

	backend, responder := setupNoiseSessionPair(t)
	defer func() { _ = backend.Close() }()

	go responder.handleOne()

	credID := []byte("cached-credential")
	_, err := backend.LoadKey(credID, pairingproto.COSEAlgES256)
	require.NoError(t, err)

	// The cached handle is bound to ES256; asking for ES384 must be refused
	// instead of returning a handle with the wrong algorithm.
	_, err = backend.LoadKey(credID, pairingproto.COSEAlgES384)
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm)
}

func TestPhoneKeyBackend_DeleteKeyEvictsCachedHandle(t *testing.T) {
	t.Parallel()

	backend, responder := setupNoiseSessionPair(t)
	defer func() { _ = backend.Close() }()

	credID := []byte("evict-me")

	go responder.handleOne()
	handle, _, err := backend.GenerateCredentialKey(pairingproto.COSEAlgES256, credID)
	require.NoError(t, err)

	backend.mu.RLock()
	_, cached := backend.handles[hex.EncodeToString(credID)]
	backend.mu.RUnlock()
	require.True(t, cached, "generate must cache the handle")

	go responder.handleOne()
	require.NoError(t, backend.DeleteKey(handle))

	backend.mu.RLock()
	_, stillCached := backend.handles[hex.EncodeToString(credID)]
	backend.mu.RUnlock()
	assert.False(t, stillCached, "delete must evict the cached handle")
}

// ---------------------------------------------------------------------------
// Pairing confirmation
// ---------------------------------------------------------------------------

// newAuditedPair builds a connected backend whose audit logger is recorded.
func newAuditedPair(t *testing.T) (*PhoneKeyBackend, *mockPhoneResponder, *recordingAuditLogger) {
	t.Helper()

	initiator, responderTransport := newPipeTransports()
	auditLog := &recordingAuditLogger{}

	backend, err := NewPhoneKeyBackendWithTransport(&PhoneKeyBackendConfig{
		TrustNewDevices:  true,
		OperationTimeout: 5 * time.Second,
		DeviceAddress:    "device-address",
		DeviceName:       "device-name",
		AuditLogger:      auditLog,
		Logger:           slog.New(slog.DiscardHandler),
	}, initiator)
	require.NoError(t, err)

	sessionCh := make(chan *bootstrap.NoiseSession, 1)
	go func() { sessionCh <- runResponderWithIdentity(t, responderTransport) }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, backend.Connect(ctx))

	return backend, newMockPhoneResponder(t, responderTransport, <-sessionCh), auditLog
}

func TestPhoneKeyBackend_SendPairingConfirm_Approved(t *testing.T) {
	t.Parallel()

	backend, responder, auditLog := newAuditedPair(t)
	defer func() { _ = backend.Close() }()

	responder.handlers[pairingproto.MethodPairingConfirm] = func(params json.RawMessage) (interface{}, error) {
		var got pairingproto.PairingConfirmParams
		require.NoError(t, json.Unmarshal(params, &got))
		assert.Equal(t, "laptop", got.DeviceName)
		assert.Equal(t, hex.EncodeToString(backend.LocalStaticPublicKey()), got.PublicKeyHex,
			"the phone must receive our Noise static key for pinning")
		return &pairingproto.PairingConfirmResult{Confirmed: true, DeviceName: "confirmed-phone"}, nil
	}
	go responder.handleOne()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := backend.SendPairingConfirm(ctx, "laptop")
	require.NoError(t, err)
	assert.True(t, result.Confirmed)

	events := auditLog.recorded()
	require.Len(t, events, 2, "connection established + pairing approved")
	assert.Equal(t, audit.OpConnectionEstablished, events[0].op)
	assert.Equal(t, audit.OpPairingApproved, events[1].op)
	assert.Equal(t, "confirmed-phone", events[1].deviceName,
		"the approval must be audited with the name the phone reported")
}

func TestPhoneKeyBackend_SendPairingConfirm_UserRejected(t *testing.T) {
	t.Parallel()

	backend, responder, auditLog := newAuditedPair(t)
	defer func() { _ = backend.Close() }()

	responder.handlers[pairingproto.MethodPairingConfirm] = func(json.RawMessage) (interface{}, error) {
		return &pairingproto.PairingConfirmResult{Confirmed: false}, nil
	}
	go responder.handleOne()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := backend.SendPairingConfirm(ctx, "laptop")
	assert.ErrorIs(t, err, ErrPairingRejected)

	events := auditLog.recorded()
	require.Len(t, events, 2)
	assert.Equal(t, audit.OpPairingDenied, events[1].op)
	assert.Equal(t, "user rejected", events[1].details["reason"])
}

func TestPhoneKeyBackend_SendPairingConfirm_PhoneError(t *testing.T) {
	t.Parallel()

	backend, responder, auditLog := newAuditedPair(t)
	defer func() { _ = backend.Close() }()

	responder.handlers[pairingproto.MethodPairingConfirm] = func(json.RawMessage) (interface{}, error) {
		return nil, errResponder
	}
	go responder.handleOne()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := backend.SendPairingConfirm(ctx, "laptop")
	require.Error(t, err)

	events := auditLog.recorded()
	require.Len(t, events, 2)
	assert.Equal(t, audit.OpPairingDenied, events[1].op)
	assert.Equal(t, errResponder.Error(), events[1].details["reason"])
}

func TestPhoneKeyBackend_CloseAuditsConnectionClosed(t *testing.T) {
	t.Parallel()

	backend, _, auditLog := newAuditedPair(t)

	require.NoError(t, backend.Close())

	events := auditLog.recorded()
	require.Len(t, events, 2)
	assert.Equal(t, audit.OpConnectionClosed, events[1].op)
	assert.Equal(t, "device-address", events[1].deviceID)
	assert.Equal(t, "device-name", events[1].deviceName)

	// A second Close must not emit a duplicate audit record.
	require.NoError(t, backend.Close())
	assert.Len(t, auditLog.recorded(), 2)
}

func TestPhoneKeyBackend_ConnectAuditsNonBLETransport(t *testing.T) {
	t.Parallel()

	backend, _, auditLog := newAuditedPair(t)
	defer func() { _ = backend.Close() }()

	events := auditLog.recorded()
	require.Len(t, events, 1)
	assert.Equal(t, audit.OpConnectionEstablished, events[0].op)
	assert.Equal(t, "non-ble", events[0].details["transport"])
}

// ---------------------------------------------------------------------------
// Bidirectional routing
// ---------------------------------------------------------------------------

func TestPhoneKeyBackend_EnableBidirectionalRoutesRequests(t *testing.T) {
	t.Parallel()

	backend, responder := setupNoiseSessionPair(t)
	defer func() { _ = backend.Close() }()

	_ = backend.EnableBidirectional(nil)

	go responder.handleOne()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// With the router active, SendRequest must still complete a round trip.
	resp, err := backend.SendRequest(ctx, pairingproto.NewRequest(pairingproto.MethodPing, nil))
	require.NoError(t, err)
	require.Nil(t, resp.Error)

	result, err := pairingproto.DecodeResult[pairingproto.PingResult](resp)
	require.NoError(t, err)
	assert.True(t, result.Pong)
}

// ---------------------------------------------------------------------------
// Typed error helpers
// ---------------------------------------------------------------------------

func TestMessageError(t *testing.T) {
	t.Parallel()

	err := &MessageError{Msg: "phone: no AOA device found"}
	assert.Equal(t, "phone: no AOA device found", err.Error())
	assert.NotErrorIs(t, err, ErrDeviceNotFound, "a bare message error must not match sentinels")
}

func TestWrappedError(t *testing.T) {
	t.Parallel()

	err := &WrappedError{Msg: "failed to enumerate USB devices", Err: ErrDeviceNotFound}
	assert.Equal(t, "failed to enumerate USB devices: pairing: device not found", err.Error())
	assert.ErrorIs(t, err, ErrDeviceNotFound, "the cause must stay reachable through Unwrap")
	assert.NotErrorIs(t, err, ErrBLEUnavailable)
}

func TestSentinelCauseError(t *testing.T) {
	t.Parallel()

	cause := errors.New("dbus: unknown object")
	err := &SentinelCauseError{Sentinel: ErrDBusStaleObject, Cause: cause}

	assert.Equal(t, "phone: bluez dbus stale object removed: dbus: unknown object", err.Error())
	assert.ErrorIs(t, err, ErrDBusStaleObject, "callers match on the sentinel")
	assert.ErrorIs(t, err, cause, "callers must also be able to inspect the cause")
	assert.NotErrorIs(t, err, ErrBLEUnavailable)
}

// ---------------------------------------------------------------------------
// Transparent reconnect
// ---------------------------------------------------------------------------

// newDisconnectedPair returns a backend that has not completed the handshake
// plus the responder side of its pipe, so operations exercise the implicit
// Connect performed on first use.
func newDisconnectedPair(t *testing.T) (*PhoneKeyBackend, *mockPipeTransport) {
	t.Helper()

	initiator, responderTransport := newPipeTransports()

	backend, err := NewPhoneKeyBackendWithTransport(&PhoneKeyBackendConfig{
		TrustNewDevices:  true,
		OperationTimeout: 5 * time.Second,
		Logger:           slog.New(slog.DiscardHandler),
	}, initiator)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	return backend, responderTransport
}

func TestPhoneKeyBackend_OperationsConnectOnDemand(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		call func(b *PhoneKeyBackend) error
	}{
		{"GenerateCredentialKey", func(b *PhoneKeyBackend) error {
			_, _, err := b.GenerateCredentialKey(pairingproto.COSEAlgES256, []byte("credential"))
			return err
		}},
		{"Sign", func(b *PhoneKeyBackend) error {
			_, err := b.Sign(&phoneKeyHandle{credentialID: []byte("credential"), algorithm: pairingproto.COSEAlgES256}, pairingproto.COSEAlgES256, []byte("digest"))
			return err
		}},
		{"LoadKey", func(b *PhoneKeyBackend) error {
			_, err := b.LoadKey([]byte("credential"), pairingproto.COSEAlgES256)
			return err
		}},
		{"DeleteKey", func(b *PhoneKeyBackend) error {
			return b.DeleteKey(&phoneKeyHandle{credentialID: []byte("credential"), algorithm: pairingproto.COSEAlgES256})
		}},
		{"GetDeviceInfo", func(b *PhoneKeyBackend) error {
			_, err := b.GetDeviceInfo(context.Background())
			return err
		}},
		{"ListFido2Credentials", func(b *PhoneKeyBackend) error {
			_, err := b.ListFido2Credentials(context.Background(), "example.com")
			return err
		}},
		{"SignFido2Assertion", func(b *PhoneKeyBackend) error {
			_, err := b.SignFido2Assertion(context.Background(), &pairingproto.LocalSignFido2AssertionParams{
				CredentialID:   []byte("credential"),
				ClientDataHash: []byte("hash"),
				RpID:           "example.com",
			})
			return err
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name+" succeeds after implicit connect", func(t *testing.T) {
			t.Parallel()

			backend, responderTransport := newDisconnectedPair(t)
			require.False(t, backend.IsConnected())

			done := make(chan struct{})
			go func() {
				defer close(done)
				session := runResponderWithIdentity(t, responderTransport)
				newMockPhoneResponder(t, responderTransport, session).handleOne()
			}()

			require.NoError(t, tt.call(backend))
			assert.True(t, backend.IsConnected(), "the operation must have established the session")
			<-done
		})

		t.Run(tt.name+" surfaces handshake failure", func(t *testing.T) {
			t.Parallel()

			backend, responderTransport := newDisconnectedPair(t)

			// Answer the identity exchange with an invalid status so the
			// handshake fails before any RPC is attempted.
			go func() {
				<-responderTransport.recvCh
				responderTransport.sendCh <- []byte{0xEE}
			}()

			err := tt.call(backend)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrNoiseHandshakeFailed)
			assert.False(t, backend.IsConnected())
		})
	}
}

func TestPhoneKeyBackend_TransportFailurePropagatesPerOperation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		call func(b *PhoneKeyBackend) error
	}{
		{"GenerateCredentialKey", func(b *PhoneKeyBackend) error {
			_, _, err := b.GenerateCredentialKey(pairingproto.COSEAlgES256, []byte("credential"))
			return err
		}},
		{"Sign", func(b *PhoneKeyBackend) error {
			_, err := b.Sign(&phoneKeyHandle{credentialID: []byte("credential"), algorithm: pairingproto.COSEAlgES256}, pairingproto.COSEAlgES256, []byte("digest"))
			return err
		}},
		{"LoadKey", func(b *PhoneKeyBackend) error {
			_, err := b.LoadKey([]byte("credential"), pairingproto.COSEAlgES256)
			return err
		}},
		{"DeleteKey", func(b *PhoneKeyBackend) error {
			return b.DeleteKey(&phoneKeyHandle{credentialID: []byte("credential"), algorithm: pairingproto.COSEAlgES256})
		}},
		{"SendPairingConfirm", func(b *PhoneKeyBackend) error {
			_, err := b.SendPairingConfirm(context.Background(), "laptop")
			return err
		}},
		{"ListFido2Credentials", func(b *PhoneKeyBackend) error {
			_, err := b.ListFido2Credentials(context.Background(), "example.com")
			return err
		}},
		{"SignFido2Assertion", func(b *PhoneKeyBackend) error {
			_, err := b.SignFido2Assertion(context.Background(), &pairingproto.LocalSignFido2AssertionParams{
				CredentialID:   []byte("credential"),
				ClientDataHash: []byte("hash"),
				RpID:           "example.com",
			})
			return err
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			backend, _ := setupNoiseSessionPair(t)
			defer func() { _ = backend.Close() }()

			backend.transport.(*mockPipeTransport).sendErr = errMockRecv

			assert.ErrorIs(t, tt.call(backend), errMockRecv)
		})
	}
}

// TestPhoneKeyBackend_SendRequestRejectsUnencodableParams verifies a request
// whose parameters cannot be serialized is refused locally with a protocol
// error instead of being sent as a malformed frame.
func TestPhoneKeyBackend_SendRequestRejectsUnencodableParams(t *testing.T) {
	t.Parallel()

	backend, _ := setupNoiseSessionPair(t)
	defer func() { _ = backend.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// A channel is not representable in JSON.
	req := pairingproto.NewRequest(pairingproto.MethodPing, make(chan int))

	resp, err := backend.SendRequest(ctx, req)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrProtocolError)

	// The session must remain usable: nothing was written to the wire.
	assert.True(t, backend.IsConnected())
}
