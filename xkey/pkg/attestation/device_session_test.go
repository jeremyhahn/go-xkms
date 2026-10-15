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

package attestation_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
	"github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation/attesttest"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// This file exercises attestOverSession, newLiveAttestor and
// verifyReattestation at the wire-transport level, complementing
// device_test.go's exercise of VerifyDeviceAttestation directly.
//
// AttestOverSession is driven over a real bootstrap.NoiseSession, established
// here by hand rather than through pairingproto.PerformHandshake: the property
// under test is what happens after the handshake, and a scripted transport
// lets each failure be produced deliberately instead of relying on a full
// phone responder to misbehave in exactly the right way.

// establishedSessionPair returns two Noise sessions that have completed a
// real XX handshake against each other -- the minimum AttestOverSession
// needs to derive a channel binding and encrypt/decrypt the exchange. It
// skips the identity-exchange framing pairingproto.PerformHandshake performs,
// because AttestOverSession itself never touches that layer.
func establishedSessionPair(t *testing.T) (client, server *bootstrap.NoiseSession) {
	t.Helper()

	client, err := bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{IsInitiator: true})
	require.NoError(t, err)
	server, err = bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{IsInitiator: false})
	require.NoError(t, err)

	require.NoError(t, client.InitHandshake())
	require.NoError(t, server.InitHandshake())

	msg1, complete, err := client.HandshakeMessage(nil)
	require.NoError(t, err)
	require.False(t, complete)

	msg2, complete, err := server.HandshakeMessage(msg1)
	require.NoError(t, err)
	require.False(t, complete)

	msg3, complete, err := client.HandshakeMessage(msg2)
	require.NoError(t, err)
	require.True(t, complete, "the initiator completes on its third message")

	_, complete, err = server.HandshakeMessage(msg3)
	require.NoError(t, err)
	require.True(t, complete, "the responder completes on receiving the third message")

	return client, server
}

// scriptedTransport implements pairingproto.Transport with a caller-supplied
// SendAndReceive, so AttestOverSession's branches past the transport call
// can be driven directly without a full phone responder goroutine.
type scriptedTransport struct {
	respond func(ctx context.Context, sent []byte) ([]byte, error)
}

func (s *scriptedTransport) Send(context.Context, []byte) error { return nil }

func (s *scriptedTransport) Receive(context.Context) ([]byte, error) {
	return nil, errors.New("scriptedTransport: Receive is unused by AttestOverSession")
}

func (s *scriptedTransport) SendAndReceive(ctx context.Context, m []byte) ([]byte, error) {
	return s.respond(ctx, m)
}

func (s *scriptedTransport) IsConnected() bool { return true }
func (s *scriptedTransport) Close() error      { return nil }

// discardLogger is a logger that never writes, so test output stays on the
// assertions rather than the (expected) refusal log lines.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// honestResponder builds a scriptedTransport that answers exactly like a
// contract-faithful phone: it decrypts the request the caller sent, signs
// the nonce it finds there with dak, and encrypts a valid result back.
func honestResponder(t *testing.T, server *bootstrap.NoiseSession, dak *attesttest.DAK) *scriptedTransport {
	t.Helper()

	return &scriptedTransport{
		respond: func(_ context.Context, sent []byte) ([]byte, error) {
			plaintext, err := server.Decrypt(sent)
			if err != nil {
				return nil, err
			}
			req, err := pairingproto.DecodeRequest(plaintext)
			if err != nil {
				return nil, err
			}
			var params pairingproto.LocalAttestDeviceParams
			raw, err := json.Marshal(req.Params)
			if err != nil {
				return nil, err
			}
			if err := json.Unmarshal(raw, &params); err != nil {
				return nil, err
			}
			binding, err := pairingproto.AttestChannelBinding(server)
			if err != nil {
				return nil, err
			}
			result := dak.Respond(t, params.Purpose, params.Nonce, binding)
			respBytes, err := pairingproto.EncodeResponse(req.ID, result)
			if err != nil {
				return nil, err
			}
			return server.Encrypt(respBytes)
		},
	}
}

// TestAttestOverSession_Success is the full round trip: a real handshake, a
// real challenge, a contract-faithful signed answer, and a verified result.
func TestAttestOverSession_Success(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	dak := attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())
	trust := &attestation.Trust{Pool: ca.Pool(), Applications: attesttest.Applications()}

	client, server := establishedSessionPair(t)
	transport := honestResponder(t, server, dak)

	verified, err := attestation.AttestOverSession(context.Background(), transport, client, trust, pairingproto.AttestPurposePair, discardLogger())

	require.NoError(t, err)
	require.NotNil(t, verified)
	assert.Equal(t, hexFingerprint(dak), verified.Result.DeviceFingerprint)
}

// TestAttestOverSession_ChannelBindingUnavailable pins that a session whose
// handshake never completed is refused before the transport is ever used --
// there is no authenticated peer key yet for the binding to commit to.
func TestAttestOverSession_ChannelBindingUnavailable(t *testing.T) {
	session, err := bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{IsInitiator: true})
	require.NoError(t, err)

	transport := &scriptedTransport{respond: func(context.Context, []byte) ([]byte, error) {
		t.Fatal("the transport must not be used before the channel binding is available")
		return nil, nil
	}}

	verified, err := attestation.AttestOverSession(context.Background(), transport, session, &attestation.Trust{}, pairingproto.AttestPurposePair, discardLogger())

	require.Error(t, err)
	assert.ErrorIs(t, err, attestation.ErrDeviceAttestFailed)
	assert.Nil(t, verified)
}

// TestAttestOverSession_TransportError pins the wrap around a transport
// failure -- the RPC never got an answer at all.
func TestAttestOverSession_TransportError(t *testing.T) {
	client, _ := establishedSessionPair(t)
	transportErr := errors.New("link dropped")
	transport := &scriptedTransport{respond: func(context.Context, []byte) ([]byte, error) {
		return nil, transportErr
	}}

	verified, err := attestation.AttestOverSession(context.Background(), transport, client, &attestation.Trust{}, pairingproto.AttestPurposePair, discardLogger())

	require.Error(t, err)
	assert.ErrorIs(t, err, attestation.ErrDeviceAttestFailed)
	assert.ErrorIs(t, err, transportErr)
	assert.Nil(t, verified)
}

// TestAttestOverSession_UndecryptableResponse pins the response-decryption
// branch: bytes that never went through the peer's cipher state must be
// refused rather than crash the caller.
func TestAttestOverSession_UndecryptableResponse(t *testing.T) {
	client, _ := establishedSessionPair(t)
	transport := &scriptedTransport{respond: func(context.Context, []byte) ([]byte, error) {
		return []byte("not a noise ciphertext"), nil
	}}

	verified, err := attestation.AttestOverSession(context.Background(), transport, client, &attestation.Trust{}, pairingproto.AttestPurposePair, discardLogger())

	require.Error(t, err)
	assert.ErrorIs(t, err, attestation.ErrDeviceAttestFailed)
	assert.Nil(t, verified)
}

// TestAttestOverSession_MalformedResponseJSON pins the decode-response
// branch: a correctly-decrypted but non-JSON-RPC payload must be refused.
func TestAttestOverSession_MalformedResponseJSON(t *testing.T) {
	client, server := establishedSessionPair(t)
	transport := &scriptedTransport{respond: func(context.Context, []byte) ([]byte, error) {
		return server.Encrypt([]byte("not json at all"))
	}}

	verified, err := attestation.AttestOverSession(context.Background(), transport, client, &attestation.Trust{}, pairingproto.AttestPurposePair, discardLogger())

	require.Error(t, err)
	assert.ErrorIs(t, err, attestation.ErrDeviceAttestFailed)
	assert.Nil(t, verified)
}

// TestAttestOverSession_RPCError pins that an RPC-level refusal from the
// peer surfaces as ErrDeviceAttestFailed carrying the peer's message.
func TestAttestOverSession_RPCError(t *testing.T) {
	client, server := establishedSessionPair(t)
	transport := &scriptedTransport{respond: func(context.Context, []byte) ([]byte, error) {
		raw, err := pairingproto.EncodeErrorResponse(1, 1000, "user declined attestation", nil)
		require.NoError(t, err)
		return server.Encrypt(raw)
	}}

	verified, err := attestation.AttestOverSession(context.Background(), transport, client, &attestation.Trust{}, pairingproto.AttestPurposePair, discardLogger())

	require.Error(t, err)
	assert.ErrorIs(t, err, attestation.ErrDeviceAttestFailed)
	assert.Contains(t, err.Error(), "user declined attestation")
	assert.Nil(t, verified)
}

// TestAttestOverSession_MalformedResult pins the result-decode branch: a
// well-formed JSON-RPC envelope whose result cannot unmarshal into
// LocalAttestDeviceResult must be refused.
func TestAttestOverSession_MalformedResult(t *testing.T) {
	client, server := establishedSessionPair(t)
	transport := &scriptedTransport{respond: func(context.Context, []byte) ([]byte, error) {
		resp := &pairingproto.Response{JSONRPC: "2.0", ID: 1, Result: json.RawMessage("123")}
		raw, err := json.Marshal(resp)
		require.NoError(t, err)
		return server.Encrypt(raw)
	}}

	verified, err := attestation.AttestOverSession(context.Background(), transport, client, &attestation.Trust{}, pairingproto.AttestPurposePair, discardLogger())

	require.Error(t, err)
	assert.ErrorIs(t, err, attestation.ErrDeviceAttestFailed)
	assert.Nil(t, verified)
}

// hexFingerprint hex-encodes a DAK's fingerprint the way the verified result
// carries it, to compare against attestation.Result.DeviceFingerprint.
func hexFingerprint(dak *attesttest.DAK) string {
	const hextable = "0123456789abcdef"
	fp := dak.Fingerprint()
	out := make([]byte, len(fp)*2)
	for i, b := range fp {
		out[i*2] = hextable[b>>4]
		out[i*2+1] = hextable[b&0x0f]
	}
	return string(out)
}

// --- verifyReattestation ---

// TestVerifyReattestation_Success is the accept path beside
// device_test.go's TestVerifyReattestationRefusesAnIncompleteBindingBeforeAsking:
// a valid binding, run over a real session against a contract-faithful
// answer, must succeed end to end.
func TestVerifyReattestation_Success(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	dak := attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())
	trust := &attestation.Trust{Pool: ca.Pool(), Applications: attesttest.Applications()}
	binding := attestation.DeviceBinding{Fingerprint: hexFingerprint(dak), ProtocolVersion: pairingproto.AttestProtocolV2}

	client, server := establishedSessionPair(t)
	transport := honestResponder(t, server, dak)

	err := attestation.VerifyReattestation(context.Background(), transport, client, binding, trust, discardLogger())

	require.NoError(t, err)
}

// TestVerifyReattestation_IdentityChangedRefusesAfterAValidProof pins that a
// device proving liveness for the WRONG identity is still refused: the proof
// alone is not enough, it must be a proof for the bound key.
func TestVerifyReattestation_IdentityChangedRefusesAfterAValidProof(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	dak := attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())
	other := attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())
	trust := &attestation.Trust{Pool: ca.Pool(), Applications: attesttest.Applications()}
	binding := attestation.DeviceBinding{Fingerprint: hexFingerprint(dak), ProtocolVersion: pairingproto.AttestProtocolV2}

	client, server := establishedSessionPair(t)
	transport := honestResponder(t, server, other)

	err := attestation.VerifyReattestation(context.Background(), transport, client, binding, trust, discardLogger())

	require.Error(t, err)
	assert.ErrorIs(t, err, attestation.ErrDeviceIdentityChanged)
}

// TestVerifyReattestation_RefusesAnotherApplication pins that re-attestation
// applies the same attestationApplicationId check as pairing (go-xkms#1305):
// the bound key presented by an application off the allow-list is refused.
func TestVerifyReattestation_RefusesAnotherApplication(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	claims := attesttest.DeviceKeyClaims()
	claims.RootOfTrust = attesttest.AttestedBootState()
	claims.ApplicationID.Packages[0].Name = "com.example.malicious"
	dak := attesttest.NewDAKWithClaims(t, ca, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, claims)
	trust := &attestation.Trust{Pool: ca.Pool(), Applications: attesttest.Applications()}
	binding := attestation.DeviceBinding{Fingerprint: hexFingerprint(dak), ProtocolVersion: pairingproto.AttestProtocolV2}

	client, server := establishedSessionPair(t)
	transport := honestResponder(t, server, dak)

	err := attestation.VerifyReattestation(context.Background(), transport, client, binding, trust, discardLogger())

	require.ErrorIs(t, err, pairing.ErrApplicationDenied)
}

// --- newLiveAttestor ---
//
// NewLiveAttestor closes over the binding and a trust loader and returns a
// pairingproto.LiveAttestFunc: an RPCExchange closure plus a channel binding the
// CALLER already derived. Both are supplied directly here, which is enough
// control to drive every branch without a Noise session at all.

// signedExchange returns an RPCExchange that answers local.attestDevice
// exactly as a contract-faithful phone would, signing whatever nonce and
// purpose the request actually carries against the given channel binding.
func signedExchange(t *testing.T, dak *attesttest.DAK, channelBinding []byte) pairingproto.RPCExchange {
	t.Helper()

	return func(_ context.Context, req *pairingproto.Request) (*pairingproto.Response, error) {
		var params pairingproto.LocalAttestDeviceParams
		raw, err := json.Marshal(req.Params)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(raw, &params))

		result := dak.Respond(t, params.Purpose, params.Nonce, channelBinding)
		resultJSON, err := json.Marshal(result)
		require.NoError(t, err)
		return &pairingproto.Response{JSONRPC: "2.0", ID: req.ID, Result: resultJSON}, nil
	}
}

// TestNewLiveAttestor_Success is the accept path: a valid binding, a
// contract-faithful exchange, matching identity.
func TestNewLiveAttestor_Success(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	dak := attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())
	binding := attestation.DeviceBinding{Fingerprint: hexFingerprint(dak), ProtocolVersion: pairingproto.AttestProtocolV2}
	channelBinding := attesttest.FixedBytes(0x77, pairingproto.AttestChannelBindingSize)

	attest := attestation.NewLiveAttestor(binding, func() (*attestation.Trust, error) {
		return &attestation.Trust{Pool: ca.Pool(), Applications: attesttest.Applications()}, nil
	}, discardLogger())

	err := attest(context.Background(), signedExchange(t, dak, channelBinding), channelBinding)

	require.NoError(t, err)
}

// TestNewLiveAttestor_RefusesAnotherSigner pins that the backend's
// connect-time re-attestation applies the attestationApplicationId check too
// (go-xkms#1305): the allow-listed package signed by another key is refused.
func TestNewLiveAttestor_RefusesAnotherSigner(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	claims := attesttest.DeviceKeyClaims()
	claims.RootOfTrust = attesttest.AttestedBootState()
	claims.ApplicationID.SignatureDigests = [][]byte{attesttest.FixedBytes(0x66, 32)}
	dak := attesttest.NewDAKWithClaims(t, ca, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, claims)
	binding := attestation.DeviceBinding{Fingerprint: hexFingerprint(dak), ProtocolVersion: pairingproto.AttestProtocolV2}
	channelBinding := attesttest.FixedBytes(0x78, pairingproto.AttestChannelBindingSize)

	attest := attestation.NewLiveAttestor(binding, func() (*attestation.Trust, error) {
		return &attestation.Trust{Pool: ca.Pool(), Applications: attesttest.Applications()}, nil
	}, discardLogger())

	err := attest(context.Background(), signedExchange(t, dak, channelBinding), channelBinding)

	require.ErrorIs(t, err, pairing.ErrApplicationDenied)
}

// TestNewLiveAttestor_InvalidBindingRefusesBeforeExchanging pins that an
// incomplete binding is refused before the exchange (and therefore
// loadTrust) is ever invoked -- nothing to prove possession of, nothing
// worth asking for.
func TestNewLiveAttestor_InvalidBindingRefusesBeforeExchanging(t *testing.T) {
	binding := attestation.DeviceBinding{ProtocolVersion: pairingproto.AttestProtocolV2} // empty fingerprint

	attest := attestation.NewLiveAttestor(binding, func() (*attestation.Trust, error) {
		t.Fatal("loadTrust must not run before the binding is validated")
		return nil, nil
	}, discardLogger())

	err := attest(context.Background(), func(context.Context, *pairingproto.Request) (*pairingproto.Response, error) {
		t.Fatal("the exchange must not run before the binding is validated")
		return nil, nil
	}, nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, attestation.ErrDeviceBindingIncomplete)
}

// TestNewLiveAttestor_LoadTrustFailureRefusesBeforeExchanging pins that a
// trust-loading failure is returned as-is, and that it happens before the
// device is ever asked to answer. The binding here is complete and
// well-formed, so the refusal under test can only be the trust-loading one.
func TestNewLiveAttestor_LoadTrustFailureRefusesBeforeExchanging(t *testing.T) {
	binding := attestation.DeviceBinding{Fingerprint: attesttest2HexFingerprint(), ProtocolVersion: pairingproto.AttestProtocolV2}
	loadErr := errors.New("trust store unavailable")

	attest := attestation.NewLiveAttestor(binding, func() (*attestation.Trust, error) {
		return nil, loadErr
	}, discardLogger())

	err := attest(context.Background(), func(context.Context, *pairingproto.Request) (*pairingproto.Response, error) {
		t.Fatal("the exchange must not run when trust material could not be loaded")
		return nil, nil
	}, nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, loadErr)
}

// TestNewLiveAttestor_ExchangeFailure pins the wrap around a transport-level
// exchange failure.
func TestNewLiveAttestor_ExchangeFailure(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	binding := attestation.DeviceBinding{
		Fingerprint:     attesttest2HexFingerprint(),
		ProtocolVersion: pairingproto.AttestProtocolV2,
	}
	exchangeErr := errors.New("session closed")

	attest := attestation.NewLiveAttestor(binding, func() (*attestation.Trust, error) {
		return &attestation.Trust{Pool: ca.Pool(), Applications: attesttest.Applications()}, nil
	}, discardLogger())

	err := attest(context.Background(), func(context.Context, *pairingproto.Request) (*pairingproto.Response, error) {
		return nil, exchangeErr
	}, nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, attestation.ErrDeviceAttestFailed)
	assert.ErrorIs(t, err, exchangeErr)
}

// TestNewLiveAttestor_RPCError pins that a device-side RPC refusal is
// wrapped and logged rather than treated as a decodable result.
func TestNewLiveAttestor_RPCError(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	binding := attestation.DeviceBinding{
		Fingerprint:     attesttest2HexFingerprint(),
		ProtocolVersion: pairingproto.AttestProtocolV2,
	}

	attest := attestation.NewLiveAttestor(binding, func() (*attestation.Trust, error) {
		return &attestation.Trust{Pool: ca.Pool(), Applications: attesttest.Applications()}, nil
	}, discardLogger())

	err := attest(context.Background(), func(_ context.Context, req *pairingproto.Request) (*pairingproto.Response, error) {
		return &pairingproto.Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &pairingproto.RPCError{Code: 1000, Message: "biometric check failed"},
		}, nil
	}, nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, attestation.ErrDeviceAttestFailed)
	assert.Contains(t, err.Error(), "biometric check failed")
}

// TestNewLiveAttestor_MalformedResult pins the result-decode branch.
func TestNewLiveAttestor_MalformedResult(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	binding := attestation.DeviceBinding{
		Fingerprint:     attesttest2HexFingerprint(),
		ProtocolVersion: pairingproto.AttestProtocolV2,
	}

	attest := attestation.NewLiveAttestor(binding, func() (*attestation.Trust, error) {
		return &attestation.Trust{Pool: ca.Pool(), Applications: attesttest.Applications()}, nil
	}, discardLogger())

	err := attest(context.Background(), func(_ context.Context, req *pairingproto.Request) (*pairingproto.Response, error) {
		return &pairingproto.Response{JSONRPC: "2.0", ID: req.ID, Result: json.RawMessage("\"not an object\"")}, nil
	}, nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, attestation.ErrDeviceAttestFailed)
}

// TestNewLiveAttestor_VerificationFailure pins that a decodable but
// evidence-free result reaches VerifyDeviceAttestation and is refused there,
// returned unwrapped.
func TestNewLiveAttestor_VerificationFailure(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	binding := attestation.DeviceBinding{
		Fingerprint:     attesttest2HexFingerprint(),
		ProtocolVersion: pairingproto.AttestProtocolV2,
	}

	attest := attestation.NewLiveAttestor(binding, func() (*attestation.Trust, error) {
		return &attestation.Trust{Pool: ca.Pool(), Applications: attesttest.Applications()}, nil
	}, discardLogger())

	err := attest(context.Background(), func(_ context.Context, req *pairingproto.Request) (*pairingproto.Response, error) {
		result := &pairingproto.LocalAttestDeviceResult{ProtocolVersion: pairingproto.AttestProtocolV2}
		resultJSON, jerr := json.Marshal(result)
		require.NoError(t, jerr)
		return &pairingproto.Response{JSONRPC: "2.0", ID: req.ID, Result: resultJSON}, nil
	}, nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, attestation.ErrEmptyCertChain)
}

// TestNewLiveAttestor_IdentityChanged pins the final refusal: a genuinely
// verified device whose attested key is not the one bound at pairing.
func TestNewLiveAttestor_IdentityChanged(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	dak := attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())
	binding := attestation.DeviceBinding{
		Fingerprint:     attesttest2HexFingerprint(), // some other device's identity
		ProtocolVersion: pairingproto.AttestProtocolV2,
	}
	channelBinding := attesttest.FixedBytes(0x88, pairingproto.AttestChannelBindingSize)

	attest := attestation.NewLiveAttestor(binding, func() (*attestation.Trust, error) {
		return &attestation.Trust{Pool: ca.Pool(), Applications: attesttest.Applications()}, nil
	}, discardLogger())

	err := attest(context.Background(), signedExchange(t, dak, channelBinding), channelBinding)

	require.Error(t, err)
	assert.ErrorIs(t, err, attestation.ErrDeviceIdentityChanged)
}

// attesttest2HexFingerprint is a well-formed but arbitrary 32-byte hex
// fingerprint, used where a test needs SOME valid-shaped stored identity
// that will never equal a freshly-generated DAK's fingerprint.
func attesttest2HexFingerprint() string {
	const hextable = "0123456789abcdef"
	b := make([]byte, pairingproto.AttestFingerprintSize)
	for i := range b {
		b[i] = 0xee
	}
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hextable[v>>4]
		out[i*2+1] = hextable[v&0x0f]
	}
	return string(out)
}
