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
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/fido2"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// The hmac-secret tests drive this authenticator with the repository's own
// FIDO2 client, pkg/fido2 -- the code xkmsctl and the SDK use against real
// security keys -- over an in-memory CTAPHID loopback. A passing round trip
// therefore means a conformant platform interoperates, not merely that this
// package agrees with itself.

const (
	hmacTestRPID    = "example.com"
	hmacTestPIN     = "123456"
	hmacTestTimeout = 10 * time.Second
)

// loopbackHID is a fido2.HIDDevice that hands every written HID report to a
// CTAPHIDHandler and reads back the reports the handler emits.
type loopbackHID struct {
	handler *CTAPHIDHandler
	reports chan []byte
}

func newLoopbackHID(t *testing.T, auth *Authenticator) *loopbackHID {
	t.Helper()
	l := &loopbackHID{
		handler: NewCTAPHIDHandler(auth),
		reports: make(chan []byte, 1024),
	}
	l.handler.SetResponseHandler(func(report []byte) {
		l.reports <- append([]byte(nil), report...)
	})
	t.Cleanup(func() { require.NoError(t, l.handler.Close()) })
	return l
}

func (l *loopbackHID) Write(report []byte) (int, error) {
	l.handler.HandleMessage(report)
	return len(report), nil
}

func (l *loopbackHID) Read(buf []byte) (int, error) {
	select {
	case report := <-l.reports:
		return copy(buf, report), nil
	case <-time.After(hmacTestTimeout):
		return 0, ErrUserPresenceTimeout
	}
}

func (l *loopbackHID) Close() error         { return nil }
func (l *loopbackHID) Path() string         { return "loopback" }
func (l *loopbackHID) ProductID() uint16    { return 0 }
func (l *loopbackHID) VendorID() uint16     { return 0 }
func (l *loopbackHID) Product() string      { return "xkey loopback" }
func (l *loopbackHID) Manufacturer() string { return "go-xkms" }
func (l *loopbackHID) SerialNumber() string { return "" }

// hmacSecretHarness is an authenticator holding one hmac-secret credential,
// reachable through a pkg/fido2 client.
type hmacSecretHarness struct {
	auth         *Authenticator
	client       *fido2.Authenticator
	ext          *fido2.HMACSecretExtension
	credentialID []byte
}

// newHMACSecretHarness enrolls an hmac-secret credential through the client
// and then sets a PIN, so assertions can run both with and without UV.
func newHMACSecretHarness(t *testing.T) *hmacSecretHarness {
	t.Helper()
	auth := createTestAuthenticator(t)

	device, err := fido2.NewCTAPHIDDevice(newLoopbackHID(t, auth), &fido2.Config{Timeout: hmacTestTimeout})
	require.NoError(t, err)
	client, err := fido2.NewAuthenticator(device, &fido2.Config{Timeout: hmacTestTimeout})
	require.NoError(t, err)
	ext, err := fido2.NewHMACSecretExtension(client)
	require.NoError(t, err)

	enrollment, err := ext.EnrollCredential(&fido2.EnrollmentConfig{
		RelyingParty: fido2.RelyingParty{ID: hmacTestRPID, Name: "Example"},
		User:         fido2.User{Name: "alice", DisplayName: "Alice"},
	})
	require.NoError(t, err)
	require.NoError(t, auth.SetInitialPIN([]byte(hmacTestPIN)))

	return &hmacSecretHarness{auth: auth, client: client, ext: ext, credentialID: enrollment.CredentialID}
}

// expectedOutput is HMAC-SHA-256(CredRandom, salt) for the harness credential.
func (h *hmacSecretHarness) expectedOutput(t *testing.T, salt []byte, uv bool) []byte {
	t.Helper()
	credential, err := h.auth.storage.Load(h.credentialID)
	require.NoError(t, err)
	credRandom, err := deriveCredRandom(credential.HMACSecretKey, uv)
	require.NoError(t, err)
	mac := hmac.New(sha256.New, credRandom)
	mac.Write(salt)
	return mac.Sum(nil)
}

// session opens a platform PIN/UV auth session for version.
func (h *hmacSecretHarness) session(t *testing.T, version uint64) *fido2.PINUVAuthSession {
	t.Helper()
	key, err := h.client.KeyAgreement(version)
	require.NoError(t, err)
	session, err := fido2.NewPINUVAuthSession(version, key)
	require.NoError(t, err)
	return session
}

// hmacSecretAssertion is one getAssertion carrying an hmac-secret input.
type hmacSecretAssertion struct {
	raw     []byte // the hmac-secret value in authData, as sent on the wire
	output  []byte // raw decrypted by the platform
	flags   AuthDataFlags
	session *fido2.PINUVAuthSession
}

// assert performs a getAssertion through the pkg/fido2 client with the given
// protocol, salts and, when uv is set, a PIN-derived pinUvAuthParam.
func (h *hmacSecretHarness) assert(t *testing.T, version uint64, salts []byte, uv bool) *hmacSecretAssertion {
	t.Helper()
	session := h.session(t, version)
	saltEnc, err := session.Encrypt(salts)
	require.NoError(t, err)

	clientDataHash := generateTestClientDataHash()
	req := &fido2.GetAssertionRequest{
		RPID:           hmacTestRPID,
		ClientDataHash: clientDataHash,
		AllowList:      []fido2.PublicKeyCredentialDescriptor{{Type: "public-key", ID: h.credentialID}},
		Extensions: map[string]interface{}{
			"hmac-secret": map[int]interface{}{
				hmacSecretKeyAgreement:      session.PlatformKeyAgreement().Map(),
				hmacSecretSaltEnc:           saltEnc,
				hmacSecretSaltAuth:          session.Authenticate(saltEnc),
				hmacSecretPinUvAuthProtocol: version,
			},
		},
		Options: fido2.AuthenticatorOptions{UP: true},
	}
	if uv {
		pin, err := secure.NewSecret([]byte(hmacTestPIN))
		require.NoError(t, err)
		token, err := h.client.GetPINToken(session, pin)
		require.NoError(t, err)
		req.PinUVAuthParam = session.AuthenticateWithToken(token, clientDataHash)
		req.PinUVAuthProtocol = version
	}

	resp, err := h.client.GetAssertion(req)
	require.NoError(t, err)

	extensions, err := fido2.ParseAuthDataExtensions(resp.AuthData)
	require.NoError(t, err)
	raw, ok := extensions["hmac-secret"].([]byte)
	require.True(t, ok, "authData must carry an hmac-secret output")
	output, err := session.Decrypt(raw)
	require.NoError(t, err)

	return &hmacSecretAssertion{raw: raw, output: output, flags: AuthDataFlags(resp.AuthData[32]), session: session}
}

func randomSalts(t *testing.T, n int) []byte {
	t.Helper()
	salts := make([]byte, n*HMACSecretSaltSize)
	_, err := rand.Read(salts)
	require.NoError(t, err)
	return salts
}

// TestHMACSecret_DeriveSecretRoundTrip runs the pkg/fido2 DeriveSecret flow
// -- the one xkmsctl and systemd-style disk unlock use -- end to end, with one
// and two salts.
func TestHMACSecret_DeriveSecretRoundTrip(t *testing.T) {
	h := newHMACSecretHarness(t)
	salts := randomSalts(t, 2)
	salt1, salt2 := salts[:HMACSecretSaltSize], salts[HMACSecretSaltSize:]

	single, err := h.ext.DeriveSecret(&fido2.AuthenticationConfig{
		RelyingPartyID: hmacTestRPID,
		CredentialID:   h.credentialID,
		Salt:           salt1,
	})
	require.NoError(t, err)
	require.Equal(t, h.expectedOutput(t, salt1, false), single.HMACSecret)
	require.Empty(t, single.HMACSecret2)

	double, err := h.ext.DeriveSecret(&fido2.AuthenticationConfig{
		RelyingPartyID: hmacTestRPID,
		CredentialID:   h.credentialID,
		Salt:           salt1,
		Salt2:          salt2,
	})
	require.NoError(t, err)
	require.Equal(t, single.HMACSecret, double.HMACSecret, "salt1's output must not depend on salt2")
	require.Equal(t, h.expectedOutput(t, salt2, false), double.HMACSecret2)
}

// TestHMACSecret_ProtocolsAndUV covers PIN/UV auth protocols 1 and 2, with and
// without user verification.
func TestHMACSecret_ProtocolsAndUV(t *testing.T) {
	h := newHMACSecretHarness(t)
	salts := randomSalts(t, 2)
	salt1, salt2 := salts[:HMACSecretSaltSize], salts[HMACSecretSaltSize:]

	outputs := map[bool][]byte{}
	for _, version := range []uint64{fido2.PINUVAuthProtocolV1, fido2.PINUVAuthProtocolV2} {
		for _, uv := range []bool{false, true} {
			got := h.assert(t, version, salts, uv)

			require.True(t, got.flags.Has(FlagUP))
			require.Equal(t, uv, got.flags.Has(FlagUV))
			require.Equal(t, h.expectedOutput(t, salt1, uv), got.output[:HMACSecretSaltSize])
			require.Equal(t, h.expectedOutput(t, salt2, uv), got.output[HMACSecretSaltSize:])

			// The wire value is ciphertext: protocol 2 prefixes a random IV.
			wantLen := len(salts)
			if version == fido2.PINUVAuthProtocolV2 {
				wantLen += AESBlockSize
			}
			require.Len(t, got.raw, wantLen)
			require.False(t, bytes.Contains(got.raw, got.output[:HMACSecretSaltSize]), "output must never be plaintext")
			require.False(t, bytes.Contains(got.raw, got.output[HMACSecretSaltSize:]), "output must never be plaintext")

			// CredRandom depends on the UV state, never on the protocol.
			if previous, ok := outputs[uv]; ok {
				require.Equal(t, previous, got.output)
			}
			outputs[uv] = got.output
		}
	}
	require.NotEqual(t, outputs[false], outputs[true], "CredRandomWithUV and CredRandomWithoutUV must differ")
}

// TestHMACSecret_StableOutput checks that the same salt and UV state give the
// same secret across assertions and fresh key agreements.
func TestHMACSecret_StableOutput(t *testing.T) {
	h := newHMACSecretHarness(t)
	salt := randomSalts(t, 1)

	first := h.assert(t, fido2.PINUVAuthProtocolV2, salt, false)
	second := h.assert(t, fido2.PINUVAuthProtocolV2, salt, false)
	require.Equal(t, first.output, second.output)
	require.NotEqual(t, first.raw, second.raw, "protocol 2 ciphertexts carry fresh IVs")
}

// hmacSecretRequest builds a raw getAssertion CBOR request for the harness
// credential with the given hmac-secret input and options.
func (h *hmacSecretHarness) hmacSecretRequest(t *testing.T, input interface{}, options map[string]bool) []byte {
	t.Helper()
	request := map[int]interface{}{
		getAssertionParamRPID:           hmacTestRPID,
		getAssertionParamClientDataHash: generateTestClientDataHash(),
		getAssertionParamAllowList: []interface{}{
			map[string]interface{}{"type": "public-key", "id": h.credentialID},
		},
		getAssertionParamExtensions: map[string]interface{}{"hmac-secret": input},
	}
	if options != nil {
		request[getAssertionParamOptions] = options
	}
	encoded, err := cbor.Marshal(request)
	require.NoError(t, err)
	return encoded
}

// validInput returns a well-formed hmac-secret input for salts, and the
// session that produced it.
func (h *hmacSecretHarness) validInput(t *testing.T, version uint64, salts []byte) map[int]interface{} {
	t.Helper()
	session := h.session(t, version)
	saltEnc, err := session.Encrypt(salts)
	require.NoError(t, err)
	return map[int]interface{}{
		hmacSecretKeyAgreement:      session.PlatformKeyAgreement().Map(),
		hmacSecretSaltEnc:           saltEnc,
		hmacSecretSaltAuth:          session.Authenticate(saltEnc),
		hmacSecretPinUvAuthProtocol: version,
	}
}

// TestHMACSecret_Refusals checks every refusal CTAP 2.1 §12.5 prescribes
// reaches the wire with its status, and that a refused assertion does not
// spend a signCount value.
func TestHMACSecret_Refusals(t *testing.T) {
	h := newHMACSecretHarness(t)

	tests := []struct {
		name    string
		input   func() interface{}
		options map[string]bool
		status  byte
	}{
		{
			name: "bad saltAuth",
			input: func() interface{} {
				in := h.validInput(t, fido2.PINUVAuthProtocolV2, randomSalts(t, 1))
				tag := in[hmacSecretSaltAuth].([]byte)
				tag[0] ^= 0x01
				return in
			},
			status: StatusPINAuthInvalid,
		},
		{
			name: "protocol 1 length saltAuth under protocol 2",
			input: func() interface{} {
				in := h.validInput(t, fido2.PINUVAuthProtocolV2, randomSalts(t, 1))
				in[hmacSecretSaltAuth] = in[hmacSecretSaltAuth].([]byte)[:PINAuthSizeV1]
				return in
			},
			status: StatusPINAuthInvalid,
		},
		{
			name: "salt of 48 bytes",
			input: func() interface{} {
				return h.validInput(t, fido2.PINUVAuthProtocolV1, make([]byte, 48))
			},
			status: StatusInvalidParameter,
		},
		{
			name: "salt of 16 bytes",
			input: func() interface{} {
				return h.validInput(t, fido2.PINUVAuthProtocolV2, make([]byte, 16))
			},
			status: StatusInvalidParameter,
		},
		{
			name: "saltEnc not a whole number of blocks",
			input: func() interface{} {
				session := h.session(t, fido2.PINUVAuthProtocolV1)
				saltEnc := make([]byte, 33)
				return map[int]interface{}{
					hmacSecretKeyAgreement: session.PlatformKeyAgreement().Map(),
					hmacSecretSaltEnc:      saltEnc,
					hmacSecretSaltAuth:     session.Authenticate(saltEnc),
				}
			},
			status: StatusInvalidParameter,
		},
		{
			name: "plaintext salt1",
			input: func() interface{} {
				return map[string]interface{}{"salt1": make([]byte, HMACSecretSaltSize)}
			},
			status: StatusInvalidParameter,
		},
		{
			name: "missing keyAgreement",
			input: func() interface{} {
				in := h.validInput(t, fido2.PINUVAuthProtocolV2, randomSalts(t, 1))
				delete(in, hmacSecretKeyAgreement)
				return in
			},
			status: StatusInvalidParameter,
		},
		{
			name: "unsupported pinUvAuthProtocol",
			input: func() interface{} {
				in := h.validInput(t, fido2.PINUVAuthProtocolV2, randomSalts(t, 1))
				in[hmacSecretPinUvAuthProtocol] = 3
				return in
			},
			status: StatusInvalidParameter,
		},
		{
			name: "up=false",
			input: func() interface{} {
				return h.validInput(t, fido2.PINUVAuthProtocolV2, randomSalts(t, 1))
			},
			options: map[string]bool{"up": false},
			status:  StatusUnsupportedOption,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before, err := h.auth.storage.Load(h.credentialID)
			require.NoError(t, err)

			resp, err := h.auth.ProcessCBOR(CmdGetAssertion, h.hmacSecretRequest(t, tt.input(), tt.options))
			require.Error(t, err)
			require.Equal(t, tt.status, resp[0])

			after, err := h.auth.storage.Load(h.credentialID)
			require.NoError(t, err)
			require.Equal(t, before.SignCount, after.SignCount, "a refused assertion must not spend a signCount")
		})
	}
}

// TestHMACSecret_ProtocolDefaultsToOne checks that an input without
// pinUvAuthProtocol is processed under protocol 1 (CTAP 2.1 §12.5).
func TestHMACSecret_ProtocolDefaultsToOne(t *testing.T) {
	h := newHMACSecretHarness(t)
	salt := randomSalts(t, 1)

	session := h.session(t, fido2.PINUVAuthProtocolV1)
	saltEnc, err := session.Encrypt(salt)
	require.NoError(t, err)
	input := map[int]interface{}{
		hmacSecretKeyAgreement: session.PlatformKeyAgreement().Map(),
		hmacSecretSaltEnc:      saltEnc,
		hmacSecretSaltAuth:     session.Authenticate(saltEnc),
	}

	resp, err := h.auth.ProcessCBOR(CmdGetAssertion, h.hmacSecretRequest(t, input, nil))
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])

	var decoded map[int]interface{}
	require.NoError(t, cbor.Unmarshal(resp[1:], &decoded))
	extensions, err := fido2.ParseAuthDataExtensions(decoded[getAssertionRespAuthData].([]byte))
	require.NoError(t, err)
	output, err := session.Decrypt(extensions["hmac-secret"].([]byte))
	require.NoError(t, err)
	require.Equal(t, h.expectedOutput(t, salt, false), output)
}

// TestHMACSecret_CredentialWithoutSecretIgnoresExtension checks CTAP 2.1
// §12.5: a credential with no CredRandom yields an assertion with no
// hmac-secret output rather than an error.
func TestHMACSecret_CredentialWithoutSecretIgnoresExtension(t *testing.T) {
	h := newHMACSecretHarness(t)
	credential, err := h.auth.storage.Load(h.credentialID)
	require.NoError(t, err)
	credential.HMACSecretKey = nil
	require.NoError(t, h.auth.storage.Store(credential))

	input := h.validInput(t, fido2.PINUVAuthProtocolV2, randomSalts(t, 1))
	resp, err := h.auth.ProcessCBOR(CmdGetAssertion, h.hmacSecretRequest(t, input, nil))
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])

	var decoded map[int]interface{}
	require.NoError(t, cbor.Unmarshal(resp[1:], &decoded))
	authData := decoded[getAssertionRespAuthData].([]byte)
	require.False(t, AuthDataFlags(authData[32]).Has(FlagED))
}

// TestHMACSecret_NoKeyAgreementIssued checks that an input cannot be
// processed before getKeyAgreement has issued an authenticator key: there is
// no key the platform could have agreed a secret with.
func TestHMACSecret_NoKeyAgreementIssued(t *testing.T) {
	auth := createTestAuthenticator(t)
	credential := createAssertionTestCredential(t, auth, hmacTestRPID, false)

	platformKey, err := generateUnrelatedPlatformKey()
	require.NoError(t, err)
	input := map[int]interface{}{
		hmacSecretKeyAgreement: platformKey,
		hmacSecretSaltEnc:      make([]byte, HMACSecretSaltSize),
		hmacSecretSaltAuth:     make([]byte, PINAuthSizeV1),
	}
	h := &hmacSecretHarness{auth: auth, credentialID: credential.CredentialID}

	resp, err := auth.ProcessCBOR(CmdGetAssertion, h.hmacSecretRequest(t, input, nil))
	require.ErrorIs(t, err, ErrHMACSecretInvalidInput)
	require.Equal(t, byte(StatusInvalidParameter), resp[0])
}

// generateUnrelatedPlatformKey returns a COSE_Key map for a fresh P-256 key.
func generateUnrelatedPlatformKey() (map[int]interface{}, error) {
	auth := &Authenticator{}
	if err := auth.initPINProtocol(); err != nil {
		return nil, err
	}
	return auth.pinState.protocol.publicKeyCOSE, nil
}

// TestHMACSecret_LeavesClientPINSessionUntouched checks that agreeing the
// request-scoped hmac-secret secret does not rewrite the clientPin session's
// active protocol or keys, which the pinUvAuthToken checks depend on.
func TestHMACSecret_LeavesClientPINSessionUntouched(t *testing.T) {
	h := newHMACSecretHarness(t)

	// Establish a protocol 2 clientPin session with a token.
	pinSession := h.session(t, fido2.PINUVAuthProtocolV2)
	pin, err := secure.NewSecret([]byte(hmacTestPIN))
	require.NoError(t, err)
	_, err = h.client.GetPINToken(pinSession, pin)
	require.NoError(t, err)

	h.auth.mu.RLock()
	wantProtocol := h.auth.pinState.protocol.activeProtocol
	wantHMACKey := append([]byte(nil), h.auth.pinState.protocol.hmacKey...)
	h.auth.mu.RUnlock()
	require.Equal(t, uint8(PINProtocol2), wantProtocol)

	h.assert(t, fido2.PINUVAuthProtocolV1, randomSalts(t, 1), false)

	h.auth.mu.RLock()
	defer h.auth.mu.RUnlock()
	require.Equal(t, wantProtocol, h.auth.pinState.protocol.activeProtocol)
	require.Equal(t, wantHMACKey, h.auth.pinState.protocol.hmacKey)
}

func TestParseHMACSecretInput(t *testing.T) {
	key, err := generateUnrelatedPlatformKey()
	require.NoError(t, err)
	saltEnc := make([]byte, HMACSecretSaltSize)
	saltAuth := make([]byte, PINAuthSizeV1)

	t.Run("CBOR-decoded map with unsigned keys", func(t *testing.T) {
		encoded, err := cbor.Marshal(map[int]interface{}{1: key, 2: saltEnc, 3: saltAuth, 4: 2})
		require.NoError(t, err)
		var decoded interface{}
		require.NoError(t, cbor.Unmarshal(encoded, &decoded))

		input, err := parseHMACSecretInput(decoded)
		require.NoError(t, err)
		require.Equal(t, uint8(PINProtocol2), input.protocol)
		require.Equal(t, saltEnc, input.saltEnc)
		require.Equal(t, saltAuth, input.saltAuth)
	})

	t.Run("protocol defaults to one", func(t *testing.T) {
		input, err := parseHMACSecretInput(map[int]interface{}{1: key, 2: saltEnc, 3: saltAuth})
		require.NoError(t, err)
		require.Equal(t, uint8(PINProtocol1), input.protocol)
	})

	invalid := map[string]interface{}{
		"nil":                     nil,
		"string-keyed map":        map[string]interface{}{"salt1": saltEnc},
		"interface map, text key": map[interface{}]interface{}{"salt1": saltEnc},
		"keyAgreement as bytes":   map[int]interface{}{1: []byte{0xa0}, 2: saltEnc, 3: saltAuth},
		"missing saltEnc":         map[int]interface{}{1: key, 3: saltAuth},
		"missing saltAuth":        map[int]interface{}{1: key, 2: saltEnc},
		"saltEnc not bytes":       map[int]interface{}{1: key, 2: "salt", 3: saltAuth},
		"protocol not integer":    map[int]interface{}{1: key, 2: saltEnc, 3: saltAuth, 4: "2"},
		"protocol zero":           map[int]interface{}{1: key, 2: saltEnc, 3: saltAuth, 4: 0},
	}
	for name, raw := range invalid {
		t.Run(name, func(t *testing.T) {
			_, err := parseHMACSecretInput(raw)
			require.ErrorIs(t, err, ErrHMACSecretInvalidInput)
		})
	}
}

func TestDeriveCredRandom(t *testing.T) {
	key, err := GenerateHMACSecretKey()
	require.NoError(t, err)

	withUV, err := deriveCredRandom(key, true)
	require.NoError(t, err)
	withoutUV, err := deriveCredRandom(key, false)
	require.NoError(t, err)
	again, err := deriveCredRandom(key, true)
	require.NoError(t, err)

	require.Len(t, withUV, HMACSecretSaltSize)
	require.NotEqual(t, withUV, withoutUV)
	require.Equal(t, withUV, again)
	require.NotEqual(t, key, withUV, "CredRandom must not be the stored key itself")
	require.NotEqual(t, key, withoutUV, "CredRandom must not be the stored key itself")
}

func TestHMACSecretErrorsMapToCTAPStatus(t *testing.T) {
	tests := []struct {
		err    error
		base   error
		status byte
	}{
		{ErrHMACSecretUserPresenceRequired, ErrUnsupportedOption, StatusUnsupportedOption},
		{ErrHMACSecretInvalidInput, ErrInvalidParameter, StatusInvalidParameter},
		{ErrHMACSecretSaltAuthMismatch, ErrPINAuthInvalid, StatusPINAuthInvalid},
		{ErrHMACSecretInvalidSalt, ErrInvalidParameter, StatusInvalidParameter},
	}
	for _, tt := range tests {
		t.Run(tt.err.Error(), func(t *testing.T) {
			require.ErrorIs(t, tt.err, tt.base)
			require.Equal(t, tt.status, errorToStatus(tt.err))
		})
	}
}

func TestDecryptData(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	a := &Authenticator{}

	for _, protocol := range []uint8{PINProtocol1, PINProtocol2} {
		plaintext := randomSalts(t, 2)
		ciphertext, err := a.encryptData(key, protocol, plaintext)
		require.NoError(t, err)

		got, err := decryptData(key, protocol, ciphertext)
		require.NoError(t, err)
		require.Equal(t, plaintext, got)
	}

	invalid := []struct {
		name       string
		protocol   uint8
		ciphertext []byte
	}{
		{"v1 empty", PINProtocol1, nil},
		{"v1 partial block", PINProtocol1, make([]byte, 33)},
		{"v2 shorter than IV", PINProtocol2, make([]byte, 15)},
		{"v2 IV only", PINProtocol2, make([]byte, AESBlockSize)},
		{"v2 partial block", PINProtocol2, make([]byte, AESBlockSize+17)},
	}
	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decryptData(key, tt.protocol, tt.ciphertext)
			require.ErrorIs(t, err, ErrDecryptionFailed)
		})
	}

	_, err = decryptData(make([]byte, 7), PINProtocol1, make([]byte, AESBlockSize))
	require.ErrorIs(t, err, ErrDecryptionFailed, "a key AES rejects is a decryption failure")
}
