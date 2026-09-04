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

package fido2

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/fxamacker/cbor/v2"
)

// Errors reported by the authenticator simulator when a platform request
// does not conform to CTAP 2.1 12.5.
var (
	errSimUnsupportedSubcommand = errors.New("simulator: unsupported authenticatorClientPIN subcommand")
	errSimMalformedInput        = errors.New("simulator: malformed hmac-secret input field")
	errSimSaltAuthMismatch      = errors.New("simulator: saltAuth does not authenticate saltEnc")
	errSimSaltLength            = errors.New("simulator: salts are not one or two 32-byte values")
)

// simStatusError is a simulator failure that must reach the platform as a
// specific CTAP status code rather than a generic one. A platform can only be
// tested for "distinguishes a wrong PIN from a refusal" if the wire carries
// the distinction.
type simStatusError struct {
	status byte
	reason string
}

// Error implements the error interface.
func (e *simStatusError) Error() string { return e.reason }

// simStatus reports the CTAP status an error should be answered with,
// defaulting to CTAP2_ERR_INVALID_PARAMETER for anything unclassified.
func simStatus(err error) byte {
	var statusErr *simStatusError
	if errors.As(err, &statusErr) {
		return statusErr.status
	}
	return StatusInvalidParameter
}

// authenticatorSim simulates the authenticator half of the CTAP2
// hmac-secret exchange. It holds a per-credential secret (CredRandom) that
// never leaves the simulator, exactly as a real authenticator does, so a
// test that recovers the expected output has proved the platform reached
// the authenticator's secret rather than reconstructing something from
// public material.
type authenticatorSim struct {
	// privateKey is the authenticator's ephemeral key agreement key.
	privateKey *ecdh.PrivateKey

	// credRandom is the per-credential secret the hmac-secret outputs are
	// keyed with. It is never transmitted.
	credRandom []byte

	// credentialID and aaguid are public values. A test may point them at
	// attacker-known bytes to prove they do not leak into the derived key.
	credentialID []byte
	aaguid       []byte

	// rpIDHash is the leading authenticator data field.
	rpIDHash []byte

	// signCount is reported in the authenticator data header.
	signCount uint32

	// failClientPIN makes the simulator reject authenticatorClientPIN, as a
	// device that does not implement the key agreement would.
	failClientPIN bool

	// suppressExtensionOutput makes the simulator complete the assertion
	// without an hmac-secret output, as an authenticator that declined the
	// extension would.
	suppressExtensionOutput bool

	// attestedCredentialData sets the AT flag, which pushes the extension
	// map past the aaguid, credential ID, and COSE public key. Real
	// GetAssertion responses rarely set it, but a platform that assumes a
	// fixed extension offset reads public data when it is set.
	attestedCredentialData bool

	// pin is the PIN the simulator verifies. Empty models a key with no PIN
	// set, which is the state every existing test runs against.
	pin string

	// pinToken is the pinUvAuthToken issued by the last successful
	// getPINToken, and the key every subsequent pinUvAuthParam is verified
	// under. pinProtocol records which protocol issued it.
	pinToken    []byte
	pinProtocol uint64

	// pinRetries is the attempts-remaining counter getPINRetries reports and
	// a wrong PIN decrements, as a real authenticator's does. It starts at
	// the CTAP 2.1 default of eight the first time it is read or decremented,
	// so a simulator built before PIN support still behaves like a key.
	pinRetries    uint64
	pinRetriesSet bool

	// failPINRetries makes the simulator refuse getPINRetries, modelling an
	// authenticator that will not report the counter.
	failPINRetries bool
}

// defaultSimPINRetries is the CTAP 2.1 initial PIN retry budget.
const defaultSimPINRetries = 8

// remainingPINRetries reports the counter, seeding it on first use.
func (s *authenticatorSim) remainingPINRetries() uint64 {
	if !s.pinRetriesSet {
		s.pinRetries = defaultSimPINRetries
		s.pinRetriesSet = true
	}
	return s.pinRetries
}

// consumePINRetry decrements the counter for a wrong PIN, as CTAP 2.1 6.5.5.7
// requires, and reports what remains.
func (s *authenticatorSim) consumePINRetry() uint64 {
	remaining := s.remainingPINRetries()
	if remaining > 0 {
		remaining--
		s.pinRetries = remaining
	}
	return remaining
}

// newAuthenticatorSim builds a simulator with random secrets and
// recognizable public values.
func newAuthenticatorSim() *authenticatorSim {
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		panic("fido2: simulator key generation failed: " + err.Error())
	}

	credRandom := make([]byte, 32)
	if _, err := rand.Read(credRandom); err != nil {
		panic("fido2: simulator secret generation failed: " + err.Error())
	}

	credentialID := make([]byte, 32)
	for i := range credentialID {
		credentialID[i] = byte(i)
	}

	aaguid := make([]byte, aaguidLen)
	for i := range aaguid {
		aaguid[i] = byte(0xA0 + i)
	}

	return &authenticatorSim{
		privateKey:   privateKey,
		credRandom:   credRandom,
		credentialID: credentialID,
		aaguid:       aaguid,
		rpIDHash:     make([]byte, authDataRPIDHashLen),
		signCount:    2,
	}
}

// hmacOutput computes the hmac-secret output for one salt, as CTAP 2.1
// 12.5 defines it.
func (s *authenticatorSim) hmacOutput(salt []byte) []byte {
	mac := hmac.New(sha256.New, s.credRandom)
	mac.Write(salt)
	return mac.Sum(nil)
}

// clientPIN answers authenticatorClientPIN. Only the getKeyAgreement
// subcommand is required by the hmac-secret exchange.
func (s *authenticatorSim) clientPIN(request []byte) ([]byte, error) {
	if s.failClientPIN {
		return nil, errSimUnsupportedSubcommand
	}

	req, err := simDecodeRequest(request)
	if err != nil {
		return nil, err
	}

	subCommand, err := simUint(req[clientPINFieldSubCommand])
	if err != nil {
		return nil, err
	}

	switch subCommand {
	case ClientPINSubCmdGetKeyAgreement:
		key, err := NewCOSEKeyEC2(s.privateKey.PublicKey())
		if err != nil {
			return nil, err
		}
		return cbor.Marshal(map[int]interface{}{clientPINRespKeyAgreement: key.Map()})

	case ClientPINSubCmdGetPINToken:
		return s.getPINToken(req)

	case ClientPINSubCmdGetPINRetries:
		if s.failPINRetries {
			return nil, errSimUnsupportedSubcommand
		}
		return cbor.Marshal(map[int]interface{}{clientPINRespPINRetries: s.remainingPINRetries()})

	default:
		return nil, errSimUnsupportedSubcommand
	}
}

// getPINToken answers the getPINToken subcommand (CTAP 2.1 6.5.5.7): it
// re-derives the shared secret from the platform's key agreement key,
// decrypts pinHashEnc, compares it against LEFT(SHA-256(pin), 16), and
// returns a freshly minted pinUvAuthToken encrypted under the same secret.
func (s *authenticatorSim) getPINToken(req map[int]interface{}) ([]byte, error) {
	if s.pin == "" {
		return nil, &simStatusError{status: StatusPINNotSet, reason: "simulator: no PIN is set"}
	}

	protocol, err := simUint(req[clientPINFieldPinUVAuthProtocol])
	if err != nil {
		return nil, err
	}

	platformKey, err := ParseCOSEKeyEC2(req[clientPINFieldKeyAgreement])
	if err != nil {
		return nil, err
	}
	peer, err := platformKey.ECDHPublicKey()
	if err != nil {
		return nil, err
	}

	session, err := newPINUVAuthSession(protocol, s.privateKey, peer)
	if err != nil {
		return nil, err
	}

	pinHashEnc, err := simBytes(req[clientPINFieldPINHashEnc])
	if err != nil {
		return nil, err
	}
	pinHash, err := session.Decrypt(pinHashEnc)
	if err != nil {
		return nil, err
	}

	expected := sha256.Sum256([]byte(s.pin))
	if !hmac.Equal(pinHash, expected[:16]) {
		// A wrong PIN costs an attempt on a real key, so it does here too:
		// otherwise a test could not tell a counter that is reported from one
		// that is merely constant.
		if s.consumePINRetry() == 0 {
			return nil, &simStatusError{status: StatusPINBlocked, reason: "simulator: PIN retries exhausted"}
		}
		return nil, &simStatusError{status: StatusPINInvalid, reason: "simulator: PIN hash mismatch"}
	}

	// A correct PIN restores the budget, as CTAP 2.1 6.5.5.7 requires.
	s.pinRetries = defaultSimPINRetries
	s.pinRetriesSet = true

	token := make([]byte, sha256.Size)
	if _, err := rand.Read(token); err != nil {
		return nil, err
	}
	s.pinToken = token
	s.pinProtocol = protocol

	tokenEnc, err := session.Encrypt(token)
	if err != nil {
		return nil, err
	}
	return cbor.Marshal(map[int]interface{}{clientPINRespPINToken: tokenEnc})
}

// authorizeMakeCredential applies the PIN half of CTAP 2.1 6.1.2 to a
// MakeCredential request, reporting the CTAP status the authenticator would
// answer with. StatusOK means the request is authorized to proceed.
//
// A simulator with no PIN set authorizes everything, which is what every
// test that predates PIN support relies on.
func (s *authenticatorSim) authorizeMakeCredential(request []byte) byte {
	if s.pin == "" {
		return StatusOK
	}

	req, err := simDecodeRequest(request)
	if err != nil {
		return StatusInvalidCBOR
	}

	// A PIN-only authenticator has no built-in user verification method, so
	// CTAP 2.1 6.1.2 makes the "uv" option an invalid option rather than a
	// second way to ask for the same thing pinUvAuthParam already proves.
	if options, ok := req[0x07].(map[interface{}]interface{}); ok {
		if uv, ok := options["uv"].(bool); ok && uv {
			return StatusInvalidOption
		}
	}

	param, err := simBytes(req[0x08])
	if err != nil {
		return StatusPINRequired
	}
	protocol, err := simUint(req[0x09])
	if err != nil {
		return StatusMissingParameter
	}

	clientDataHash, err := simBytes(req[0x01])
	if err != nil {
		return StatusMissingParameter
	}

	if s.pinToken == nil || protocol != s.pinProtocol {
		return StatusPINAuthInvalid
	}
	if !hmac.Equal(pinUVAuthenticate(protocol, s.pinToken, clientDataHash), param) {
		return StatusPINAuthInvalid
	}
	return StatusOK
}

// authorizeGetAssertion applies the PIN half of CTAP 2.1 6.2.2 to a
// GetAssertion request, reporting the CTAP status the authenticator would
// answer with. StatusOK means the request is authorized to proceed.
//
// It is the assertion counterpart of authorizeMakeCredential and reads the
// GetAssertion parameter numbering: clientDataHash is 0x02, options 0x05,
// pinUvAuthParam 0x06 and pinUvAuthProtocol 0x07 — all different from the
// MakeCredential numbering, which is why the two cannot share one decoder.
//
// A simulator with no PIN set authorizes everything, which is what every test
// that predates PIN support relies on.
func (s *authenticatorSim) authorizeGetAssertion(request []byte) byte {
	if s.pin == "" {
		return StatusOK
	}

	req, err := simDecodeRequest(request)
	if err != nil {
		return StatusInvalidCBOR
	}

	// A PIN-only authenticator has no built-in user verification method, so
	// CTAP 2.1 6.2.2 makes the "uv" option an invalid option rather than a
	// second way to ask for the same thing pinUvAuthParam already proves.
	if options, ok := req[0x05].(map[interface{}]interface{}); ok {
		if uv, ok := options["uv"].(bool); ok && uv {
			return StatusInvalidOption
		}
	}

	param, err := simBytes(req[0x06])
	if err != nil {
		return StatusPINRequired
	}
	protocol, err := simUint(req[0x07])
	if err != nil {
		return StatusMissingParameter
	}

	clientDataHash, err := simBytes(req[0x02])
	if err != nil {
		return StatusMissingParameter
	}

	if s.pinToken == nil || protocol != s.pinProtocol {
		return StatusPINAuthInvalid
	}
	if !hmac.Equal(pinUVAuthenticate(protocol, s.pinToken, clientDataHash), param) {
		return StatusPINAuthInvalid
	}
	return StatusOK
}

// getAssertion answers authenticatorGetAssertion, honoring the hmac-secret
// extension input: it verifies saltAuth, decrypts the salts, keys the
// outputs with CredRandom, and returns them encrypted under the same
// shared secret.
func (s *authenticatorSim) getAssertion(request []byte) ([]byte, error) {
	req, err := simDecodeRequest(request)
	if err != nil {
		return nil, err
	}

	encrypted, err := s.hmacSecretExtensionOutput(req[0x04])
	if err != nil {
		return nil, err
	}

	authData, err := s.authData(encrypted)
	if err != nil {
		return nil, err
	}

	return cbor.Marshal(map[int]interface{}{
		0x01: map[string]interface{}{"type": "public-key", "id": s.credentialID},
		0x02: authData,
		0x03: make([]byte, 64),
	})
}

// hmacSecretExtensionOutput produces the encrypted hmac-secret output for
// a GetAssertion request, or nil when the request carries no hmac-secret
// input a conforming authenticator would recognize. Inputs that are
// well-formed but cryptographically wrong are hard errors: a platform must
// not be able to pass a bad tag or a bad salt length unnoticed.
func (s *authenticatorSim) hmacSecretExtensionOutput(rawExtensions interface{}) ([]byte, error) {
	if s.suppressExtensionOutput {
		return nil, nil
	}

	extensions, ok := rawExtensions.(map[interface{}]interface{})
	if !ok {
		return nil, nil
	}

	rawInput, ok := extensions[ExtensionHMACSecret]
	if !ok {
		return nil, nil
	}

	input, err := coseLabelMap(rawInput)
	if err != nil {
		// Not a CTAP2 hmac-secret input: the authenticator ignores the
		// extension and completes the assertion without an output.
		return nil, nil
	}

	platformKey, err := ParseCOSEKeyEC2(input[hmacSecretInputKeyAgreement])
	if err != nil {
		return nil, err
	}
	saltEnc, err := simBytes(input[hmacSecretInputSaltEnc])
	if err != nil {
		return nil, err
	}
	saltAuth, err := simBytes(input[hmacSecretInputSaltAuth])
	if err != nil {
		return nil, err
	}
	protocol, err := simUint(input[hmacSecretInputPinUVAuthProtocol])
	if err != nil {
		return nil, err
	}

	peer, err := platformKey.ECDHPublicKey()
	if err != nil {
		return nil, err
	}

	session, err := newPINUVAuthSession(protocol, s.privateKey, peer)
	if err != nil {
		return nil, err
	}

	if !hmac.Equal(session.Authenticate(saltEnc), saltAuth) {
		return nil, errSimSaltAuthMismatch
	}

	salts, err := session.Decrypt(saltEnc)
	if err != nil {
		return nil, err
	}
	if len(salts) != hmacSecretSaltLen && len(salts) != 2*hmacSecretSaltLen {
		return nil, errSimSaltLength
	}

	outputs := make([]byte, 0, len(salts))
	for offset := 0; offset < len(salts); offset += hmacSecretSaltLen {
		outputs = append(outputs, s.hmacOutput(salts[offset:offset+hmacSecretSaltLen])...)
	}

	return session.Encrypt(outputs)
}

// authData assembles authenticator data terminating in the hmac-secret
// extension map.
func (s *authenticatorSim) authData(encryptedOutput []byte) ([]byte, error) {
	flags := FlagUserPresent

	var extensions []byte
	if encryptedOutput != nil {
		flags |= FlagExtensionData

		encoded, err := cbor.Marshal(map[string]interface{}{ExtensionHMACSecret: encryptedOutput})
		if err != nil {
			return nil, err
		}
		extensions = encoded
	}

	var attested []byte
	if s.attestedCredentialData {
		flags |= FlagAttestedCredentialData

		coseKey, err := s.credentialPublicKey()
		if err != nil {
			return nil, err
		}

		attested = append(attested, s.aaguid...)
		attested = binary.BigEndian.AppendUint16(attested, uint16(len(s.credentialID)))
		attested = append(attested, s.credentialID...)
		attested = append(attested, coseKey...)
	}

	authData := make([]byte, authDataHeaderLen, authDataHeaderLen+len(attested)+len(extensions))
	copy(authData, s.rpIDHash)
	authData[authDataRPIDHashLen] = flags
	binary.BigEndian.PutUint32(authData[authDataRPIDHashLen+1:authDataHeaderLen], s.signCount)

	authData = append(authData, attested...)
	authData = append(authData, extensions...)
	return authData, nil
}

// credentialPublicKey renders a COSE_Key for the attested credential data.
func (s *authenticatorSim) credentialPublicKey() ([]byte, error) {
	key, err := NewCOSEKeyEC2(s.privateKey.PublicKey())
	if err != nil {
		return nil, err
	}
	key.Algorithm = COSEAlgES256
	return cbor.Marshal(key.Map())
}

// respond answers a complete CTAPHID_CBOR payload — a CTAP2 command byte
// followed by the CBOR request — returning the CTAPHID response payload: a
// status byte followed by the CBOR response. Mock devices use it to answer
// the commands that carry real cryptography.
func (s *authenticatorSim) respond(payload []byte) []byte {
	if len(payload) == 0 {
		return []byte{StatusInvalidLength}
	}

	var (
		encoded []byte
		err     error
	)
	switch payload[0] {
	case CmdClientPIN:
		encoded, err = s.clientPIN(payload[1:])
	case CmdGetAssertion:
		if status := s.authorizeGetAssertion(payload[1:]); status != StatusOK {
			return []byte{status}
		}
		encoded, err = s.getAssertion(payload[1:])
	default:
		return []byte{StatusInvalidCommand}
	}
	if err != nil {
		return []byte{StatusInvalidParameter}
	}

	return append([]byte{StatusOK}, encoded...)
}

// writeCTAPHIDResponse frames a CTAPHID_CBOR response payload into HID
// packets and queues them for the platform to read. Mock devices use it
// instead of hand-rolled framing so that responses larger than one packet —
// a key agreement response always is — are transmitted completely.
func writeCTAPHIDResponse(buf *bytes.Buffer, cid uint32, payload []byte) {
	packet := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(packet[0:4], cid)
	packet[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(packet[5:7], uint16(len(payload)))

	first := HIDPacketSize - 7
	if len(payload) < first {
		first = len(payload)
	}
	copy(packet[7:], payload[:first])
	buf.Write(packet)

	remaining := payload[first:]
	for seq := byte(0); len(remaining) > 0; seq++ {
		cont := make([]byte, HIDPacketSize)
		binary.BigEndian.PutUint32(cont[0:4], cid)
		cont[4] = seq

		n := HIDPacketSize - 5
		if len(remaining) < n {
			n = len(remaining)
		}
		copy(cont[5:], remaining[:n])
		buf.Write(cont)

		remaining = remaining[n:]
	}
}

// ctapHIDAssembler reassembles the CTAPHID message a platform writes. A
// CBOR request larger than one 64-byte packet arrives as an initialization
// packet followed by continuation packets, so a mock device can only
// interpret a request once every packet has landed.
type ctapHIDAssembler struct {
	cmd    byte
	length int
	data   []byte
}

// accept feeds one written packet to the assembler, reporting the CTAPHID
// command and its complete payload once the final packet lands.
func (a *ctapHIDAssembler) accept(packet []byte) (byte, []byte, bool) {
	// An initialization packet has the high bit of the command byte set;
	// anything else is a continuation packet carrying a sequence number.
	if packet[4]&0x80 != 0 {
		a.cmd = packet[4]
		a.length = int(binary.BigEndian.Uint16(packet[5:7]))
		a.data = append([]byte(nil), packet[7:]...)
	} else {
		a.data = append(a.data, packet[5:]...)
	}

	if len(a.data) < a.length {
		return 0, nil, false
	}

	payload := a.data[:a.length]
	a.data = nil
	return a.cmd, payload, true
}

// simDecodeRequest decodes the CBOR map at the front of a CTAP2 request.
// Only the first item is read, so a request that still carries the HID
// packet's zero padding decodes exactly as a reassembled one does.
func simDecodeRequest(request []byte) (map[int]interface{}, error) {
	var req map[int]interface{}
	if err := cbor.NewDecoder(bytes.NewReader(request)).Decode(&req); err != nil {
		return nil, err
	}
	return req, nil
}

// simUint reads an unsigned integer from a decoded CBOR value.
func simUint(value interface{}) (uint64, error) {
	switch v := value.(type) {
	case uint64:
		return v, nil
	case int64:
		return uint64(v), nil
	case int:
		return uint64(v), nil
	default:
		return 0, errSimMalformedInput
	}
}

// simBytes reads a byte string from a decoded CBOR value.
func simBytes(value interface{}) ([]byte, error) {
	b, ok := value.([]byte)
	if !ok {
		return nil, errSimMalformedInput
	}
	return b, nil
}
