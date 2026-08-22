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
	"errors"
	"testing"
)

// TestChangePIN_DoesNotWriteIntoNeighbouringDecodedBytes pins that verifying
// pinUvAuthParam over newPinEnc || pinHashEnc does not write into the buffer
// those fields were decoded from.
//
// handleChangePIN used to build that concatenation with
//
//	authData := append(req.NewPinEnc, req.PinHashEnc...)
//
// which appends IN PLACE whenever NewPinEnc has spare capacity, writing
// pinHashEnc's bytes into whatever follows NewPinEnc's length. Both fields
// arrive from one CBOR message, so what follows is other decoded content.
//
// The existing ChangePIN tests cannot catch that: they go through ProcessCBOR,
// so the decoder owns the allocation and hands out slices with no exploitable
// spare capacity. This one builds the request directly, with the layout the
// bug needs:
//
//	backing = [ newPinEnc | neighbour | pinHashEnc ]
//
// NewPinEnc is sliced with its capacity extending over the rest, so an
// in-place append lands squarely on `neighbour`. The test then asserts
// `neighbour` is untouched.
//
// It deliberately does not care whether the request authenticates -- the
// PinUvAuthParam here is wrong, so it will not. The corruption happens before
// that check, and memory safety is the property under test.
func TestChangePIN_DoesNotWriteIntoNeighbouringDecodedBytes(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	if err := auth.SetPINForTesting("1234"); err != nil {
		t.Fatalf("failed to set initial PIN: %v", err)
	}
	if err := initKeyAgreement(t, auth); err != nil {
		t.Fatalf("failed to get key agreement: %v", err)
	}

	auth.mu.Lock()
	platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	if err != nil {
		t.Fatalf("failed to generate platform key: %v", err)
	}

	newPinEnc, _, err := encryptNewPIN(sharedSecret, "5678")
	if err != nil {
		t.Fatalf("failed to encrypt new PIN: %v", err)
	}
	pinHashEnc, err := encryptPINHash(sharedSecret, "1234")
	if err != nil {
		t.Fatalf("failed to encrypt PIN hash: %v", err)
	}

	// One buffer holding all three, the way a decoder slicing fields out of a
	// single message would.
	const neighbourLen = 16
	const neighbourByte = 0xAB

	backing := make([]byte, 0, len(newPinEnc)+neighbourLen+len(pinHashEnc))
	backing = append(backing, newPinEnc...)
	neighbourAt := len(backing)
	backing = append(backing, bytes.Repeat([]byte{neighbourByte}, neighbourLen)...)
	hashAt := len(backing)
	backing = append(backing, pinHashEnc...)

	neighbour := backing[neighbourAt : neighbourAt+neighbourLen]
	wantNeighbour := bytes.Clone(neighbour)

	req := &ClientPINRequest{
		PinUvAuthProtocol: PINProtocol1,
		SubCommand:        ClientPINSubCmdChangePIN,
		KeyAgreement:      platformCOSE,
		PinUvAuthParam:    make([]byte, 16),
		// Capacity spans the neighbour and the hash: this is the condition
		// under test, not an accident of this buffer.
		NewPinEnc:  backing[0:len(newPinEnc):cap(backing)],
		PinHashEnc: backing[hashAt : hashAt+len(pinHashEnc)],
	}

	// The error is NOT irrelevant: it is what proves the test reached the code
	// it is about.
	//
	// Discarding it made this test able to pass without exercising anything.
	// The only thing asserted below is that a buffer did not change, and a
	// buffer that was never written to has also not changed -- so a setup
	// failure, or a future guard returning before authData is built, would
	// leave the test green while proving nothing.
	//
	// verifyPinAuth runs immediately AFTER the concatenation, and the auth
	// param here is deliberately wrong, so ErrPINAuthInvalid is the terminal
	// result of exactly the path under test. Reaching it means authData was
	// constructed.
	_, err = auth.handleChangePIN(req)
	if !errors.Is(err, ErrPINAuthInvalid) {
		t.Fatalf("handleChangePIN returned %v, want ErrPINAuthInvalid: without it "+
			"there is no evidence the concatenation this test guards was reached", err)
	}

	if !bytes.Equal(neighbour, wantNeighbour) {
		t.Errorf("verifying pinUvAuthParam wrote into the bytes following newPinEnc: "+
			"neighbour is now %x, want %x -- the concatenation is appending in place "+
			"and corrupting adjacent decoded fields", neighbour, wantNeighbour)
	}
}
