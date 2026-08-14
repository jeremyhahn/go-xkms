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

package module

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// gcmTransport is a spec-faithful AES-GCM backend for the encrypt/decrypt half
// of PKCS11Transport, backed by a real AES key.
//
// It implements exactly the contract transport.EncryptRequest documents:
// TagSize selects the authentication tag length, zero meaning the full
// 128-bit tag. Getting that wrong on either side shows up as a ciphertext
// crypto/cipher cannot reproduce or a tag it will not accept.
type gcmTransport struct {
	*mockClient
	key []byte
}

// Compile-time check: gcmTransport satisfies PKCS11Transport.
//
// Every test double in this package carries this assertion so that adding a
// method to the interface fails here, at the definition, rather than at each
// place the double is passed to WithClient or NewCryptoManager.
var _ PKCS11Transport = (*gcmTransport)(nil)

// errTestTagSize is returned for a tag length outside the set NIST
// SP 800-38D section 5.2.1.2 approves, as a real backend must.
var errTestTagSize = errors.New("pkcs11test transport: unsupported AES-GCM tag size")

func newGCMTransport(t *testing.T) *gcmTransport {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return &gcmTransport{mockClient: newMockClient(), key: key}
}

// aead builds the AEAD for a request's tag length. Shared by both directions
// on purpose: the encrypt and decrypt halves have to resolve identically or a
// truncated tag never authenticates.
func (g *gcmTransport) aead(tagSize int) (cipher.AEAD, error) {
	block, err := aes.NewCipher(g.key)
	if err != nil {
		return nil, err
	}
	if tagSize == 0 {
		return cipher.NewGCM(block)
	}
	if tagSize < 12 || tagSize > 16 {
		return nil, errTestTagSize
	}
	return cipher.NewGCMWithTagSize(block, tagSize)
}

func (g *gcmTransport) Encrypt(ctx context.Context, req *transport.EncryptRequest) (*transport.EncryptResponse, error) {
	g.mockClient.encryptCalled = true
	g.mockClient.lastEncryptReq = req

	gcm, err := g.aead(req.TagSize)
	if err != nil {
		return nil, err
	}

	nonce := req.Nonce
	if len(nonce) == 0 {
		nonce = make([]byte, gcm.NonceSize())
	}

	sealed := gcm.Seal(nil, nonce, req.Plaintext, req.AdditionalData)
	split := len(sealed) - gcm.Overhead()
	return &transport.EncryptResponse{
		Ciphertext: sealed[:split],
		Nonce:      nonce,
		Tag:        sealed[split:],
	}, nil
}

func (g *gcmTransport) Decrypt(ctx context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error) {
	g.mockClient.decryptCalled = true
	g.mockClient.lastDecryptReq = req

	gcm, err := g.aead(req.TagSize)
	if err != nil {
		return nil, err
	}
	if len(req.Tag) != gcm.Overhead() {
		return nil, errTestTagSize
	}

	sealed := make([]byte, 0, len(req.Ciphertext)+len(req.Tag))
	sealed = append(sealed, req.Ciphertext...)
	sealed = append(sealed, req.Tag...)

	plaintext, err := gcm.Open(nil, req.Nonce, sealed, req.AdditionalData)
	if err != nil {
		return nil, err
	}
	return &transport.DecryptResponse{Plaintext: plaintext}, nil
}

// gcmMechanism builds a CKM_AES_GCM mechanism carrying the given parameters.
func gcmMechanism(iv, aad []byte, tagBits uint32) *Mechanism {
	return &Mechanism{
		Type:           CKM_AES_GCM,
		TypedParameter: &AESGCMParams{IV: iv, AAD: aad, TagBits: tagBits},
	}
}

// TestGCMTagBits_EncryptProducesTheRequestedTagLength checks the encrypt half
// against crypto/cipher computed independently in the test.
//
// PKCS#11 v3.2 section 6.13.7 says the AES-GCM output is the ciphertext with
// the tag appended, and NIST SP 800-38D section 5.2.1.2 defines a t-bit tag as
// the leading t bits of the full 128-bit tag. The module used to refuse every
// ulTagBits other than 128 because the transport had no field to carry the
// length; refusing was honest but left five of the standard's own tag lengths
// unreachable.
func TestGCMTagBits_EncryptProducesTheRequestedTagLength(t *testing.T) {
	plaintext := []byte("forty-one bytes of plaintext to encrypt..")
	aad := []byte("bound header")

	for _, tagBits := range []uint32{96, 104, 112, 120, 128} {
		t.Run(tagBitsName(tagBits), func(t *testing.T) {
			client := newGCMTransport(t)
			cm := NewCryptoManager(client, &CryptoManagerConfig{DefaultBackend: "test-backend"})
			iv := testGCMIV()

			op, err := cm.EncryptInit(gcmMechanism(iv, aad, tagBits), 1, "aes-key", "test-backend")
			if err != nil {
				t.Fatalf("EncryptInit: %v", err)
			}

			got, err := cm.Encrypt(context.Background(), op, plaintext)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}

			// Independent oracle: crypto/cipher with the same truncation.
			tagSize := int(tagBits / 8)
			block, err := aes.NewCipher(client.key)
			if err != nil {
				t.Fatalf("aes.NewCipher: %v", err)
			}
			gcm, err := cipher.NewGCMWithTagSize(block, tagSize)
			if err != nil {
				t.Fatalf("cipher.NewGCMWithTagSize: %v", err)
			}
			want := gcm.Seal(nil, iv, plaintext, aad)

			if !bytes.Equal(got, want) {
				t.Fatalf("C_Encrypt output = %x, want %x", got, want)
			}
			if len(got) != len(plaintext)+tagSize {
				t.Fatalf("C_Encrypt returned %d bytes, want %d (ciphertext || %d-byte tag)",
					len(got), len(plaintext)+tagSize, tagSize)
			}
			if client.lastEncryptReq.TagSize != tagSize {
				t.Errorf("EncryptRequest.TagSize = %d, want %d", client.lastEncryptReq.TagSize, tagSize)
			}
		})
	}
}

// TestGCMTagBits_RoundTrip drives C_Encrypt then C_Decrypt at every permitted
// tag length.
//
// This is the check that catches the two halves disagreeing. The decrypt path
// sizes its ciphertext||tag split from the same ulTagBits the encrypt path
// truncated with, so if either side resolves the length differently the split
// lands in the wrong place and every round trip fails.
func TestGCMTagBits_RoundTrip(t *testing.T) {
	plaintext := []byte("round trip me at every approved tag length")
	aad := []byte("authenticated but not encrypted")

	for _, tagBits := range []uint32{0, 96, 104, 112, 120, 128} {
		t.Run(tagBitsName(tagBits), func(t *testing.T) {
			client := newGCMTransport(t)
			cm := NewCryptoManager(client, &CryptoManagerConfig{DefaultBackend: "test-backend"})
			iv := testGCMIV()

			encOp, err := cm.EncryptInit(gcmMechanism(iv, aad, tagBits), 1, "aes-key", "test-backend")
			if err != nil {
				t.Fatalf("EncryptInit: %v", err)
			}
			ciphertext, err := cm.Encrypt(context.Background(), encOp, plaintext)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}

			decOp, err := cm.DecryptInit(gcmMechanism(iv, aad, tagBits), 1, "aes-key", "test-backend")
			if err != nil {
				t.Fatalf("DecryptInit: %v", err)
			}
			recovered, err := cm.Decrypt(context.Background(), decOp, ciphertext)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}

			if !bytes.Equal(recovered, plaintext) {
				t.Fatalf("round trip returned %q, want %q", recovered, plaintext)
			}
			if client.lastDecryptReq.TagSize != client.lastEncryptReq.TagSize {
				t.Errorf("TagSize differs across the round trip: encrypt=%d decrypt=%d",
					client.lastEncryptReq.TagSize, client.lastDecryptReq.TagSize)
			}
		})
	}
}

// TestGCMTagBits_TruncatedToTheWrongLengthFailsAuthentication covers the three
// ways a tag length can go wrong, and pins which of them must succeed.
//
// A 128-bit ciphertext handed to a 96-bit-tag decrypt must fail: the split
// lands four bytes early, so both the ciphertext and the tag are wrong. That
// is exactly what happens when encrypt and decrypt disagree on t. A tampered
// tag of the right length must also fail. But the same ciphertext re-framed at
// 96 bits -- the leading 96 bits of the full tag, which is what SP 800-38D
// section 5.2.1.2 defines the 96-bit tag to be -- must succeed, or the
// truncation is not the standard's.
func TestGCMTagBits_TruncatedToTheWrongLengthFailsAuthentication(t *testing.T) {
	plaintext := []byte("authenticate me")
	aad := []byte("header")
	iv := testGCMIV()

	client := newGCMTransport(t)
	cm := NewCryptoManager(client, &CryptoManagerConfig{DefaultBackend: "test-backend"})

	encOp, err := cm.EncryptInit(gcmMechanism(iv, aad, 128), 1, "aes-key", "test-backend")
	if err != nil {
		t.Fatalf("EncryptInit: %v", err)
	}
	full, err := cm.Encrypt(context.Background(), encOp, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	t.Run("full-length ciphertext presented as a 96-bit-tag ciphertext", func(t *testing.T) {
		// The trailing four tag bytes are now read as ciphertext, so both the
		// ciphertext and the tag are wrong. This is exactly what happens when
		// the two halves disagree on t.
		decOp, err := cm.DecryptInit(gcmMechanism(iv, aad, 96), 1, "aes-key", "test-backend")
		if err != nil {
			t.Fatalf("DecryptInit: %v", err)
		}
		if _, err := cm.Decrypt(context.Background(), decOp, full); err == nil {
			t.Fatal("Decrypt accepted a ciphertext framed for a different tag length")
		}
	})

	t.Run("tampered tag of the correct length is rejected", func(t *testing.T) {
		tampered := make([]byte, len(full))
		copy(tampered, full)
		tampered[len(tampered)-1] ^= 0xFF

		decOp, err := cm.DecryptInit(gcmMechanism(iv, aad, 128), 1, "aes-key", "test-backend")
		if err != nil {
			t.Fatalf("DecryptInit: %v", err)
		}
		_, err = cm.Decrypt(context.Background(), decOp, tampered)
		if err == nil {
			t.Fatal("Decrypt accepted a tampered authentication tag")
		}
		var pkcsErr *PKCS11Error
		if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_ENCRYPTED_DATA_INVALID {
			t.Fatalf("Decrypt error = %v, want CKR_ENCRYPTED_DATA_INVALID", err)
		}
	})

	t.Run("truncated tag at a length neither side agreed on", func(t *testing.T) {
		// Cut the ciphertext down as though a 96-bit tag had been produced,
		// then ask for a 96-bit-tag decrypt. The tag bytes are a prefix of the
		// 128-bit tag, so this is the one case that could succeed by accident
		// if the backend verified fewer bits than it was told to.
		short := make([]byte, len(full)-4)
		copy(short, full[:len(full)-4])

		decOp, err := cm.DecryptInit(gcmMechanism(iv, aad, 96), 1, "aes-key", "test-backend")
		if err != nil {
			t.Fatalf("DecryptInit: %v", err)
		}
		recovered, err := cm.Decrypt(context.Background(), decOp, short)
		if err != nil {
			t.Fatalf("Decrypt of a correctly re-framed 96-bit tag failed: %v", err)
		}
		if !bytes.Equal(recovered, plaintext) {
			t.Fatalf("recovered %q, want %q", recovered, plaintext)
		}
	})
}

// TestGCMTagBits_InvalidLengthsAreRefused checks the validation that replaced
// the blanket refusal.
//
// PKCS#11 v3.2 section 6.13.7 itself allows ulTagBits from 0 to 128, but the
// tag it describes is GCM's and NIST SP 800-38D section 5.2.1.2 approves only
// 96, 104, 112, 120 and 128. The module enforces the intersection, and
// CKR_MECHANISM_PARAM_INVALID is what v3.2 section 5.10.1 provides for a
// mechanism parameter the token will not accept. Rounding to the nearest
// permitted value instead would produce output no conforming peer can verify.
func TestGCMTagBits_InvalidLengthsAreRefused(t *testing.T) {
	invalid := []uint32{1, 8, 32, 64, 95, 100, 127, 129, 256}

	for _, tagBits := range invalid {
		t.Run(tagBitsName(tagBits), func(t *testing.T) {
			cm, _ := newTestCryptoManager()
			iv := testGCMIV()

			// All four AEAD init paths must refuse identically. A parameter
			// accepted by one and refused by another is how encrypt and
			// decrypt end up disagreeing.
			t.Run("EncryptInit", func(t *testing.T) {
				_, err := cm.EncryptInit(gcmMechanism(iv, nil, tagBits), 1, "aes-key", "test-backend")
				requireMechanismParamInvalid(t, err)
			})
			t.Run("DecryptInit", func(t *testing.T) {
				_, err := cm.DecryptInit(gcmMechanism(iv, nil, tagBits), 1, "aes-key", "test-backend")
				requireMechanismParamInvalid(t, err)
			})
			t.Run("MessageDecryptInit", func(t *testing.T) {
				_, err := cm.MessageDecryptInit(gcmMechanism(iv, nil, tagBits), 1, "aes-key", "test-backend")
				requireMechanismParamInvalid(t, err)
			})
		})
	}
}

// TestGCMTagBits_MessageInitPathsAgreeWithEncryptInit pins the four init paths
// to the same resolution.
//
// C_MessageEncryptInit delegates to C_EncryptInit, so it is covered by the
// encrypt case; C_MessageDecryptInit has its own implementation and is the one
// that can drift. An earlier defect of exactly this shape -- CK_GCM_PARAMS.pAAD
// wired into EncryptInit and MessageDecryptInit but missed in DecryptInit --
// made every AEAD round trip with AAD fail as CKR_ENCRYPTED_DATA_INVALID,
// which reads like corrupt ciphertext rather than a dropped parameter.
func TestGCMTagBits_MessageInitPathsAgreeWithEncryptInit(t *testing.T) {
	iv := testGCMIV()
	aad := []byte("shared associated data")

	for _, tagBits := range []uint32{0, 96, 128} {
		t.Run(tagBitsName(tagBits), func(t *testing.T) {
			cm, _ := newTestCryptoManager()
			mech := gcmMechanism(iv, aad, tagBits)

			encOp, err := cm.EncryptInit(mech, 1, "aes-key", "test-backend")
			if err != nil {
				t.Fatalf("EncryptInit: %v", err)
			}
			decOp, err := cm.DecryptInit(mech, 1, "aes-key", "test-backend")
			if err != nil {
				t.Fatalf("DecryptInit: %v", err)
			}
			msgDecOp, err := cm.MessageDecryptInit(mech, 1, "aes-key", "test-backend")
			if err != nil {
				t.Fatalf("MessageDecryptInit: %v", err)
			}

			if encOp.tagSize != decOp.tagSize {
				t.Errorf("EncryptInit tagSize=%d, DecryptInit tagSize=%d", encOp.tagSize, decOp.tagSize)
			}
			if encOp.tagSize != msgDecOp.tagSize {
				t.Errorf("EncryptInit tagSize=%d, MessageDecryptInit tagSize=%d", encOp.tagSize, msgDecOp.tagSize)
			}

			// AAD is the parameter that drifted before; check it in the same
			// place so a future divergence is caught by one test.
			if !bytes.Equal(encOp.aad, decOp.aad) {
				t.Errorf("EncryptInit aad=%q, DecryptInit aad=%q", encOp.aad, decOp.aad)
			}
			if !bytes.Equal(encOp.aad, msgDecOp.aad) {
				t.Errorf("EncryptInit aad=%q, MessageDecryptInit aad=%q", encOp.aad, msgDecOp.aad)
			}
		})
	}
}

// requireMechanismParamInvalid asserts err is CKR_MECHANISM_PARAM_INVALID.
func requireMechanismParamInvalid(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected CKR_MECHANISM_PARAM_INVALID, got nil")
	}
	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_MECHANISM_PARAM_INVALID {
		t.Fatalf("error = %v, want CKR_MECHANISM_PARAM_INVALID", err)
	}
}

// tagBitsName renders a ulTagBits value as a subtest name.
func tagBitsName(tagBits uint32) string {
	if tagBits == 0 {
		return "ulTagBits=0 (backend default)"
	}
	return "ulTagBits=" + itoa(int(tagBits))
}

// itoa avoids pulling strconv in for one call site.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
