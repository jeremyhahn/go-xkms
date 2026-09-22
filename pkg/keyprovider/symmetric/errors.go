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

package symmetric

import "errors"

var (
	// ErrStorageClosed is returned when attempting to use a closed backend.
	ErrStorageClosed = errors.New("storage is closed")

	// ErrInvalidPassword is returned when password decryption fails.
	ErrInvalidPassword = errors.New("invalid password or corrupted data")

	// ErrUnsupportedCipherMode is returned when types.EncryptOptions.Mode or
	// types.DecryptOptions.Mode names anything other than the empty default
	// (AEAD), types.CipherModeCBC, types.CipherModeCBCPad, or
	// types.CipherModeECB.
	ErrUnsupportedCipherMode = errors.New("symmetric: unsupported cipher mode")

	// ErrCBCRequiresAES is returned when Mode selects an AES-CBC variant but
	// the key's algorithm has no block-cipher form (e.g. ChaCha20-Poly1305 /
	// XChaCha20-Poly1305, which have no CBC mode).
	ErrCBCRequiresAES = errors.New("symmetric: CBC modes require an AES key")

	// ErrECBRequiresAES is returned when Mode selects types.CipherModeECB but
	// the key's algorithm is a stream AEAD with no block-cipher form, for the
	// same reason as ErrCBCRequiresAES.
	ErrECBRequiresAES = errors.New("symmetric: ECB mode requires an AES key")

	// ErrIVNotSupported is returned when an IV accompanies a mode that has
	// none. AES-ECB enciphers every block independently (PKCS#11 v3.2
	// §6.10.4 gives CKM_AES_ECB no mechanism parameter at all), so an IV can
	// only mean the caller expects a chained mode; using it would silently
	// produce something other than what was asked for, and ignoring it would
	// report success for an operation the caller did not get.
	ErrIVNotSupported = errors.New("symmetric: an IV is not supported for this cipher mode")

	// ErrInvalidTagSize is returned when types.EncryptOptions.TagSize or
	// types.DecryptOptions.TagSize names a tag length the selected AEAD
	// cannot produce. NIST SP 800-38D section 5.2.1.2 defines a t-bit GCM
	// tag as the leading t bits of the full tag and approves t of 96, 104,
	// 112, 120 and 128, so AES-GCM accepts 12 to 16 bytes.
	ErrInvalidTagSize = errors.New("symmetric: invalid authentication tag size")

	// ErrTagSizeNotSupported is returned when a truncated tag is requested of
	// a cipher that has no truncation construction. Poly1305 is a one-time
	// MAC whose 16-byte output is not defined bit-by-bit (RFC 8439 section
	// 2.5), so ChaCha20-Poly1305 and XChaCha20-Poly1305 have no shorter tag
	// to give. Returning the full tag anyway would tell a caller its
	// truncation request had been honoured when it had not.
	ErrTagSizeNotSupported = errors.New("symmetric: this cipher supports only its full-length authentication tag")

	// ErrArbitraryIVGCMUnavailable is returned when an AES-GCM operation
	// requires a caller-supplied nonce -- opts.Nonce was set on Encrypt, or
	// the ciphertext's GCMNonceMode is the explicit legacy framing on
	// Decrypt -- and this process is GODEBUG=fips140=only, which refuses
	// every AES-GCM construction that accepts an externally supplied IV.
	// There is no substitute construction that honours a caller-supplied
	// nonce, so the operation fails closed rather than silently switching to
	// a framing the caller did not ask for. See pkg/crypto/aead's identical
	// sentinel, ArbitraryIVGCMUsable and NewGCMForFreshEncrypt.
	ErrArbitraryIVGCMUnavailable = errors.New("symmetric: this FIPS 140-only process cannot construct an AES-GCM AEAD over a caller-supplied nonce")

	// ErrAdditionalDataNotSupported is returned when AdditionalData is
	// supplied for a non-AEAD cipher mode. AES-CBC has no authenticated-data
	// input, so silently accepting and ignoring it would misrepresent the
	// operation actually performed to the caller.
	ErrAdditionalDataNotSupported = errors.New("symmetric: additional data is not supported for this cipher mode")

	// ErrInvalidIVSize is returned when a caller-supplied AES-CBC IV is not
	// exactly one AES block (16 bytes). crypto/cipher's NewCBCEncrypter and
	// NewCBCDecrypter both panic on a mismatched IV length; this check runs
	// first so a bad IV from the wire becomes a typed error instead of
	// taking the daemon down.
	ErrInvalidIVSize = errors.New("symmetric: invalid IV size")

	// ErrPlaintextNotBlockAligned is returned by unpadded AES-CBC
	// (CipherModeCBC) encryption when the plaintext length is zero or not a
	// whole number of AES blocks. Unpadded CBC has no way to encode the
	// original length, so the caller must supply block-aligned plaintext.
	ErrPlaintextNotBlockAligned = errors.New("symmetric: plaintext is not a whole number of AES blocks")

	// ErrCiphertextNotBlockAligned is returned by AES-CBC decryption
	// (padded or unpadded) when the ciphertext length is zero or not a
	// whole number of AES blocks. crypto/cipher's CBC BlockMode.CryptBlocks
	// panics on a non-block-aligned input; this check runs first. It is
	// evaluated purely from the caller-supplied ciphertext length -- which
	// is public information regardless of key or plaintext -- so returning
	// it as a distinct error from ErrInvalidPadding does not create a
	// padding oracle.
	ErrCiphertextNotBlockAligned = errors.New("symmetric: ciphertext is not a whole number of AES blocks")

	// ErrInvalidPadding is returned when PKCS#7 unpadding fails after a
	// successful AES-CBC-PAD decryption, whether because the trailing
	// padding-length byte is out of range or because the padding bytes
	// don't match it. Both conditions return this identical error value,
	// and the check that produces it runs in constant time relative to the
	// padding length, so a caller cannot distinguish "wrong padding length"
	// from "wrong padding bytes" -- either by error content or by timing --
	// to mount a CBC padding-oracle attack (Vaudenay, 2002).
	ErrInvalidPadding = errors.New("symmetric: invalid padding")
)
