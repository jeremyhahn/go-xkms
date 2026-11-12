# Deterministic PIN protocol V1 invalid-padding test (#1794, E4)

## Cause

`TestPINProtocolV1_Decapsulate_InvalidPadding`
(pkg/fido2/authenticator/pin_protocol_v1_test.go:485) flips the last byte of
the last ciphertext block. In AES-CBC the last plaintext block is
D_K(C_n) XOR C_{n-1}, so a changed C_n makes the whole last block random
under the random ECDH key of `setupKeyExchange`. `pkcs7Unpad`
(pkg/fido2/authenticator/pin_protocol_v1.go:405-424) then accepts it when the
last byte is 0x01 (1/256), 0x02 0x02 (1/65536), and so on: about 0.4% of
runs `Decapsulate` returns nil and the test fails. Production code is correct.

## Fix

Table-driven test: fixed 16-byte plaintext blocks that are invalid PKCS7 by
construction, encrypted in the test with the shared secret and a zero IV (as
`Encapsulate` does), so `Decapsulate` decrypts back to exactly these bytes:

- last byte 0x00 (padding 0);
- last byte 0x11 (padding > block size);
- 14 x 0xAA + 0x01 0x02 (padding 2, mismatched pad byte).

Each case asserts `errors.Is(err, ErrInvalidPKCS7Padding)`.

## Out of scope

The V2 test (pin_protocol_v2_test.go:549) is deterministic; no production change.

## Result
