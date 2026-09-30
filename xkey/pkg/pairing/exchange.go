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

package pairing

import "context"

// InlineExchange builds an RPCExchange from raw send/receive primitives over
// an already-established Noise session, for a caller that normally acts as
// the RESPONDER on a connection (it reacts to the peer's requests) but needs
// to issue exactly one request of its own -- a live attestation challenge,
// most commonly -- before it starts reacting.
//
// It encodes and encrypts req, hands the ciphertext to send, then decrypts
// and decodes whatever receive returns next as the matching response. This
// is deliberately NOT a general bidirectional multiplexer like MessageRouter:
// it assumes nothing else is reading the connection concurrently, so it must
// only be used in the narrow window between a connection's handshake
// completing and its normal request-serving loop starting -- exactly where
// TCPPairingServer and BLEPeripheral call it.
func InlineExchange(
	session *NoiseSession,
	send func(ctx context.Context, ciphertext []byte) error,
	receive func(ctx context.Context) ([]byte, error),
) RPCExchange {
	return func(ctx context.Context, req *Request) (*Response, error) {
		plaintext, err := EncodeRequest(req)
		if err != nil {
			return nil, err
		}
		ciphertext, err := session.Encrypt(plaintext)
		if err != nil {
			return nil, err
		}
		if err := send(ctx, ciphertext); err != nil {
			return nil, err
		}
		responseCiphertext, err := receive(ctx)
		if err != nil {
			return nil, err
		}
		responsePlaintext, err := session.Decrypt(responseCiphertext)
		if err != nil {
			return nil, err
		}
		return DecodeResponse(responsePlaintext)
	}
}
