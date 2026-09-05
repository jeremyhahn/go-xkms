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

package peer

import (
	"crypto/sha256"
	"crypto/tls"
)

const (
	// ExporterLabel is the TLS exporter label (RFC 5705 / RFC 8446 §7.5)
	// both ends use to derive the channel binding for an attested-peer
	// exchange.
	ExporterLabel = "EXPORTER-attested-peer"

	// ChannelBindingLength is the number of exporter bytes derived.
	ChannelBindingLength = 32
)

// ChannelBinding derives the channel binding for a TLS connection: 32 bytes
// of exported keying material under ExporterLabel with no context. Both
// ends of a connection derive the same value, and no other connection
// yields it, which is what lets a quote be tied to one session.
//
// It fails on a nil state, on a connection whose handshake has not
// completed, and on a connection that cannot export keying material (TLS 1.2
// without the extended master secret extension). Callers that require
// binding must treat that as a refusal, not fall back to an unbound nonce.
func ChannelBinding(state *tls.ConnectionState) ([]byte, error) {
	if state == nil {
		return nil, &ChannelBindingError{Reason: "no TLS connection state"}
	}
	if !state.HandshakeComplete {
		return nil, &ChannelBindingError{Reason: "TLS handshake not complete"}
	}
	material, err := state.ExportKeyingMaterial(ExporterLabel, nil, ChannelBindingLength)
	if err != nil {
		return nil, &ChannelBindingError{Reason: "TLS exporter refused", Cause: err}
	}
	return material, nil
}

// QualifyingData computes the value the quoting side hands to TPM2_Quote as
// qualifying data and the verifier expects in TPMS_ATTEST.extraData.
//
// With a channel binding it is SHA-256(nonce || channelBinding): 32 bytes,
// within every TPM's TPM2B_DATA limit, and unforgeable for another channel
// without the exporter secret. Without one it is the nonce itself, so a
// verifier that does not bind to a channel and a quoter that was given no
// binding still agree.
func QualifyingData(nonce, channelBinding []byte) []byte {
	if len(channelBinding) == 0 {
		out := make([]byte, len(nonce))
		copy(out, nonce)
		return out
	}
	h := sha256.New()
	h.Write(nonce)
	h.Write(channelBinding)
	return h.Sum(nil)
}
