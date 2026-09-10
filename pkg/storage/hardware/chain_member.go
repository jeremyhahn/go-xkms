// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-or-later

package hardware

import (
	"strconv"
	"strings"
)

// chainMemberIndex reports whether candidate is the CKA_ID of a member of
// id's certificate chain, and which member: chain members are stored under
// exactly id-chain-<n> with n a non-negative decimal index. A prefix match
// on id-chain is not enough: it also matches a certificate whose own id is
// id-chain, and every member of the chain of an id such as id-chain2, so a
// release or a read of one chain would touch objects that belong to another
// record.
func chainMemberIndex(id, candidate string) (int, bool) {
	prefix := id + "-chain-"
	if len(candidate) <= len(prefix) || candidate[:len(prefix)] != prefix {
		return 0, false
	}
	suffix := candidate[len(prefix):]
	for _, r := range suffix {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(suffix)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// chainMemberInfix separates a record id from a chain member's index.
const chainMemberInfix = "-chain-"

// isChainMemberID reports whether candidate has the shape of a chain member's
// CKA_ID, <id>-chain-<n> with a non-empty id and n a non-negative decimal
// index, judged on the LAST occurrence of the infix so that the chain of an
// id that itself contains "-chain-" is still recognised. It is the
// classification a listing uses when it has no id to match against; ids of
// this shape are refused as primary certificate ids so that the
// classification is exact by construction rather than a guess.
func isChainMemberID(candidate string) bool {
	at := strings.LastIndex(candidate, chainMemberInfix)
	if at <= 0 {
		return false
	}
	_, ok := chainMemberIndex(candidate[:at], candidate)
	return ok
}

// isReservedChainID reports whether id has a shape the chain encoding
// reserves and so cannot name a certificate: <id>-chain (the adapter key
// certs/<id>-chain.pem and the PKCS#11 label prefix of <id>'s chain) or a
// chain member's CKA_ID. Every path that accepts a certificate id refuses
// these with ErrIDReservedForChain.
func isReservedChainID(id string) bool {
	return strings.HasSuffix(id, "-chain") || isChainMemberID(id)
}
