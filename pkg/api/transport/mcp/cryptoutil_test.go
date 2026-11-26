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

package mcp

import "testing"

// cryptoUtilityVerbs is every cryptoutil.go verb with the MCP method it calls.
func cryptoUtilityVerbs() map[string]verbCase {
	return map[string]verbCase{
		"Rewrap":                 verb("xkms.rewrap", (*Transport).Rewrap),
		"EncryptBatch":           verb("xkms.encryptBatch", (*Transport).EncryptBatch),
		"DecryptBatch":           verb("xkms.decryptBatch", (*Transport).DecryptBatch),
		"GenerateDataKey":        verb("xkms.generateDataKey", (*Transport).GenerateDataKey),
		"GenerateWrappedDataKey": verb("xkms.generateWrappedDataKey", (*Transport).GenerateWrappedDataKey),
		"GenerateHMAC":           verb("xkms.generateHMAC", (*Transport).GenerateHMAC),
		"VerifyHMAC":             verb("xkms.verifyHMAC", (*Transport).VerifyHMAC),
		"GenerateRandom":         verb("xkms.generateRandom", (*Transport).GenerateRandom),
		"Hash":                   verb("xkms.hash", (*Transport).Hash),
	}
}

func TestCryptoUtilityVerbs_CallTheTool(t *testing.T) {
	assertVerbsCallTheTool(t, cryptoUtilityVerbs())
}

func TestCryptoUtilityVerbs_ServerRefusal(t *testing.T) {
	assertVerbsServerRefusal(t, cryptoUtilityVerbs())
}

func TestCryptoUtilityVerbs_MalformedAnswer(t *testing.T) {
	assertVerbsRejectMalformedAnswer(t, cryptoUtilityVerbs())
}

func TestCryptoUtilityVerbs_NotConnected(t *testing.T) {
	assertVerbsNotConnected(t, cryptoUtilityVerbs())
}
