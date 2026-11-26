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

// keyManagementVerbs is every keymgmt.go verb with the MCP method it calls.
func keyManagementVerbs() map[string]verbCase {
	return map[string]verbCase{
		"GetPublicKey":            verb("xkms.getPublicKey", (*Transport).GetPublicKey),
		"RevokeKey":               verb("xkms.revokeKey", (*Transport).RevokeKey),
		"UpdateKeyStatus":         verb("xkms.updateKeyStatus", (*Transport).UpdateKeyStatus),
		"GetKeyMetadata":          verb("xkms.getKeyMetadata", (*Transport).GetKeyMetadata),
		"UpdateKeyMetadata":       verb("xkms.updateKeyMetadata", (*Transport).UpdateKeyMetadata),
		"SetKeyPolicy":            verb("xkms.setKeyPolicy", (*Transport).SetKeyPolicy),
		"GetKeyPolicy":            verb("xkms.getKeyPolicy", (*Transport).GetKeyPolicy),
		"DeleteKeyPolicy":         verb("xkms.deleteKeyPolicy", (*Transport).DeleteKeyPolicy),
		"SetKeyRotationPolicy":    verb("xkms.setKeyRotationPolicy", (*Transport).SetKeyRotationPolicy),
		"GetKeyRotationPolicy":    verb("xkms.getKeyRotationPolicy", (*Transport).GetKeyRotationPolicy),
		"DeleteKeyRotationPolicy": verb("xkms.deleteKeyRotationPolicy", (*Transport).DeleteKeyRotationPolicy),
		"GetSupportedAlgorithms":  verb("xkms.getSupportedAlgorithms", (*Transport).GetSupportedAlgorithms),
		"BackendStatus":           verb("xkms.backendStatus", (*Transport).BackendStatus),
		"BackendTest":             verb("xkms.backendTest", (*Transport).BackendTest),
		"SetKeySafety":            verb("xkms.setKeySafety", (*Transport).SetKeySafety),
		"ClearKeySafety":          verb("xkms.clearKeySafety", (*Transport).ClearKeySafety),
		"SafetyCheck":             verb("xkms.safetyCheck", (*Transport).SafetyCheck),
		"SafetyReport":            verb("xkms.safetyReport", (*Transport).SafetyReport),
	}
}

func TestKeyManagementVerbs_CallTheTool(t *testing.T) {
	assertVerbsCallTheTool(t, keyManagementVerbs())
}

func TestKeyManagementVerbs_ServerRefusal(t *testing.T) {
	assertVerbsServerRefusal(t, keyManagementVerbs())
}

func TestKeyManagementVerbs_MalformedAnswer(t *testing.T) {
	assertVerbsRejectMalformedAnswer(t, keyManagementVerbs())
}

func TestKeyManagementVerbs_NotConnected(t *testing.T) {
	assertVerbsNotConnected(t, keyManagementVerbs())
}
