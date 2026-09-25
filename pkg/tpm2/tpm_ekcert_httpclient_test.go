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

package tpm2

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestEkCertHTTPClient_NoInjectedClient_ReturnsHTTPDefaultClient proves that a
// TPM2 built without an injected Params.HTTPClient (every non-test caller)
// falls back to http.DefaultClient for the manufacturer EK certificate
// service request, rather than a nil client that would panic on Do.
func TestEkCertHTTPClient_NoInjectedClient_ReturnsHTTPDefaultClient(t *testing.T) {
	tpm := &TPM2{}
	assert.Same(t, http.DefaultClient, tpm.ekCertHTTPClient())
}

// TestEkCertHTTPClient_InjectedClient_ReturnsIt proves the injected client
// (used by tests to point the EK certificate download at an httptest server)
// takes priority over http.DefaultClient.
func TestEkCertHTTPClient_InjectedClient_ReturnsIt(t *testing.T) {
	custom := &http.Client{}
	tpm := &TPM2{httpClient: custom}
	assert.Same(t, custom, tpm.ekCertHTTPClient())
}
