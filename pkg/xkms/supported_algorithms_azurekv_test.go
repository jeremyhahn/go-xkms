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

//go:build azurekv

package xkms

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/backend/azurekv"
)

func TestSupportedAlgorithms_AzureKeyVaultAdvertisesNoEd25519(t *testing.T) {
	algorithms := supportedAlgorithms((&azurekv.Backend{}).Capabilities().KeyAlgorithms, false)

	assert.ElementsMatch(t, []transport.KeyAlgorithm{
		transport.KeyAlgorithmRSA2048, transport.KeyAlgorithmECDSAP256,
		transport.KeyAlgorithmAES128GCM, transport.KeyAlgorithmAES192GCM, transport.KeyAlgorithmAES256GCM,
	}, algorithms)
	assert.NotContains(t, algorithms, transport.KeyAlgorithmEd25519,
		"Key Vault refuses Ed25519 keys, so it must not advertise them")
}
