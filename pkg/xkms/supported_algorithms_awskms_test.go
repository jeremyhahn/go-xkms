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

//go:build awskms

package xkms

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/backend/awskms"
)

func TestSupportedAlgorithms_AWSKMSListsOnlyAES256GCM(t *testing.T) {
	algorithms := supportedAlgorithms((&awskms.Backend{}).Capabilities().KeyAlgorithms, false)

	assert.ElementsMatch(t, []transport.KeyAlgorithm{
		transport.KeyAlgorithmRSA2048, transport.KeyAlgorithmRSA3072, transport.KeyAlgorithmRSA4096,
		transport.KeyAlgorithmECDSAP256, transport.KeyAlgorithmECDSAP384, transport.KeyAlgorithmECDSAP521,
		transport.KeyAlgorithmAES256GCM,
	}, algorithms)
	assert.NotContains(t, algorithms, transport.KeyAlgorithmAES128GCM)
	assert.NotContains(t, algorithms, transport.KeyAlgorithmAES192GCM)
}
