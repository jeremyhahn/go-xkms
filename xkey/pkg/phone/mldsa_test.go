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

package phone

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
)

// TestIsAlgorithmSupported_MLDSA covers #2405: the phone backend accepts the
// ML-DSA COSE ids next to the ECDSA ones and still refuses unknown ids.
func TestIsAlgorithmSupported_MLDSA(t *testing.T) {
	// The local ids are the wire values of pkg/pairingproto.
	assert.Equal(t, pairingproto.COSEAlgMLDSA44, coseAlgMLDSA44)
	assert.Equal(t, pairingproto.COSEAlgMLDSA65, coseAlgMLDSA65)
	assert.Equal(t, pairingproto.COSEAlgMLDSA87, coseAlgMLDSA87)

	b := &PhoneKeyBackend{}
	for _, alg := range []int{
		pairingproto.COSEAlgES256, pairingproto.COSEAlgES384, pairingproto.COSEAlgES512,
		pairingproto.COSEAlgMLDSA44, pairingproto.COSEAlgMLDSA65, pairingproto.COSEAlgMLDSA87,
	} {
		assert.True(t, b.isAlgorithmSupported(alg), "COSE id %d", alg)
	}
	assert.False(t, b.isAlgorithmSupported(-257), "RS256 stays unsupported")
	assert.False(t, b.isAlgorithmSupported(0))
}
