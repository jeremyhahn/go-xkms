//go:build codec_json

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

package handlers

import (
	"encoding/pem"
	"math/big"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFinalizeTCGCSR_IAKDERReachesHooksAndClientUnchanged pins the contract the
// platform records the IAK certificate against: the DER the CA returned from
// SignTCGCSRIDevID is what the order-finalize hooks receive in
// TCGData.IAKCertificateDER and what the client gets as the first PEM block,
// byte for byte. The handler computes no IAK subject of its own -- that name
// is ca.IAKCommonName, applied by the CA when it issues (#371).
func TestFinalizeTCGCSR_IAKDERReachesHooksAndClientUnchanged(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	const (
		prodModel  = "xkms-node"
		prodSerial = "SN-0371"
	)
	iakDER := selfSignedDER(t, ca.IAKCommonName(prodModel, prodSerial), big.NewInt(31), 30*24*time.Hour)
	idevidDER := selfSignedDER(t, prodModel+"-"+prodSerial, big.NewInt(32), 60*24*time.Hour)
	enrollCA := &tcgEnrollmentCA{iakDER: iakDER, idevidDER: idevidDER}
	service.ca = enrollCA

	var hookIAKDER, hookIDevIDDER []byte
	hookCalls := 0
	service.params.OrderFinalizeHooks = NewOrderFinalizeHookRegistry()
	service.params.OrderFinalizeHooks.Register(func(ctx *OrderFinalizeHookContext) error {
		hookCalls++
		require.True(t, ctx.IsTCGCSR)
		require.NotNil(t, ctx.TCGData)
		hookIAKDER = ctx.TCGData.IAKCertificateDER
		hookIDevIDDER = ctx.TCGData.IDevIDCertificateDER
		return nil
	})

	csrDER := packTCGCSR(t, prodModel, prodSerial, selfSignedDER(t, "ek-"+prodSerial, big.NewInt(33), 365*24*time.Hour))
	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	order := &entities.ACMEOrder{
		ID:        371,
		AccountID: account.ID,
		Status:    common.StatusReady,
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypePermanentIdentifier, Value: prodModel + "-" + prodSerial},
		},
	}
	req := httptest.NewRequest("POST", service.baseRESTURI+"/acme/order/371/finalize", nil)

	_, pemBytes, err := service.finalizeTCGCSR("198.51.100.21:4444", csrDER, req, account, order)
	require.NoError(t, err)

	require.Equal(t, 1, hookCalls, "the finalize hook runs once per enrollment")
	assert.Equal(t, iakDER, hookIAKDER, "hooks must receive the CA's IAK DER unchanged")
	assert.Equal(t, idevidDER, hookIDevIDDER, "hooks must receive the CA's IDevID DER unchanged")

	// The CA asked to sign the request common name; the handler must not
	// have substituted an IAK-shaped name for the device identity.
	assert.Equal(t, prodModel+"-"+prodSerial, enrollCA.idevidCN)

	first, rest := pem.Decode(pemBytes)
	require.NotNil(t, first, "the response carries a PEM block")
	assert.Equal(t, "CERTIFICATE", first.Type)
	assert.Equal(t, iakDER, first.Bytes, "the IAK certificate is the first PEM block")
	second, rest := pem.Decode(rest)
	require.NotNil(t, second, "the response carries a second PEM block")
	assert.Equal(t, idevidDER, second.Bytes, "the IDevID certificate is the second PEM block")

	// Everything after the two end-entity certificates is the CA's issuing
	// chain, which RFC 8555 §7.4.2 requires under the
	// application/pem-certificate-chain media type this body is served as.
	// The enrolled device needs it to resolve the issuer of its own
	// certificate, whose CA is remote to it (go-trusted-platform#653).
	assert.Equal(t, []byte("mock-bundle"), rest,
		"the issuing chain follows the two end-entity certificates")
}
