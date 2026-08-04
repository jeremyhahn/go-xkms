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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
)

// tcgOrderContext builds a TCG-CSR-IDEVID pre-sign hook context whose order
// carries the given permanent-identifier value.
func tcgOrderContext(permanentID string) *OrderPreSignHookContext {
	return &OrderPreSignHookContext{
		Context: context.Background(),
		Order: &entities.ACMEOrder{
			ID: 1,
			Identifiers: []entities.ACMEIdentifier{
				{Type: common.AuthzTypePermanentIdentifier, Value: permanentID},
			},
		},
		IsTCGCSR: true,
		TCGData: &TCGEnrollmentData{
			ProductModel:        "model",
			ProductSerial:       "serial",
			PermanentIdentifier: "model-serial",
		},
	}
}

func TestPermanentIdentifierURISANHook_StampsURI(t *testing.T) {
	hook := NewPermanentIdentifierURISANHook(func(permanentID string) string {
		require.Equal(t, "10.0.0.1:8300", permanentID)
		return "spiffe://xkms.cluster/node/10.0.0.1:8300"
	})

	exts, err := hook(tcgOrderContext("10.0.0.1:8300"))
	require.NoError(t, err)
	require.Len(t, exts, 1)
	assert.Equal(t, oidExtensionSubjectAltName, exts[0].Id)
	assert.False(t, exts[0].Critical)

	// End-to-end DER validation: issue a self-signed certificate carrying the
	// extension and confirm Go's parser recovers the URI SAN.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "model-serial"},
		NotBefore:       time.Now().Add(-time.Minute),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: exts,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	require.Len(t, cert.URIs, 1)
	assert.Equal(t, "spiffe://xkms.cluster/node/10.0.0.1:8300", cert.URIs[0].String())
}

func TestPermanentIdentifierURISANHook_SkipsNonTCG(t *testing.T) {
	hook := NewPermanentIdentifierURISANHook(func(string) string {
		t.Fatal("uriFor must not be called on the standard CSR path")
		return ""
	})

	hookCtx := tcgOrderContext("10.0.0.1:8300")
	hookCtx.IsTCGCSR = false

	exts, err := hook(hookCtx)
	require.NoError(t, err)
	assert.Nil(t, exts)
}

func TestPermanentIdentifierURISANHook_SkipsWithoutPermanentIdentifier(t *testing.T) {
	hook := NewPermanentIdentifierURISANHook(func(string) string {
		t.Fatal("uriFor must not be called without a permanent-identifier")
		return ""
	})

	hookCtx := tcgOrderContext("unused")
	hookCtx.Order.Identifiers = []entities.ACMEIdentifier{
		{Type: common.AuthzTypeDNS, Value: "node.example.com"},
	}

	exts, err := hook(hookCtx)
	require.NoError(t, err)
	assert.Nil(t, exts)
}

func TestPermanentIdentifierURISANHook_SkipsWhenPolicyDeclines(t *testing.T) {
	hook := NewPermanentIdentifierURISANHook(func(string) string {
		return ""
	})

	exts, err := hook(tcgOrderContext("intruder:9999"))
	require.NoError(t, err)
	assert.Nil(t, exts)
}

func TestPermanentIdentifierURISANHook_SkipsNilContextAndOrder(t *testing.T) {
	hook := NewPermanentIdentifierURISANHook(func(string) string { return "spiffe://d/node/x" })

	exts, err := hook(nil)
	require.NoError(t, err)
	assert.Nil(t, exts)

	hookCtx := tcgOrderContext("10.0.0.1:8300")
	hookCtx.Order = nil
	exts, err = hook(hookCtx)
	require.NoError(t, err)
	assert.Nil(t, exts)
}

func TestPermanentIdentifierURISANHook_RejectsNonIA5URI(t *testing.T) {
	hook := NewPermanentIdentifierURISANHook(func(string) string {
		return "spiffe://xkms.cluster/node/nöde"
	})

	exts, err := hook(tcgOrderContext("10.0.0.1:8300"))
	require.Error(t, err)
	assert.Nil(t, exts)

	var ia5Err ErrURISANNotIA5
	require.ErrorAs(t, err, &ia5Err)
	assert.Contains(t, ia5Err.Error(), "not an IA5")
}

func TestBuildURISANExtension_ValidAndInvalid(t *testing.T) {
	ext, err := buildURISANExtension("spiffe://td/node/a")
	require.NoError(t, err)
	assert.Equal(t, oidExtensionSubjectAltName, ext.Id)
	assert.NotEmpty(t, ext.Value)

	_, err = buildURISANExtension("spiffe://td/node/ü")
	require.Error(t, err)
}

func TestOrderPermanentIdentifier(t *testing.T) {
	order := &entities.ACMEOrder{
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypeDNS, Value: "a.example.com"},
			{Type: common.AuthzTypePermanentIdentifier, Value: "node-1"},
		},
	}
	assert.Equal(t, "node-1", orderPermanentIdentifier(order))

	order.Identifiers = order.Identifiers[:1]
	assert.Equal(t, "", orderPermanentIdentifier(order))
}
