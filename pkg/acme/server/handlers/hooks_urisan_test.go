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

// testTrustDomain and testMembers are the cluster the hook tests stamp for.
const testTrustDomain = "xkms.cluster"

var testMembers = map[uint64]string{
	1: "10.0.0.1:8300",
	2: "10.0.0.2:8300",
}

// tcgOrderContext builds a TCG-CSR-IDEVID pre-sign hook context whose order
// carries the given permanent-identifier value and was validated by enroll-01.
func tcgOrderContext(permanentID string) *OrderPreSignHookContext {
	return &OrderPreSignHookContext{
		Context: context.Background(),
		Order: &entities.ACMEOrder{
			ID: 1,
			Identifiers: []entities.ACMEIdentifier{
				{Type: common.AuthzTypePermanentIdentifier, Value: permanentID},
			},
		},
		IsTCGCSR:            true,
		ValidatedChallenges: []string{common.ChallengeTypeEnroll01},
		TCGData: &TCGEnrollmentData{
			ProductModel:        "model",
			ProductSerial:       "serial",
			PermanentIdentifier: "model-serial",
		},
	}
}

func TestClusterNodeURISANHook_StampsEnrolledMember(t *testing.T) {
	hook := NewClusterNodeURISANHook(testTrustDomain, testMembers)

	exts, err := hook(tcgOrderContext("10.0.0.2:8300"))
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
	assert.Equal(t, "spiffe://xkms.cluster/node/10.0.0.2:8300", cert.URIs[0].String())
}

// TestClusterNodeURISANHook_RefusesWithoutProof covers every way an order can
// fall short of membership plus an enroll-01 validation. Each must leave the
// certificate without a node URI rather than fail issuance.
func TestClusterNodeURISANHook_RefusesWithoutProof(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*OrderPreSignHookContext)
	}{
		{"non-member address", func(c *OrderPreSignHookContext) {
			c.Order.Identifiers[0].Value = "10.0.0.9:8300"
		}},
		{"member host on another port", func(c *OrderPreSignHookContext) {
			c.Order.Identifiers[0].Value = "10.0.0.1:9999"
		}},
		{"member host without port", func(c *OrderPreSignHookContext) {
			c.Order.Identifiers[0].Value = "10.0.0.1"
		}},
		{"validated by endorse-01", func(c *OrderPreSignHookContext) {
			c.ValidatedChallenges = []string{common.ChallengeTypeEndorse01}
		}},
		{"validated by device-attest-01", func(c *OrderPreSignHookContext) {
			c.ValidatedChallenges = []string{common.ChallengeTypeDeviceAttest01}
		}},
		{"enroll-01 alongside another challenge", func(c *OrderPreSignHookContext) {
			c.ValidatedChallenges = []string{common.ChallengeTypeEndorse01, common.ChallengeTypeEnroll01}
		}},
		{"no attestation challenge", func(c *OrderPreSignHookContext) {
			c.ValidatedChallenges = nil
		}},
		{"standard CSR path", func(c *OrderPreSignHookContext) {
			c.IsTCGCSR = false
		}},
		{"no permanent-identifier", func(c *OrderPreSignHookContext) {
			c.Order.Identifiers[0] = entities.ACMEIdentifier{Type: common.AuthzTypeDNS, Value: "10.0.0.1:8300"}
		}},
		{"nil order", func(c *OrderPreSignHookContext) {
			c.Order = nil
		}},
	}

	hook := NewClusterNodeURISANHook(testTrustDomain, testMembers)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hookCtx := tcgOrderContext("10.0.0.1:8300")
			tt.mutate(hookCtx)

			exts, err := hook(hookCtx)
			require.NoError(t, err)
			assert.Nil(t, exts)
		})
	}
}

func TestClusterNodeURISANHook_NilContextAndNoMembers(t *testing.T) {
	exts, err := NewClusterNodeURISANHook(testTrustDomain, testMembers)(nil)
	require.NoError(t, err)
	assert.Nil(t, exts)

	// An empty address in the membership must not admit an order without a
	// permanent-identifier.
	hook := NewClusterNodeURISANHook(testTrustDomain, map[uint64]string{1: ""})
	hookCtx := tcgOrderContext("")
	exts, err = hook(hookCtx)
	require.NoError(t, err)
	assert.Nil(t, exts)
}

func TestClusterNodeURISANHook_CopiesMembers(t *testing.T) {
	members := map[uint64]string{1: "10.0.0.1:8300"}
	hook := NewClusterNodeURISANHook(testTrustDomain, members)
	members[2] = "10.0.0.2:8300"

	exts, err := hook(tcgOrderContext("10.0.0.2:8300"))
	require.NoError(t, err)
	assert.Nil(t, exts, "a member added after construction must not be stamped")
}

func TestValidatedByEnroll01Only(t *testing.T) {
	assert.True(t, validatedByEnroll01Only([]string{common.ChallengeTypeEnroll01}))
	assert.False(t, validatedByEnroll01Only(nil))
	assert.False(t, validatedByEnroll01Only([]string{common.ChallengeTypeEndorse01}))
	assert.False(t, validatedByEnroll01Only([]string{common.ChallengeTypeEndorse01, common.ChallengeTypeEnroll01}))
}

func TestBuildURISANExtension_ValidAndInvalid(t *testing.T) {
	ext, err := buildURISANExtension("spiffe://td/node/a")
	require.NoError(t, err)
	assert.Equal(t, oidExtensionSubjectAltName, ext.Id)
	assert.NotEmpty(t, ext.Value)

	_, err = buildURISANExtension("spiffe://td/node/ü")
	var ia5Err ErrURISANNotIA5
	require.ErrorAs(t, err, &ia5Err)
	assert.Contains(t, ia5Err.Error(), "not an IA5")
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
