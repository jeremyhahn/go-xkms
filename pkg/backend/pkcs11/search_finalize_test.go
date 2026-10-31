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

//go:build pkcs11

package pkcs11

import (
	"crypto/elliptic"
	"testing"

	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/require"
)

// TestSearchPaths_FailedInitLeavesSessionUsable leaves a search active on a
// session, as a C_FindObjectsInit that fails part way through does (SoftHSM2
// under concurrent writes, #1720), and proves every backend search path
// reports that Init failure and finalizes the stale search, so the session's
// next search succeeds instead of failing CKR_OPERATION_ACTIVE forever.
func TestSearchPaths_FailedInitLeavesSessionUsable(t *testing.T) {
	b := newProvisionedBackend(t, "search-finalize")
	attrs := provisionDerivableECKey(t, b, "search-finalize-key", elliptic.P256())
	id, err := b.resolveKeyID(attrs)
	require.NoError(t, err)
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}

	searches := map[string]func(session pkcs11.SessionHandle) error{
		"findAllObjects": func(session pkcs11.SessionHandle) error {
			handles, err := b.findAllObjects(session, template)
			if err == nil {
				require.Len(t, handles, 1)
			}
			return err
		},
		"findOneObject": func(session pkcs11.SessionHandle) error {
			handle, err := b.findOneObject(session, template)
			if err == nil {
				require.NotZero(t, handle)
			}
			return err
		},
		"findPrivateKeyHandle": func(session pkcs11.SessionHandle) error {
			handle, err := b.findPrivateKeyHandle(session, attrs)
			if err == nil {
				require.NotZero(t, handle)
			}
			return err
		},
		"allCertificateValues": func(session pkcs11.SessionHandle) error {
			_, err := b.allCertificateValues(session)
			return err
		},
	}

	for name, search := range searches {
		t.Run(name, func(t *testing.T) {
			session := openIntrospectionSession(t, b)
			require.NoError(t, b.p11ctx.FindObjectsInit(session, nil), "leave a stale search on the session")

			err := search(session)
			require.ErrorIs(t, err, pkcs11.Error(pkcs11.CKR_OPERATION_ACTIVE), "the failed Init must be reported")

			require.NoError(t, search(session), "the failed search must not leave the session searching")
		})
	}
}
