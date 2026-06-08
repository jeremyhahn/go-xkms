// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package objstore

import (
	"fmt"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// Factory implements the storage.Factory interface over a go-qrdb KVStore. All DAO instances are created through qrdb's built-in
// GenericDAO, which handles codec selection and entity serialization internally.
type Factory struct {
	kvStore xkmssdk.QRDBKVStore
}

// NewFactoryFromKVStore creates a Factory over a go-qrdb KVStore directly. This
// is the datastore path: callers wrap any storage.Backend (file, pebble, qrdb)
// with kvadapter.New and pass it here, so ACME persistence shares the server's
// configured datastore instead of a separate object store.
func NewFactoryFromKVStore(kv xkmssdk.QRDBKVStore) (storage.Factory, error) {
	if kv == nil {
		return nil, xkmssdk.QRDBDAOInvalidConfigError{
			Field:  "kvStore",
			Reason: "kv store not configured",
		}
	}
	return &Factory{kvStore: kv}, nil
}

// Entity-type prefixes for the ACME DAOs. The first `:` is the
// QuicBaaS catalog's namespace/path separator — without it the
// catalog's ParseKey rejects the key with `KEY_INVALID: missing
// separator ':'`. The `/` that follows inside the path portion
// stays as before (qrdb's makeKey appends "/<id>" to whatever we
// pass as entityType). Net result: `acme:accounts/<id>`.
//
// Per-account scoped DAOs (orders / authorizations / challenges)
// use `acme:orders-<account>` style with `-` instead of a second
// `/`, because QuicBaaS namespace validation is strict about the
// path component and allowing an embedded account-id segment
// collides with some catalog implementations. Keep these flat.
const (
	acmeAccountNamespace     = "acme:accounts"
	acmeOrderNamespace       = "acme:orders"
	acmeAuthzNamespace       = "acme:authorizations"
	acmeChallengeNamespace   = "acme:challenges"
	acmeCertificateNamespace = "acme:certificates"
	acmeNonceNamespace       = "acme:nonces"
	acmeEABNamespace         = "acme:eab"
)

// AccountDAO returns a GenericDAO for ACME accounts.
func (f *Factory) AccountDAO() (qrdbsdk.GenericDAO[*entities.ACMEAccount], error) {
	return qrdbsdk.NewDAO(f.kvStore, acmeAccountNamespace,
		func() *entities.ACMEAccount { return &entities.ACMEAccount{} })
}

// OrderDAO returns a GenericDAO for ACME orders scoped to a specific account.
func (f *Factory) OrderDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEOrder], error) {
	if accountID == 0 {
		return nil, xkmssdk.QRDBDAOInvalidEntityIDError{
			EntityType: "order",
			Reason:     "account ID must be non-zero",
		}
	}
	return qrdbsdk.NewDAO(f.kvStore, fmt.Sprintf("%s-%d", acmeOrderNamespace, accountID),
		func() *entities.ACMEOrder { return &entities.ACMEOrder{} })
}

// AuthorizationDAO returns a GenericDAO for ACME authorizations scoped to a specific account.
func (f *Factory) AuthorizationDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEAuthorization], error) {
	if accountID == 0 {
		return nil, xkmssdk.QRDBDAOInvalidEntityIDError{
			EntityType: "authorization",
			Reason:     "account ID must be non-zero",
		}
	}
	return qrdbsdk.NewDAO(f.kvStore, fmt.Sprintf("%s-%d", acmeAuthzNamespace, accountID),
		func() *entities.ACMEAuthorization { return &entities.ACMEAuthorization{} })
}

// ChallengeDAO returns a GenericDAO for ACME challenges scoped to a specific account.
func (f *Factory) ChallengeDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEChallenge], error) {
	if accountID == 0 {
		return nil, xkmssdk.QRDBDAOInvalidEntityIDError{
			EntityType: "challenge",
			Reason:     "account ID must be non-zero",
		}
	}
	return qrdbsdk.NewDAO(f.kvStore, fmt.Sprintf("%s-%d", acmeChallengeNamespace, accountID),
		func() *entities.ACMEChallenge { return &entities.ACMEChallenge{} })
}

// CertificateDAO returns a GenericDAO for ACME certificates.
func (f *Factory) CertificateDAO() (qrdbsdk.GenericDAO[*entities.ACMECertificate], error) {
	return qrdbsdk.NewDAO(f.kvStore, acmeCertificateNamespace,
		func() *entities.ACMECertificate { return &entities.ACMECertificate{} })
}

// NonceDAO returns a GenericDAO for ACME nonces.
func (f *Factory) NonceDAO() (qrdbsdk.GenericDAO[*entities.ACMENonce], error) {
	return qrdbsdk.NewDAO(f.kvStore, acmeNonceNamespace,
		func() *entities.ACMENonce { return &entities.ACMENonce{} })
}

// ExternalAccountBindingDAO returns a GenericDAO for external account bindings.
func (f *Factory) ExternalAccountBindingDAO() (qrdbsdk.GenericDAO[*entities.ExternalAccountBinding], error) {
	return qrdbsdk.NewDAO(f.kvStore, acmeEABNamespace,
		func() *entities.ExternalAccountBinding { return &entities.ExternalAccountBinding{} })
}
