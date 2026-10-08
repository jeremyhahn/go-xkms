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

package objstore

import (
	"fmt"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	"github.com/jeremyhahn/go-xkms/pkg/dao"
)

// Factory implements the storage.Factory interface over an injected go-qrdb
// DAO factory: every ACME DAO is a go-qrdb GenericDAO that pkg/dao builds from
// the factory's default database, so ACME never holds a KVStore of its own.
type Factory struct {
	daos *qrdbsdk.DAOFactory
}

// NewFactory creates a Factory over daos, typically the server datastore's
// DAOFactory (pkg/datastore), so ACME state persists in the one configured
// datastore.
func NewFactory(daos *qrdbsdk.DAOFactory) (storage.Factory, error) {
	if daos == nil {
		return nil, errNilDAOFactory()
	}
	return &Factory{daos: daos}, nil
}

// NewFactoryFromKVStore creates a Factory over a DAO factory serving kv as
// its default database, for a caller that holds a bare go-qrdb KVStore (the
// ACME client's local state, a kvadapter-wrapped storage.Backend) rather than
// a datastore.
func NewFactoryFromKVStore(kv qrdbsdk.KVStore) (storage.Factory, error) {
	if kv == nil {
		return nil, errNilKVStore()
	}
	return NewFactory(daoFactoryOver(kv))
}

// daoFactoryOver returns a DAO factory whose default database is kv.
func daoFactoryOver(kv qrdbsdk.KVStore) *qrdbsdk.DAOFactory {
	return qrdbsdk.NewDAOFactoryWithConfig(&qrdbsdk.DAOFactoryConfig{
		KVStoreProvider: func(uint64) qrdbsdk.KVStore { return kv },
	})
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
	return dao.New(f.daos, "", acmeAccountNamespace,
		func() *entities.ACMEAccount { return &entities.ACMEAccount{} })
}

// OrderDAO returns a GenericDAO for ACME orders scoped to a specific account.
func (f *Factory) OrderDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEOrder], error) {
	if accountID == 0 {
		return nil, qrdbsdk.DAOInvalidEntityIDError{
			EntityType: "order",
			Reason:     "account ID must be non-zero",
		}
	}
	return dao.New(f.daos, "", fmt.Sprintf("%s-%d", acmeOrderNamespace, accountID),
		func() *entities.ACMEOrder { return &entities.ACMEOrder{} })
}

// AuthorizationDAO returns a GenericDAO for ACME authorizations scoped to a specific account.
func (f *Factory) AuthorizationDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEAuthorization], error) {
	if accountID == 0 {
		return nil, qrdbsdk.DAOInvalidEntityIDError{
			EntityType: "authorization",
			Reason:     "account ID must be non-zero",
		}
	}
	return dao.New(f.daos, "", fmt.Sprintf("%s-%d", acmeAuthzNamespace, accountID),
		func() *entities.ACMEAuthorization { return &entities.ACMEAuthorization{} })
}

// ChallengeDAO returns a GenericDAO for ACME challenges scoped to a specific account.
func (f *Factory) ChallengeDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEChallenge], error) {
	if accountID == 0 {
		return nil, qrdbsdk.DAOInvalidEntityIDError{
			EntityType: "challenge",
			Reason:     "account ID must be non-zero",
		}
	}
	return dao.New(f.daos, "", fmt.Sprintf("%s-%d", acmeChallengeNamespace, accountID),
		func() *entities.ACMEChallenge { return &entities.ACMEChallenge{} })
}

// CertificateDAO returns a GenericDAO for ACME certificates.
func (f *Factory) CertificateDAO() (qrdbsdk.GenericDAO[*entities.ACMECertificate], error) {
	return dao.New(f.daos, "", acmeCertificateNamespace,
		func() *entities.ACMECertificate { return &entities.ACMECertificate{} })
}

// NonceDAO returns a GenericDAO for ACME nonces.
func (f *Factory) NonceDAO() (qrdbsdk.GenericDAO[*entities.ACMENonce], error) {
	return dao.New(f.daos, "", acmeNonceNamespace,
		func() *entities.ACMENonce { return &entities.ACMENonce{} })
}

// ExternalAccountBindingDAO returns a GenericDAO for external account bindings.
func (f *Factory) ExternalAccountBindingDAO() (qrdbsdk.GenericDAO[*entities.ExternalAccountBinding], error) {
	return dao.New(f.daos, "", acmeEABNamespace,
		func() *entities.ExternalAccountBinding { return &entities.ExternalAccountBinding{} })
}
