// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package ssh

import (
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	pkgauthorized "github.com/jeremyhahn/go-xkms/pkg/ssh/authorized"
	pkgkeys "github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	pkgknownhosts "github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
)

// Stores holds the persistent stores an embedded Client works over: SSH
// keys, host-key pins and authorized_keys entries, each kept as go-qrdb
// DAO entities.
type Stores struct {
	Keys       *pkgkeys.DAOStore
	KnownHosts *pkgknownhosts.DAOStore
	Authorized *pkgauthorized.DAOStore
}

// NewStores builds the platform-partition Stores over the DAOs daos builds.
func NewStores(daos *qrdbsdk.DAOFactory) (*Stores, error) {
	if daos == nil {
		return nil, &NilInputError{Field: "daos"}
	}
	keys, err := pkgkeys.NewDAOStore(daos)
	if err != nil {
		return nil, err
	}
	hosts, err := pkgknownhosts.NewDAOStore(daos)
	if err != nil {
		return nil, err
	}
	authorized, err := pkgauthorized.NewDAOStore(daos)
	if err != nil {
		return nil, err
	}
	return &Stores{Keys: keys, KnownHosts: hosts, Authorized: authorized}, nil
}

// Partition returns the view of s through tenantID's partition ("" is the
// platform partition). The views share s's DAOs.
func (s *Stores) Partition(tenantID string) (*Stores, error) {
	keys, err := s.Keys.Partition(tenantID)
	if err != nil {
		return nil, err
	}
	hosts, err := s.KnownHosts.Partition(tenantID)
	if err != nil {
		return nil, err
	}
	authorized, err := s.Authorized.Partition(tenantID)
	if err != nil {
		return nil, err
	}
	return &Stores{Keys: keys, KnownHosts: hosts, Authorized: authorized}, nil
}
