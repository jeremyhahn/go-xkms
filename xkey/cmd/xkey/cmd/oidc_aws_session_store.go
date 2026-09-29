// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package cmd

// The AWS DPoP session store (go-xkms#1325): the refresh token and DPoP
// signing private key "xkey oidc aws" persists between invocations so its
// auto-refresh loop and background worker can obtain fresh AWS credentials
// without a fresh interactive login. It was, until this change, always an
// unencrypted 0600 file at --session-store -- the one xkey secret store that
// never moved behind the barrier-first decision every other one already
// makes (openOATHStore/oath.go, openOIDCTokenStore/oidc_token_store.go,
// resolveSecretStoreBackend/barrier_store.go). This file closes that gap: an
// initialized barrier encrypts the session; without one, the CLI falls back
// to the historical plain file with the one standard "unencrypted at rest"
// warning, exactly like every other store resolveSecretStoreBackend backs.
//
// There is no migration from the pre-#1325 ~/.xkey/aws-session.json format:
// this is pre-release alpha, so a file in that shape is simply not read by
// this store, and the operator runs `xkey oidc aws` again.

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"path/filepath"

	"github.com/spf13/cobra"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// ErrAWSSessionStoreFailed indicates the AWS session store could not be
// opened or accessed: a barrier that is initialized but could not be
// unsealed, or a plain-file backend that could not be created.
var ErrAWSSessionStoreFailed = errors.New("aws: failed to access session store")

// awsSessionStoreKey is the storage key holding the CLI's single active AWS
// DPoP session, prefixed distinctly from every other store sharing the same
// barrier-backed namespace (xkey oath uses "oath/"; the OIDC RP token store
// uses "oidc/tokens.json"; see barrier_store.go and oidc_token_store.go).
const awsSessionStoreKey = "oidc/aws-session.json"

// awsCLISessionStore persists the CLI's single active AWS DPoP session
// through a xkms.StorageBackend: barrier-encrypted when a barrier is
// initialized (openAWSSessionStore), or the historical unencrypted file
// otherwise. It reduces to Put/Get on a xkms.StorageBackend, exactly like
// xkey/pkg/oath's BackendStore/FileStore and this CLI's own
// oidcCLITokenStore -- there is one storage primitive in this CLI, not a
// second one invented for the AWS session.
type awsCLISessionStore struct {
	backend xkms.StorageBackend
	key     string
}

// Save persists session, overwriting whatever was stored before.
func (s *awsCLISessionStore) Save(session AWSStoredSession) error {
	data, err := json.Marshal(session)
	if err != nil {
		return err
	}
	return s.backend.Put(context.Background(), s.key, data)
}

// Load retrieves the stored session. Returns xkms.ErrStorageNotFound when
// nothing is stored; the caller decides how to report that (a fresh login
// versus a background worker that expected an existing session).
func (s *awsCLISessionStore) Load() (*AWSStoredSession, error) {
	data, err := s.backend.Get(context.Background(), s.key)
	if err != nil {
		return nil, err
	}

	var session AWSStoredSession
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, err
	}
	return &session, nil
}

// openAWSSessionStore opens the CLI's AWS DPoP session store: barrier-backed
// when a barrier is initialized in the xkey data directory
// (resolveSecretStoreBackend, barrier_store.go -- the same decision `xkey
// oath` and `xkey oidc` make), or a plain xkms.StorageBackend file
// otherwise, with the one standard "unencrypted at rest" warning
// resolveSecretStoreBackend already logs.
//
// explicitPath, when non-empty, is a plain file path the caller has already
// determined the operator explicitly asked for (an --session-store flag
// actually set on the command, or a provider's saved AWSSessionStore
// configuration) -- resolved to exactly that file, matching how `xkey
// oath`'s --store override and `xkey oidc`'s --token-store override bypass
// barrier auto-detection entirely: the operator asked for a specific file,
// so the barrier decision does not apply. An empty explicitPath uses the
// barrier-or-fallback decision above, rooted at the shared xkey data
// directory rather than the historical fixed ~/.xkey/aws-session.json path.
func openAWSSessionStore(cmd *cobra.Command, explicitPath string) (*awsCLISessionStore, error) {
	if explicitPath != "" {
		path := expandPath(explicitPath)
		backend, err := xkms.NewFileStorageBackend(filepath.Dir(path))
		if err != nil {
			return nil, &SentinelCauseError{Sentinel: ErrAWSSessionStoreFailed, Cause: err}
		}
		return &awsCLISessionStore{backend: backend, key: filepath.Base(path)}, nil
	}

	dataDir, err := resolveDataDir("")
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrAWSSessionStoreFailed, Cause: err}
	}

	backend, opened, err := resolveSecretStoreBackend(cmd, dataDir, "AWS session", slog.Default())
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrAWSSessionStoreFailed, Cause: err}
	}
	if !opened {
		backend, err = xkms.NewFileStorageBackend(dataDir)
		if err != nil {
			return nil, &SentinelCauseError{Sentinel: ErrAWSSessionStoreFailed, Cause: err}
		}
	}

	return &awsCLISessionStore{backend: backend, key: awsSessionStoreKey}, nil
}

// storeAWSSession is a convenience wrapper around openAWSSessionStore + Save.
func storeAWSSession(cmd *cobra.Command, explicitPath string, session AWSStoredSession) error {
	store, err := openAWSSessionStore(cmd, explicitPath)
	if err != nil {
		return err
	}
	return store.Save(session)
}

// loadAWSSession is a convenience wrapper around openAWSSessionStore + Load.
func loadAWSSession(cmd *cobra.Command, explicitPath string) (*AWSStoredSession, error) {
	store, err := openAWSSessionStore(cmd, explicitPath)
	if err != nil {
		return nil, err
	}
	return store.Load()
}
