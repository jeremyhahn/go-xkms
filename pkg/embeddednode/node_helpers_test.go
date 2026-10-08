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

package embeddednode

import (
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// newTestQRDBConfig returns a defaulted go-qrdb daemon config. It touches no
// disk and starts nothing; it exists so option-validation tests can supply a
// structurally valid QRDB field without standing up an engine.
func newTestQRDBConfig() *qrdbsdk.DaemonConfig {
	return qrdbsdk.DefaultDaemonConfig()
}

// newLocalQRDBConfig returns a go-qrdb daemon config that really starts: a
// pebble engine in a test temp dir, with authentication, the seal and every
// network protocol off, so the only socket a clustered node binds is its Raft
// transport. It mirrors the shape EmbeddedNodeStorageConfig derives for an
// unsealed deployment.
func newLocalQRDBConfig(t *testing.T) *qrdbsdk.DaemonConfig {
	t.Helper()
	cfg := &qrdbsdk.DaemonConfig{}
	cfg.Auth.Enabled = qrdbsdk.BoolPtr(false)
	cfg.Raft.DataDir = t.TempDir()
	cfg.Databases = []qrdbsdk.DaemonDatabaseConfig{{Name: "default", Backend: "pebble"}}
	cfg.Seal.Enabled = false
	return cfg
}
