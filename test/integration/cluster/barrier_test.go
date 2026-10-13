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

//go:build integration

package cluster

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jeremyhahn/go-xkms/test/integration/xkmsdtest"
)

// barrierPassphrase is the passphrase the harness unseals every node's
// barrier with. The standalone fixture's XKMS_SO_PIN in docker-compose.yml,
// which `xkmsd init` makes its barrier passphrase, must equal it.
const barrierPassphrase = "xkms-cluster-harness-barrier-passphrase"

// barrierTimeout bounds bringing one node past its sealed window.
const barrierTimeout = 90 * time.Second

// nodeDataDirs maps each node URL variable to the mount of that node's data
// volume in the test container (docker-compose.yml).
var nodeDataDirs = map[string]string{
	envNode1URL:              "/node1-data",
	envNode2URL:              "/node2-data",
	envNode3URL:              "/node3-data",
	"CLUSTER_STANDALONE_URL": "/standalone-data",
}

// openBarriers brings every configured node past its sealed window. A node
// with a passphrase barrier boots sealed, so nothing answers on its REST
// listener -- not /health, not the CA bootstrap -- until it is opened.
func openBarriers() error {
	for env, dir := range nodeDataDirs {
		url := os.Getenv(env)
		if url == "" {
			continue
		}
		if err := openBarrier(url, dir); err != nil {
			return fmt.Errorf("%s: %w", url, err)
		}
	}
	return nil
}

// datastore returns the node datastore directory inside a node data volume
// mounted at volume: XKMS_STORAGE_PATH=/data puts the datastore, and with it
// the sealed-window certificate and the first-boot admin credential, under
// storage/.
func datastore(volume string) string {
	return volume + "/storage"
}

// openBarrier unseals the barrier of the node at url through its sealed
// window, trusting the certificate the node persisted in its data volume. The
// window refuses initialization, so a node whose barrier `xkmsd init` never
// initialized fails with xkmsdtest.ErrBarrierUninitialized.
func openBarrier(url, volume string) error {
	ctx, cancel := context.WithTimeout(context.Background(), barrierTimeout)
	defer cancel()
	client, err := xkmsdtest.SealedWindowClient(ctx, datastore(volume)+"/unified-tls/cert.pem")
	if err != nil {
		return err
	}
	return xkmsdtest.OpenBarrier(ctx, client, url, []byte(barrierPassphrase))
}
