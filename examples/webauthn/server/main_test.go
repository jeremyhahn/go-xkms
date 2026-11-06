package main

import (
	"context"
	"os"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/datastore"
)

// TestNewStores builds the example's WebAuthn stores on the same in-memory
// qrdb node main starts, so a store option the adapter requires and the
// example omits fails here rather than at the example's startup.
func TestNewStores(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	node, dataDir, err := startQRDBNode(ctx)
	if err != nil {
		t.Fatalf("startQRDBNode: %v", err)
	}
	t.Cleanup(func() {
		if err := node.Close(); err != nil {
			t.Errorf("close node: %v", err)
		}
		if err := os.RemoveAll(dataDir); err != nil {
			t.Errorf("remove data dir: %v", err)
		}
	})
	ds, err := datastore.New(node.Client(), config.DatastoreConfig{})
	if err != nil {
		t.Fatalf("datastore.New: %v", err)
	}

	users, credentials, err := newStores(node, ds)
	if err != nil {
		t.Fatalf("newStores: %v", err)
	}
	if users == nil || credentials == nil {
		t.Fatalf("newStores returned users=%v credentials=%v", users, credentials)
	}
}
