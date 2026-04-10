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

package unix

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGRPCServer_Start_MkdirAllError tests the error path when the socket
// directory cannot be created (e.g., parent is a file, not a directory).
func TestGRPCServer_Start_MkdirAllError(t *testing.T) {
	// Create a temp file that prevents MkdirAll from creating a subdirectory
	tmpFile, err := os.CreateTemp("", "xkms-block-*")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	// Try to create a socket under a file path (impossible)
	socketPath := filepath.Join(tmpFile.Name(), "subdir", "test.sock")

	cfg := &GRPCConfig{
		SocketPath: socketPath,
	}

	server, err := NewGRPCServer(cfg)
	require.NoError(t, err)

	err = server.Start()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create socket directory")
}

// TestGRPCServer_Start_RemoveExistingSocketError tests the error path when an
// existing socket file cannot be removed (e.g., it is a directory).
func TestGRPCServer_Start_RemoveExistingSocketError(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "xkms-grpc-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	socketPath := filepath.Join(tmpDir, "test-grpc.sock")

	// Create a directory at the socket path that contains files,
	// so os.Remove will fail with "directory not empty"
	err = os.Mkdir(socketPath, 0750)
	require.NoError(t, err)

	// Put a file in the directory so it can't be removed with os.Remove
	f, err := os.Create(filepath.Join(socketPath, "blocker"))
	require.NoError(t, err)
	f.Close()

	cfg := &GRPCConfig{
		SocketPath: socketPath,
	}

	server, err := NewGRPCServer(cfg)
	require.NoError(t, err)

	err = server.Start()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to remove existing socket")
}

// TestGRPCServer_Stop_ContextAlreadyCancelled tests the Stop timeout path
// where the context is already cancelled before GracefulStop completes.
func TestGRPCServer_Stop_ContextAlreadyCancelled(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "xkms-grpc-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	socketPath := filepath.Join(tmpDir, "test-grpc.sock")

	cfg := &GRPCConfig{
		SocketPath: socketPath,
	}

	server, err := NewGRPCServer(cfg)
	require.NoError(t, err)

	// Start the server
	go func() {
		_ = server.Start()
	}()

	// Wait for socket to appear
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)

	// Use an already-cancelled context to force the timeout path
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	err = server.Stop(ctx)
	assert.NoError(t, err) // Stop should still succeed
}
