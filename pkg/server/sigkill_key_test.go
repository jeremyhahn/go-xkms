//go:build linux

package server

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/keyversion"
)

// sigkillChildDirEnv names the datastore directory of the child xkmsd
// process TestServerSIGKILLKeepsCreatedKey re-executes.
const sigkillChildDirEnv = "XKMS_SIGKILL_KEY_DIR"

// sigkillKeyBackend is the backend the test key and its version record
// belong to.
const sigkillKeyBackend = "software"

// sigkillKeyRecord is the key record the child stores through the shared
// storage backend software key records take.
type sigkillKeyRecord struct {
	PKCS8  []byte `json:"pkcs8"`
	Public []byte `json:"public"`
}

// newSIGKILLTestServer opens the standalone xkmsd storage on dir with the
// pebble engine, as Server.New does on the run path.
func newSIGKILLTestServer(t *testing.T, dir string) *Server {
	t.Helper()
	s := &Server{
		ctx: context.Background(),
		config: &config.Config{
			Datastore: config.DatastoreConfig{Path: dir, Engine: "pebble"},
		},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	require.NoError(t, s.initializeQRDBStorage())
	require.NotNil(t, s.sharedStorage())
	return s
}

func sigkillKeyRecordKey(keyID string) string {
	return "keys/" + keyID
}

// TestServerSIGKILLKeepsCreatedKey is issue #2252's acceptance on the xkmsd
// run path: a key xkmsd acknowledges as created, and its version record,
// read back after the process is SIGKILLed and restarted on the same
// datastore.
func TestServerSIGKILLKeepsCreatedKey(t *testing.T) {
	if dir := os.Getenv(sigkillChildDirEnv); dir != "" {
		runSIGKILLKeyChild(t, dir)
		return
	}

	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$")
	cmd.Env = append(os.Environ(), sigkillChildDirEnv+"="+dir)
	cmd.Stderr = io.Discard
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())

	acked := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			if line := sc.Text(); strings.HasPrefix(line, "acked ") {
				acked <- line
				break
			}
		}
		_, _ = io.Copy(io.Discard, stdout)
	}()

	var line string
	select {
	case line = <-acked:
	case <-time.After(60 * time.Second):
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal("child xkmsd did not acknowledge the key within 60 s")
	}
	require.NoError(t, cmd.Process.Signal(syscall.SIGKILL))
	_ = cmd.Wait()

	fields := strings.Fields(line)
	require.Len(t, fields, 3, "acked line %q", line)
	keyID := fields[1]
	wantPub, err := hex.DecodeString(fields[2])
	require.NoError(t, err)

	s := newSIGKILLTestServer(t, dir)
	t.Cleanup(func() { _ = s.closeQRDBStorage() })
	ctx := context.Background()

	raw, err := s.sharedStorage().Get(ctx, sigkillKeyRecordKey(keyID))
	require.NoError(t, err, "the acknowledged key record must survive SIGKILL")
	var rec sigkillKeyRecord
	require.NoError(t, json.Unmarshal(raw, &rec))
	require.Equal(t, wantPub, rec.Public)

	parsed, err := x509.ParsePKCS8PrivateKey(rec.PKCS8)
	require.NoError(t, err)
	priv, ok := parsed.(ed25519.PrivateKey)
	require.True(t, ok, "private key type %T", parsed)
	msg := []byte("issue 2252: signed after restart")
	require.True(t, ed25519.Verify(ed25519.PublicKey(wantPub), msg, ed25519.Sign(priv, msg)))

	daos, err := s.daoFactory(keyversion.DatabaseName)
	require.NoError(t, err)
	versions, err := keyversion.NewStore(daos)
	require.NoError(t, err)
	got, found, err := versions.Load(ctx, "", sigkillKeyBackend, keyID)
	require.NoError(t, err)
	require.True(t, found, "the acknowledged key version record must survive SIGKILL")
	require.Equal(t, keyID, got.KeyID)
}

// runSIGKILLKeyChild is the xkmsd side: it creates a key, records its
// version, acknowledges both on stdout and blocks until it is killed.
func runSIGKILLKeyChild(t *testing.T, dir string) {
	s := newSIGKILLTestServer(t, dir)
	ctx := context.Background()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	keyID := "sigkill-" + hex.EncodeToString(pub[:8])

	raw, err := json.Marshal(sigkillKeyRecord{PKCS8: pkcs8, Public: pub})
	require.NoError(t, err)
	require.NoError(t, s.sharedStorage().Put(ctx, sigkillKeyRecordKey(keyID), raw))

	daos, err := s.daoFactory(keyversion.DatabaseName)
	require.NoError(t, err)
	versions, err := keyversion.NewStore(daos)
	require.NoError(t, err)
	require.NoError(t, versions.Put(ctx, "", keyversion.Implicit(keyID, sigkillKeyBackend)))

	fmt.Fprintf(os.Stdout, "acked %s %s\n", keyID, hex.EncodeToString(pub))
	select {}
}
