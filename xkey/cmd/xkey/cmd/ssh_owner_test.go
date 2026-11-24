package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/serverid/serveridtest"
)

// ownerRecorder is an xkmsd stand-in that records the path and the decoded
// body owner of every SSH request it answers.
type ownerRecorder struct {
	mu     sync.Mutex
	paths  []string
	owners []string
}

func newOwnerRecorder(t *testing.T) *ownerRecorder {
	t.Helper()
	rec, url := serveOwnerRecorder(t)
	xkmsdURL = url
	return rec
}

// serveOwnerRecorder starts the recording server and trusts its CA, but
// leaves the global xkmsd URL alone, so a test can name the server with
// the ssh --server flag only.
func serveOwnerRecorder(t *testing.T) (*ownerRecorder, string) {
	t.Helper()
	rec := &ownerRecorder{}
	srv, caFile := serveridtest.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		var body struct {
			Owner *string `json:"owner"`
		}
		_ = json.Unmarshal(data, &body)
		rec.mu.Lock()
		rec.paths = append(rec.paths, r.URL.EscapedPath())
		if body.Owner != nil {
			rec.owners = append(rec.owners, *body.Owner)
		}
		rec.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
		}
		_, _ = w.Write([]byte(`{"scope":"user","owner":"116704235864723456","name":"laptop","algorithm":"ed25519"}`))
	}))
	t.Setenv(envXKMSdTLSCA, caFile)
	return rec, srv.URL
}

// Against a server an unset --owner sends no owner: the server serves the
// caller itself (ruling 937), whose account id no client can know.
func TestSSHOwner_UnsetSendsNoneToServer(t *testing.T) {
	withEmbeddedSSHStore(t)
	t.Setenv("USER", "alice")
	rec := newOwnerRecorder(t)

	gen, _ := sshTestCmd(t)
	setSSHFlags(t, gen, map[string]string{"scope": "user", "name": "laptop"})
	require.NoError(t, runSSHKeysGenerate(gen, nil))
	get, _ := sshTestCmd(t)
	setSSHFlags(t, get, map[string]string{"scope": "user", "name": "laptop"})
	require.NoError(t, runSSHKeysGet(get, nil))

	rec.mu.Lock()
	defer rec.mu.Unlock()
	assert.Equal(t, []string{""}, rec.owners, "generate sends an empty owner, not $USER")
	require.Len(t, rec.paths, 2)
	assert.Equal(t, "/xkms/v1/ssh/keys/user//laptop", rec.paths[1], "get addresses the caller's own key")
}

// An explicit --owner is sent as given.
func TestSSHOwner_ExplicitSentToServer(t *testing.T) {
	withEmbeddedSSHStore(t)
	rec := newOwnerRecorder(t)

	gen, _ := sshTestCmd(t)
	setSSHFlags(t, gen, map[string]string{"scope": "user", "owner": "someone-else", "name": "laptop"})
	require.NoError(t, runSSHKeysGenerate(gen, nil))

	rec.mu.Lock()
	defer rec.mu.Unlock()
	assert.Equal(t, []string{"someone-else"}, rec.owners)
}

// The embedded store has no authenticated caller, so it keeps the local
// login as the owner; --local against a configured server does too.
func TestSSHOwner_EmbeddedKeepsLocalDefault(t *testing.T) {
	withEmbeddedSSHStore(t)
	t.Setenv("USER", "alice")
	cmd, _ := sshTestCmd(t)
	assert.Equal(t, "alice", sshDefaultOwner(cmd))

	newOwnerRecorder(t)
	assert.Equal(t, "", sshDefaultOwner(cmd))
	setSSHFlags(t, cmd, map[string]string{"local": "true"})
	assert.Equal(t, "alice", sshDefaultOwner(cmd))
}

// TestSSHOwner_ServerFlagSendsNone checks that naming the server with the
// ssh --server flag alone (no global xkmsd URL, env or config) is the same
// remote decision for the owner default as for the client: an unset
// --owner sends no owner (ruling 937).
func TestSSHOwner_ServerFlagSendsNone(t *testing.T) {
	withEmbeddedSSHStore(t)
	t.Setenv("USER", "alice")
	rec, url := serveOwnerRecorder(t)
	require.Empty(t, resolveXKMSdURL(), "the server is named by --server only")

	gen, _ := sshTestCmd(t)
	setSSHFlags(t, gen, map[string]string{"scope": "user", "name": "laptop", "server": url})
	assert.Equal(t, "", sshDefaultOwner(gen))
	require.NoError(t, runSSHKeysGenerate(gen, nil))

	rec.mu.Lock()
	defer rec.mu.Unlock()
	assert.Equal(t, []string{""}, rec.owners, "generate sends an empty owner, not $USER")
}

// TestSSHOwner_ServerFlagWithLocalKeepsDefault checks that --local wins over
// --server for both decisions: the command runs on the local store and the
// owner defaults to $USER; nothing reaches the server.
func TestSSHOwner_ServerFlagWithLocalKeepsDefault(t *testing.T) {
	withEmbeddedSSHStore(t)
	t.Setenv("USER", "alice")
	rec, url := serveOwnerRecorder(t)

	gen, _ := sshTestCmd(t)
	setSSHFlags(t, gen, map[string]string{"scope": "user", "name": "laptop", "server": url, "local": "true"})
	assert.Equal(t, "alice", sshDefaultOwner(gen))
	require.NoError(t, runSSHKeysGenerate(gen, nil))

	rec.mu.Lock()
	defer rec.mu.Unlock()
	assert.Empty(t, rec.paths, "--local keeps the command off the server")
}
