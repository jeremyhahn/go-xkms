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

package serveridtest

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/serverid"
)

func TestNewTLSServer_EachServerIsItsOwnIdentity(t *testing.T) {
	a, caA := NewTLSServer(t, http.NotFoundHandler())
	b, _ := NewTLSServer(t, http.NotFoundHandler())
	assert.NotEqual(t, serverid.Of(a.Certificate()), serverid.Of(b.Certificate()))

	pem, err := os.ReadFile(caA)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(pem))
	id, err := serverid.Probe(context.Background(), a.URL, &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13})
	require.NoError(t, err, "the CA file trusts the server")
	assert.Equal(t, serverid.Of(a.Certificate()), id)
}

var errNoEntropy = errors.New("no entropy")

// fatalRecorder is a testing.TB whose Fatalf records the message and ends
// the calling goroutine, as testing.T does, without failing the real test.
type fatalRecorder struct {
	testing.TB
	tempDir string
	msg     string
}

func (r *fatalRecorder) Fatalf(format string, args ...any) {
	r.msg = fmt.Sprintf(format, args...)
	runtime.Goexit()
}

func (r *fatalRecorder) TempDir() string {
	if r.tempDir != "" {
		return r.tempDir
	}
	return r.TB.TempDir()
}

// fatalOf runs NewTLSServer against r and returns the message it failed
// with, or "" when it returned a server.
func fatalOf(r *fatalRecorder) string {
	done := make(chan struct{})
	go func() {
		defer close(done)
		NewTLSServer(r, http.NotFoundHandler())
	}()
	<-done
	return r.msg
}

func TestNewTLSServer_FailsTheTestWithoutAKey(t *testing.T) {
	saved := generateKey
	t.Cleanup(func() { generateKey = saved })
	generateKey = func() (*ecdsa.PrivateKey, error) { return nil, errNoEntropy }

	msg := fatalOf(&fatalRecorder{TB: t})
	assert.Equal(t, "serveridtest: key: no entropy", msg)
}

func TestNewTLSServer_FailsTheTestWithoutASerial(t *testing.T) {
	saved := serialRandom
	t.Cleanup(func() { serialRandom = saved })
	serialRandom = iotest.ErrReader(errNoEntropy)

	msg := fatalOf(&fatalRecorder{TB: t})
	assert.Equal(t, "serveridtest: serial: no entropy", msg)
}

func TestNewTLSServer_FailsTheTestWhenTheCAFileCannotBeWritten(t *testing.T) {
	notADir := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(notADir, nil, 0o600))

	msg := fatalOf(&fatalRecorder{TB: t, tempDir: notADir})
	assert.True(t, strings.HasPrefix(msg, "serveridtest: ca file: "), "got %q", msg)
}

func TestNewTLSServer_ReturnsWithoutFailingTheTest(t *testing.T) {
	r := &fatalRecorder{TB: t}
	assert.Empty(t, fatalOf(r), "a working host gives a server, not a failure")
}
