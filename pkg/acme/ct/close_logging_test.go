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

package ct

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// failingCloseBody wraps a real response body so the underlying connection
// is still released, but Close always reports a synthetic error.
type failingCloseBody struct {
	io.ReadCloser
}

func (b failingCloseBody) Close() error {
	_ = b.ReadCloser.Close()
	return errors.New("simulated close failure")
}

// failingCloseTransport decorates every response's body with
// failingCloseBody so response-body closes fail without touching what the
// server actually sends.
type failingCloseTransport struct {
	inner http.RoundTripper
}

func (t failingCloseTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.inner.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	resp.Body = failingCloseBody{ReadCloser: resp.Body}
	return resp, nil
}

// TestSubmitPrecert_ClosingResponseBodyFails confirms a resp.Body close
// failure is logged rather than propagated: SubmitPrecert must still return
// the SCT the log server issued, unchanged, exactly like it does when Close
// succeeds (go-xkms#866).
func TestSubmitPrecert_ClosingResponseBodyFails(t *testing.T) {
	ca, caKey := newTestCA(t, "Test CA")
	entry := newTestPrecert(t, ca, caKey, nil, nil)
	ctLog := newTestCTLog(t, newP256Key(t), entry)
	server := ctLog.server

	var logBuf bytes.Buffer
	restore := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(restore)

	httpClient := server.Client()
	httpClient.Transport = failingCloseTransport{inner: httpClient.Transport}

	submitter := NewHTTPLogSubmitter(httpClient)
	sct, err := submitter.SubmitPrecert(context.Background(), entry.der, entry.chain, ctLog.group())
	require.NoError(t, err)
	require.NotNil(t, sct)

	if !bytes.Contains(logBuf.Bytes(), []byte("ct: failed to close response body")) {
		t.Fatalf("expected the close failure to be logged, got: %q", logBuf.String())
	}
	if !bytes.Contains(logBuf.Bytes(), []byte("simulated close failure")) {
		t.Fatalf("expected the close error to be included in the log, got: %q", logBuf.String())
	}
}
