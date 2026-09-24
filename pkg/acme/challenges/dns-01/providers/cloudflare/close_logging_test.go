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

package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// failingCloseBody wraps a real response body so the underlying data is
// still readable and the real Close is still attempted, but Close always
// reports a synthetic error.
type failingCloseBody struct {
	io.ReadCloser
}

func (b failingCloseBody) Close() error {
	_ = b.ReadCloser.Close()
	return errors.New("simulated close failure")
}

// TestMakeRequest_ClosingResponseBodyFails confirms a resp.Body close
// failure is logged rather than propagated: makeRequest must still return
// the decoded API response, unchanged, exactly like it does when Close
// succeeds (go-xkms#866).
func TestMakeRequest_ClosingResponseBodyFails(t *testing.T) {
	var logBuf bytes.Buffer
	restore := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(restore)

	mockClient := &mockHTTPClient{
		doFunc: func(req *http.Request) (*http.Response, error) {
			resp := mockResponse(200, apiResponse{
				Success: true,
				Result:  json.RawMessage(`[]`),
			})
			resp.Body = failingCloseBody{ReadCloser: resp.Body}
			return resp, nil
		},
	}

	provider, err := New(context.Background(), Config{
		APIToken:   "my-token",
		HTTPClient: mockClient,
	})
	require.NoError(t, err)

	result, err := provider.makeRequest(context.Background(), "GET", "/test", nil, false)
	require.NoError(t, err)
	require.Equal(t, json.RawMessage(`[]`), result)

	if !bytes.Contains(logBuf.Bytes(), []byte("cloudflare: failed to close response body")) {
		t.Fatalf("expected the close failure to be logged, got: %q", logBuf.String())
	}
	if !bytes.Contains(logBuf.Bytes(), []byte("simulated close failure")) {
		t.Fatalf("expected the close error to be included in the log, got: %q", logBuf.String())
	}
}
