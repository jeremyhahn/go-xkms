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

package rest

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

const otaBadBoard = "Bad--Board"

// newOTAImageRESTServer answers the OTA image-key routes the way the xkmsd
// REST server does: a malformed board id is a 400, any other board gets a
// response naming its key.
func newOTAImageRESTServer(t *testing.T) *Transport {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeOTAJSON(t, w, http.StatusOK, transport.HealthResponse{Status: "ok"})
	})
	mux.HandleFunc("/api/v1/ota-image-keys/", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		var body struct {
			Backend string `json:"backend"`
			Data    []byte `json:"data"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, "software", body.Backend)

		rest := strings.TrimPrefix(r.URL.Path, "/api/v1/ota-image-keys/")
		board, action, _ := strings.Cut(rest, "/")
		if board == otaBadBoard {
			writeOTAJSON(t, w, http.StatusBadRequest, map[string]string{"error": "invalid board id"})
			return
		}
		switch action {
		case "":
			writeOTAJSON(t, w, http.StatusOK, transport.GenerateKeyResponse{KeyID: "ota-image-" + board})
		case "rotate":
			writeOTAJSON(t, w, http.StatusOK, transport.RotateKeyResponse{KeyID: "ota-image-" + board, KeyVersion: 2})
		case "sign":
			require.Equal(t, []byte("image"), body.Data)
			writeOTAJSON(t, w, http.StatusOK, transport.SignResponse{Signature: []byte("sig"), KeyVersion: 2})
		default:
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return connectFullMock(t, srv)
}

func writeOTAJSON(t *testing.T, w http.ResponseWriter, status int, v interface{}) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	require.NoError(t, json.NewEncoder(w).Encode(v))
}

func TestOTAImageKey_REST(t *testing.T) {
	tr := newOTAImageRESTServer(t)
	ctx := context.Background()

	created, err := tr.CreateOTAImageKey(ctx, &transport.OTAImageKeyRequest{Backend: "software", BoardID: "cm4"})
	require.NoError(t, err)
	assert.Equal(t, "ota-image-cm4", created.KeyID)

	rotated, err := tr.RotateOTAImageKey(ctx, &transport.OTAImageKeyRequest{Backend: "software", BoardID: "cm4"})
	require.NoError(t, err)
	assert.Equal(t, uint32(2), rotated.KeyVersion)

	signed, err := tr.SignOTAImage(ctx, &transport.OTAImageSignRequest{Backend: "software", BoardID: "cm4", Data: []byte("image")})
	require.NoError(t, err)
	assert.Equal(t, []byte("sig"), signed.Signature)
	assert.Equal(t, uint32(2), signed.KeyVersion)
}

func TestOTAImageKey_REST_InvalidBoard(t *testing.T) {
	tr := newOTAImageRESTServer(t)
	ctx := context.Background()

	calls := map[string]func() error{
		"create": func() error {
			_, err := tr.CreateOTAImageKey(ctx, &transport.OTAImageKeyRequest{Backend: "software", BoardID: otaBadBoard})
			return err
		},
		"rotate": func() error {
			_, err := tr.RotateOTAImageKey(ctx, &transport.OTAImageKeyRequest{Backend: "software", BoardID: otaBadBoard})
			return err
		},
		"sign": func() error {
			_, err := tr.SignOTAImage(ctx, &transport.OTAImageSignRequest{Backend: "software", BoardID: otaBadBoard, Data: []byte("image")})
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			err := call()
			var msgErr *errs.Message
			require.True(t, errors.As(err, &msgErr), "error %T is not an errs.Message", err)
			assert.Contains(t, msgErr.Error(), "invalid board id")
		})
	}
}
