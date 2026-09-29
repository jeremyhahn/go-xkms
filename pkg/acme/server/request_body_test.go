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

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingReader counts how many Read calls reach the underlying body, so a
// test can prove the connection is read once however many consumers ask.
type countingReader struct {
	r     io.Reader
	reads int
}

func (c *countingReader) Read(p []byte) (int, error) {
	c.reads++
	return c.r.Read(p)
}

// errReader fails every read, standing in for a connection that drops
// mid-body.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

// TestRequestBodyMiddleware_OversizedBodyIs413Problem proves a body one byte
// over MaxRequestBodySize is refused with 413 and an RFC 7807 "malformed"
// problem, and never reaches the next handler.
func TestRequestBodyMiddleware_OversizedBodyIs413Problem(t *testing.T) {
	reached := false
	handler := RequestBodyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))

	body := bytes.Repeat([]byte("a"), int(MaxRequestBodySize)+1)
	req := httptest.NewRequest(http.MethodPost, "/acme/new-order", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.False(t, reached, "an oversized request must not reach the handler")
	require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	require.Equal(t, "application/problem+json", rec.Header().Get("Content-Type"))

	var problem entities.Error
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&problem))
	assert.Equal(t, "urn:ietf:params:acme:error:"+common.ErrTypeMalformedError, problem.Type)
	assert.Contains(t, problem.Detail, "262144 byte limit")
}

// TestRequestBodyMiddleware_BodyAtLimitIsAccepted proves the cap is
// inclusive: a body of exactly MaxRequestBodySize bytes is served.
func TestRequestBodyMiddleware_BodyAtLimitIsAccepted(t *testing.T) {
	var got []byte
	handler := RequestBodyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		got, err = RequestBody(r)
		require.NoError(t, err)
	}))

	body := bytes.Repeat([]byte("a"), int(MaxRequestBodySize))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))

	require.Equal(t, http.StatusOK, rec.Code)
	require.Len(t, got, int(MaxRequestBodySize))
}

// TestRequestBodyMiddleware_ReadErrorIs400Problem proves a transport failure
// mid-body is a 400 "malformed" problem, not a 413.
func TestRequestBodyMiddleware_ReadErrorIs400Problem(t *testing.T) {
	handler := RequestBodyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("a failed read must not reach the handler")
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", errReader{}))

	require.Equal(t, http.StatusBadRequest, rec.Code)
	var problem entities.Error
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&problem))
	assert.Equal(t, "urn:ietf:params:acme:error:"+common.ErrTypeMalformedError, problem.Type)
}

// derivedKey is the context key the test uses to derive a request.
type derivedKey struct{}

// TestRequestBody_ReadsConnectionOnce proves every consumer after the
// middleware — including one on a request derived with WithContext — gets
// the same bytes without another read of the connection, and that a reader
// consuming r.Body directly still sees the whole body.
func TestRequestBody_ReadsConnectionOnce(t *testing.T) {
	const payload = `{"protected":"x","payload":"y","signature":"z"}`
	conn := &countingReader{r: strings.NewReader(payload)}

	var first, second []byte
	var direct []byte
	handler := RequestBodyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		readsAfterMiddleware := conn.reads
		var err error
		first, err = RequestBody(r)
		require.NoError(t, err)
		derived := r.WithContext(context.WithValue(r.Context(), derivedKey{}, "v"))
		second, err = RequestBody(derived)
		require.NoError(t, err)
		direct, err = io.ReadAll(r.Body)
		require.NoError(t, err)
		require.Equal(t, readsAfterMiddleware, conn.reads, "no consumer may read the connection again")
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", conn))

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, payload, string(first))
	require.Equal(t, payload, string(second))
	require.Equal(t, payload, string(direct))
}

// TestRequestBody_WithoutMiddlewareIsCappedAndSticky proves RequestBody
// enforces the cap on its own when no middleware ran, and that the failure
// is remembered: a second call reports the same error instead of reading
// the rest of the oversized body.
func TestRequestBody_WithoutMiddlewareIsCappedAndSticky(t *testing.T) {
	body := bytes.Repeat([]byte("a"), int(MaxRequestBodySize)+10)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))

	data, err := RequestBody(req)
	require.Nil(t, data)
	var bodyErr *RequestBodyError
	require.ErrorAs(t, err, &bodyErr)
	require.True(t, bodyErr.TooLarge())

	_, again := RequestBody(req)
	require.Same(t, bodyErr, again, "a failed read must be reported identically, never retried")
}

// TestRequestBody_NoBody proves a request without a body yields an empty
// body and no error.
func TestRequestBody_NoBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	data, err := RequestBody(req)
	require.NoError(t, err)
	require.Empty(t, data)
}

// TestRequestBodyError_Problem proves the problem mapping: 413 only for an
// oversized body, 400 for every other failure, both "malformed".
func TestRequestBodyError_Problem(t *testing.T) {
	tooLarge := &RequestBodyError{Err: &http.MaxBytesError{Limit: MaxRequestBodySize}}
	require.True(t, tooLarge.TooLarge())
	require.Equal(t, http.StatusRequestEntityTooLarge, tooLarge.Problem().Status)
	require.Contains(t, tooLarge.Error(), "acme: read request body")

	broken := &RequestBodyError{Err: io.ErrUnexpectedEOF}
	require.False(t, broken.TooLarge())
	require.Equal(t, http.StatusBadRequest, broken.Problem().Status)
	require.ErrorIs(t, broken, io.ErrUnexpectedEOF)
}

// TestSlowBodyDoesNotBlockDirectory is the #1171 regression: a client
// trickling its POST body must not delay any other client's request. It
// drives the production middleware order (RequestBodyMiddleware, then the
// blanket per-client limiter) over a real listener, holds one POST body open
// mid-read, and requires a concurrent GET /directory to complete within a
// deadline. Before the fix the limiter's mutex was held across the body read
// and the handler, so the GET queued behind the slow POST until its body
// arrived.
func TestSlowBodyDoesNotBlockDirectory(t *testing.T) {
	bodyReadStarted := make(chan struct{})
	signalFirstRead := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				r.Body = &firstReadSignal{ReadCloser: r.Body, started: bodyReadStarted}
			}
			next.ServeHTTP(w, r)
		})
	}

	limiter := NewClientRateLimiterMiddleware(100, time.Minute, nil)
	mux := http.NewServeMux()
	mux.HandleFunc("/acme/directory", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/acme/new-order", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	srv := httptest.NewServer(signalFirstRead(RequestBodyMiddleware(limiter(mux))))
	defer srv.Close()

	// The slow client: sends the first byte of its body, then stalls.
	bodyReaderSide, bodyWriter := io.Pipe()
	slowReq, err := http.NewRequest(http.MethodPost, srv.URL+"/acme/new-order", bodyReaderSide)
	require.NoError(t, err)
	slowDone := make(chan error, 1)
	go func() {
		resp, doErr := srv.Client().Do(slowReq)
		if doErr != nil {
			// Expected: the test aborts this body below.
			slowDone <- nil
			return
		}
		slowDone <- resp.Body.Close()
	}()
	firstByteWritten := make(chan error, 1)
	go func() {
		_, writeErr := bodyWriter.Write([]byte("{"))
		firstByteWritten <- writeErr
	}()

	select {
	case <-bodyReadStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("the server never started reading the slow request body")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dirReq, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/acme/directory", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(dirReq)
	require.NoError(t, err, "GET /directory must not wait for another client's slow body")
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Release the slow client so the server can shut down.
	require.NoError(t, <-firstByteWritten)
	require.NoError(t, bodyWriter.CloseWithError(io.ErrUnexpectedEOF))
	require.NoError(t, <-slowDone)
}

// firstReadSignal closes started on the first Read that reaches the
// connection, telling the test the server is now blocked inside the body
// read.
type firstReadSignal struct {
	io.ReadCloser
	started chan struct{}
	once    bool
}

func (f *firstReadSignal) Read(p []byte) (int, error) {
	if !f.once {
		f.once = true
		close(f.started)
	}
	return f.ReadCloser.Read(p)
}
