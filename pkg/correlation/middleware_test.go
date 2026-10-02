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

package correlation

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func TestMiddleware(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{name: "correlation header", headers: map[string]string{CorrelationIDHeader: "corr-1"}, want: "corr-1"},
		{name: "request header fallback", headers: map[string]string{RequestIDHeader: "req-1"}, want: "req-1"},
		{name: "correlation header wins", headers: map[string]string{CorrelationIDHeader: "corr-2", RequestIDHeader: "req-2"}, want: "corr-2"},
		{name: "generated when absent", headers: nil, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var seen string
			h := Middleware()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				seen = GetCorrelationID(r.Context())
			}))
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if seen == "" {
				t.Fatal("handler saw no correlation ID")
			}
			if tc.want != "" && seen != tc.want {
				t.Fatalf("handler saw %q, want %q", seen, tc.want)
			}
			if got := rec.Header().Get(CorrelationIDHeader); got != seen {
				t.Fatalf("response header %q, want the context's %q", got, seen)
			}
		})
	}
}

// recordingStream is a grpc.ServerStream double that records the header it
// is sent, or fails SetHeader when failHeader is set.
type recordingStream struct {
	grpc.ServerStream
	ctx        context.Context
	header     metadata.MD
	failHeader bool
}

func (s *recordingStream) Context() context.Context { return s.ctx }

func (s *recordingStream) SetHeader(md metadata.MD) error {
	if s.failHeader {
		return errors.New("transport closed")
	}
	s.header = md
	return nil
}

func incoming(pairs ...string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(pairs...))
}

func TestUnaryServerInterceptor(t *testing.T) {
	cases := []struct {
		name string
		ctx  context.Context
		want string
	}{
		{name: "correlation key", ctx: incoming(GRPCCorrelationIDKey, "corr-1"), want: "corr-1"},
		{name: "request key fallback", ctx: incoming(GRPCRequestIDKey, "req-1"), want: "req-1"},
		{name: "correlation key wins", ctx: incoming(GRPCCorrelationIDKey, "corr-2", GRPCRequestIDKey, "req-2"), want: "corr-2"},
		{name: "empty correlation value falls through", ctx: incoming(GRPCCorrelationIDKey, "", GRPCRequestIDKey, "req-3"), want: "req-3"},
		{name: "no metadata generates", ctx: context.Background(), want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			interceptor := UnaryServerInterceptor(slog.New(slog.NewTextHandler(&buf, nil)))
			var seen string
			resp, err := interceptor(tc.ctx, "req", &grpc.UnaryServerInfo{}, func(ctx context.Context, req any) (any, error) {
				seen = GetCorrelationID(ctx)
				return req, nil
			})
			if err != nil || resp != "req" {
				t.Fatalf("interceptor = (%v, %v), want the handler's response", resp, err)
			}
			if seen == "" || (tc.want != "" && seen != tc.want) {
				t.Fatalf("handler saw %q, want %q", seen, tc.want)
			}
			// Outside a real gRPC server grpc.SetHeader fails; the call must
			// still succeed and the failure must be logged.
			if !strings.Contains(buf.String(), "correlation ID response header") {
				t.Fatalf("SetHeader failure was not logged: %q", buf.String())
			}
		})
	}
}

func TestUnaryServerInterceptor_HandlerErrorPropagates(t *testing.T) {
	want := errors.New("boom")
	_, err := UnaryServerInterceptor(nil)(context.Background(), nil, &grpc.UnaryServerInfo{}, func(context.Context, any) (any, error) {
		return nil, want
	})
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want the handler's error", err)
	}
}

func TestStreamServerInterceptor(t *testing.T) {
	stream := &recordingStream{ctx: incoming(GRPCRequestIDKey, "req-9")}
	var seen string
	err := StreamServerInterceptor(nil)(nil, stream, &grpc.StreamServerInfo{}, func(_ any, ss grpc.ServerStream) error {
		seen = GetCorrelationID(ss.Context())
		return nil
	})
	if err != nil {
		t.Fatalf("interceptor: %v", err)
	}
	if seen != "req-9" {
		t.Fatalf("handler saw %q, want req-9", seen)
	}
	if got := first(stream.header.Get(GRPCCorrelationIDKey)); got != "req-9" {
		t.Fatalf("response header %q, want req-9", got)
	}
	if GetCorrelationID(stream.Context()) != "" {
		t.Fatal("the original stream context was modified")
	}
}

// A stream whose SetHeader fails (a transport that already closed) still
// reaches the handler with a correlated context, and the failure is logged.
func TestStreamServerInterceptor_SetHeaderFailureIsNotFatal(t *testing.T) {
	var buf bytes.Buffer
	stream := &recordingStream{ctx: context.Background(), failHeader: true}
	called := false
	err := StreamServerInterceptor(slog.New(slog.NewTextHandler(&buf, nil)))(nil, stream, &grpc.StreamServerInfo{}, func(_ any, ss grpc.ServerStream) error {
		called = true
		if GetCorrelationID(ss.Context()) == "" {
			t.Error("handler observed no correlation ID")
		}
		return nil
	})
	if err != nil || !called {
		t.Fatalf("interceptor = %v, handler called = %v", err, called)
	}
	if !strings.Contains(buf.String(), "transport closed") {
		t.Fatalf("SetHeader failure was not logged: %q", buf.String())
	}
}
