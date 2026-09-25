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

package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func BenchmarkRecordRequest(b *testing.B) {
	Init()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			RecordRequest("new-account", "200")
		}
	})
}

func BenchmarkRecordCertificateIssued(b *testing.B) {
	Init()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			RecordCertificateIssued()
		}
	})
}

func BenchmarkRecordCertificateRevoked(b *testing.B) {
	Init()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			RecordCertificateRevoked()
		}
	})
}

func BenchmarkRecordChallengeCompleted(b *testing.B) {
	Init()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			RecordChallengeCompleted("http-01", "valid")
		}
	})
}

func BenchmarkRecordError(b *testing.B) {
	Init()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			RecordError("client_error")
		}
	})
}

func BenchmarkIncActiveOrders(b *testing.B) {
	Init()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			IncActiveOrders()
		}
	})
}

func BenchmarkDecActiveOrders(b *testing.B) {
	Init()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			DecActiveOrders()
		}
	})
}

func BenchmarkIncPendingChallenges(b *testing.B) {
	Init()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			IncPendingChallenges()
		}
	})
}

func BenchmarkDecPendingChallenges(b *testing.B) {
	Init()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			DecPendingChallenges()
		}
	})
}

func BenchmarkObserveRequestDuration(b *testing.B) {
	Init()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ObserveRequestDuration("new-account", 0.05)
		}
	})
}

func BenchmarkObserveCertificateIssuanceDuration(b *testing.B) {
	Init()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ObserveCertificateIssuanceDuration(1.5)
		}
	})
}

func BenchmarkExtractEndpoint(b *testing.B) {
	paths := []string{
		"/acme/new-account",
		"/acme/account/12345",
		"/acme/order/67890/finalize",
		"/acme/challenge/999",
		"/acme/directory",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		extractEndpoint(paths[i%len(paths)])
	}
}

func BenchmarkExtractEndpointComplex(b *testing.B) {
	path := "/acme/account/123/order/456/finalize"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		extractEndpoint(path)
	}
}

func BenchmarkMiddleware(b *testing.B) {
	Init()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := Middleware(handler)
	req := httptest.NewRequest("POST", "/acme/new-account", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)
	}
}

func BenchmarkMiddlewareParallel(b *testing.B) {
	Init()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := Middleware(handler)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		req := httptest.NewRequest("POST", "/acme/new-account", nil)
		for pb.Next() {
			rec := httptest.NewRecorder()
			wrapped.ServeHTTP(rec, req)
		}
	})
}

func BenchmarkResponseWriterWriteHeader(b *testing.B) {
	rec := httptest.NewRecorder()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rw := &responseWriter{
			ResponseWriter: rec,
			statusCode:     http.StatusOK,
		}
		rw.WriteHeader(http.StatusCreated)
	}
}
