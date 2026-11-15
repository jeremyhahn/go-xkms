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

package xkms

import (
	"context"
	"testing"

	pkgtransport "github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// verdictServicer answers the attestation verdict verbs and nothing else;
// the embedded nil XKMSServicer panics on any other call.
type verdictServicer struct {
	XKMSServicer
	list   *pkgtransport.ListAttestationVerdictsResponse
	latest *pkgtransport.AttestationVerdict
	fresh  *pkgtransport.AttestationVerdict
	got    []*pkgtransport.AttestationVerdictRequest
}

func (s *verdictServicer) ListAttestationVerdicts(_ context.Context, req *pkgtransport.AttestationVerdictRequest) (*pkgtransport.ListAttestationVerdictsResponse, error) {
	s.got = append(s.got, req)
	return s.list, nil
}

func (s *verdictServicer) GetLatestAttestationVerdict(_ context.Context, req *pkgtransport.AttestationVerdictRequest) (*pkgtransport.AttestationVerdict, error) {
	s.got = append(s.got, req)
	return s.latest, nil
}

func (s *verdictServicer) ReattestDevice(_ context.Context, req *pkgtransport.AttestationVerdictRequest) (*pkgtransport.AttestationVerdict, error) {
	s.got = append(s.got, req)
	return s.fresh, nil
}

// TestClient_AttestationVerdictVerbsThroughSDKConstructors calls the verdict
// verbs through the Client that sdk.New and sdk.NewEmbedded return, and
// requires the embedded transport to forward each to the service.
func TestClient_AttestationVerdictVerbsThroughSDKConstructors(t *testing.T) {
	ctx := context.Background()
	constructors := map[string]func(XKMSServicer) (Client, error){
		"NewEmbedded": NewEmbedded,
		"New": func(s XKMSServicer) (Client, error) {
			return New(&BackendConfig{Protocol: ProtocolEmbedded, Service: s})
		},
	}
	for name, construct := range constructors {
		svc := &verdictServicer{
			list:   &pkgtransport.ListAttestationVerdictsResponse{},
			latest: &pkgtransport.AttestationVerdict{},
			fresh:  &pkgtransport.AttestationVerdict{},
		}
		client, err := construct(svc)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var _ pkgtransport.AttestationVerdictService = client
		req := &pkgtransport.AttestationVerdictRequest{}
		list, err := client.ListAttestationVerdicts(ctx, req)
		if err != nil || list != svc.list {
			t.Fatalf("%s: ListAttestationVerdicts = %v, %v; want the service's response", name, list, err)
		}
		latest, err := client.GetLatestAttestationVerdict(ctx, req)
		if err != nil || latest != svc.latest {
			t.Fatalf("%s: GetLatestAttestationVerdict = %v, %v; want the service's verdict", name, latest, err)
		}
		fresh, err := client.ReattestDevice(ctx, req)
		if err != nil || fresh != svc.fresh {
			t.Fatalf("%s: ReattestDevice = %v, %v; want the service's verdict", name, fresh, err)
		}
		if len(svc.got) != 3 {
			t.Fatalf("%s: service saw %d calls, want 3", name, len(svc.got))
		}
		for i, r := range svc.got {
			if r != req {
				t.Fatalf("%s: call %d got another request", name, i)
			}
		}
	}
}
