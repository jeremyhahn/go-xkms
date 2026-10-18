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

package services

import (
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/agent"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
)

// agentTestListenAddress keeps test agent servers on loopback.
const agentTestListenAddress = "127.0.0.1:0"

func saveRemovableAgent(t *testing.T, store agent.EnrollmentStore) {
	t.Helper()
	if err := store.SaveAgent(&agent.AgentInfo{
		ID:                "agent-1",
		Name:              "agent one",
		Status:            "active",
		CertificateSerial: "0a0b",
		EnrolledAt:        time.Now(),
		LastSeen:          time.Now(),
	}); err != nil {
		t.Fatalf("SaveAgent: %v", err)
	}
}

func TestAgentService_SetClient_StartServerSucceeds(t *testing.T) {
	for _, storeFirst := range []bool{true, false} {
		svc, _ := setupAgentService(t)
		store := agent.NewMemoryStore()
		client := &mockCAClient{}

		if storeFirst {
			svc.SetEnrollmentStore(store)
		}
		if err := svc.SetClient(client); err != nil {
			t.Fatalf("SetClient: %v", err)
		}
		if !storeFirst {
			svc.SetEnrollmentStore(store)
		}

		if err := svc.StartServer(agentTestListenAddress); err != nil {
			t.Fatalf("StartServer (store first: %v) = %v, want success", storeFirst, err)
		}
		if err := svc.StopServer(); err != nil {
			t.Fatalf("StopServer: %v", err)
		}
	}
}

func TestAgentService_SetClient_WithoutStoreIsNotReady(t *testing.T) {
	svc, _ := setupAgentService(t)

	if err := svc.SetClient(&mockCAClient{}); err != nil {
		t.Fatalf("SetClient: %v", err)
	}
	if err := svc.StartServer(agentTestListenAddress); !errors.Is(err, ErrAgentServiceNotReady) {
		t.Fatalf("StartServer = %v, want ErrAgentServiceNotReady", err)
	}
}

func TestAgentService_SetClient_RevokesThroughTheServerCA(t *testing.T) {
	tests := []struct {
		name    string
		client  *mockCAClient
		wantErr bool
	}{
		{"authority revokes", &mockCAClient{revokeCertificateResp: &transport.RevokeCertificateResponse{Success: true}}, false},
		{"authority fails", &mockCAClient{revokeCertificateErr: errMockCA}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _ := setupAgentService(t)
			store := agent.NewMemoryStore()
			svc.SetEnrollmentStore(store)
			if err := svc.SetClient(tt.client); err != nil {
				t.Fatalf("SetClient: %v", err)
			}
			saveRemovableAgent(t, store)

			err := svc.RemoveAgent("agent-1")
			if (err != nil) != tt.wantErr {
				t.Fatalf("RemoveAgent = %v, want error: %v", err, tt.wantErr)
			}
			_, getErr := store.GetAgent("agent-1")
			if kept := getErr == nil; kept != tt.wantErr {
				t.Errorf("agent record kept = %v, want %v", kept, tt.wantErr)
			}
		})
	}
}

func TestAgentService_SetClient_NilStopsTheServer(t *testing.T) {
	svc, collector := setupAgentService(t)
	svc.SetEnrollmentStore(agent.NewMemoryStore())
	if err := svc.SetClient(&mockCAClient{}); err != nil {
		t.Fatalf("SetClient: %v", err)
	}
	if err := svc.StartServer(agentTestListenAddress); err != nil {
		t.Fatalf("StartServer: %v", err)
	}

	if err := svc.SetClient(nil); err != nil {
		t.Fatalf("SetClient(nil): %v", err)
	}

	if svc.GetServerStatus().Running {
		t.Error("the agent server kept running after the xkmsd client went away")
	}
	if !collector.hasEventType(events.EventAgentServerStopped) {
		t.Error("expected EventAgentServerStopped when the client went away")
	}
	if err := svc.StartServer(agentTestListenAddress); !errors.Is(err, ErrAgentServiceNotReady) {
		t.Fatalf("StartServer after disconnect = %v, want ErrAgentServiceNotReady", err)
	}
}

func TestAgentService_SetClient_NilWithoutServer(t *testing.T) {
	svc, collector := setupAgentService(t)

	if err := svc.SetClient(nil); err != nil {
		t.Fatalf("SetClient(nil) = %v, want nil when nothing is bound", err)
	}
	if collector.hasEventType(events.EventAgentServerStopped) {
		t.Error("SetClient(nil) reported a stop for a server that never ran")
	}
}

func TestAgentService_SetEnrollmentStore_NilDropsTheBinding(t *testing.T) {
	svc, _ := setupAgentService(t)
	svc.SetEnrollmentStore(agent.NewMemoryStore())
	if err := svc.SetClient(&mockCAClient{}); err != nil {
		t.Fatalf("SetClient: %v", err)
	}

	svc.SetEnrollmentStore(nil)

	if err := svc.StartServer(agentTestListenAddress); !errors.Is(err, ErrAgentServiceNotReady) {
		t.Fatalf("StartServer = %v, want ErrAgentServiceNotReady", err)
	}
}
