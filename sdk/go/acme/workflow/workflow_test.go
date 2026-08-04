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

package workflow

import (
	"context"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/account"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/authorization"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/certificate"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/challenge"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/order"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
)

// Compile-time interface check.
var _ Client = (*mockClient)(nil)

// =============================================================================
// Mock Infrastructure
// =============================================================================

type mockAccountClient struct {
	createFunc     func(ctx context.Context, req *account.CreateRequest) (*account.CreateResponse, error)
	getFunc        func(ctx context.Context, req *account.GetRequest) (*account.GetResponse, error)
	updateFunc     func(ctx context.Context, req *account.UpdateRequest) (*account.UpdateResponse, error)
	deactivateFunc func(ctx context.Context, req *account.DeactivateRequest) (*account.DeactivateResponse, error)
	keyChangeFunc  func(ctx context.Context, req *account.KeyChangeRequest) (*account.KeyChangeResponse, error)
}

func (m *mockAccountClient) Create(ctx context.Context, req *account.CreateRequest) (*account.CreateResponse, error) {
	if m.createFunc != nil {
		return m.createFunc(ctx, req)
	}
	return nil, nil
}

func (m *mockAccountClient) Get(ctx context.Context, req *account.GetRequest) (*account.GetResponse, error) {
	if m.getFunc != nil {
		return m.getFunc(ctx, req)
	}
	return nil, nil
}

func (m *mockAccountClient) Update(ctx context.Context, req *account.UpdateRequest) (*account.UpdateResponse, error) {
	if m.updateFunc != nil {
		return m.updateFunc(ctx, req)
	}
	return nil, nil
}

func (m *mockAccountClient) Deactivate(ctx context.Context, req *account.DeactivateRequest) (*account.DeactivateResponse, error) {
	if m.deactivateFunc != nil {
		return m.deactivateFunc(ctx, req)
	}
	return nil, nil
}

func (m *mockAccountClient) KeyChange(ctx context.Context, req *account.KeyChangeRequest) (*account.KeyChangeResponse, error) {
	if m.keyChangeFunc != nil {
		return m.keyChangeFunc(ctx, req)
	}
	return nil, nil
}

type mockOrderClient struct {
	createFunc   func(ctx context.Context, req *order.CreateRequest) (*order.CreateResponse, error)
	getFunc      func(ctx context.Context, req *order.GetRequest) (*order.GetResponse, error)
	listFunc     func(ctx context.Context, req *order.ListRequest) (*order.ListResponse, error)
	finalizeFunc func(ctx context.Context, req *order.FinalizeRequest) (*order.FinalizeResponse, error)
}

func (m *mockOrderClient) Create(ctx context.Context, req *order.CreateRequest) (*order.CreateResponse, error) {
	if m.createFunc != nil {
		return m.createFunc(ctx, req)
	}
	return nil, nil
}

func (m *mockOrderClient) Get(ctx context.Context, req *order.GetRequest) (*order.GetResponse, error) {
	if m.getFunc != nil {
		return m.getFunc(ctx, req)
	}
	return nil, nil
}

func (m *mockOrderClient) List(ctx context.Context, req *order.ListRequest) (*order.ListResponse, error) {
	if m.listFunc != nil {
		return m.listFunc(ctx, req)
	}
	return nil, nil
}

func (m *mockOrderClient) Finalize(ctx context.Context, req *order.FinalizeRequest) (*order.FinalizeResponse, error) {
	if m.finalizeFunc != nil {
		return m.finalizeFunc(ctx, req)
	}
	return nil, nil
}

type mockAuthorizationClient struct {
	getFunc        func(ctx context.Context, req *authorization.GetRequest) (*authorization.GetResponse, error)
	deactivateFunc func(ctx context.Context, req *authorization.DeactivateRequest) (*authorization.DeactivateResponse, error)
}

func (m *mockAuthorizationClient) Get(ctx context.Context, req *authorization.GetRequest) (*authorization.GetResponse, error) {
	if m.getFunc != nil {
		return m.getFunc(ctx, req)
	}
	return nil, nil
}

func (m *mockAuthorizationClient) Deactivate(ctx context.Context, req *authorization.DeactivateRequest) (*authorization.DeactivateResponse, error) {
	if m.deactivateFunc != nil {
		return m.deactivateFunc(ctx, req)
	}
	return nil, nil
}

type mockChallengeClient struct {
	getFunc     func(ctx context.Context, req *challenge.GetRequest) (*challenge.GetResponse, error)
	respondFunc func(ctx context.Context, req *challenge.RespondRequest) (*challenge.RespondResponse, error)
}

func (m *mockChallengeClient) Get(ctx context.Context, req *challenge.GetRequest) (*challenge.GetResponse, error) {
	if m.getFunc != nil {
		return m.getFunc(ctx, req)
	}
	return nil, nil
}

func (m *mockChallengeClient) Respond(ctx context.Context, req *challenge.RespondRequest) (*challenge.RespondResponse, error) {
	if m.respondFunc != nil {
		return m.respondFunc(ctx, req)
	}
	return nil, nil
}

type mockCertificateClient struct {
	getFunc    func(ctx context.Context, req *certificate.GetRequest) (*certificate.GetResponse, error)
	revokeFunc func(ctx context.Context, req *certificate.RevokeRequest) (*certificate.RevokeResponse, error)
}

func (m *mockCertificateClient) Get(ctx context.Context, req *certificate.GetRequest) (*certificate.GetResponse, error) {
	if m.getFunc != nil {
		return m.getFunc(ctx, req)
	}
	return nil, nil
}

func (m *mockCertificateClient) Revoke(ctx context.Context, req *certificate.RevokeRequest) (*certificate.RevokeResponse, error) {
	if m.revokeFunc != nil {
		return m.revokeFunc(ctx, req)
	}
	return nil, nil
}

// mockClient assembles mock sub-clients into a unified Client.
type mockClient struct {
	accountClient       *mockAccountClient
	orderClient         *mockOrderClient
	authorizationClient *mockAuthorizationClient
	challengeClient     *mockChallengeClient
	certificateClient   *mockCertificateClient
}

func newMockClient() *mockClient {
	return &mockClient{
		accountClient:       &mockAccountClient{},
		orderClient:         &mockOrderClient{},
		authorizationClient: &mockAuthorizationClient{},
		challengeClient:     &mockChallengeClient{},
		certificateClient:   &mockCertificateClient{},
	}
}

func (m *mockClient) Account() account.Client             { return m.accountClient }
func (m *mockClient) Order() order.Client                 { return m.orderClient }
func (m *mockClient) Authorization() authorization.Client { return m.authorizationClient }
func (m *mockClient) Challenge() challenge.Client         { return m.challengeClient }
func (m *mockClient) Certificate() certificate.Client     { return m.certificateClient }

// noopHandler is a challenge handler that does nothing.
var noopHandler = ChallengeHandlerFunc(func(challengeType, token, keyAuth, domain string) (func(), error) {
	return func() {}, nil
})

// =============================================================================
// NewWorkflow Tests
// =============================================================================

func TestNewWorkflow_NilClient(t *testing.T) {
	w := NewWorkflow(nil)
	if w != nil {
		t.Fatal("expected nil workflow for nil client")
	}
}

func TestNewWorkflow_Defaults(t *testing.T) {
	mc := newMockClient()
	w := NewWorkflow(mc)
	if w == nil {
		t.Fatal("expected non-nil workflow")
	}
	impl := w.(*workflow)
	if impl.pollTimeout != 120*time.Second {
		t.Errorf("expected default pollTimeout 120s, got %v", impl.pollTimeout)
	}
	if impl.pollInterval != 2*time.Second {
		t.Errorf("expected default pollInterval 2s, got %v", impl.pollInterval)
	}
}

func TestNewWorkflow_WithOptions(t *testing.T) {
	mc := newMockClient()
	w := NewWorkflow(mc,
		WithPollTimeout(60*time.Second),
		WithPollInterval(500*time.Millisecond),
	)
	impl := w.(*workflow)
	if impl.pollTimeout != 60*time.Second {
		t.Errorf("expected pollTimeout 60s, got %v", impl.pollTimeout)
	}
	if impl.pollInterval != 500*time.Millisecond {
		t.Errorf("expected pollInterval 500ms, got %v", impl.pollInterval)
	}
}

func TestWithPollTimeout_InvalidIgnored(t *testing.T) {
	mc := newMockClient()
	w := NewWorkflow(mc, WithPollTimeout(-1*time.Second))
	impl := w.(*workflow)
	if impl.pollTimeout != 120*time.Second {
		t.Errorf("expected default pollTimeout preserved, got %v", impl.pollTimeout)
	}
}

func TestWithPollInterval_InvalidIgnored(t *testing.T) {
	mc := newMockClient()
	w := NewWorkflow(mc, WithPollInterval(0))
	impl := w.(*workflow)
	if impl.pollInterval != 2*time.Second {
		t.Errorf("expected default pollInterval preserved, got %v", impl.pollInterval)
	}
}

// =============================================================================
// Register Tests
// =============================================================================

func TestRegister_Success(t *testing.T) {
	mc := newMockClient()
	mc.accountClient.createFunc = func(ctx context.Context, req *account.CreateRequest) (*account.CreateResponse, error) {
		if len(req.Contact) != 1 || req.Contact[0] != "mailto:admin@example.com" {
			t.Errorf("unexpected contact: %v", req.Contact)
		}
		if !req.TermsOfServiceAgreed {
			t.Error("expected TermsOfServiceAgreed to be true")
		}
		return &account.CreateResponse{
			Account: &account.Account{
				Status:  account.StatusValid,
				Contact: req.Contact,
			},
			Location: "https://ca.example.com/acme/acct/1",
		}, nil
	}

	w := NewWorkflow(mc)
	resp, err := w.Register(context.Background(), &RegisterRequest{
		Email:                "admin@example.com",
		TermsOfServiceAgreed: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.AccountURL != "https://ca.example.com/acme/acct/1" {
		t.Errorf("unexpected account URL: %s", resp.AccountURL)
	}
	if resp.Status != "valid" {
		t.Errorf("unexpected status: %s", resp.Status)
	}
	if len(resp.Contact) != 1 {
		t.Errorf("unexpected contact count: %d", len(resp.Contact))
	}
}

func TestRegister_NilRequest(t *testing.T) {
	mc := newMockClient()
	w := NewWorkflow(mc)
	_, err := w.Register(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil request")
	}
	if !errors.IsInvalidInput(err) {
		t.Errorf("expected invalid input error, got: %v", err)
	}
}

func TestRegister_EmptyEmail(t *testing.T) {
	mc := newMockClient()
	w := NewWorkflow(mc)
	_, err := w.Register(context.Background(), &RegisterRequest{})
	if err == nil {
		t.Fatal("expected error for empty email")
	}
	if !errors.IsInvalidInput(err) {
		t.Errorf("expected invalid input error, got: %v", err)
	}
}

func TestRegister_TransportError(t *testing.T) {
	mc := newMockClient()
	mc.accountClient.createFunc = func(ctx context.Context, req *account.CreateRequest) (*account.CreateResponse, error) {
		return nil, errors.NewUnavailable("test", "server unavailable")
	}

	w := NewWorkflow(mc)
	_, err := w.Register(context.Background(), &RegisterRequest{
		Email:                "admin@example.com",
		TermsOfServiceAgreed: true,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	var regErr *RegistrationError
	if !unwrapAs(err, &regErr) {
		t.Errorf("expected RegistrationError, got: %T", err)
	}
}

func TestRegister_NilAccountResponse(t *testing.T) {
	mc := newMockClient()
	mc.accountClient.createFunc = func(ctx context.Context, req *account.CreateRequest) (*account.CreateResponse, error) {
		return &account.CreateResponse{
			Account:  nil,
			Location: "https://ca.example.com/acme/acct/1",
		}, nil
	}

	w := NewWorkflow(mc)
	_, err := w.Register(context.Background(), &RegisterRequest{
		Email:                "admin@example.com",
		TermsOfServiceAgreed: true,
	})
	if err == nil {
		t.Fatal("expected error for nil account in response")
	}
	var regErr *RegistrationError
	if !unwrapAs(err, &regErr) {
		t.Errorf("expected RegistrationError, got: %T", err)
	}
}

// =============================================================================
// RequestCertificate Tests
// =============================================================================

func TestRequestCertificate_Success(t *testing.T) {
	mc := newMockClient()
	authzCallCount := 0

	mc.orderClient.createFunc = func(ctx context.Context, req *order.CreateRequest) (*order.CreateResponse, error) {
		if len(req.Identifiers) != 1 || req.Identifiers[0].Value != "example.com" {
			t.Errorf("unexpected identifiers: %v", req.Identifiers)
		}
		return &order.CreateResponse{
			Order: &order.Order{
				Status:         order.StatusPending,
				Authorizations: []string{"https://ca.example.com/acme/authz/1"},
				Finalize:       "https://ca.example.com/acme/order/1/finalize",
			},
			Location: "https://ca.example.com/acme/order/1",
		}, nil
	}

	mc.authorizationClient.getFunc = func(ctx context.Context, req *authorization.GetRequest) (*authorization.GetResponse, error) {
		authzCallCount++
		if authzCallCount == 1 {
			return &authorization.GetResponse{
				Authorization: &authorization.Authorization{
					Identifier: authorization.Identifier{Type: "dns", Value: "example.com"},
					Status:     authorization.StatusPending,
					Challenges: []authorization.Challenge{
						{
							Type:   "http-01",
							URL:    "https://ca.example.com/acme/chall/1",
							Status: "pending",
							Token:  "test-token-123",
						},
					},
				},
			}, nil
		}
		return &authorization.GetResponse{
			Authorization: &authorization.Authorization{
				Identifier: authorization.Identifier{Type: "dns", Value: "example.com"},
				Status:     authorization.StatusValid,
			},
		}, nil
	}

	mc.challengeClient.respondFunc = func(ctx context.Context, req *challenge.RespondRequest) (*challenge.RespondResponse, error) {
		if req.ChallengeURL != "https://ca.example.com/acme/chall/1" {
			t.Errorf("unexpected challenge URL: %s", req.ChallengeURL)
		}
		return &challenge.RespondResponse{
			Challenge: &challenge.Challenge{Status: challenge.StatusProcessing},
		}, nil
	}

	mc.orderClient.finalizeFunc = func(ctx context.Context, req *order.FinalizeRequest) (*order.FinalizeResponse, error) {
		if req.FinalizeURL != "https://ca.example.com/acme/order/1/finalize" {
			t.Errorf("unexpected finalize URL: %s", req.FinalizeURL)
		}
		if req.CSR == "" {
			t.Error("expected non-empty CSR")
		}
		return &order.FinalizeResponse{
			Order: &order.Order{
				Status:      order.StatusProcessing,
				Certificate: "https://ca.example.com/acme/cert/1",
			},
			Location: "https://ca.example.com/acme/order/1",
		}, nil
	}

	mc.orderClient.getFunc = func(ctx context.Context, req *order.GetRequest) (*order.GetResponse, error) {
		return &order.GetResponse{
			Order: &order.Order{
				Status:      order.StatusValid,
				Certificate: "https://ca.example.com/acme/cert/1",
			},
		}, nil
	}

	mc.certificateClient.getFunc = func(ctx context.Context, req *certificate.GetRequest) (*certificate.GetResponse, error) {
		if req.CertificateURL != "https://ca.example.com/acme/cert/1" {
			t.Errorf("unexpected certificate URL: %s", req.CertificateURL)
		}
		return &certificate.GetResponse{
			Chain: "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
		}, nil
	}

	handlerCalled := false
	cleanupCalled := false
	handler := ChallengeHandlerFunc(func(cType, token, keyAuth, domain string) (func(), error) {
		handlerCalled = true
		if cType != "http-01" {
			t.Errorf("unexpected challenge type: %s", cType)
		}
		if token != "test-token-123" {
			t.Errorf("unexpected token: %s", token)
		}
		if domain != "example.com" {
			t.Errorf("unexpected domain: %s", domain)
		}
		return func() { cleanupCalled = true }, nil
	})

	w := NewWorkflow(mc,
		WithPollTimeout(5*time.Second),
		WithPollInterval(10*time.Millisecond),
	)

	resp, err := w.RequestCertificate(context.Background(), &CertificateRequest{
		Domains:          []string{"example.com"},
		CSR:              []byte{0x30, 0x82, 0x01},
		ChallengeType:    "http-01",
		ChallengeHandler: handler,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !handlerCalled {
		t.Error("expected challenge handler to be called")
	}
	if !cleanupCalled {
		t.Error("expected cleanup function to be called")
	}
	if resp.CertificateChain == "" {
		t.Error("expected non-empty certificate chain")
	}
	if resp.OrderURL != "https://ca.example.com/acme/order/1" {
		t.Errorf("unexpected order URL: %s", resp.OrderURL)
	}
	if resp.CertificateURL != "https://ca.example.com/acme/cert/1" {
		t.Errorf("unexpected certificate URL: %s", resp.CertificateURL)
	}
}

func TestRequestCertificate_NilRequest(t *testing.T) {
	mc := newMockClient()
	w := NewWorkflow(mc)
	_, err := w.RequestCertificate(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil request")
	}
	if !errors.IsInvalidInput(err) {
		t.Errorf("expected invalid input error, got: %v", err)
	}
}

func TestRequestCertificate_NoDomains(t *testing.T) {
	mc := newMockClient()
	w := NewWorkflow(mc)
	_, err := w.RequestCertificate(context.Background(), &CertificateRequest{
		CSR:              []byte{0x30},
		ChallengeType:    "http-01",
		ChallengeHandler: noopHandler,
	})
	if err == nil {
		t.Fatal("expected error for empty domains")
	}
	if !errors.IsInvalidInput(err) {
		t.Errorf("expected invalid input error, got: %v", err)
	}
}

func TestRequestCertificate_NoCSR(t *testing.T) {
	mc := newMockClient()
	w := NewWorkflow(mc)
	_, err := w.RequestCertificate(context.Background(), &CertificateRequest{
		Domains:          []string{"example.com"},
		ChallengeType:    "http-01",
		ChallengeHandler: noopHandler,
	})
	if err == nil {
		t.Fatal("expected error for empty CSR")
	}
	if !errors.IsInvalidInput(err) {
		t.Errorf("expected invalid input error, got: %v", err)
	}
}

func TestRequestCertificate_NoChallengeType(t *testing.T) {
	mc := newMockClient()
	w := NewWorkflow(mc)
	_, err := w.RequestCertificate(context.Background(), &CertificateRequest{
		Domains:          []string{"example.com"},
		CSR:              []byte{0x30},
		ChallengeHandler: noopHandler,
	})
	if err == nil {
		t.Fatal("expected error for empty challenge type")
	}
	if !errors.IsInvalidInput(err) {
		t.Errorf("expected invalid input error, got: %v", err)
	}
}

func TestRequestCertificate_NoChallengeHandler(t *testing.T) {
	mc := newMockClient()
	w := NewWorkflow(mc)
	_, err := w.RequestCertificate(context.Background(), &CertificateRequest{
		Domains:       []string{"example.com"},
		CSR:           []byte{0x30},
		ChallengeType: "http-01",
	})
	if err == nil {
		t.Fatal("expected error for nil challenge handler")
	}
	if !errors.IsInvalidInput(err) {
		t.Errorf("expected invalid input error, got: %v", err)
	}
}

func TestRequestCertificate_OrderCreateError(t *testing.T) {
	mc := newMockClient()
	mc.orderClient.createFunc = func(ctx context.Context, req *order.CreateRequest) (*order.CreateResponse, error) {
		return nil, errors.NewUnavailable("test", "server down")
	}

	w := NewWorkflow(mc)
	_, err := w.RequestCertificate(context.Background(), &CertificateRequest{
		Domains:          []string{"example.com"},
		CSR:              []byte{0x30},
		ChallengeType:    "http-01",
		ChallengeHandler: noopHandler,
	})
	if err == nil {
		t.Fatal("expected error from order create")
	}
	var finErr *FinalizationError
	if !unwrapAs(err, &finErr) {
		t.Errorf("expected FinalizationError, got: %T", err)
	}
}

func TestRequestCertificate_OrderCreateNilOrder(t *testing.T) {
	mc := newMockClient()
	mc.orderClient.createFunc = func(ctx context.Context, req *order.CreateRequest) (*order.CreateResponse, error) {
		return &order.CreateResponse{Order: nil, Location: "https://ca.example.com/acme/order/1"}, nil
	}

	w := NewWorkflow(mc)
	_, err := w.RequestCertificate(context.Background(), &CertificateRequest{
		Domains:          []string{"example.com"},
		CSR:              []byte{0x30},
		ChallengeType:    "http-01",
		ChallengeHandler: noopHandler,
	})
	if err == nil {
		t.Fatal("expected error for nil order")
	}
	var finErr *FinalizationError
	if !unwrapAs(err, &finErr) {
		t.Errorf("expected FinalizationError, got: %T", err)
	}
}

func TestRequestCertificate_AuthorizationGetError(t *testing.T) {
	mc := newMockClient()
	mc.orderClient.createFunc = func(ctx context.Context, req *order.CreateRequest) (*order.CreateResponse, error) {
		return &order.CreateResponse{
			Order: &order.Order{
				Status:         order.StatusPending,
				Authorizations: []string{"https://ca.example.com/acme/authz/1"},
				Finalize:       "https://ca.example.com/acme/order/1/finalize",
			},
			Location: "https://ca.example.com/acme/order/1",
		}, nil
	}
	mc.authorizationClient.getFunc = func(ctx context.Context, req *authorization.GetRequest) (*authorization.GetResponse, error) {
		return nil, errors.NewInternal("test", "authorization fetch failed")
	}

	w := NewWorkflow(mc)
	_, err := w.RequestCertificate(context.Background(), &CertificateRequest{
		Domains:          []string{"example.com"},
		CSR:              []byte{0x30},
		ChallengeType:    "http-01",
		ChallengeHandler: noopHandler,
	})
	if err == nil {
		t.Fatal("expected error from authorization get")
	}
	var authzErr *AuthorizationError
	if !unwrapAs(err, &authzErr) {
		t.Errorf("expected AuthorizationError, got: %T", err)
	}
}

func TestRequestCertificate_NoChallengeMatch(t *testing.T) {
	mc := newMockClient()
	mc.orderClient.createFunc = func(ctx context.Context, req *order.CreateRequest) (*order.CreateResponse, error) {
		return &order.CreateResponse{
			Order: &order.Order{
				Status:         order.StatusPending,
				Authorizations: []string{"https://ca.example.com/acme/authz/1"},
				Finalize:       "https://ca.example.com/acme/order/1/finalize",
			},
			Location: "https://ca.example.com/acme/order/1",
		}, nil
	}
	mc.authorizationClient.getFunc = func(ctx context.Context, req *authorization.GetRequest) (*authorization.GetResponse, error) {
		return &authorization.GetResponse{
			Authorization: &authorization.Authorization{
				Identifier: authorization.Identifier{Type: "dns", Value: "example.com"},
				Status:     authorization.StatusPending,
				Challenges: []authorization.Challenge{
					{Type: "dns-01", URL: "https://ca.example.com/acme/chall/1", Token: "tok"},
				},
			},
		}, nil
	}

	w := NewWorkflow(mc)
	_, err := w.RequestCertificate(context.Background(), &CertificateRequest{
		Domains:          []string{"example.com"},
		CSR:              []byte{0x30},
		ChallengeType:    "http-01",
		ChallengeHandler: noopHandler,
	})
	if err == nil {
		t.Fatal("expected error for no matching challenge")
	}
	var noCh *NoChallengeError
	if !unwrapAs(err, &noCh) {
		t.Errorf("expected NoChallengeError, got: %T", err)
	}
	if noCh.Domain != "example.com" {
		t.Errorf("unexpected domain: %s", noCh.Domain)
	}
	if noCh.RequestedType != "http-01" {
		t.Errorf("unexpected requested type: %s", noCh.RequestedType)
	}
}

func TestRequestCertificate_ChallengeHandlerError(t *testing.T) {
	mc := newMockClient()
	mc.orderClient.createFunc = func(ctx context.Context, req *order.CreateRequest) (*order.CreateResponse, error) {
		return &order.CreateResponse{
			Order: &order.Order{
				Status:         order.StatusPending,
				Authorizations: []string{"https://ca.example.com/acme/authz/1"},
				Finalize:       "https://ca.example.com/acme/order/1/finalize",
			},
			Location: "https://ca.example.com/acme/order/1",
		}, nil
	}
	mc.authorizationClient.getFunc = func(ctx context.Context, req *authorization.GetRequest) (*authorization.GetResponse, error) {
		return &authorization.GetResponse{
			Authorization: &authorization.Authorization{
				Identifier: authorization.Identifier{Type: "dns", Value: "example.com"},
				Status:     authorization.StatusPending,
				Challenges: []authorization.Challenge{
					{Type: "http-01", URL: "https://ca.example.com/acme/chall/1", Token: "tok"},
				},
			},
		}, nil
	}

	failHandler := ChallengeHandlerFunc(func(cType, token, keyAuth, domain string) (func(), error) {
		return nil, errors.NewInternal("test", "handler setup failed")
	})

	w := NewWorkflow(mc)
	_, err := w.RequestCertificate(context.Background(), &CertificateRequest{
		Domains:          []string{"example.com"},
		CSR:              []byte{0x30},
		ChallengeType:    "http-01",
		ChallengeHandler: failHandler,
	})
	if err == nil {
		t.Fatal("expected error from challenge handler")
	}
	var chErr *ChallengeError
	if !unwrapAs(err, &chErr) {
		t.Errorf("expected ChallengeError, got: %T", err)
	}
}

func TestRequestCertificate_ChallengeRespondError(t *testing.T) {
	mc := newMockClient()
	mc.orderClient.createFunc = func(ctx context.Context, req *order.CreateRequest) (*order.CreateResponse, error) {
		return &order.CreateResponse{
			Order: &order.Order{
				Status:         order.StatusPending,
				Authorizations: []string{"https://ca.example.com/acme/authz/1"},
				Finalize:       "https://ca.example.com/acme/order/1/finalize",
			},
			Location: "https://ca.example.com/acme/order/1",
		}, nil
	}
	mc.authorizationClient.getFunc = func(ctx context.Context, req *authorization.GetRequest) (*authorization.GetResponse, error) {
		return &authorization.GetResponse{
			Authorization: &authorization.Authorization{
				Identifier: authorization.Identifier{Type: "dns", Value: "example.com"},
				Status:     authorization.StatusPending,
				Challenges: []authorization.Challenge{
					{Type: "http-01", URL: "https://ca.example.com/acme/chall/1", Token: "tok"},
				},
			},
		}, nil
	}
	mc.challengeClient.respondFunc = func(ctx context.Context, req *challenge.RespondRequest) (*challenge.RespondResponse, error) {
		return nil, errors.NewInternal("test", "respond failed")
	}

	w := NewWorkflow(mc)
	_, err := w.RequestCertificate(context.Background(), &CertificateRequest{
		Domains:          []string{"example.com"},
		CSR:              []byte{0x30},
		ChallengeType:    "http-01",
		ChallengeHandler: noopHandler,
	})
	if err == nil {
		t.Fatal("expected error from challenge respond")
	}
	var chErr *ChallengeError
	if !unwrapAs(err, &chErr) {
		t.Errorf("expected ChallengeError, got: %T", err)
	}
}

func TestRequestCertificate_AuthorizationInvalid(t *testing.T) {
	mc := newMockClient()
	authzCallCount := 0

	mc.orderClient.createFunc = func(ctx context.Context, req *order.CreateRequest) (*order.CreateResponse, error) {
		return &order.CreateResponse{
			Order: &order.Order{
				Status:         order.StatusPending,
				Authorizations: []string{"https://ca.example.com/acme/authz/1"},
				Finalize:       "https://ca.example.com/acme/order/1/finalize",
			},
			Location: "https://ca.example.com/acme/order/1",
		}, nil
	}
	mc.authorizationClient.getFunc = func(ctx context.Context, req *authorization.GetRequest) (*authorization.GetResponse, error) {
		authzCallCount++
		if authzCallCount == 1 {
			return &authorization.GetResponse{
				Authorization: &authorization.Authorization{
					Identifier: authorization.Identifier{Type: "dns", Value: "example.com"},
					Status:     authorization.StatusPending,
					Challenges: []authorization.Challenge{
						{Type: "http-01", URL: "https://ca.example.com/acme/chall/1", Token: "tok"},
					},
				},
			}, nil
		}
		return &authorization.GetResponse{
			Authorization: &authorization.Authorization{
				Identifier: authorization.Identifier{Type: "dns", Value: "example.com"},
				Status:     authorization.StatusInvalid,
			},
		}, nil
	}
	mc.challengeClient.respondFunc = func(ctx context.Context, req *challenge.RespondRequest) (*challenge.RespondResponse, error) {
		return &challenge.RespondResponse{Challenge: &challenge.Challenge{Status: challenge.StatusProcessing}}, nil
	}

	w := NewWorkflow(mc, WithPollTimeout(5*time.Second), WithPollInterval(10*time.Millisecond))
	_, err := w.RequestCertificate(context.Background(), &CertificateRequest{
		Domains:          []string{"example.com"},
		CSR:              []byte{0x30},
		ChallengeType:    "http-01",
		ChallengeHandler: noopHandler,
	})
	if err == nil {
		t.Fatal("expected error for invalid authorization")
	}
	var authzErr *AuthorizationError
	if !unwrapAs(err, &authzErr) {
		t.Errorf("expected AuthorizationError, got: %T", err)
	}
}

func TestRequestCertificate_AlreadyValidAuthorization(t *testing.T) {
	mc := newMockClient()

	mc.orderClient.createFunc = func(ctx context.Context, req *order.CreateRequest) (*order.CreateResponse, error) {
		return &order.CreateResponse{
			Order: &order.Order{
				Status:         order.StatusReady,
				Authorizations: []string{"https://ca.example.com/acme/authz/1"},
				Finalize:       "https://ca.example.com/acme/order/1/finalize",
			},
			Location: "https://ca.example.com/acme/order/1",
		}, nil
	}
	mc.authorizationClient.getFunc = func(ctx context.Context, req *authorization.GetRequest) (*authorization.GetResponse, error) {
		return &authorization.GetResponse{
			Authorization: &authorization.Authorization{
				Identifier: authorization.Identifier{Type: "dns", Value: "example.com"},
				Status:     authorization.StatusValid,
			},
		}, nil
	}
	mc.orderClient.finalizeFunc = func(ctx context.Context, req *order.FinalizeRequest) (*order.FinalizeResponse, error) {
		return &order.FinalizeResponse{
			Order:    &order.Order{Status: order.StatusProcessing, Certificate: "https://ca.example.com/acme/cert/1"},
			Location: "https://ca.example.com/acme/order/1",
		}, nil
	}
	mc.orderClient.getFunc = func(ctx context.Context, req *order.GetRequest) (*order.GetResponse, error) {
		return &order.GetResponse{
			Order: &order.Order{Status: order.StatusValid, Certificate: "https://ca.example.com/acme/cert/1"},
		}, nil
	}
	mc.certificateClient.getFunc = func(ctx context.Context, req *certificate.GetRequest) (*certificate.GetResponse, error) {
		return &certificate.GetResponse{Chain: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"}, nil
	}

	w := NewWorkflow(mc, WithPollTimeout(5*time.Second), WithPollInterval(10*time.Millisecond))
	resp, err := w.RequestCertificate(context.Background(), &CertificateRequest{
		Domains:          []string{"example.com"},
		CSR:              []byte{0x30},
		ChallengeType:    "http-01",
		ChallengeHandler: noopHandler,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.CertificateChain == "" {
		t.Error("expected non-empty certificate chain")
	}
}

func TestRequestCertificate_FinalizeError(t *testing.T) {
	mc := newMockClient()
	mc.orderClient.createFunc = func(ctx context.Context, req *order.CreateRequest) (*order.CreateResponse, error) {
		return &order.CreateResponse{
			Order: &order.Order{
				Status:         order.StatusReady,
				Authorizations: []string{},
				Finalize:       "https://ca.example.com/acme/order/1/finalize",
			},
			Location: "https://ca.example.com/acme/order/1",
		}, nil
	}
	mc.orderClient.finalizeFunc = func(ctx context.Context, req *order.FinalizeRequest) (*order.FinalizeResponse, error) {
		return nil, errors.NewACMEOrderNotReady("test", "order not ready")
	}

	w := NewWorkflow(mc)
	_, err := w.RequestCertificate(context.Background(), &CertificateRequest{
		Domains:          []string{"example.com"},
		CSR:              []byte{0x30},
		ChallengeType:    "http-01",
		ChallengeHandler: noopHandler,
	})
	if err == nil {
		t.Fatal("expected error from finalize")
	}
	var finErr *FinalizationError
	if !unwrapAs(err, &finErr) {
		t.Errorf("expected FinalizationError, got: %T", err)
	}
}

func TestRequestCertificate_FinalizeNilOrder(t *testing.T) {
	mc := newMockClient()
	mc.orderClient.createFunc = func(ctx context.Context, req *order.CreateRequest) (*order.CreateResponse, error) {
		return &order.CreateResponse{
			Order: &order.Order{
				Status:         order.StatusReady,
				Authorizations: []string{},
				Finalize:       "https://ca.example.com/acme/order/1/finalize",
			},
			Location: "https://ca.example.com/acme/order/1",
		}, nil
	}
	mc.orderClient.finalizeFunc = func(ctx context.Context, req *order.FinalizeRequest) (*order.FinalizeResponse, error) {
		return &order.FinalizeResponse{Order: nil, Location: "https://ca.example.com/acme/order/1"}, nil
	}

	w := NewWorkflow(mc)
	_, err := w.RequestCertificate(context.Background(), &CertificateRequest{
		Domains:          []string{"example.com"},
		CSR:              []byte{0x30},
		ChallengeType:    "http-01",
		ChallengeHandler: noopHandler,
	})
	if err == nil {
		t.Fatal("expected error for nil order after finalize")
	}
}

func TestRequestCertificate_OrderInvalid(t *testing.T) {
	mc := newMockClient()
	mc.orderClient.createFunc = func(ctx context.Context, req *order.CreateRequest) (*order.CreateResponse, error) {
		return &order.CreateResponse{
			Order: &order.Order{
				Status:         order.StatusReady,
				Authorizations: []string{},
				Finalize:       "https://ca.example.com/acme/order/1/finalize",
			},
			Location: "https://ca.example.com/acme/order/1",
		}, nil
	}
	mc.orderClient.finalizeFunc = func(ctx context.Context, req *order.FinalizeRequest) (*order.FinalizeResponse, error) {
		return &order.FinalizeResponse{
			Order:    &order.Order{Status: order.StatusProcessing},
			Location: "https://ca.example.com/acme/order/1",
		}, nil
	}
	mc.orderClient.getFunc = func(ctx context.Context, req *order.GetRequest) (*order.GetResponse, error) {
		return &order.GetResponse{
			Order: &order.Order{Status: order.StatusInvalid},
		}, nil
	}

	w := NewWorkflow(mc, WithPollTimeout(5*time.Second), WithPollInterval(10*time.Millisecond))
	_, err := w.RequestCertificate(context.Background(), &CertificateRequest{
		Domains:          []string{"example.com"},
		CSR:              []byte{0x30},
		ChallengeType:    "http-01",
		ChallengeHandler: noopHandler,
	})
	if err == nil {
		t.Fatal("expected error for invalid order")
	}
	var finErr *FinalizationError
	if !unwrapAs(err, &finErr) {
		t.Errorf("expected FinalizationError, got: %T", err)
	}
}

func TestRequestCertificate_OrderPollNilOrder(t *testing.T) {
	mc := newMockClient()
	mc.orderClient.createFunc = func(ctx context.Context, req *order.CreateRequest) (*order.CreateResponse, error) {
		return &order.CreateResponse{
			Order: &order.Order{
				Status:         order.StatusReady,
				Authorizations: []string{},
				Finalize:       "https://ca.example.com/acme/order/1/finalize",
			},
			Location: "https://ca.example.com/acme/order/1",
		}, nil
	}
	mc.orderClient.finalizeFunc = func(ctx context.Context, req *order.FinalizeRequest) (*order.FinalizeResponse, error) {
		return &order.FinalizeResponse{
			Order:    &order.Order{Status: order.StatusProcessing},
			Location: "https://ca.example.com/acme/order/1",
		}, nil
	}
	mc.orderClient.getFunc = func(ctx context.Context, req *order.GetRequest) (*order.GetResponse, error) {
		return &order.GetResponse{Order: nil}, nil
	}

	w := NewWorkflow(mc, WithPollTimeout(5*time.Second), WithPollInterval(10*time.Millisecond))
	_, err := w.RequestCertificate(context.Background(), &CertificateRequest{
		Domains:          []string{"example.com"},
		CSR:              []byte{0x30},
		ChallengeType:    "http-01",
		ChallengeHandler: noopHandler,
	})
	if err == nil {
		t.Fatal("expected error for nil order during poll")
	}
}

func TestRequestCertificate_OrderPollError(t *testing.T) {
	mc := newMockClient()
	mc.orderClient.createFunc = func(ctx context.Context, req *order.CreateRequest) (*order.CreateResponse, error) {
		return &order.CreateResponse{
			Order: &order.Order{
				Status:         order.StatusReady,
				Authorizations: []string{},
				Finalize:       "https://ca.example.com/acme/order/1/finalize",
			},
			Location: "https://ca.example.com/acme/order/1",
		}, nil
	}
	mc.orderClient.finalizeFunc = func(ctx context.Context, req *order.FinalizeRequest) (*order.FinalizeResponse, error) {
		return &order.FinalizeResponse{
			Order:    &order.Order{Status: order.StatusProcessing},
			Location: "https://ca.example.com/acme/order/1",
		}, nil
	}
	mc.orderClient.getFunc = func(ctx context.Context, req *order.GetRequest) (*order.GetResponse, error) {
		return nil, errors.NewInternal("test", "poll error")
	}

	w := NewWorkflow(mc, WithPollTimeout(5*time.Second), WithPollInterval(10*time.Millisecond))
	_, err := w.RequestCertificate(context.Background(), &CertificateRequest{
		Domains:          []string{"example.com"},
		CSR:              []byte{0x30},
		ChallengeType:    "http-01",
		ChallengeHandler: noopHandler,
	})
	if err == nil {
		t.Fatal("expected error from order poll")
	}
}

func TestRequestCertificate_CertificateDownloadError(t *testing.T) {
	mc := newMockClient()
	mc.orderClient.createFunc = func(ctx context.Context, req *order.CreateRequest) (*order.CreateResponse, error) {
		return &order.CreateResponse{
			Order: &order.Order{
				Status:         order.StatusReady,
				Authorizations: []string{},
				Finalize:       "https://ca.example.com/acme/order/1/finalize",
			},
			Location: "https://ca.example.com/acme/order/1",
		}, nil
	}
	mc.orderClient.finalizeFunc = func(ctx context.Context, req *order.FinalizeRequest) (*order.FinalizeResponse, error) {
		return &order.FinalizeResponse{
			Order:    &order.Order{Status: order.StatusProcessing},
			Location: "https://ca.example.com/acme/order/1",
		}, nil
	}
	mc.orderClient.getFunc = func(ctx context.Context, req *order.GetRequest) (*order.GetResponse, error) {
		return &order.GetResponse{
			Order: &order.Order{Status: order.StatusValid, Certificate: "https://ca.example.com/acme/cert/1"},
		}, nil
	}
	mc.certificateClient.getFunc = func(ctx context.Context, req *certificate.GetRequest) (*certificate.GetResponse, error) {
		return nil, errors.NewInternal("test", "download failed")
	}

	w := NewWorkflow(mc, WithPollTimeout(5*time.Second), WithPollInterval(10*time.Millisecond))
	_, err := w.RequestCertificate(context.Background(), &CertificateRequest{
		Domains:          []string{"example.com"},
		CSR:              []byte{0x30},
		ChallengeType:    "http-01",
		ChallengeHandler: noopHandler,
	})
	if err == nil {
		t.Fatal("expected error from certificate download")
	}
}

func TestRequestCertificate_NoCertificateURL(t *testing.T) {
	mc := newMockClient()
	mc.orderClient.createFunc = func(ctx context.Context, req *order.CreateRequest) (*order.CreateResponse, error) {
		return &order.CreateResponse{
			Order: &order.Order{
				Status:         order.StatusReady,
				Authorizations: []string{},
				Finalize:       "https://ca.example.com/acme/order/1/finalize",
			},
			Location: "https://ca.example.com/acme/order/1",
		}, nil
	}
	mc.orderClient.finalizeFunc = func(ctx context.Context, req *order.FinalizeRequest) (*order.FinalizeResponse, error) {
		return &order.FinalizeResponse{
			Order:    &order.Order{Status: order.StatusProcessing},
			Location: "https://ca.example.com/acme/order/1",
		}, nil
	}
	mc.orderClient.getFunc = func(ctx context.Context, req *order.GetRequest) (*order.GetResponse, error) {
		return &order.GetResponse{
			Order: &order.Order{Status: order.StatusValid, Certificate: ""},
		}, nil
	}

	w := NewWorkflow(mc, WithPollTimeout(5*time.Second), WithPollInterval(10*time.Millisecond))
	_, err := w.RequestCertificate(context.Background(), &CertificateRequest{
		Domains:          []string{"example.com"},
		CSR:              []byte{0x30},
		ChallengeType:    "http-01",
		ChallengeHandler: noopHandler,
	})
	if err == nil {
		t.Fatal("expected error for missing certificate URL")
	}
}

func TestRequestCertificate_ContextCanceled(t *testing.T) {
	mc := newMockClient()
	mc.orderClient.createFunc = func(ctx context.Context, req *order.CreateRequest) (*order.CreateResponse, error) {
		return &order.CreateResponse{
			Order: &order.Order{
				Status:         order.StatusReady,
				Authorizations: []string{},
				Finalize:       "https://ca.example.com/acme/order/1/finalize",
			},
			Location: "https://ca.example.com/acme/order/1",
		}, nil
	}
	mc.orderClient.finalizeFunc = func(ctx context.Context, req *order.FinalizeRequest) (*order.FinalizeResponse, error) {
		return &order.FinalizeResponse{
			Order:    &order.Order{Status: order.StatusProcessing},
			Location: "https://ca.example.com/acme/order/1",
		}, nil
	}
	mc.orderClient.getFunc = func(ctx context.Context, req *order.GetRequest) (*order.GetResponse, error) {
		return &order.GetResponse{
			Order: &order.Order{Status: order.StatusProcessing},
		}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	w := NewWorkflow(mc, WithPollTimeout(5*time.Second), WithPollInterval(10*time.Millisecond))
	_, err := w.RequestCertificate(ctx, &CertificateRequest{
		Domains:          []string{"example.com"},
		CSR:              []byte{0x30},
		ChallengeType:    "http-01",
		ChallengeHandler: noopHandler,
	})
	if err == nil {
		t.Fatal("expected error for canceled context")
	}
}

func TestRequestCertificate_MultipleDomains(t *testing.T) {
	mc := newMockClient()
	authzURLs := map[string]string{
		"https://ca.example.com/acme/authz/1": "example.com",
		"https://ca.example.com/acme/authz/2": "www.example.com",
	}

	mc.orderClient.createFunc = func(ctx context.Context, req *order.CreateRequest) (*order.CreateResponse, error) {
		if len(req.Identifiers) != 2 {
			t.Errorf("expected 2 identifiers, got %d", len(req.Identifiers))
		}
		return &order.CreateResponse{
			Order: &order.Order{
				Status:         order.StatusPending,
				Authorizations: []string{"https://ca.example.com/acme/authz/1", "https://ca.example.com/acme/authz/2"},
				Finalize:       "https://ca.example.com/acme/order/1/finalize",
			},
			Location: "https://ca.example.com/acme/order/1",
		}, nil
	}

	authzCalls := make(map[string]int)
	mc.authorizationClient.getFunc = func(ctx context.Context, req *authorization.GetRequest) (*authorization.GetResponse, error) {
		authzCalls[req.AuthorizationURL]++
		domain := authzURLs[req.AuthorizationURL]
		if authzCalls[req.AuthorizationURL] == 1 {
			return &authorization.GetResponse{
				Authorization: &authorization.Authorization{
					Identifier: authorization.Identifier{Type: "dns", Value: domain},
					Status:     authorization.StatusPending,
					Challenges: []authorization.Challenge{
						{Type: "http-01", URL: req.AuthorizationURL + "/chall", Token: "tok-" + domain},
					},
				},
			}, nil
		}
		return &authorization.GetResponse{
			Authorization: &authorization.Authorization{
				Identifier: authorization.Identifier{Type: "dns", Value: domain},
				Status:     authorization.StatusValid,
			},
		}, nil
	}
	mc.challengeClient.respondFunc = func(ctx context.Context, req *challenge.RespondRequest) (*challenge.RespondResponse, error) {
		return &challenge.RespondResponse{Challenge: &challenge.Challenge{Status: challenge.StatusProcessing}}, nil
	}
	mc.orderClient.finalizeFunc = func(ctx context.Context, req *order.FinalizeRequest) (*order.FinalizeResponse, error) {
		return &order.FinalizeResponse{
			Order:    &order.Order{Status: order.StatusProcessing, Certificate: "https://ca.example.com/acme/cert/1"},
			Location: "https://ca.example.com/acme/order/1",
		}, nil
	}
	mc.orderClient.getFunc = func(ctx context.Context, req *order.GetRequest) (*order.GetResponse, error) {
		return &order.GetResponse{
			Order: &order.Order{Status: order.StatusValid, Certificate: "https://ca.example.com/acme/cert/1"},
		}, nil
	}
	mc.certificateClient.getFunc = func(ctx context.Context, req *certificate.GetRequest) (*certificate.GetResponse, error) {
		return &certificate.GetResponse{Chain: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"}, nil
	}

	handlerDomains := make(map[string]bool)
	handler := ChallengeHandlerFunc(func(cType, token, keyAuth, domain string) (func(), error) {
		handlerDomains[domain] = true
		return func() {}, nil
	})

	w := NewWorkflow(mc, WithPollTimeout(5*time.Second), WithPollInterval(10*time.Millisecond))
	resp, err := w.RequestCertificate(context.Background(), &CertificateRequest{
		Domains:          []string{"example.com", "www.example.com"},
		CSR:              []byte{0x30},
		ChallengeType:    "http-01",
		ChallengeHandler: handler,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.CertificateChain == "" {
		t.Error("expected non-empty certificate chain")
	}
	if !handlerDomains["example.com"] || !handlerDomains["www.example.com"] {
		t.Errorf("expected handler called for both domains, got: %v", handlerDomains)
	}
}

func TestRequestCertificate_AuthorizationNilResponse(t *testing.T) {
	mc := newMockClient()
	mc.orderClient.createFunc = func(ctx context.Context, req *order.CreateRequest) (*order.CreateResponse, error) {
		return &order.CreateResponse{
			Order: &order.Order{
				Status:         order.StatusPending,
				Authorizations: []string{"https://ca.example.com/acme/authz/1"},
				Finalize:       "https://ca.example.com/acme/order/1/finalize",
			},
			Location: "https://ca.example.com/acme/order/1",
		}, nil
	}
	mc.authorizationClient.getFunc = func(ctx context.Context, req *authorization.GetRequest) (*authorization.GetResponse, error) {
		return &authorization.GetResponse{Authorization: nil}, nil
	}

	w := NewWorkflow(mc)
	_, err := w.RequestCertificate(context.Background(), &CertificateRequest{
		Domains:          []string{"example.com"},
		CSR:              []byte{0x30},
		ChallengeType:    "http-01",
		ChallengeHandler: noopHandler,
	})
	if err == nil {
		t.Fatal("expected error for nil authorization")
	}
}

func TestRequestCertificate_AuthorizationPollNilResponse(t *testing.T) {
	mc := newMockClient()
	authzCallCount := 0

	mc.orderClient.createFunc = func(ctx context.Context, req *order.CreateRequest) (*order.CreateResponse, error) {
		return &order.CreateResponse{
			Order: &order.Order{
				Status:         order.StatusPending,
				Authorizations: []string{"https://ca.example.com/acme/authz/1"},
				Finalize:       "https://ca.example.com/acme/order/1/finalize",
			},
			Location: "https://ca.example.com/acme/order/1",
		}, nil
	}
	mc.authorizationClient.getFunc = func(ctx context.Context, req *authorization.GetRequest) (*authorization.GetResponse, error) {
		authzCallCount++
		if authzCallCount == 1 {
			return &authorization.GetResponse{
				Authorization: &authorization.Authorization{
					Identifier: authorization.Identifier{Type: "dns", Value: "example.com"},
					Status:     authorization.StatusPending,
					Challenges: []authorization.Challenge{
						{Type: "http-01", URL: "https://ca.example.com/acme/chall/1", Token: "tok"},
					},
				},
			}, nil
		}
		return &authorization.GetResponse{Authorization: nil}, nil
	}
	mc.challengeClient.respondFunc = func(ctx context.Context, req *challenge.RespondRequest) (*challenge.RespondResponse, error) {
		return &challenge.RespondResponse{Challenge: &challenge.Challenge{Status: challenge.StatusProcessing}}, nil
	}

	w := NewWorkflow(mc, WithPollTimeout(5*time.Second), WithPollInterval(10*time.Millisecond))
	_, err := w.RequestCertificate(context.Background(), &CertificateRequest{
		Domains:          []string{"example.com"},
		CSR:              []byte{0x30},
		ChallengeType:    "http-01",
		ChallengeHandler: noopHandler,
	})
	if err == nil {
		t.Fatal("expected error for nil authorization during poll")
	}
}

// =============================================================================
// RevokeCertificate Tests
// =============================================================================

func TestRevokeCertificate_Success(t *testing.T) {
	mc := newMockClient()
	mc.certificateClient.revokeFunc = func(ctx context.Context, req *certificate.RevokeRequest) (*certificate.RevokeResponse, error) {
		if req.Certificate != "base64url-der-cert" {
			t.Errorf("unexpected certificate: %s", req.Certificate)
		}
		if req.Reason != certificate.ReasonKeyCompromise {
			t.Errorf("unexpected reason: %d", req.Reason)
		}
		return &certificate.RevokeResponse{}, nil
	}

	w := NewWorkflow(mc)
	err := w.RevokeCertificate(context.Background(), &RevokeRequest{
		Certificate: "base64url-der-cert",
		Reason:      1,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRevokeCertificate_NilRequest(t *testing.T) {
	mc := newMockClient()
	w := NewWorkflow(mc)
	err := w.RevokeCertificate(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil request")
	}
	if !errors.IsInvalidInput(err) {
		t.Errorf("expected invalid input error, got: %v", err)
	}
}

func TestRevokeCertificate_EmptyCertificate(t *testing.T) {
	mc := newMockClient()
	w := NewWorkflow(mc)
	err := w.RevokeCertificate(context.Background(), &RevokeRequest{})
	if err == nil {
		t.Fatal("expected error for empty certificate")
	}
	if !errors.IsInvalidInput(err) {
		t.Errorf("expected invalid input error, got: %v", err)
	}
}

func TestRevokeCertificate_TransportError(t *testing.T) {
	mc := newMockClient()
	mc.certificateClient.revokeFunc = func(ctx context.Context, req *certificate.RevokeRequest) (*certificate.RevokeResponse, error) {
		return nil, errors.NewACMEAlreadyRevoked("test", "already revoked")
	}

	w := NewWorkflow(mc)
	err := w.RevokeCertificate(context.Background(), &RevokeRequest{
		Certificate: "base64url-der-cert",
	})
	if err == nil {
		t.Fatal("expected error from revoke")
	}
	var revErr *RevocationError
	if !unwrapAs(err, &revErr) {
		t.Errorf("expected RevocationError, got: %T", err)
	}
}

// =============================================================================
// Error Type Tests
// =============================================================================

func TestErrors_RegistrationError(t *testing.T) {
	err := NewRegistrationError("test.op", "test message")
	if err.Error() == "" {
		t.Error("expected non-empty error string")
	}
	if err.Op != "test.op" {
		t.Errorf("unexpected op: %s", err.Op)
	}
}

func TestErrors_WrapRegistrationError(t *testing.T) {
	cause := errors.NewInternal("inner", "inner error")
	err := WrapRegistrationError(cause, "test.op", "wrapping")
	if err.Unwrap() != cause {
		t.Error("expected wrapped error to match cause")
	}
}

func TestErrors_AuthorizationError(t *testing.T) {
	err := NewAuthorizationError("test.op", "auth failed", "example.com", "https://ca/authz/1")
	if err.Domain != "example.com" {
		t.Errorf("unexpected domain: %s", err.Domain)
	}
	if err.AuthorizationURL != "https://ca/authz/1" {
		t.Errorf("unexpected authz URL: %s", err.AuthorizationURL)
	}
}

func TestErrors_WrapAuthorizationError(t *testing.T) {
	cause := errors.NewInternal("inner", "inner error")
	err := WrapAuthorizationError(cause, "test.op", "wrapping", "example.com", "https://ca/authz/1")
	if err.Unwrap() != cause {
		t.Error("expected wrapped error to match cause")
	}
}

func TestErrors_ChallengeError(t *testing.T) {
	err := NewChallengeError("test.op", "challenge failed", "example.com", "http-01", "https://ca/chall/1")
	if err.Domain != "example.com" {
		t.Errorf("unexpected domain: %s", err.Domain)
	}
	if err.ChallengeType != "http-01" {
		t.Errorf("unexpected challenge type: %s", err.ChallengeType)
	}
	if err.ChallengeURL != "https://ca/chall/1" {
		t.Errorf("unexpected challenge URL: %s", err.ChallengeURL)
	}
}

func TestErrors_WrapChallengeError(t *testing.T) {
	cause := errors.NewInternal("inner", "inner error")
	err := WrapChallengeError(cause, "test.op", "wrapping", "example.com", "http-01", "https://ca/chall/1")
	if err.Unwrap() != cause {
		t.Error("expected wrapped error to match cause")
	}
}

func TestErrors_FinalizationError(t *testing.T) {
	err := NewFinalizationError("test.op", "finalize failed", "https://ca/order/1")
	if err.OrderURL != "https://ca/order/1" {
		t.Errorf("unexpected order URL: %s", err.OrderURL)
	}
}

func TestErrors_WrapFinalizationError(t *testing.T) {
	cause := errors.NewInternal("inner", "inner error")
	err := WrapFinalizationError(cause, "test.op", "wrapping", "https://ca/order/1")
	if err.Unwrap() != cause {
		t.Error("expected wrapped error to match cause")
	}
}

func TestErrors_PollTimeoutError(t *testing.T) {
	err := NewPollTimeoutError("test.op", "timed out", "https://ca/order/1", "processing")
	if err.ResourceURL != "https://ca/order/1" {
		t.Errorf("unexpected resource URL: %s", err.ResourceURL)
	}
	if err.LastStatus != "processing" {
		t.Errorf("unexpected last status: %s", err.LastStatus)
	}
	if !errors.IsTimeout(err.CAError) {
		t.Error("expected timeout error code")
	}
}

func TestErrors_RevocationError(t *testing.T) {
	err := NewRevocationError("test.op", "revoke failed")
	if err.Error() == "" {
		t.Error("expected non-empty error string")
	}
}

func TestErrors_WrapRevocationError(t *testing.T) {
	cause := errors.NewInternal("inner", "inner error")
	err := WrapRevocationError(cause, "test.op", "wrapping")
	if err.Unwrap() != cause {
		t.Error("expected wrapped error to match cause")
	}
}

func TestErrors_NoChallengeError(t *testing.T) {
	err := NewNoChallengeError("test.op", "example.com", "tls-alpn-01")
	if err.Domain != "example.com" {
		t.Errorf("unexpected domain: %s", err.Domain)
	}
	if err.RequestedType != "tls-alpn-01" {
		t.Errorf("unexpected requested type: %s", err.RequestedType)
	}
	if !errors.IsNotFound(err.CAError) {
		t.Error("expected not found error code")
	}
}

// =============================================================================
// ChallengeHandlerFunc Tests
// =============================================================================

func TestChallengeHandlerFunc_Adapter(t *testing.T) {
	called := false
	var handler ChallengeHandler = ChallengeHandlerFunc(func(cType, token, keyAuth, domain string) (func(), error) {
		called = true
		if cType != "dns-01" {
			t.Errorf("unexpected challenge type: %s", cType)
		}
		if domain != "example.com" {
			t.Errorf("unexpected domain: %s", domain)
		}
		return func() {}, nil
	})

	cleanup, err := handler.Setup("dns-01", "token", "keyAuth", "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("expected handler function to be called")
	}
	if cleanup == nil {
		t.Error("expected non-nil cleanup function")
	}
}

// =============================================================================
// Poll Tests
// =============================================================================

func TestPoll_ImmediateSuccess(t *testing.T) {
	mc := newMockClient()
	w := NewWorkflow(mc, WithPollTimeout(5*time.Second), WithPollInterval(10*time.Millisecond))
	impl := w.(*workflow)

	err := impl.poll(context.Background(), func(ctx context.Context) (bool, error) {
		return true, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPoll_ImmediateError(t *testing.T) {
	mc := newMockClient()
	w := NewWorkflow(mc, WithPollTimeout(5*time.Second), WithPollInterval(10*time.Millisecond))
	impl := w.(*workflow)

	expected := errors.NewInternal("test", "poll error")
	err := impl.poll(context.Background(), func(ctx context.Context) (bool, error) {
		return false, expected
	})
	if err != expected {
		t.Errorf("expected poll error, got: %v", err)
	}
}

func TestPoll_EventualSuccess(t *testing.T) {
	mc := newMockClient()
	w := NewWorkflow(mc, WithPollTimeout(5*time.Second), WithPollInterval(10*time.Millisecond))
	impl := w.(*workflow)

	count := 0
	err := impl.poll(context.Background(), func(ctx context.Context) (bool, error) {
		count++
		return count >= 3, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count < 3 {
		t.Errorf("expected at least 3 poll attempts, got %d", count)
	}
}

func TestPoll_ContextCanceled(t *testing.T) {
	mc := newMockClient()
	w := NewWorkflow(mc, WithPollTimeout(5*time.Second), WithPollInterval(10*time.Millisecond))
	impl := w.(*workflow)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := impl.poll(ctx, func(ctx context.Context) (bool, error) {
		return false, nil
	})
	if err == nil {
		t.Fatal("expected error for canceled context")
	}
	if !errors.IsCanceled(err) {
		t.Errorf("expected canceled error, got: %v", err)
	}
}

func TestPoll_Timeout(t *testing.T) {
	mc := newMockClient()
	w := NewWorkflow(mc, WithPollTimeout(50*time.Millisecond), WithPollInterval(10*time.Millisecond))
	impl := w.(*workflow)

	err := impl.poll(context.Background(), func(ctx context.Context) (bool, error) {
		return false, nil
	})
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !errors.IsTimeout(err) {
		t.Errorf("expected timeout error, got: %v", err)
	}
}

// =============================================================================
// Helpers
// =============================================================================

// unwrapAs walks the error chain to find a target error type.
func unwrapAs[T error](err error, target *T) bool {
	for err != nil {
		if e, ok := err.(T); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
