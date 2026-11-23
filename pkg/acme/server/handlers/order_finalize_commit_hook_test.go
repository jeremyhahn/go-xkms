package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
)

// commitRecorder records every commit hook call: the error it was told
// about and the hook context it saw.
type commitRecorder struct {
	errs []error
	ctxs []*OrderFinalizeHookContext
}

func (r *commitRecorder) hook(ctx *OrderFinalizeHookContext, persistErr error) {
	r.errs = append(r.errs, persistErr)
	r.ctxs = append(r.ctxs, ctx)
}

type commitHookStore int

const (
	commitStoreWorking commitHookStore = iota
	commitStoreFailCert
	commitStoreFailOrder
)

// runTCGFinalizeWithCommitHook drives a TCG enrollment through
// finalizeTCGCSR (whose finalize hook records state, as a consumer such as
// go-trusted-platform does) and then sendFinalizeResponse against the
// given store. It returns the response, the commit hook record, the
// finalize hook's recorded state and the IDevID DER the CA issued.
func runTCGFinalizeWithCommitHook(t *testing.T, store commitHookStore) (*httptest.ResponseRecorder, *commitRecorder, int, []byte) {
	t.Helper()
	service, _, cleanup := setupTestService(t)
	t.Cleanup(cleanup)

	const (
		prodModel  = "xkms-node"
		prodSerial = "SN-2282"
	)
	iakDER := selfSignedDER(t, ca.IAKCommonName(prodModel, prodSerial), big.NewInt(41), 30*24*time.Hour)
	idevidDER := selfSignedDER(t, prodModel+"-"+prodSerial, big.NewInt(42), 60*24*time.Hour)
	setCA(t, service, &tcgEnrollmentCA{iakDER: iakDER, idevidDER: idevidDER})

	// The finalize hook stands in for a consumer that records the
	// enrollment before the certificate is persisted.
	recordedState := 0
	service.params.OrderFinalizeHooks = NewOrderFinalizeHookRegistry()
	service.params.OrderFinalizeHooks.Register(func(ctx *OrderFinalizeHookContext) error {
		recordedState++
		return nil
	})
	rec := &commitRecorder{}
	service.params.OrderFinalizeCommitHooks = NewOrderFinalizeCommitHookRegistry()
	service.params.OrderFinalizeCommitHooks.Register(rec.hook)

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady
	order.Identifiers = []entities.ACMEIdentifier{
		{Type: common.AuthzTypePermanentIdentifier, Value: prodModel + "-" + prodSerial},
	}

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	require.NoError(t, orderDAO.Save(ctx, order))

	csrDER := packTCGCSR(t, prodModel, prodSerial, selfSignedDER(t, "ek-"+prodSerial, big.NewInt(43), 365*24*time.Hour))
	req := httptest.NewRequest("POST", fmt.Sprintf("%s/acme/order/%d/finalize", service.baseRESTURI, order.ID), nil)

	serialNumber, pemBytes, hookCtx, err := service.finalizeTCGCSR("198.51.100.22:4444", csrDER, req, account, order, nil)
	require.NoError(t, err)
	require.NotNil(t, hookCtx, "finalizeTCGCSR returns the hook context it built")
	require.Equal(t, 1, recordedState, "the finalize hook runs before persistence")
	require.Empty(t, rec.errs, "the commit hook never runs before persistence")

	switch store {
	case commitStoreFailCert:
		service.storageFactory = &MockStorageFactory{
			realFactory:     service.storageFactory,
			failCertDAOSave: true,
		}
	case commitStoreFailOrder:
		mockFactory := &MockStorageFactory{
			realFactory:      service.storageFactory,
			failOrderDAOSave: true,
		}
		service.storageFactory = mockFactory
		orderDAO, err = mockFactory.OrderDAO(account.ID)
		require.NoError(t, err)
		if dao, ok := orderDAO.(*MockOrderDAO); ok {
			dao.saveFailOnCall = 1
		}
	}

	w := httptest.NewRecorder()
	service.sendFinalizeResponse(ctx, orderDAO, order, account, time.Now(), serialNumber, pemBytes, hookCtx, w)
	return w, rec, recordedState, idevidDER
}

func TestSendFinalizeResponse_TCGCommitHookAfterPersistence(t *testing.T) {
	w, rec, _, idevidDER := runTCGFinalizeWithCommitHook(t, commitStoreWorking)

	require.Equal(t, http.StatusOK, w.Code)
	require.Len(t, rec.errs, 1, "the commit hook runs once")
	assert.NoError(t, rec.errs[0], "both saves succeeded")
	require.NotNil(t, rec.ctxs[0])
	assert.True(t, rec.ctxs[0].IsTCGCSR)
	require.NotNil(t, rec.ctxs[0].TCGData)
	assert.Equal(t, idevidDER, rec.ctxs[0].TCGData.IDevIDCertificateDER)
}

func TestSendFinalizeResponse_TCGCommitHookOnCertificateSaveFailure(t *testing.T) {
	w, rec, _, _ := runTCGFinalizeWithCommitHook(t, commitStoreFailCert)

	assertErrorType(t, w, common.ErrTypeServerInternal, http.StatusInternalServerError)
	require.Len(t, rec.errs, 1, "the commit hook runs once")
	assert.Error(t, rec.errs[0], "the commit hook is told the certificate save failed")
	require.NotNil(t, rec.ctxs[0])
	assert.True(t, rec.ctxs[0].IsTCGCSR)
}

func TestSendFinalizeResponse_TCGCommitHookOnOrderSaveFailure(t *testing.T) {
	w, rec, _, _ := runTCGFinalizeWithCommitHook(t, commitStoreFailOrder)

	assertErrorType(t, w, common.ErrTypeServerInternal, http.StatusInternalServerError)
	require.Len(t, rec.errs, 1, "the commit hook runs once")
	assert.Error(t, rec.errs[0], "the commit hook is told the order save failed")
	require.NotNil(t, rec.ctxs[0])
	assert.True(t, rec.ctxs[0].IsTCGCSR)
}

func TestOrderFinalizeHandler_StandardCommitHookAfterSuccess(t *testing.T) {
	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	finalizeRan := false
	hooks := NewOrderFinalizeHookRegistry()
	hooks.Register(func(ctx *OrderFinalizeHookContext) error {
		finalizeRan = true
		return nil
	})
	rec := &commitRecorder{}
	commitHooks := NewOrderFinalizeCommitHookRegistry()
	commitHooks.Register(rec.hook)
	require.Equal(t, 1, commitHooks.Count())
	service.params = &Params{
		OrderFinalizeHooks:       hooks,
		OrderFinalizeCommitHooks: commitHooks,
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	require.NoError(t, orderDAO.Save(ctx, order))

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "example.com"},
		DNSNames: []string{"example.com"},
	}, csrKey)
	require.NoError(t, err)

	payload := OrderFinalizeRequest{CSR: base64.RawURLEncoding.EncodeToString(csrDER)}
	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)
	assert.True(t, finalizeRan)
	require.Len(t, rec.errs, 1, "the commit hook runs once")
	assert.NoError(t, rec.errs[0])
	require.NotNil(t, rec.ctxs[0])
	assert.False(t, rec.ctxs[0].IsTCGCSR)
	assert.NotNil(t, rec.ctxs[0].Certificate)
}
