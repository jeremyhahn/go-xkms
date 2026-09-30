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
	"context"
	"crypto/fips140"
	"errors"
	"log/slog"
	"os"
	"path/filepath"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"

	"github.com/jeremyhahn/go-xkms/pkg/daemon"
	initialize "github.com/jeremyhahn/go-xkms/pkg/init"
)

// AdminCredentialError reports a failure to write the bootstrap administrator's
// certificate or private key to disk.
type AdminCredentialError struct {
	Path string
	Err  error
}

// Error implements error.
func (e *AdminCredentialError) Error() string {
	return "server: writing admin credential to " + e.Path + ": " + e.Err.Error()
}

// Unwrap exposes the underlying cause.
func (e *AdminCredentialError) Unwrap() error { return e.Err }

// FirstBootError wraps a failure of the canonical first-boot bootstrap.
type FirstBootError struct {
	Op    string
	Cause error
}

// Error implements error.
func (e *FirstBootError) Error() string {
	return "server: first-boot " + e.Op + " failed: " + e.Cause.Error()
}

// Unwrap exposes the underlying cause for errors.Is / errors.As.
func (e *FirstBootError) Unwrap() error { return e.Cause }

// ErrFirstBootServicesUnavailable is returned when the embedded qrdb node
// exposes none of the identity services first-boot requires.
//
// It is a refusal rather than a skip: silently continuing would start a daemon
// with no system tenant, no roles and no administrator, which presents as an
// authentication failure at the first request rather than as the bootstrap
// having never run.
var ErrFirstBootServicesUnavailable = errors.New("server: qrdb node exposes no identity services for first-boot")

// runFirstBoot executes qrdb's canonical first-boot bootstrap against the
// embedded node.
//
// This is deliberately the SAME process qrdbd runs (go-qrdb cmd/qrdbd
// runFirstBoot) and that quicbaas runs (runBootstrapSystem): one system tenant,
// the built-in roles, one administrator, and the administrator's client
// certificate — created by qrdb, not by xkms. xkms adds exactly one thing on
// top, and it is not a second bootstrap: the FIDO2 and PIV login factors it
// registers into the node's factor registry, which qrdb defines the vocabulary
// for but does not implement.
//
// It calls FirstBootInitialize directly rather than BootstrapSystem, which is
// the one place xkms legitimately differs from qrdbd — and it is a difference in
// what has ALREADY happened, not in what gets created. BootstrapSystem's extra
// job is initializing and unsealing the system barrier; by the time this runs,
// initEmbeddedQRDBNode has adopted a node whose barrier is already unsealed and
// fails closed if it is not. Routing through BootstrapSystem would re-run a
// no-op against a barrier registry xkms wraps in its own type.
//
// It is idempotent: a node whose administrator already exists is a no-op, so
// this is safe on every start and on every node of a cluster.
func (s *Server) runFirstBoot(ctx context.Context) error {
	if s.qrdbNode == nil {
		// No embedded node: this deployment stores identity elsewhere and has
		// no first-boot of its own to run.
		return nil
	}

	deps, err := BuildFirstBootDependencies(s.qrdbNode, FirstBootParams{
		CA:          s.ca,
		TrustDomain: s.firstBootTrustDomain(),
		Logger:      s.logger,
	})
	if err != nil {
		return err
	}

	// On a cluster, first-boot runs on every node concurrently while the
	// initial leader election is still settling. The service layer answers
	// "not leader" until a leader is known (and forwards afterwards), so a
	// not-leader failure here is transient by construction: retry with
	// backoff until the election settles or the deadline expires. Once the
	// leader's first-boot replicates, the idempotent initialize becomes a
	// no-op on every follower.
	result, err := s.firstBootWithLeaderRetry(ctx, deps)
	if err != nil {
		return &FirstBootError{Op: "initialize", Cause: err}
	}

	if result != nil && result.AdminCreated {
		s.logger.Info("first-boot: system tenant, roles and administrator created",
			slog.String("admin_thumbprint", result.AdminCertThumbprint))
	}

	if err := s.persistAdminCredential(result); err != nil {
		return &FirstBootError{Op: "persist admin credential", Cause: err}
	}

	return nil
}

// FirstBootParams bundles what BuildFirstBootDependencies / RunFirstBoot need
// beyond the node itself.
type FirstBootParams struct {
	// CA issues the administrator's certificate (Path A: generate-and-distribute).
	// A nil CA is not a silent downgrade: first-boot then creates the
	// administrator without a bound certificate and the operator enrolls one
	// afterwards, which is the documented behaviour when no CA is injected.
	CA initialize.CeremonyCA

	// TrustDomain is the SPIFFE trust domain stamped onto the administrator's
	// certificate. Empty stamps none.
	TrustDomain string

	// Logger receives first-boot events. Required.
	Logger *slog.Logger
}

// BuildFirstBootDependencies projects an already-open embedded qrdb node and
// a CA onto the qrdbsdk.FirstBootDependencies FirstBootInitialize needs. It is
// the exported, Server-independent core of (*Server).runFirstBoot's
// dependency wiring, shared by RunFirstBoot (the standalone form xkmsd init
// uses) and (*Server).runFirstBoot (which wraps the same dependencies in the
// cluster not-leader retry).
func BuildFirstBootDependencies(node *qrdbnode.Node, p FirstBootParams) (qrdbsdk.FirstBootDependencies, error) {
	svcs := node.Services()
	if svcs == nil || svcs.Tenant == nil || svcs.User == nil || svcs.Role == nil {
		return qrdbsdk.FirstBootDependencies{}, ErrFirstBootServicesUnavailable
	}

	deps := qrdbsdk.FirstBootDependencies{
		Tenants: svcs.Tenant,
		Users:   svcs.User,
		Roles:   svcs.Role,
		Logger:  p.Logger,

		// Binder pins the issued admin certificate's SPKI thumbprint to the
		// admin user record via the same UserServicer first-boot already
		// creates the user through, so a subsequent mTLS handshake -- and
		// the durable node's UserByCertThumbprint / GetUserByCertThumbprint
		// lookup this package's own callers use to resolve the admin's
		// numeric userID -- both resolve to the administrator. Without a
		// Binder the seam docs call out exactly this: "the cert is issued
		// but not bound".
		Binder: userCertBinder{users: svcs.User},

		// SeparationOfDuties follows the daemon's compliance posture, derived
		// the same way qrdbd derives it (cmd/qrdbd: fips140.Enabled() ||
		// config). xkms exposes no separate config knob, so FIPS mode is the
		// whole signal here; adding one is a config change, not a bootstrap
		// decision.
		//
		// Under strict separation the bootstrap admin receives only the
		// Admin@system grant and is NOT also made Owner, so the FIPS 140-3 /
		// PCI-DSS least-privilege split survives bootstrap.
		SeparationOfDuties: fips140.Enabled(),
	}

	// The administrator's certificate comes from xkms's TrustedCA, wrapped in
	// the firstboot adapter that already implements both of qrdb's seams:
	// GenerateAdminCert (Path A) and SignAdminCSR (Path B). This is the
	// ownership chain the architecture prescribes — qrdb owns the bootstrap,
	// xkms owns the CA that issues for it — and it is why the node's own
	// CertProv is deliberately NOT used: that is qrdb's dev/single-node
	// fallback, and a deployment running xkms has a production CA.
	if p.CA != nil {
		adapter := initialize.NewCAAdapter(p.CA, p.TrustDomain)
		deps.CA = adapter
		deps.Signer = adapter
	}

	return deps, nil
}

// userCertBinder adapts qrdbsdk.UserServicer.AddCertBinding to the narrow
// qrdbsdk.CertBinder seam BuildFirstBootDependencies wires into first-boot.
// notAfterUnix is always 0 (never expires): the administrator's bootstrap
// certificate is a long-lived credential with rotation handled like any other
// admin cert, not a time-boxed one.
type userCertBinder struct {
	users qrdbsdk.UserServicer
}

// BindAdminCert implements qrdbsdk.CertBinder.
func (b userCertBinder) BindAdminCert(ctx context.Context, _ string, userID uint64, thumbprint string) error {
	_, err := b.users.AddCertBinding(ctx, userID, thumbprint, 0)
	return err
}

// RunFirstBoot executes qrdb's canonical first-boot bootstrap against an
// already-open, unsealed embedded node: one system tenant, the built-in
// roles, one administrator, and the administrator's client certificate --
// created by qrdb, not by xkms. xkms adds exactly one thing on top, and it is
// not a second bootstrap: the FIDO2 and PIV login factors it registers into
// the node's factor registry, which qrdb defines the vocabulary for but does
// not implement.
//
// It is idempotent: a node whose administrator already exists is a no-op.
// This is the standalone form (no cluster not-leader retry) xkmsd init calls,
// which now runs first-boot itself against the durable node it just opened,
// so the admin's login factors can be persisted immediately.
// (*Server).runFirstBoot (kept as a safety net for a deployment that runs
// `xkmsd run` directly without `xkmsd init` first) reaches the same
// dependency wiring through BuildFirstBootDependencies and adds the cluster
// retry.
func RunFirstBoot(ctx context.Context, node *qrdbnode.Node, p FirstBootParams) (*qrdbsdk.FirstBootResult, error) {
	deps, err := BuildFirstBootDependencies(node, p)
	if err != nil {
		return nil, err
	}
	result, err := firstBootInitialize(ctx, deps)
	if err != nil {
		return nil, &FirstBootError{Op: "initialize", Cause: err}
	}
	return result, nil
}

// firstBootInitialize indirects qrdbsdk.FirstBootInitialize so the retry
// loop is unit-testable; production always uses the SDK function.
var firstBootInitialize = qrdbsdk.FirstBootInitialize

// firstBootWithLeaderRetry runs FirstBootInitialize under the boot-time
// leader retry (leader_retry.go).
func (s *Server) firstBootWithLeaderRetry(ctx context.Context, deps qrdbsdk.FirstBootDependencies) (*qrdbsdk.FirstBootResult, error) {
	var result *qrdbsdk.FirstBootResult
	err := retryNotLeader(ctx, s.logger, "first-boot", func() error {
		var innerErr error
		result, innerErr = firstBootInitialize(ctx, deps)
		return innerErr
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Admin credential filenames, matching the names qrdbd writes so an operator
// finds the same two files whichever daemon of the stack they bootstrapped.
const (
	adminCertFilename = "admin-cert.pem"
	adminKeyFilename  = "admin-key.pem"
)

// persistAdminCredential writes the administrator's certificate and private key
// into the data directory.
//
// Without this the bootstrap is self-defeating: first-boot creates the only
// account on the daemon and binds a certificate to it, adaptive authentication
// stops serving anonymous requests the moment that account exists, and the one
// credential that could authenticate would be discarded when this function
// returned — leaving a daemon nobody can log into.
//
// It is idempotent in the same way qrdbd's is: if both files are already there
// they are left alone, so a restart never overwrites the credential an operator
// has already taken delivery of.
func (s *Server) persistAdminCredential(result *qrdbsdk.FirstBootResult) error {
	return PersistAdminCredential(s.config.Datastore.Path, result, s.logger)
}

// PersistAdminCredential writes the administrator's certificate and private
// key into dataDir. It is the exported, Server-independent form of
// (*Server).persistAdminCredential, shared with xkmsd init: since first-boot
// now runs there (against the durable node it just opened), init is what
// must write admin-cert.pem / admin-key.pem, not (*Server).runFirstBoot --
// which sees AdminCreated == false on every later `xkmsd run` and would
// otherwise never write them.
//
// Without this the bootstrap is self-defeating: first-boot creates the only
// account on the daemon and binds a certificate to it, adaptive authentication
// stops serving anonymous requests the moment that account exists, and the one
// credential that could authenticate would be discarded when this function
// returned — leaving a daemon nobody can log into.
//
// It is idempotent in the same way qrdbd's is: if both files are already there
// they are left alone, so a restart never overwrites the credential an operator
// has already taken delivery of.
func PersistAdminCredential(dataDir string, result *qrdbsdk.FirstBootResult, logger *slog.Logger) error {
	if result == nil || len(result.AdminCertPEM) == 0 || len(result.AdminKeyPEM) == 0 {
		// No credential was issued — first-boot ran without a CA, the admin
		// already existed on an earlier boot, or Path B left the key with the
		// admin. A newly created admin with a cert but no key is the one
		// combination that must not pass silently: generate-and-distribute
		// exists to deliver the key, and losing it here strands the operator.
		if result != nil && result.AdminCreated && len(result.AdminCertPEM) > 0 && len(result.AdminKeyPEM) == 0 {
			logger.Warn("first-boot: admin certificate issued without a distributable key; no credential persisted",
				slog.String("thumbprint", result.AdminCertThumbprint))
		}
		return nil
	}

	if dataDir == "" {
		// An in-memory deployment has no directory to write to. The credential
		// is reported rather than dropped silently, because it is the only way
		// in and it does not survive this process.
		logger.Warn("first-boot: no storage path configured; the admin credential cannot be persisted",
			slog.String("thumbprint", result.AdminCertThumbprint))
		return nil
	}

	certPath := filepath.Join(dataDir, adminCertFilename)
	keyPath := filepath.Join(dataDir, adminKeyFilename)

	if fileExists(certPath) && fileExists(keyPath) {
		logger.Info("first-boot: admin credential already present", slog.String("cert", certPath))
		return nil
	}

	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return &AdminCredentialError{Path: dataDir, Err: err}
	}
	if err := os.WriteFile(certPath, result.AdminCertPEM, 0o644); err != nil { // #nosec G306 -- a certificate is public
		return &AdminCredentialError{Path: certPath, Err: err}
	}
	// The private key is owner-read-only: it authenticates as the highest
	// privilege account on the daemon.
	if err := os.WriteFile(keyPath, result.AdminKeyPEM, 0o600); err != nil {
		return &AdminCredentialError{Path: keyPath, Err: err}
	}

	logger.Info("first-boot: admin credential written",
		slog.String("cert", certPath),
		slog.String("key", keyPath))
	return nil
}

// fileExists reports whether path names an existing file.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// firstBootTrustDomain returns the SPIFFE trust domain stamped into the
// administrator's certificate.
//
// It reuses the operator's cluster enrollment trust domain so a node
// certificate and an administrator certificate issued by the same deployment
// live in one trust domain; a deployment that has not configured one gets the
// same default the enrollment path uses, rather than an empty domain that would
// produce an unusable SPIFFE ID.
func (s *Server) firstBootTrustDomain() string {
	if td := s.config.Cluster.RaftEnrollment.TrustDomain; td != "" {
		return td
	}
	return daemon.DefaultTrustDomain
}
