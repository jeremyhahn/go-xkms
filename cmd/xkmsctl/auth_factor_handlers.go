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

// auth_factor_handlers.go wires the canonical "auth login" and "auth
// factor" subcommands to the qrdb SDK user-side AuthFactor service
// (M14, accessed via UserAuthFactorClient). xkms (layer 3) sits below
// quicbaas (layer 4), so xkmsctl cannot import go-quicbaas without
// inverting the dependency graph; instead, it delegates directly to
// go-qrdb's user-side AuthFactor transport (the same underlying
// primitive that quicbaas SDK re-exports as
// Security().Auth().Factors()).
package main

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// validFactorTypes is the canonical "--type" set per
// docs/08-bootstrap-auth-architecture.md §5e.
var validFactorTypes = map[string]struct{}{
	"mtls":   {},
	"fido2":  {},
	"piv":    {},
	"pkcs11": {},
}

// validAuthMethods is the canonical "--method" set per
// docs/08-bootstrap-auth-architecture.md §5e.
var validAuthMethods = map[string]struct{}{
	"mtls":   {},
	"fido2":  {},
	"piv":    {},
	"pkcs11": {},
}

// ---------------------------------------------------------------------------
// Typed errors
// ---------------------------------------------------------------------------

// MissingFactorIDError is returned when a factor subcommand requires a
// positional <factor-id> argument and none was supplied.
type MissingFactorIDError struct {
	Op string
}

// Error returns a human-readable description.
func (e *MissingFactorIDError) Error() string {
	return e.Op + ": factor id is required"
}

// MissingLabelError is returned when --label is required and missing.
type MissingLabelError struct {
	Op string
}

// Error returns a human-readable description.
func (e *MissingLabelError) Error() string {
	return e.Op + ": --label is required"
}

// MissingUserError is returned when --user is required and missing.
type MissingUserError struct {
	Op string
}

// Error returns a human-readable description.
func (e *MissingUserError) Error() string {
	return e.Op + ": --user is required"
}

// InvalidUserIDError is returned when --user cannot be parsed as a
// uint64. The user-side AuthFactor service uses uint64 user identifiers.
type InvalidUserIDError struct {
	Value string
	Cause error
}

// Error returns a human-readable description.
func (e *InvalidUserIDError) Error() string {
	return "invalid --user " + e.Value + " (must be a numeric user id): " + e.Cause.Error()
}

// Unwrap returns the wrapped cause for errors.Is/As.
func (e *InvalidUserIDError) Unwrap() error { return e.Cause }

// InvalidFactorTypeError is returned when --type is not one of the
// canonical factor types.
type InvalidFactorTypeError struct {
	Type string
}

// Error returns a human-readable description.
func (e *InvalidFactorTypeError) Error() string {
	return "invalid --type " + e.Type + " (must be one of: mtls, fido2, piv, pkcs11)"
}

// InvalidAuthMethodError is returned when --method is not one of the
// canonical auth methods.
type InvalidAuthMethodError struct {
	Method string
}

// Error returns a human-readable description.
func (e *InvalidAuthMethodError) Error() string {
	return "invalid --method " + e.Method + " (must be one of: mtls, fido2, piv, pkcs11)"
}

// MissingCertPathError is returned when "--type mtls" is selected but
// --cert was not supplied.
type MissingCertPathError struct{}

// Error returns a human-readable description.
func (e *MissingCertPathError) Error() string {
	return "auth factor add --type mtls: --cert <path> is required"
}

// MissingCredentialError is returned when --type fido2|piv|pkcs11 is
// selected for an operation that requires the credential bytes and no
// source for them was supplied.
type MissingCredentialError struct {
	Type string
}

// Error returns a human-readable description.
func (e *MissingCredentialError) Error() string {
	return "auth factor add --type " + e.Type + ": --credential-hex <hex> is required (FIDO2 credentialID / PIV slot cert hash / PKCS#11 SPKI SHA-256)"
}

// CertReadError wraps errors raised while reading or parsing a cert
// PEM file.
type CertReadError struct {
	Path  string
	Cause error
}

// Error returns a human-readable description.
func (e *CertReadError) Error() string {
	if e.Path == "" {
		return "cert read error: " + e.Cause.Error()
	}
	return "cert read error (" + e.Path + "): " + e.Cause.Error()
}

// Unwrap returns the wrapped cause for errors.Is/As.
func (e *CertReadError) Unwrap() error { return e.Cause }

// InvalidCredentialHexError is returned when --credential-hex cannot be
// decoded as a hex string.
type InvalidCredentialHexError struct {
	Cause error
}

// Error returns a human-readable description.
func (e *InvalidCredentialHexError) Error() string {
	return "invalid --credential-hex: " + e.Cause.Error()
}

// Unwrap returns the wrapped cause for errors.Is/As.
func (e *InvalidCredentialHexError) Unwrap() error { return e.Cause }

// AuthFactorMissingClientError is returned when the qrdb SDK user-side
// AuthFactor client has not been wired (e.g., during tests that don't
// construct a transport).
type AuthFactorMissingClientError struct{}

// Error returns a human-readable description.
func (e *AuthFactorMissingClientError) Error() string {
	return "auth factor: qrdb SDK user-side AuthFactor client is not configured (set --qrdb-server or use the embedded test transport)"
}

// ---------------------------------------------------------------------------
// SDK client wiring
// ---------------------------------------------------------------------------

// UserAuthFactorClientFactory builds a qrdb SDK user-side AuthFactor
// client (M14) suitable for issuing factor commands. The default
// factory dials the qrdb server using the global xkmsctl config; tests
// override it.
type UserAuthFactorClientFactory func(ctx context.Context) (qrdbtransport.UserAuthFactorClient, func() error, error)

// userAuthFactorClientFactory is the active factory used by handlers.
// Tests can override this to inject an in-process embedded client.
var userAuthFactorClientFactory UserAuthFactorClientFactory = defaultUserAuthFactorClientFactory

// defaultUserAuthFactorClientFactory builds a client against xkmsd's
// auth-factor endpoints, which proxy the embedded qrdb node.
//
// The CLI reaches identity through the server it already talks to rather than
// a second connection to qrdb: xkmsd holds the node, and factor state stays
// qrdb's either way. When no server is configured the factory reports
// AuthFactorMissingClientError so the caller sees a clear operator-facing
// message instead of a stack trace.
func defaultUserAuthFactorClientFactory(_ context.Context) (qrdbtransport.UserAuthFactorClient, func() error, error) {
	cfg := getConfig()
	if cfg == nil || cfg.Server == "" {
		return nil, nil, &AuthFactorMissingClientError{}
	}

	client, err := newAuthFactorRESTClient(cfg)
	if err != nil {
		return nil, nil, err
	}

	// The HTTP client owns no long-lived resource that needs releasing; the
	// closer exists so callers can keep one uniform shape.
	return client, func() error { return nil }, nil
}

// SetUserAuthFactorClientFactory replaces the active factory. Intended
// for tests; production code should not call this.
func SetUserAuthFactorClientFactory(f UserAuthFactorClientFactory) func() {
	prev := userAuthFactorClientFactory
	userAuthFactorClientFactory = f
	return func() { userAuthFactorClientFactory = prev }
}

// userAuthFactorClient resolves the active factory, opens a client,
// and returns it together with a close function that the caller must
// invoke before returning.
func userAuthFactorClient(ctx context.Context) (qrdbtransport.UserAuthFactorClient, func() error, error) {
	if userAuthFactorClientFactory == nil {
		return nil, nil, &AuthFactorMissingClientError{}
	}
	return userAuthFactorClientFactory(ctx)
}

// ---------------------------------------------------------------------------
// Flag struct
// ---------------------------------------------------------------------------

// authFactorAddFlags consolidates the type-agnostic + type-specific
// "auth factor add" flag set.
type authFactorAddFlags struct {
	factorType    string
	label         string
	user          string
	createdBy     string
	certPath      string
	credentialHex string
	fido2Device   string
	pivReader     string
	pivSlot       string
	pkcs11Slot    string
	pkcs11Label   string
}

// ---------------------------------------------------------------------------
// Login + factor command builders
// ---------------------------------------------------------------------------

// newAuthLoginRunCmd implements "auth login [--method] [--cert]
// [--credential-hex]" against the qrdb user-side AuthFactor transport.
func newAuthLoginRunCmd() *cobra.Command {
	var (
		method   string
		certPath string
		credHex  string
	)
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate the active session",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runXKMSAuthLogin(cmd.Context(), method, certPath, credHex)
		},
	}
	cmd.Flags().StringVar(&method, "method", "", "Auth method: mtls | fido2 | piv | pkcs11 (required)")
	cmd.Flags().StringVar(&certPath, "cert", "", "Certificate PEM path (--method mtls)")
	cmd.Flags().StringVar(&credHex, "credential-hex", "", "Credential bytes as hex (--method fido2|piv|pkcs11)")
	return cmd
}

// newAuthFactorListRunCmd implements "auth factor list --user <id>".
func newAuthFactorListRunCmd() *cobra.Command {
	var user string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List enrolled factors for a user",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runXKMSAuthFactorList(cmd.Context(), user)
		},
	}
	cmd.Flags().StringVar(&user, "user", "", "Numeric user id (required)")
	return cmd
}

// newAuthFactorAddRunCmd implements "auth factor add".
func newAuthFactorAddRunCmd() *cobra.Command {
	flags := authFactorAddFlags{}
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Enroll a new factor",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runXKMSAuthFactorAdd(cmd.Context(), &flags)
		},
	}
	bindAuthFactorAddFlags(cmd, &flags)
	return cmd
}

// newAuthFactorRemoveRunCmd implements "auth factor remove
// <factor-id> [--force]".
func newAuthFactorRemoveRunCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "remove <factor-id>",
		Short: "Remove an enrolled factor",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return &MissingFactorIDError{Op: "auth factor remove"}
			}
			return runXKMSAuthFactorRemove(cmd.Context(), args[0], force)
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "Allow removing the last factor (admin)")
	return cmd
}

// newAuthFactorRotateRunCmd implements "auth factor rotate
// <factor-id> --type <t> --label <name>".
func newAuthFactorRotateRunCmd() *cobra.Command {
	flags := authFactorAddFlags{}
	cmd := &cobra.Command{
		Use:   "rotate <factor-id>",
		Short: "Rotate an enrolled factor",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return &MissingFactorIDError{Op: "auth factor rotate"}
			}
			return runXKMSAuthFactorRotate(cmd.Context(), args[0], &flags)
		},
	}
	bindAuthFactorAddFlags(cmd, &flags)
	return cmd
}

// newAuthFactorRelabelRunCmd implements "auth factor relabel
// <factor-id> --label <name>" against the M14 RelabelAuthFactor RPC.
func newAuthFactorRelabelRunCmd() *cobra.Command {
	var label string
	cmd := &cobra.Command{
		Use:   "relabel <factor-id>",
		Short: "Relabel an enrolled factor",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return &MissingFactorIDError{Op: "auth factor relabel"}
			}
			if label == "" {
				return &MissingLabelError{Op: "auth factor relabel"}
			}
			return runXKMSAuthFactorRelabel(cmd.Context(), args[0], label)
		},
	}
	cmd.Flags().StringVar(&label, "label", "", "New human-readable label (required)")
	return cmd
}

// bindAuthFactorAddFlags wires the canonical add/rotate flag set onto
// a cobra command.
func bindAuthFactorAddFlags(cmd *cobra.Command, f *authFactorAddFlags) {
	cmd.Flags().StringVar(&f.factorType, "type", "", "Factor type: mtls | fido2 | piv | pkcs11 (required)")
	cmd.Flags().StringVar(&f.label, "label", "", "Human-readable factor label (required)")
	cmd.Flags().StringVar(&f.user, "user", "", "Numeric user id (required for add; inherited for rotate)")
	cmd.Flags().StringVar(&f.createdBy, "created-by", "self", "Provenance string: self | admin | ceremony")
	cmd.Flags().StringVar(&f.certPath, "cert", "", "Certificate PEM path (--type mtls)")
	cmd.Flags().StringVar(&f.credentialHex, "credential-hex", "", "Credential bytes as hex (--type fido2|piv|pkcs11)")
	cmd.Flags().StringVar(&f.fido2Device, "device", "", "FIDO2 device id metadata (--type fido2)")
	cmd.Flags().StringVar(&f.pivReader, "reader", "", "PC/SC reader name metadata (--type piv)")
	cmd.Flags().StringVar(&f.pivSlot, "slot", "9a", "PIV slot id metadata (--type piv; default 9a)")
	cmd.Flags().StringVar(&f.pkcs11Slot, "pkcs11-slot", "", "PKCS#11 slot id metadata (--type pkcs11)")
	cmd.Flags().StringVar(&f.pkcs11Label, "pkcs11-label", "", "PKCS#11 object label metadata (--type pkcs11)")
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// runXKMSAuthFactorList lists enrolled factors for the given user.
func runXKMSAuthFactorList(ctx context.Context, user string) error {
	if user == "" {
		return &MissingUserError{Op: "auth factor list"}
	}
	userID, err := parseUserID(user)
	if err != nil {
		return err
	}
	cl, closeFn, err := userAuthFactorClient(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = invokeClose(closeFn) }()

	resp, err := cl.ListAuthFactors(ctx, &qrdbtransport.AuthFactorListRequest{UserID: userID})
	if err != nil {
		return err
	}

	out := os.Stdout
	if len(resp.Factors) == 0 {
		_, _ = fmt.Fprintln(out, "(no enrolled factors)")
		return nil
	}
	_, _ = fmt.Fprintln(out, "ID\tTYPE\tUSER\tLABEL\tREGISTERED\tREVOKED")
	for _, f := range resp.Factors {
		revoked := "-"
		if f.RevokedAt != nil {
			revoked = f.RevokedAt.Format("2006-01-02T15:04:05Z")
		}
		_, _ = fmt.Fprintf(out, "%s\t%s\t%d\t%s\t%s\t%s\n",
			f.ID,
			f.Type,
			f.UserID,
			f.Label,
			f.RegisteredAt.Format("2006-01-02T15:04:05Z"),
			revoked,
		)
	}
	return nil
}

// runXKMSAuthFactorAdd enrolls a new factor.
func runXKMSAuthFactorAdd(ctx context.Context, f *authFactorAddFlags) error {
	if f.user == "" {
		return &MissingUserError{Op: "auth factor add"}
	}
	userID, err := parseUserID(f.user)
	if err != nil {
		return err
	}
	cl, closeFn, err := userAuthFactorClient(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = invokeClose(closeFn) }()

	req, err := buildXKMSAddRequest(userID, f)
	if err != nil {
		return err
	}
	resp, err := cl.AddAuthFactor(ctx, req)
	if err != nil {
		return err
	}
	printXKMSFactorRecord(&resp.Factor)
	return nil
}

// runXKMSAuthFactorRemove revokes a factor.
func runXKMSAuthFactorRemove(ctx context.Context, factorID string, force bool) error {
	if factorID == "" {
		return &MissingFactorIDError{Op: "auth factor remove"}
	}
	cl, closeFn, err := userAuthFactorClient(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = invokeClose(closeFn) }()

	if _, err := cl.RemoveAuthFactor(ctx, &qrdbtransport.AuthFactorRemoveRequest{
		FactorID: factorID,
		Force:    force,
	}); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(os.Stdout, "OK")
	return nil
}

// runXKMSAuthFactorRotate atomically rotates a factor via the M14
// RotateAuthFactor RPC.
func runXKMSAuthFactorRotate(ctx context.Context, oldID string, f *authFactorAddFlags) error {
	if oldID == "" {
		return &MissingFactorIDError{Op: "auth factor rotate"}
	}
	var userID uint64
	if f.user != "" {
		parsed, err := parseUserID(f.user)
		if err != nil {
			return err
		}
		userID = parsed
	}
	cl, closeFn, err := userAuthFactorClient(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = invokeClose(closeFn) }()

	addReq, err := buildXKMSAddRequest(userID, f)
	if err != nil {
		return err
	}
	resp, err := cl.RotateAuthFactor(ctx, &qrdbtransport.AuthFactorRotateRequest{
		OldFactorID: oldID,
		NewFactor:   *addReq,
	})
	if err != nil {
		return err
	}
	out := os.Stdout
	_, _ = fmt.Fprintf(out, "Old factor revoked: %s\n", oldID)
	printXKMSFactorRecord(&resp.NewFactor)
	return nil
}

// runXKMSAuthFactorRelabel renames a factor via the M14
// RelabelAuthFactor RPC.
func runXKMSAuthFactorRelabel(ctx context.Context, factorID, label string) error {
	cl, closeFn, err := userAuthFactorClient(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = invokeClose(closeFn) }()

	resp, err := cl.RelabelAuthFactor(ctx, &qrdbtransport.AuthFactorRelabelRequest{
		FactorID: factorID,
		Label:    label,
	})
	if err != nil {
		return err
	}
	printXKMSFactorRecord(&resp.Factor)
	return nil
}

// runXKMSAuthLogin resolves an inbound (method, lookup-key) tuple to a
// principal via the M14 LoginAuthFactor RPC. Hardware verification is
// performed by the caller; this RPC only does the database mapping.
func runXKMSAuthLogin(ctx context.Context, method, certPath, credHex string) error {
	if method == "" {
		return &InvalidAuthMethodError{Method: ""}
	}
	if _, ok := validAuthMethods[method]; !ok {
		return &InvalidAuthMethodError{Method: method}
	}
	lookupKey, err := buildXKMSLoginLookupKey(method, certPath, credHex)
	if err != nil {
		return err
	}
	cl, closeFn, err := userAuthFactorClient(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = invokeClose(closeFn) }()

	resp, err := cl.LoginAuthFactor(ctx, &qrdbtransport.AuthFactorLoginRequest{
		Type:      method,
		LookupKey: lookupKey,
	})
	if err != nil {
		return err
	}
	out := os.Stdout
	_, _ = fmt.Fprintf(out, "User ID:   %d\n", resp.UserID)
	_, _ = fmt.Fprintf(out, "Username:  %s\n", resp.Username)
	if resp.Email != "" {
		_, _ = fmt.Fprintf(out, "Email:     %s\n", resp.Email)
	}
	if resp.TenantID != "" {
		_, _ = fmt.Fprintf(out, "Tenant:    %s\n", resp.TenantID)
	}
	_, _ = fmt.Fprintf(out, "Active:    %t\n", resp.Active)
	if len(resp.Roles) > 0 {
		_, _ = fmt.Fprintf(out, "Roles:     %v\n", resp.Roles)
	}
	_, _ = fmt.Fprintf(out, "Factor ID: %s\n", resp.Factor.ID)
	_, _ = fmt.Fprintf(out, "Factor:    %s (%s)\n", resp.Factor.Label, resp.Factor.Type)
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// printXKMSFactorRecord renders an AuthFactorRecord to stdout.
func printXKMSFactorRecord(rec *qrdbtransport.AuthFactorRecord) {
	out := os.Stdout
	_, _ = fmt.Fprintf(out, "ID:            %s\n", rec.ID)
	_, _ = fmt.Fprintf(out, "Type:          %s\n", rec.Type)
	_, _ = fmt.Fprintf(out, "User:          %d\n", rec.UserID)
	if rec.Label != "" {
		_, _ = fmt.Fprintf(out, "Label:         %s\n", rec.Label)
	}
	_, _ = fmt.Fprintf(out, "Registered At: %s\n", rec.RegisteredAt.Format("2006-01-02T15:04:05Z"))
	if rec.RevokedAt != nil {
		_, _ = fmt.Fprintf(out, "Revoked At:    %s\n", rec.RevokedAt.Format("2006-01-02T15:04:05Z"))
	}
	if rec.CreatedBy != "" {
		_, _ = fmt.Fprintf(out, "Created By:    %s\n", rec.CreatedBy)
	}
}

// buildXKMSAddRequest validates the canonical add/rotate flag set and
// builds an AuthFactorAddRequest with type-specific Credential and
// Metadata.
func buildXKMSAddRequest(userID uint64, f *authFactorAddFlags) (*qrdbtransport.AuthFactorAddRequest, error) {
	if f.factorType == "" {
		return nil, &InvalidFactorTypeError{Type: ""}
	}
	if _, ok := validFactorTypes[f.factorType]; !ok {
		return nil, &InvalidFactorTypeError{Type: f.factorType}
	}
	if f.label == "" {
		return nil, &MissingLabelError{Op: "auth factor add"}
	}

	credential, metadata, err := xkmsCredentialAndMetadata(f)
	if err != nil {
		return nil, err
	}

	return &qrdbtransport.AuthFactorAddRequest{
		UserID:     userID,
		Type:       f.factorType,
		Label:      f.label,
		Credential: credential,
		Metadata:   metadata,
		CreatedBy:  f.createdBy,
	}, nil
}

// xkmsCredentialAndMetadata derives the canonical credential lookup
// key bytes and the type-specific metadata map.
func xkmsCredentialAndMetadata(f *authFactorAddFlags) ([]byte, map[string]string, error) {
	metadata := map[string]string{}
	switch f.factorType {
	case "mtls":
		if f.certPath == "" {
			return nil, nil, &MissingCertPathError{}
		}
		credBytes, certMeta, err := xkmsLoadCertCredentialAndMetadata(f.certPath)
		if err != nil {
			return nil, nil, err
		}
		for k, v := range certMeta {
			metadata[k] = v
		}
		return credBytes, metadata, nil
	case "fido2":
		if f.credentialHex == "" {
			return nil, nil, &MissingCredentialError{Type: "fido2"}
		}
		credBytes, err := hex.DecodeString(f.credentialHex)
		if err != nil {
			return nil, nil, &InvalidCredentialHexError{Cause: err}
		}
		if f.fido2Device != "" {
			metadata["device_id"] = f.fido2Device
		}
		return credBytes, metadata, nil
	case "piv":
		if f.credentialHex == "" {
			return nil, nil, &MissingCredentialError{Type: "piv"}
		}
		credBytes, err := hex.DecodeString(f.credentialHex)
		if err != nil {
			return nil, nil, &InvalidCredentialHexError{Cause: err}
		}
		if f.pivReader != "" {
			metadata["reader"] = f.pivReader
		}
		if f.pivSlot != "" {
			metadata["slot"] = f.pivSlot
		}
		return credBytes, metadata, nil
	case "pkcs11":
		// The credential is SHA-256(SubjectPublicKeyInfo DER) of the enrolled
		// public key — 32 bytes encoded as hex, matching the canonical PKCS#11
		// lookup-key format documented in pkg/auth/factors.go.
		if f.credentialHex == "" {
			return nil, nil, &MissingCredentialError{Type: "pkcs11"}
		}
		credBytes, err := hex.DecodeString(f.credentialHex)
		if err != nil {
			return nil, nil, &InvalidCredentialHexError{Cause: err}
		}
		if f.pkcs11Slot != "" {
			metadata["slot"] = f.pkcs11Slot
		}
		if f.pkcs11Label != "" {
			metadata["label"] = f.pkcs11Label
		}
		return credBytes, metadata, nil
	}
	return nil, nil, &InvalidFactorTypeError{Type: f.factorType}
}

// buildXKMSLoginLookupKey derives the canonical lookup key bytes for
// an auth method.
func buildXKMSLoginLookupKey(method, certPath, credHex string) ([]byte, error) {
	switch method {
	case "mtls":
		if certPath == "" {
			return nil, &MissingCertPathError{}
		}
		key, _, err := xkmsLoadCertCredentialAndMetadata(certPath)
		return key, err
	case "fido2", "piv", "pkcs11":
		// All three methods identify themselves with a hex-encoded credential
		// blob (FIDO2 credentialID, PIV slot-cert SHA-256, or PKCS#11
		// SubjectPublicKeyInfo SHA-256).
		if credHex == "" {
			return nil, &MissingCredentialError{Type: method}
		}
		key, err := hex.DecodeString(credHex)
		if err != nil {
			return nil, &InvalidCredentialHexError{Cause: err}
		}
		return key, nil
	}
	return nil, &InvalidAuthMethodError{Method: method}
}

// xkmsLoadCertCredentialAndMetadata reads a PEM certificate from path and
// returns the canonical mTLS lookup key — qrdb's SPKI SHA-256 thumbprint
// (base64url) — plus selected metadata. The SPKI thumbprint is the single
// stack-wide mTLS identifier: it binds to the public key, so it is stable
// across certificate renewal and matches the binding written by the admin
// enrollment path (cmd/xkmsctl/admin.go). It is computed via the qrdb SDK,
// never reimplemented locally (a full-cert SHA-256 would diverge).
func xkmsLoadCertCredentialAndMetadata(path string) ([]byte, map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, &CertReadError{Path: path, Cause: err}
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, &CertReadError{Path: path, Cause: errors.New("no CERTIFICATE block found")}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, &CertReadError{Path: path, Cause: err}
	}
	thumbprint := qrdbsdk.ComputeSPKIThumbprint(cert)
	meta := map[string]string{
		"cert_cn":              cert.Subject.CommonName,
		"cert_serial":          cert.SerialNumber.String(),
		"cert_not_after":       cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
		"cert_not_before":      cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
		"cert_spki_thumbprint": thumbprint,
	}
	return []byte(thumbprint), meta, nil
}

// invokeClose calls a closer callback if non-nil.
func invokeClose(fn func() error) error {
	if fn == nil {
		return nil
	}
	return fn()
}

// parseUserID parses a numeric user identifier string.
func parseUserID(s string) (uint64, error) {
	id, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, &InvalidUserIDError{Value: s, Cause: err}
	}
	return id, nil
}
