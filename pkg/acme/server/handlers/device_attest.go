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

package handlers

import (
	"context"
	"crypto/x509"
	"net"
	"strconv"
	"strings"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	deviceattest01 "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/device-attest-01"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
)

// device-attest-01: identity at the challenge, key at finalization
// (go-xkms#789, go-xkms#828)
//
// A device-attest-01 attestation proves two different things and neither
// alone is an authorization: that the evidence's key lives in a genuine,
// chain-anchored device (VerifyAttestation), and, separately, WHICH device --
// the identity draft-ietf-acme-device-attest's permanent-identifier binds an
// order to. Both are established here, at the challenge: NewDeviceAttestVerifier
// reads the attested device identity from the evidence and reports it as
// common.AttestedIdentity.Identifier. ChallengeHandler is what refuses a
// challenge whose identity does not authorize the order, for every
// attestation challenge type alike (common.AttestingVerifier); there is no
// comparison here and no device-attest-01 special case in the handler.
//
// The evidence is the client's payload (common.AttestationChallenge.Payload):
// the draft has the client POST its attestation, so the server never dials a
// device and the device needs no address.
//
// What is still missing at this point is the certificate request: it exists
// one request later, at finalization, and comparing it against the recorded
// evidence is bindDeviceAttestationKey's job, not this one's. That two-phase
// split is deviceattest01.VerifiedAttestation's own documented contract
// (BindCSRKey); NewDeviceAttestVerifier carries the verified evidence forward
// as common.AttestedIdentity.Attestation, and ChallengeHandler persists it
// through the same ACMEChallenge record every other challenge outcome is
// kept on (pkg/acme/storage), not a side store.

// NewDeviceAttestVerifier returns the device-attest-01 common.AttestingVerifier
// (go-xkms#737, go-xkms#789, go-xkms#828).
//
// verifier is the server's trust policy over the attestation: the anchors an
// x5c chain must reach and any check on the attestation object. It is injected
// rather than asserted from the CA handle because the CA that issues
// certificates and the roots that vouch for a device are different
// configuration, and the shipped CA type cannot implement
// deviceattest01.AttestationVerifier without an import cycle. A nil verifier is
// refused at verification time with deviceattest01.ErrNoAttestationVerifier,
// never run without anchors.
//
// draft-ietf-acme-device-attest's identifier binding is defined for
// permanent-identifier only, and deviceattest01.VerifiedAttestation.DeviceIdentity
// reads exactly that otherName -- there is no attested identity a TPM/DICE
// evidence chain could carry for a "dns" authorization, so any other
// identifier type is refused before the evidence is even read. (ChallengeHandler
// refuses "ip" earlier still, for every attestation challenge.)
//
// For "dice", verifier is also where the device registry lives
// (deviceattest01.RegisteredDeviceVerifier, go-xkms#1441): the evidence is
// anchored in the device's provisioning record before the identity is
// reported, and the same verifier is asked again at finalization
// (bindDeviceAttestationKey).
func NewDeviceAttestVerifier(verifier deviceattest01.AttestationVerifier) common.AttestingVerifier {
	return &deviceAttestVerifier{verifier: verifier}
}

// deviceAttestVerifier is the device-attest-01 common.AttestingVerifier. It
// keeps the deviceattest01.AttestationVerifier it was built with so
// finalization re-confirms a "dice" device against the same registry the
// challenge anchored it in.
type deviceAttestVerifier struct {
	verifier deviceattest01.AttestationVerifier
}

// VerifyAttested implements common.AttestingVerifier.
//
// The challenge seam carries no request context, so the registry lookup runs
// under context.Background(); the resolver bounds its own lookups.
func (v *deviceAttestVerifier) VerifyAttested(
	_ *net.Resolver,
	_ common.CertificateAuthority,
	challenge common.AttestationChallenge,
) (*common.AttestedIdentity, error) {
	if challenge.IdentifierType != common.AuthzTypePermanentIdentifier {
		return nil, &ErrAttestationIdentifierType{Challenge: common.ChallengeTypeDeviceAttest01, Type: challenge.IdentifierType}
	}

	verified, err := deviceattest01.VerifyAttestation(context.Background(), v.verifier, challenge.Payload, challenge.KeyAuthorization)
	if err != nil {
		return nil, err
	}

	deviceIdentity, err := verified.DeviceIdentity()
	if err != nil {
		return nil, err
	}

	return &common.AttestedIdentity{
		Identifier:  deviceIdentity,
		Attestation: verified.Record(challenge.IdentifierType, deviceIdentity),
	}, nil
}

// deviceAttestationVerifier returns the deviceattest01.AttestationVerifier
// the device-attest-01 challenge was verified with, or nil when none is
// registered -- which refuses a "dice" record at finalization.
func (s *RestService) deviceAttestationVerifier() deviceattest01.AttestationVerifier {
	registered, ok := s.attestingVerifiers[common.ChallengeTypeDeviceAttest01].(*deviceAttestVerifier)
	if !ok {
		return nil
	}
	return registered.verifier
}

// orderAuthorizations loads every authorization the order references, in the
// order's own order.
//
// A reference that cannot be loaded REFUSES THE REQUEST. The callers draw
// conclusions from the authorizations that exist -- "none of them was
// validated by device-attest-01, so this is not a device-attest-01 order" --
// and a partial restore or a replication fault that dropped one would let those
// conclusions be drawn from incomplete state, at exactly the moment the
// binding they gate is most needed. It is reported as ErrOrderAuthorizationMissing.
func (s *RestService) orderAuthorizations(
	ctx context.Context,
	authzDAO qrdbsdk.GenericDAO[*entities.ACMEAuthorization],
	order *entities.ACMEOrder,
) ([]*entities.ACMEAuthorization, *entities.Error) {

	authzs := make([]*entities.ACMEAuthorization, 0, len(order.Authorizations))
	for _, authzURL := range order.Authorizations {
		pieces := strings.Split(authzURL, "/")
		authzID, err := strconv.ParseUint(pieces[len(pieces)-1], 10, 64)
		if err != nil {
			return nil, common.MalformedError("Invalid authorization ID", nil)
		}

		authz, err := authzDAO.Get(ctx, authzID)
		if err != nil {
			if qrdbsdk.IsDAONotFound(err) {
				missing := &ErrOrderAuthorizationMissing{OrderID: order.ID, AuthorizationID: authzID}
				s.logger.Error("Refusing the request", "error", missing.Error())
				return nil, missing.Problem()
			}
			s.logger.Error("Failed to retrieve authorization",
				"error", err, "orderID", order.ID, "authorizationID", authzID)
			return nil, common.ServerInternal("Failed to retrieve authorization")
		}
		authzs = append(authzs, authz)
	}
	return authzs, nil
}

// findDeviceAttestation returns the persisted device-attest-01 record for
// the device the certificate request names. It never falls back to signing
// without one: every permanent-identifier order this handler reaches with a
// standard x509 CSR (never an endorse-01 or TCG-CSR-IDEVID order -- both take
// earlier, separate paths in OrderFinalizeHandler) is a device-attest-01
// order, and a missing record means the identity/key binding this gate exists
// for was never established.
//
// An order may authorize several devices, and each validated challenge left
// the record of its own. deviceIdentity is the permanent identifier the
// certificate request names, and only the record attesting that identity is
// returned: the request's key must be bound to the device it claims to be,
// never to whichever other device the order happens to list first.
func (s *RestService) findDeviceAttestation(
	ctx context.Context,
	authzDAO qrdbsdk.GenericDAO[*entities.ACMEAuthorization],
	order *entities.ACMEOrder,
	deviceIdentity string,
) (*entities.DeviceAttestation, *entities.Error) {

	validated, problem := s.validatedAttestations(ctx, authzDAO, order)
	if problem != nil {
		return nil, problem
	}
	for _, rec := range validated.records(common.ChallengeTypeDeviceAttest01) {
		if rec.DeviceIdentityValue == deviceIdentity {
			return rec, nil
		}
	}
	return nil, nil
}

// bindDeviceAttestationKey refuses a certificate request whose key is not the
// key a device-attest-01 challenge attested (go-xkms#789) and, for the DICE
// format, one that is not the device's possession request for order. rec is what
// findDeviceAttestation returned; a nil rec is refused as badCSR rather than
// treated as "not a device-attest-01 order", since by the time
// OrderFinalizeHandler reaches this call every permanent-identifier order
// with a standard x509 CSR is one.
//
// A "dice" record is then confirmed against the device registry again
// (go-xkms#1441): a device whose provisioning record was deleted, or whose
// provisioned key changed, since the challenge is refused as unauthorized.
// The CSR is judged first, so a request for the wrong key is badCSR whatever
// the registry says.
func (s *RestService) bindDeviceAttestationKey(ctx context.Context, rec *entities.DeviceAttestation, order *entities.ACMEOrder, csr *x509.CertificateRequest) *entities.Error {
	if rec == nil {
		return common.BadCSR((&ErrDeviceAttestationNotFound{OrderID: order.ID}).Error())
	}

	verified, err := deviceattest01.FromRecord(rec)
	if err != nil {
		return common.BadCSR("device-attest-01: " + err.Error())
	}
	// A DICE device mints its request from the possession template, so the
	// request itself must be that template: it is what proves the attested
	// key answered this challenge (go-xkms#1441).
	if verified.Format == deviceattest01.FormatDICE {
		if err := verified.VerifyPossessionCSR(csr, order.Identifiers); err != nil {
			return common.BadCSR("device-attest-01: certificate request is not the attested device's possession request: " + err.Error())
		}
	}
	if err := verified.BindCSRKey(csr); err != nil {
		return common.BadCSR("device-attest-01: certificate request key does not match the attested key: " + err.Error())
	}
	// The cause can carry the registry's own error, so it is logged rather
	// than returned to the client.
	if err := verified.ConfirmRegistration(ctx, s.deviceAttestationVerifier()); err != nil {
		s.logger.Warn("Refusing finalization: the device registry no longer vouches for the attested key",
			"error", err, "orderID", order.ID)
		return common.Unauthorized("device-attest-01: the device's provisioning record no longer authorizes the attested key")
	}
	return nil
}
