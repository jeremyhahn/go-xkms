- **Issuer-stamped fleet agent claim (go-xkms#1686).** `SignOptions.FleetAgent`
  stamps `tp-fleetAgent` (1.3.6.1.4.1.29377.101.25, non-critical, value NULL)
  into the certificate, and only the issuing call sets it. Every CSR path
  refuses a CSR that requests the extension with `ErrFleetAgentClaimRequested`:
  400 on REST, `InvalidArgument` on gRPC and unix, invalid params on MCP.
  `ExtraExtensions` may not carry it either (`ErrFleetAgentClaimReserved`).
  `VerifyFleetAgentClaim` accepts the claim only on a certificate that chains
  to roots the caller supplies, so another CA's claim is rejected. `sdk/go`
  re-exports the option, the verifier, `OIDFleetAgent` and the
  `ErrCAFleetAgentClaim*` errors for go-quicbaas fleet enrolment
  (go-quicbaas#1821). Code: `pkg/ca/fleet_agent.go`; docs:
  `docs/certificate-authority/engineering.md#fleet-agent-claim`.
