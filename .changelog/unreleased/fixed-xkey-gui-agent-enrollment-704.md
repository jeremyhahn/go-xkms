- **The xkey GUI can start the agent server.** The GUI's agent service was never
  given an enrollment service, so starting the agent server always failed. When
  the GUI connects to xkmsd it now enrolls agents through the xkmsd certificate
  authority (`agent.XKMSdCA`, the same adapter the CLI uses). Enrollment records
  live in the CLI's store under the xKey data directory, so agents enrolled from
  either the CLI or the GUI show up in both. A disconnect or shutdown stops the
  running agent server. Without a connection, starting it fails with
  `ErrAgentServiceNotReady` (#704).
- **The xkey GUI's FIDO2 authenticator writes its audit records.** The audit
  logger was attached in `NewApp`, but there the authenticator does not exist
  yet, so it never got one. The logger is now attached where the authenticator
  is built, and PIN establishment and credential creation are recorded in the
  GUI's audit store (#704).
