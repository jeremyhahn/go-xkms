- **The ACME challenge listeners bind a configured host (#140, cluster 2).**
  The client's http-01 challenge server and the three enrollment listeners
  (enroll-01, endorse-01, device-attest-01) built their address as `":"+port`,
  so every one bound every interface whatever the operator configured.
  `acmeclient.EnrollmentConfig` gains `ListenHost`, and xkmsd passes its
  `server.host` through `clusterca.ACMEOptions.ChallengeHost`, so a joining
  node serves the enroll-01 exchange on the interface every other daemon
  listener binds. The standalone client gains `challenge.http01.host`
  (`ACME_CLIENT_CHALLENGE_HTTP01_HOST`; `challengeHost` on the GUI config
  API), joined with the port through `net.JoinHostPort`. `enroll01.Setup`
  takes a listen address (a bare port still means every interface). Empty
  remains the defaults-layer value everywhere: every interface.
