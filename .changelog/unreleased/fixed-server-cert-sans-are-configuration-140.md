- **The server certificate's SANs are configuration, not literals (#140,
  cluster 3).** Every auto-issued server certificate carried `localhost`,
  `127.0.0.1` and `::1` unconditionally, and the CA-issued one an
  unconditional `0.0.0.0` IP SAN as well; no configuration could remove them.
  `tls.include_localhost_sans` (`XKMS_TLS_INCLUDE_LOCALHOST_SANS`,
  defaults-layer `true`) now governs the loopback names for both the
  bootstrap and the CA-issued certificate through one shared builder, and
  the wildcard address is gone: no client dials it, and a wildcard is not a
  name a certificate should present. A certificate issued under an earlier
  configuration is reissued at the next start rather than served stale. The
  CA-issued certificate, shared by every node, no longer carries the issuing
  node's hostname; list a name clients dial in `tls.extra_sans`.
