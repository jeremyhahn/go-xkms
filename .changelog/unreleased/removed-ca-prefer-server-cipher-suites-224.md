- **`ca.TLSConfigOptions.PreferServerCipherSuites` is gone (#224).** The field was
  never propagated to `tls.Config` — Go has ignored
  `tls.Config.PreferServerCipherSuites` since 1.18, so it had been a
  no-op deprecated knob kept only so existing callers compiled. The two
  call sites that set it (`ServerTLSConfig`, `MutualTLSConfig`) are
  updated. This is a breaking removal of an exported field; callers
  setting it must delete the reference, which changes nothing about
  the resulting TLS configuration.
