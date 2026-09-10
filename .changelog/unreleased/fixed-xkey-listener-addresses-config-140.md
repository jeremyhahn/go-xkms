- **xkey: the agent server and the pairing relay bind configured addresses (#140, xkey mechanism gaps).**
  `xkey agent start` bound `:9443` with `--listen` as its only path, and
  `xkey device relay` bound `:8444` from a flag default no config file or
  variable could reach. The xkey config gains `agent.listen_address` and
  `phone.relay_listen_address` (each validated as host:port;
  `XKEY_AGENT_LISTEN_ADDRESS`, `XKEY_PHONE_RELAY_LISTEN_ADDRESS`), and each
  command resolves flag over configuration over the built-in default, which
  is unchanged. The audit's third xkey gap, the agent client's
  `LocalAddress`, is a declared field nothing reads; it gets no
  configuration path until the client binds it.
