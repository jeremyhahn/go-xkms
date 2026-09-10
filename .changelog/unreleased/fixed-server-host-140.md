- **`server.host` binds the listeners it names, through one configuration
  chain (#140, cluster 1).** The REST listener configuration was built
  without a host, so `server.host` validated and was then discarded on the
  listen path, and the library gRPC server had no host field at all and bound
  the wildcard from a literal. `pkg/config.Load` now resolves defaults → file
  → environment through viper (`XKMS_<SECTION>_<KEY>` works for every key,
  the optional `acme`, `trust`, `webauthn` and `backends.*` sections
  included, whether or not the file declares them; `XKMS_HOST` stays as an
  alias below the canonical `XKMS_SERVER_HOST`), a
  `Defaults()` layer holds the one allowed literal, `xkmsd --host` sits on top
  with `Changed()` semantics, and both `rest.Config.Host` and the new
  `grpc.ServerConfig.Host` consume the resolved value. A value that cannot
  decode into its field now fails `Load` rather than being dropped. The
  legacy environment ladder cedes to the canonical names: where both
  `XKMS_SERVER_REST_PORT` and `XKMS_REST_PORT` are set the canonical form
  wins, as documented, for every name the ladder still owns. A SIGHUP
  re-applies the command-line flags over the reloaded file, so
  `xkmsd --host` is not silently dropped on reload. New feature folder
  `docs/xkmsd-configuration/`.
