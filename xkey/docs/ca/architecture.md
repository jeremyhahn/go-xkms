# CA: architecture

## One local CA for CLI and GUI

`localca.NewClient(dataDir, keyStorage)` (`xkey/pkg/localca/localca.go:30`)
is the only way xkey opens its local CA. It returns `sdk/go`'s embedded
client (`NewEmbeddedClient`) over `EmbeddedServiceConfig{KeyDir:
<dataDir>/ca, KeyStorage, CA: DefaultMultiIdentityCAConfig(), Isolated:
true}`.

- `EmbeddedServiceConfig.CA` (`sdk/go/embedded.go:50`): when set,
  `NewEmbeddedService` builds the CA with `compose.BuildCA`
  (`embedded.go:141`) on stores under KeyDir, loads it again on reopen and
  wires it into the service.
- `EmbeddedServiceConfig.Isolated` (`embedded.go:56`): the CA's embedded
  service leaves the process-wide key-service singleton alone, so the GUI's
  own key service is not replaced.

The CLI passes no key storage (file stores); the GUI passes its barrier
storage, so the CA keys are barrier-encrypted under the `ca/` prefix.

## GUI client selection

`CAService` holds two atomic clients: the server client (`SetClient`,
`ca_service.go:96`) and the local client (`SetLocalClient`,
`ca_service.go:102`). `getClient` (`ca_service.go:120`) uses the server
client when set, else the local one.

- `App.initLocalCA` (`xkey/pkg/gui/app.go:1398`) opens the local CA when the
  store unlocks and calls `SetLocalClient`; `closeLocalCA`
  (`app.go:1424`) clears it.
- `applyConnectionEvent` sets the server client on connect
  (`app.go:2716`) and clears it on disconnect or error (`app.go:2726`), so
  the view falls back to the local CA.
