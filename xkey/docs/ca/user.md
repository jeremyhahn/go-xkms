# CA: user guide

## CLI

`xkey ca <verb>` talks to the connected xkms server. Add `--local` to serve
the same verbs from xkey's own embedded CA instead, with no xkmsd:

```
xkey ca --local info
xkey ca --local issue --cn host.example --profile server
```

The local CA is created on first use under `<data dir>/ca` and loaded again
on every later run. When xkey's store is barrier-encrypted the CLI refuses
`--local` with "local store is barrier-encrypted; unlock via the xkey app":
open the CA from the GUI instead.

## GUI

The Certificate Authority view shows the CA certificate and issues, signs,
revokes and lists revocations. A badge shows which CA serves:

- `remote`: a server is connected; the view uses its CA.
- `local`: no server is connected; the view uses xkey's local CA, whose keys
  are barrier-encrypted in xkey's store.
- `none`: neither is available (the store is locked).

Connecting to a server switches the view to the server's CA; disconnecting
switches it back to the local CA.
