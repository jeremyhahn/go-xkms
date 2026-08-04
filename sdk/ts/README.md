# @go-xkms/sdk (TypeScript)

The TypeScript SDK for go-xkms. Its first capability is a framework-agnostic
**embedded SSH console** client (xterm.js + the go-xkms console WebSocket
protocol), reusable by any web UI — xkey (Svelte), the future xkms web UI, and
go-trusted-platform's device view (React).

## SSH console

```ts
import { SSHConsoleClient } from '@go-xkms/sdk';

const client = new SSHConsoleClient({ fontSize: 13 });
client.onError = (msg) => console.error(msg);
client.onClose = () => console.log('session ended');

// `url` comes from the host app (xkey loopback service, or the xkms REST
// /xkms/v1/ssh/console endpoint) and already carries a one-time token.
client.open(document.getElementById('terminal')!, { url });

// On container resize:
client.fit();

// On teardown:
client.dispose();
```

`@xterm/xterm` and `@xterm/addon-fit` are peer-style dependencies the consuming
app provides (the bundle keeps them external).

## WebSocket protocol

The client connects to a WebSocket served by the go-xkms console bridge
(`pkg/ssh/console.NewWSHandler`, re-exported as `sshclient.NewConsoleWSHandler`):

| Frame | Direction | Meaning |
|-------|-----------|---------|
| **binary** | client→server | keystrokes (stdin) |
| **binary** | server→client | terminal output (stdout) |
| **text** `{"type":"resize","rows":R,"cols":C}` | client→server | window resize |
| **text** `{"type":"error","message":"..."}` | server→client | error |
| **text** `{"type":"exit"}` | server→client | session ended |

The pure helpers `parseControl` / `encodeResize` implement the text-frame
encoding and are tested independently of the DOM.

## Build & test

```bash
npm install
npm run build   # tsup → dist (ESM + CJS + d.ts)
npm test        # vitest (protocol unit tests)
```
