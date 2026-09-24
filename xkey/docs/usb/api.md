# USB — API

> **Status: NORMATIVE** · Feature: `usb` · Module: `go-xkms/xkey` · Last verified: 2026-09-24

No REST, gRPC, or GUI (Wails IPC) surface for either sub-feature. Both are
local, host-level operations reachable only through the CLI (`cli.md`):

- The **virtual CCID device** presents a smartcard interface to the local
  operating system (and, in gadget mode, to whatever host the USB cable is
  plugged into) — there is nothing for a network client or the desktop GUI
  to call.
- **Disk image creation/update** manipulates block devices and files
  directly and requires root; it is not something a remote client or the
  GUI's Wails bridge exposes either.

No `xkey/pkg/gui/services` file imports `xkey/pkg/usb`, `xkey/pkg/ccid`, or
`xkey/pkg/gadget`, and no frontend component references either feature —
this is CLI-only by construction, not an oversight this folder is filling
a gap for.

The one indirect API surface is what the virtual CCID device presents
*to other software* once running: standard PC/SC (via `pcscd`) sees it as
an ordinary CCID reader, and PIV/OpenPGP-aware tools (OpenSC, GnuPG,
browsers, VM smartcard passthrough) talk to it exactly as they would a
physical reader — that surface is the ISO 7816/CCID and PC/SC standards
themselves, not an xKey-specific API, so there is nothing further to
document here.
