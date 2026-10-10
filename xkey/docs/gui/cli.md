# xKey Desktop GUI — CLI

> **Status: NORMATIVE** · Feature: `gui` · Module: `go-xkms/xkey` · Last verified: 2026-10-09

The GUI has no launch subcommand of its own (`xkey app-access`, below, only
changes one of its settings) — `xkey` is one binary that launches
either the GUI or the Cobra CLI tree depending on how it is invoked. This page
documents that dispatch, implemented in `xkey/cmd/xkey/main.go:41-94`.

## Dispatch rules

| Condition | Result |
|---|---|
| `--gui` passed | Launch GUI (unless `--help`/`-h` also passed) |
| `--no-gui`, `--help`, or `-h` passed | Launch CLI |
| A subcommand is present (e.g. `xkey oath list`) and `--gui` was not passed | Launch CLI — subcommand intent overrides environment detection (`main.go:59-61`) |
| None of the above, and a GUI environment is detected | Launch GUI |
| None of the above, and no GUI environment is detected | Launch CLI |

`hasGUIEnvironment()` (`main.go:287-302`): always true on macOS and Windows;
on Linux, true only if `$DISPLAY` or `$WAYLAND_DISPLAY` is set; false on any
other `GOOS`.

```
xkey                 # GUI if a display is available, else CLI
xkey --gui           # force GUI
xkey --no-gui        # force CLI (equivalent to omitting all xkey subcommands)
xkey oath list        # CLI — a subcommand always means CLI intent
```

## Binaries without GUI support

A binary built without one of Wails' required tags (`production`, `dev`, or
`bindings`) cannot start the GUI. Attempting to (via `--gui` or GUI-environment
auto-detection) prints build guidance and exits with status 2 rather than
Wails' own opaque build-tag error (`printGUIBuildHelp`, `main.go:104-118`):

```
xkey: this binary was built without GUI support.

The Wails GUI requires one of the build tags 'production', 'dev', or 'bindings'.

Rebuild with:
  make -C xkey build-local
  make -C xkey build
Or pass tags directly:
  cd xkey && go build -tags 'ble production codec_json' -o xkey ./cmd/xkey
Or run the CLI explicitly with --no-gui.
```

## GUI-mode logging flags

When the GUI launches, `--log-level` and `--log-file` are parsed from the
CLI args *before* Wails starts, so they configure the global `slog` logger
for the whole GUI process (`initGUILogging`, referenced at `main.go:68-70`)
— the same flags the CLI subcommands use.

## `xkey app-access status|enable|disable`

Shows or changes **local app access**, the Settings → Browser toggle "Let
other apps use my keys while xKey is open" (`cmd/xkey/cmd/app_access.go`).
It writes `local_app_access_enabled` in the GUI settings file. When it is on,
the GUI opens its IPC socket while it is open and unlocked. When it is off
(the default), nothing listens and `xkey extension serve` refuses to start.
No flags.

```
xkey app-access status    # Local app access: off
xkey app-access enable    # Local app access: on
xkey app-access disable   # Local app access: off
```

A running GUI reads the file only at startup, so restart xKey after
changing the setting here, or use the Settings toggle, which applies at
once. An unreadable settings file fails with `ErrAppAccessLoadFailed`, and a
failed write fails with `ErrAppAccessSaveFailed`.

## Browser native messaging

`xkey` invoked the way Chrome launches a native-messaging host
(`xkey chrome-extension://<id>/`) is rewritten to `xkey extension host`
before dispatch (`main.go:46-51`); this is unrelated to GUI/CLI selection
and always resolves to the CLI's `extension host` command. See
[../autofill/cli.md](../autofill/cli.md).
