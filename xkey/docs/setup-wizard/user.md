# Setup Wizard — User Guide

> **Status: NORMATIVE** · Feature: `setup-wizard` · Module: `go-xkms/xkey` · Last verified: 2026-09-21

The wizard runs the first time you open xKey. It sets up two PINs and the
encrypted storage behind them.

## Your two PINs

| PIN | You use it for | Where it lives |
|---|---|---|
| **User PIN** | unlocking the app, FIDO2, PKCS#11, the password store | in your head, and (quick setup) a copy in the `xKey` folder of your password store |
| **SO PIN** | resetting a forgotten User PIN, unlocking after too many wrong attempts, factory reset | **only where you put it** |

The SO PIN is your recovery credential. xKey shows it to you **once** and
keeps no copy, because the password store is unlocked by the User PIN, and
a recovery code stored behind the thing it recovers is not a recovery code.
Write it on paper, put it in a different password manager, or keep it in a
safe. Anywhere except this device.

## Quick setup (personal)

1. Choose **Quick Setup**, then **Personal**.
2. On **Generated Credentials**, reveal the **SO PIN** and record it. The
   copy button puts it on the clipboard for 30 seconds.
3. Tick **I have recorded the SO PIN somewhere outside this device**.
   Continue stays disabled until you do, and setup refuses to run without
   it.
4. Review and apply.

The User PIN is also shown on that step and is saved to the `xKey` folder of
the password store for the first lock. Note it too; once the app locks you
need it to open the store it is in.

If you go back and run Quick Setup again, new PINs are generated and the
acknowledgement resets. The earlier SO PIN is gone.

## Manual setup (personal)

You choose both PINs and confirm each one. There is no acknowledgement step
because you already know them. **Save User PIN to password store** keeps a
copy of the User PIN for convenience; the SO PIN is not saved whichever way
the switch is set.

## Enterprise

The Security Officer runs **SO provisioning** and chooses the SO PIN
themselves. Each user is later onboarded by entering the SO PIN the
administrator gives them, then choosing their own User PIN. The SO PIN is
not stored on the user's device at any point.

## Too many wrong User PINs

Unlocking xKey from the command line (`xkey unlock`) is limited to 8 wrong
attempts before it refuses outright, whatever you type next. This is a
separate budget from anything the authenticator itself enforces, kept
specifically because a locked device's own credential store is sealed and
cannot count attempts against itself while it is sealed — the very state a
wrong PIN leaves it in.

If you hit the limit, the SO PIN clears it:

```
xkey pin reset-lockout
```

Setting the User PIN again (`xkey pin set-user`) clears it too, since that
already requires the SO PIN. Either way the count goes back to 8. There is
no way to clear it without the SO PIN — which is the point: see "If you lose
the SO PIN" below for what that means if you no longer have it.

## If you lose the SO PIN

xKey cannot recover it, and nothing in the app will show it. As long as you
still know the User PIN the device keeps working, but you cannot reset a
forgotten User PIN, clear a lockout, or factory reset from the app. Treat
that as the moment to move your credentials off the device while you still
can. If both PINs are lost, the device has to be re-initialised by removing
its data directory (`~/.xkey/`), and everything stored on it is lost.

## Re-running the wizard

Set `"setup_complete": false` in `~/.xkey/gui.json` and restart xKey.
Existing data is not touched; the wizard offers to override the choices it
knows about.
