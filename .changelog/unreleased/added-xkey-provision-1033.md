- **`xkey provision --agent <name>` sets up a complete xkey instance for an agent in one unattended step** (#1033). In one command it:
  - generates the agent's SSH service key;
  - initializes the barrier;
  - sets the host PIN service's SO and user PINs;
  - initializes the FIDO2 token (with persistent storage);
  - generates the four primary PIV slots;
  - records the display name in the instance's own `config.yaml`;
  - optionally pairs a Chrome profile (`--chrome-profile-dir`).

  The target home must be named with `--home` or `XKEY_HOME`, never the operator's default home, and an initialized home is refused without `--force`. The command takes three distinct secrets through xkey's existing inputs: the user PIN (`--pin-stdin`/`XKEY_PIN`), the SO PIN (`--so-pin-stdin`/`XKEY_SO_PIN`) and the barrier password (`--barrier-password[-file]`/`XKEY_BARRIER_PASSWORD`). A missing one is refused by name, and no secret stands in for another. It prints human-readable output or `--json` with no secrets. Verified by `provision_test.go`, including a four-way check that the SO PIN verifies only as SO and the user PIN only as user.
