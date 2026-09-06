- **The setup wizard no longer stores the generated SO PIN in the device's
  own password store** (#290). The SO PIN is the recovery credential that
  resets a forgotten User PIN, and the password store is unlocked by the
  User PIN, so the copy was unreachable in every situation the SO role
  exists for (a forgotten User PIN after a lock or restart, a sealed
  barrier, a wiped store) and readable by anything that could drive the IPC
  socket once the store was open. Quick setup now shows the generated SO PIN
  once on the Generated Credentials step (masked, with reveal and copy) and
  requires the operator to acknowledge recording it out of band; `ApplySetup`
  refuses a quick setup without that acknowledgement with the new typed
  `ErrSetupSOPINNotRecorded`, before any step runs. Only the PIN service's
  verifier persists; the User PIN copy in the `xKey` folder is unchanged.
  Frontend contract: `SetupChoices` gains `so_pin_recorded` (bool);
  `save_pins_to_store` now saves the User PIN only. No reader of the stored
  entry existed to migrate. New feature folder `xkey/docs/setup-wizard/`.
  Files: `xkey/pkg/gui/services/setup_wizard_service.go`, `errors.go`,
  `xkey/frontend/src/views/SetupWizard.svelte`, `lib/types/setup.ts`,
  `lib/stores/wizard.ts`, `tests/e2e/global-setup.ts`. Verification:
  `setup_wizard_so_pin_test.go` asserts the store holds no `SO PIN` entry
  and no entry with the value after a quick-setup and a manual opt-in run,
  with the User PIN entry as positive control; reinstating the write turns
  both red, deleting the gate turns the acknowledgement test red.
