- **xkey no longer leaks the xkms TPM2 backend's own TPM connection.** When the
  local key store hands the tpm2 backend the GUI's shared TPM, the connection
  `AutoInitialize` opened was dropped without being closed. `SetTPM` leaves that
  connection to its caller. The leak held a TPM device handle for the life of the
  process, and with the simulator it held go-tpm-tools' process-wide lock, so the
  next simulator open hung. `initLocalKeyStore` now closes the replaced
  connection (`xkey/pkg/gui/app.go`). Verified by the gui tests that bring up a
  simulated tpm2 backend twice in one run (#704).
