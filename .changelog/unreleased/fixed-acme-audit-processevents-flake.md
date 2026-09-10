### Fixed

- `TestFileAuditLogger_ProcessEvents` waited a fixed fifty milliseconds for the background writer and failed on a loaded CI runner; it now synchronises on `Flush`, which returns only after the buffer is drained and the writer synced.
