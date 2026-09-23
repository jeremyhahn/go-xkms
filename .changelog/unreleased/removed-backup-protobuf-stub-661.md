- **`BackupFormatProtobuf` deleted — BREAKING.** `pkg/backup`'s `CreateBackup`
  had a `BackupFormatProtobuf` case that unconditionally returned "protobuf
  format not yet implemented": API surface that could be selected but never
  worked. JSON and Encrypted are the only backup formats go-xkms ships, so
  the `BackupFormatProtobuf` constant is deleted along with its dead
  serialization branch. Selecting an unrecognized `BackupFormat` (including
  the string `"protobuf"`) now falls through to the existing typed
  `ErrInvalidBackupFormat`, exactly as any other unknown format already did.
  Files: `pkg/backup/backup.go`, `pkg/backup/file.go`,
  `pkg/backup/backup_test.go`. go-xkms#661.
