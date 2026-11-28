package continuous

import "fmt"

// ConfigError reports an engine or store configuration that cannot work.
type ConfigError struct {
	Field  string
	Reason string
	Cause  error
}

func (e *ConfigError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("continuous: %s %s: %v", e.Field, e.Reason, e.Cause)
	}
	return fmt.Sprintf("continuous: %s %s", e.Field, e.Reason)
}

func (e *ConfigError) Unwrap() error { return e.Cause }

// InputError reports an unusable tenant or device ID.
type InputError struct {
	Field string
	Cause error
}

func (e *InputError) Error() string {
	return fmt.Sprintf("continuous: invalid %s: %v", e.Field, e.Cause)
}

func (e *InputError) Unwrap() error { return e.Cause }

// StoreError reports a failure of the verdict store's backing DAO.
type StoreError struct {
	Op  string
	Key string
	Err error
}

func (e *StoreError) Error() string {
	return fmt.Sprintf("continuous: verdict store %s %q: %v", e.Op, e.Key, e.Err)
}

func (e *StoreError) Unwrap() error { return e.Err }

// VerdictNotFoundError reports a device with no stored verdict.
type VerdictNotFoundError struct {
	Tenant   string
	DeviceID string
}

func (e *VerdictNotFoundError) Error() string {
	return fmt.Sprintf("continuous: no verdict for device %q of tenant %q", e.DeviceID, e.Tenant)
}
