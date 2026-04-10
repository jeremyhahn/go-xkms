// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// Package events defines the event types and structures for the xKey GUI.
// Events are emitted from the Go backend to the Svelte frontend via the
// Wails v2 runtime event system.
package events

import "time"

// EventType identifies the kind of event being emitted.
type EventType string

// Phone events.
const (
	EventPhoneConnected    EventType = "phone:connected"
	EventPhoneDisconnected EventType = "phone:disconnected"
	EventPhoneScanResult   EventType = "phone:scan_result"
	EventPhonePairingReq   EventType = "phone:pairing_request"
)

// Key events.
const (
	EventKeyCreated EventType = "key:created"
	EventKeyDeleted EventType = "key:deleted"
	EventKeyUsed    EventType = "key:used"
)

// OATH events.
const (
	EventTOTPGenerated EventType = "oath:totp_generated"
)

// FIDO2 events.
const (
	EventBridgeStarted          EventType = "fido2:bridge_started"
	EventBridgeStopped          EventType = "fido2:bridge_stopped"
	EventFIDO2TouchRequired     EventType = "fido2:touch_required"
	EventFIDO2TouchResolved     EventType = "fido2:touch_resolved"
	EventFIDO2CredentialCreated EventType = "fido2:credential_created"
)

// Attestation events.
const (
	EventAttestationResult EventType = "attestation:result"
)

// Policy events.
const (
	EventPolicyViolation EventType = "policy:violation"
)

// TPM events.
const (
	EventTPMProvisioned    EventType = "tpm:provisioned"
	EventTPMQuoteGenerated EventType = "tpm:quote_generated"
	EventTPMKeyCertified   EventType = "tpm:key_certified"
)

// Settings events.
const (
	EventSettingsChanged EventType = "settings:changed"
)

// Audit events.
const (
	EventAuditEntry EventType = "audit:entry"
)

// Server connection events.
const (
	EventServerConnected    EventType = "server:connected"
	EventServerDisconnected EventType = "server:disconnected"
	EventServerError        EventType = "server:error"
)

// System events.
const (
	EventError EventType = "error"
)

// Setup wizard events.
const (
	EventSetupCompleted EventType = "setup:completed"
	EventSetupSkipped   EventType = "setup:skipped"
	EventSetupProgress  EventType = "setup:progress"
)

// Storage events.
const (
	EventStorageLUKSLocked  EventType = "storage:luks_locked"
	EventDataDirInitialized EventType = "storage:data_dir_initialized"
)

// Barrier events.
const (
	EventBarrierLocked   EventType = "barrier:locked"
	EventBarrierUnlocked EventType = "barrier:unlocked"
)

// Auth events.
const (
	EventAuthModeChanged EventType = "auth:mode_changed"
)

// App lock events.
const (
	EventAppLocked EventType = "app:locked"
)

// Enterprise provisioning events.
const (
	EventSOProvisioningCompleted EventType = "setup:so_provisioned"
	EventUserOnboarded           EventType = "setup:user_onboarded"
)

// Policy integrity events.
const (
	EventPolicyTamperDetected EventType = "policy:tamper_detected"
)

// Share events.
const (
	EventShareReceived  EventType = "share:received"
	EventShareSubmitted EventType = "share:submitted"
	EventShareDeleted   EventType = "share:deleted"
	EventShareImported  EventType = "share:imported"
)

// Custodian events.
const (
	EventCustodianGroupCreated      EventType = "custodian:group_created"
	EventCustodianGroupDeleted      EventType = "custodian:group_deleted"
	EventCustodianMemberAdded       EventType = "custodian:member_added"
	EventCustodianMemberRemoved     EventType = "custodian:member_removed"
	EventCustodianSharesDistributed EventType = "custodian:shares_distributed"
)

// Tenant events.
const (
	EventTenantCreated         EventType = "tenant:created"
	EventTenantDeleted         EventType = "tenant:deleted"
	EventTenantBarrierInited   EventType = "tenant:barrier_initialized"
	EventTenantBarrierUnsealed EventType = "tenant:barrier_unsealed"
)

// AutoFill events.
const (
	EventAutofillCredentialAccess EventType = "autofill:credential_access"
	EventAutofillTOTPAccess       EventType = "autofill:totp_access"
	EventAutofillPolicyChanged    EventType = "autofill:policy_changed"
)

// Agent events.
const (
	EventAgentServerStarted      EventType = "agent:server_started"
	EventAgentServerStopped      EventType = "agent:server_stopped"
	EventAgentCodeGenerated      EventType = "agent:code_generated"
	EventAgentEnrollmentApproved EventType = "agent:enrollment_approved"
	EventAgentEnrollmentRejected EventType = "agent:enrollment_rejected"
	EventAgentConnected          EventType = "agent:connected"
	EventAgentDisconnected       EventType = "agent:disconnected"
	EventAgentRemoved            EventType = "agent:removed"
)

// Extension pairing events.
const (
	EventExtensionPairingRequest EventType = "extension:pairing_request"
	EventExtensionPaired         EventType = "extension:paired"
	EventExtensionUnpaired       EventType = "extension:unpaired"
)

// DataDirInitializedPayload carries data for the storage:data_dir_initialized event.
type DataDirInitializedPayload struct {
	DataDir string `json:"data_dir"`
}

// Event represents an event emitted from the Go backend to the frontend.
type Event struct {
	// Type identifies the event kind.
	Type EventType `json:"type"`

	// Payload carries the event-specific data.
	Payload any `json:"payload"`

	// Time is when the event was created.
	Time time.Time `json:"time"`
}

// NewEvent creates an Event with the given type and payload, timestamped to now.
func NewEvent(eventType EventType, payload any) Event {
	return Event{
		Type:    eventType,
		Payload: payload,
		Time:    time.Now(),
	}
}

// PhoneConnectedPayload carries data for the phone:connected event.
type PhoneConnectedPayload struct {
	DeviceName string `json:"device_name"`
	Address    string `json:"address"`
}

// PhoneDisconnectedPayload carries data for the phone:disconnected event.
type PhoneDisconnectedPayload struct {
	DeviceName string `json:"device_name"`
	Reason     string `json:"reason"`
}

// PhoneScanResultPayload carries data for the phone:scan_result event.
type PhoneScanResultPayload struct {
	Devices []DiscoveredDevicePayload `json:"devices"`
}

// DiscoveredDevicePayload describes a device found during BLE scanning.
type DiscoveredDevicePayload struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	RSSI    int    `json:"rssi"`
}

// PhonePairingRequestPayload carries data for the phone:pairing_request event.
type PhonePairingRequestPayload struct {
	DeviceName string `json:"device_name"`
	Address    string `json:"address"`
}

// KeyEventPayload carries data for key lifecycle events.
type KeyEventPayload struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	Backend   string `json:"backend"`
}

// TOTPGeneratedPayload carries data for the oath:totp_generated event.
type TOTPGeneratedPayload struct {
	AccountID   string `json:"account_id"`
	Code        string `json:"code"`
	TimeLeft    int    `json:"time_left"`
	AccountName string `json:"account_name"`
}

// BridgeEventPayload carries data for fido2 bridge events.
type BridgeEventPayload struct {
	Reason string `json:"reason,omitempty"`
}

// AttestationResultPayload carries data for the attestation:result event.
type AttestationResultPayload struct {
	DeviceName string `json:"device_name"`
	Success    bool   `json:"success"`
	Details    string `json:"details"`
}

// PolicyViolationPayload carries data for the policy:violation event.
type PolicyViolationPayload struct {
	DeviceName string            `json:"device_name"`
	Mismatches map[string]string `json:"mismatches"`
	Message    string            `json:"message"`
}

// TPMProvisionedPayload carries data for the tpm:provisioned event.
type TPMProvisionedPayload struct {
	Success bool   `json:"success"`
	Details string `json:"details"`
}

// TPMQuotePayload carries data for the tpm:quote_generated event.
type TPMQuotePayload struct {
	PCRSelection []int  `json:"pcr_selection"`
	Bank         string `json:"bank"`
	QuoteHex     string `json:"quote_hex"`
}

// TPMKeyCertifiedPayload carries data for the tpm:key_certified event.
type TPMKeyCertifiedPayload struct {
	KeyID   string `json:"key_id"`
	Success bool   `json:"success"`
}

// ErrorPayload carries data for the error event.
type ErrorPayload struct {
	Message   string `json:"message"`
	Component string `json:"component"`
}

// ServerConnectedPayload carries data for the server:connected event.
type ServerConnectedPayload struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Version  string `json:"version"`
}

// ServerErrorPayload carries data for the server:error event.
type ServerErrorPayload struct {
	Message   string `json:"message"`
	Operation string `json:"operation"`
}

// TouchRequiredPayload carries data for the fido2:touch_required event.
type TouchRequiredPayload struct {
	Operation string `json:"operation"`
	RPID      string `json:"rp_id"`
	RPName    string `json:"rp_name"`
	UserName  string `json:"user_name"`
}

// TouchResolvedPayload carries data for the fido2:touch_resolved event.
type TouchResolvedPayload struct {
	Approved bool `json:"approved"`
}

// CredentialCreatedPayload carries data for the fido2:credential_created event.
type CredentialCreatedPayload struct {
	ID              string `json:"id"`
	RelyingPartyID  string `json:"relying_party_id"`
	RelyingParty    string `json:"relying_party"`
	UserName        string `json:"user_name"`
	UserDisplayName string `json:"user_display_name"`
	CreatedAt       string `json:"created_at"`
}

// SetupCompletedPayload carries data for the setup:completed event.
type SetupCompletedPayload struct {
	Mode                  string `json:"mode"`
	StorageCreated        bool   `json:"storage_created"`
	MasterPWSet           bool   `json:"master_password_set"`
	PlatformPolicyCreated bool   `json:"platform_policy_created"`
	TPMSealedPasswords    bool   `json:"tpm_sealed_passwords"`
	UserPINSet            bool   `json:"user_pin_set"`
	SOPINSet              bool   `json:"so_pin_set"`
	BarrierInitialized    bool   `json:"barrier_initialized"`
	BarrierStrategy       string `json:"barrier_strategy"`
}

// SetupProgressPayload carries data for the setup:progress event.
// It is emitted before each step during ApplySetup so the frontend
// can show a live progress indicator.
type SetupProgressPayload struct {
	Step      int    `json:"step"`
	TotalStep int    `json:"total_steps"`
	Label     string `json:"label"`
}

// SetupSkippedPayload carries data for the setup:skipped event.
type SetupSkippedPayload struct {
	Reason string `json:"reason"`
}

// AuthModeChangedPayload carries data for the auth:mode_changed event.
type AuthModeChangedPayload struct {
	Mode           string `json:"mode"`
	PolicyVerified bool   `json:"policy_verified"`
}

// SOProvisioningCompletedPayload carries data for the setup:so_provisioned event.
type SOProvisioningCompletedPayload struct {
	OrganizationName string `json:"organization_name"`
	PolicyVersion    int    `json:"policy_version"`
}

// UserOnboardedPayload carries data for the setup:user_onboarded event.
type UserOnboardedPayload struct {
	BarrierInitialized bool   `json:"barrier_initialized"`
	BarrierStrategy    string `json:"barrier_strategy"`
}

// PolicyTamperDetectedPayload carries data for the policy:tamper_detected event.
type PolicyTamperDetectedPayload struct {
	ChangedFields []string `json:"changed_fields"`
	Message       string   `json:"message"`
}

// AgentServerStartedPayload carries data for the agent:server_started event.
type AgentServerStartedPayload struct {
	ListenAddress string `json:"listen_address"`
}

// AgentServerStoppedPayload carries data for the agent:server_stopped event.
type AgentServerStoppedPayload struct{}

// AgentCodeGeneratedPayload carries data for the agent:code_generated event.
type AgentCodeGeneratedPayload struct {
	ExpiresAt string `json:"expires_at"`
}

// AgentEnrollmentPayload carries data for enrollment approval/rejection events.
type AgentEnrollmentPayload struct {
	RequestID   string `json:"request_id"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// AgentConnectionPayload carries data for agent connected/disconnected events.
type AgentConnectionPayload struct {
	AgentID   string `json:"agent_id"`
	AgentName string `json:"agent_name"`
	Address   string `json:"address"`
}

// AgentRemovedPayload carries data for the agent:removed event.
type AgentRemovedPayload struct {
	AgentID string `json:"agent_id"`
}

// ExtensionPairingRequestPayload carries data for the extension:pairing_request event.
type ExtensionPairingRequestPayload struct {
	Code   string `json:"code"`
	Origin string `json:"origin"`
}

// ExtensionPairedPayload carries data for the extension:paired event.
type ExtensionPairedPayload struct {
	Origin string `json:"origin"`
}

// AutofillCredentialAccessPayload carries data for the autofill:credential_access event.
type AutofillCredentialAccessPayload struct {
	Domain       string `json:"domain"`
	CredentialID string `json:"credential_id"`
	Source       string `json:"source"` // "extension" or "gui"
}

// AutofillTOTPAccessPayload carries data for the autofill:totp_access event.
type AutofillTOTPAccessPayload struct {
	Domain    string `json:"domain"`
	AccountID string `json:"account_id"`
	Source    string `json:"source"`
}

// AutofillPolicyChangedPayload carries data for the autofill:policy_changed event.
type AutofillPolicyChangedPayload struct {
	FillMode string `json:"fill_mode"`
	Enabled  bool   `json:"enabled"`
}
