/**
 * xKey Desktop GUI - Core Type Definitions
 *
 * Copyright (c) Jeremy Hahn. All rights reserved.
 */

/** Application view identifiers for navigation */
export type ViewId =
  | 'dashboard'
  | 'pairing'
  | 'pairing-detail'
  | 'fido2'
  | 'fido2-credential'
  | 'oath'
  | 'piv'
  | 'piv-slot'
  | 'tpm'
  | 'tpm-info'
  | 'seal'
  | 'settings'
  | 'audit-log'
  | 'admin'
  | 'admin-backends';

/** Theme variants */
export type ThemeMode = 'light' | 'dark' | 'system';

/** Card component variants */
export type CardVariant = 'elevated' | 'outlined' | 'security' | 'gradient';

/** Button component variants */
export type ButtonVariant = 'primary' | 'secondary' | 'tertiary' | 'outline' | 'text' | 'danger';

/** Button sizes */
export type ButtonSize = 'sm' | 'md' | 'lg';

/** Status badge states */
export type StatusType =
  | 'connected'
  | 'disconnected'
  | 'advertising'
  | 'error'
  | 'pairing'
  | 'verified'
  | 'unverified'
  | 'warning'
  | 'neutral';

/** Notification severity levels */
export type NotificationLevel = 'info' | 'success' | 'warning' | 'error';

/** Notification entry */
export interface Notification {
  id: string;
  level: NotificationLevel;
  title: string;
  message: string;
  timestamp: number;
  duration?: number;
}

/** Paired phone device */
export interface PairedDevice {
  id: string;
  name: string;
  address: string;
  status: StatusType;
  pairedAt: string;
  lastSeen: string;
  isDefault: boolean;
  signalStrength: number;
  keystoreType: string;
  biometricsAvailable: boolean;
  bootState: string;
  lastAttested: string;
  attestationStatus: StatusType;
  keyCount: number;
  publicKeyFingerprint: string;
}

/** Phone connection state */
export interface PhoneState {
  connected: boolean;
  deviceName: string;
  devices: PairedDevice[];
  scanning: boolean;
  connectedDevice: PairedDevice | null;
}

/** Cryptographic key entry */
export interface KeyEntry {
  id: string;
  label: string;
  algorithm: string;
  backend: string;
  created: string;
  lastUsed: string;
  keyType: string;
  exportable: boolean;
}

/** Keys state */
export interface KeysState {
  keys: KeyEntry[];
  totalCount: number;
  byBackend: Record<string, number>;
  byType: Record<string, number>;
  loading: boolean;
  error: string | null;
}

/** OATH account entry */
export interface OATHAccount {
  id: string;
  issuer: string;
  accountName: string;
  type: 'totp' | 'hotp';
  algorithm: string;
  digits: number;
  period: number;
  counter?: number;
  secret?: string;
}

/** OATH state */
export interface OATHState {
  accounts: OATHAccount[];
  selectedAccount: OATHAccount | null;
  loading: boolean;
  error: string | null;
}

/** FIDO2 credential */
export interface FIDO2Credential {
  id: string;
  credentialId: string;
  rpId: string;
  rpName: string;
  userName: string;
  userDisplayName: string;
  created: string;
  lastUsed: string;
  usageCount: number;
  algorithm: string;
  keyType: string;
  backend: string;
  discoverable: boolean;
  userVerification: string;
}

/** FIDO2 bridge status */
export interface BridgeStatus {
  enabled: boolean;
  connected: boolean;
  transport: string;
  recentAuths: BridgeAuthEvent[];
  uptime: string;
}

/** FIDO2 bridge authentication event */
export interface BridgeAuthEvent {
  id: string;
  rpId: string;
  userName: string;
  timestamp: string;
  success: boolean;
  backend: string;
}

/** Relying party group */
export interface RelyingParty {
  id: string;
  name: string;
  domain: string;
  credentials: FIDO2Credential[];
}

/** FIDO2 state */
export interface FIDO2State {
  credentials: FIDO2Credential[];
  bridgeStatus: BridgeStatus;
  relyingParties: RelyingParty[];
  loading: boolean;
  error: string | null;
}

/** PIV slot entry */
export interface PIVSlot {
  slotId: string;
  label: string;
  purpose: string;
  loaded: boolean;
  algorithm: string | null;
  subject: string | null;
  issuer: string | null;
  serialNumber: string | null;
  notBefore: string | null;
  notAfter: string | null;
  keyUsage: string[];
  fingerprint: string | null;
  daysRemaining: number | null;
}

/** TPM hardware information */
export interface TPMInfo {
  available: boolean;
  manufacturer: string;
  model: string;
  firmwareVersion: string;
  specVersion: string;
  ekProvisioned: boolean;
  iakProvisioned: boolean;
  idevidProvisioned: boolean;
  pcrBanks: TPMPCRBank[];
  capabilities: string[];
  supportedAlgorithms: string[];
}

/** TPM PCR bank */
export interface TPMPCRBank {
  algorithm: string;
  registerCount: number;
  values: TPMPCRValue[];
}

/** TPM PCR value */
export interface TPMPCRValue {
  index: number;
  value: string;
  description: string;
}

/** TPM quote */
export interface TPMQuote {
  pcrSelection: number[];
  bank: string;
  nonce: string;
  quote: string;
  signature: string;
  timestamp: string;
}

/** Audit log entry */
export interface AuditEntry {
  id: string;
  timestamp: string;
  operation: string;
  device: string;
  backend: string;
  keyId: string;
  success: boolean;
  details: string;
  ipAddress: string;
}

/** Backend info */
export interface BackendInfo {
  name: string;
  type: string;
  status: StatusType;
  keyCount: number;
  configuration: Record<string, string>;
}

/** Server status */
export interface ServerStatus {
  url: string;
  status: StatusType;
  uptime: string;
  version: string;
  backends: BackendInfo[];
}

/** Settings categories */
export type SettingsCategory =
  | 'general'
  | 'appearance'
  | 'phone'
  | 'security'
  | 'notifications'
  | 'advanced';

/** Application settings */
export interface AppSettings {
  startWithSystem: boolean;
  startMinimized: boolean;
  autoConnect: boolean;
  theme: ThemeMode;
  fontSize: number;
  defaultDevice: string;
  attestationPolicy: string;
  gracePeriod: number;
  lockTimeout: number;
  requireAuth: boolean;
  notifyOnConnect: boolean;
  notifyOnAuth: boolean;
  notifyOnError: boolean;
  xkmsdUrl: string;
  defaultBackend: string;
  logLevel: string;
  debugMode: boolean;
}

/** Activity/event for the dashboard feed */
export interface ActivityEvent {
  id: string;
  type: string;
  title: string;
  description: string;
  timestamp: string;
  icon: string;
  severity: NotificationLevel;
}

/** Tab definition for Tabs component */
export interface TabDef {
  id: string;
  label: string;
}

/** Application state */
export interface AppState {
  currentView: ViewId;
  viewParams: Record<string, string>;
  initialized: boolean;
  loading: boolean;
  error: string | null;
  serverConnected: boolean;
}
