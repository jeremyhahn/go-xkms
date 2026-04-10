import { writable, derived } from 'svelte/store';

export interface AttestCertInfo {
  label: string;
  subject: string;
  issuer: string;
  algorithm: string;
  public_key_fp: string;
  cert_fp: string;
  not_before: string;
  not_after: string;
  is_ca: boolean;
  is_trust_anchor: boolean;
}

export interface DeviceAttestation {
  device_name: string;
  verified: boolean;
  chain_length: number;
  attest_time: string;
  error_message?: string;
  security_level: string;
  boot_state: string;
  boot_hash: string;
  boot_key_hash: string;
  device_locked: boolean;
  key_algorithm: string;
  key_size: number;
  key_purposes: string[];
  key_origin: string;
  attest_version: number;
  keymaster_version: number;
  keymaster_security: string;
  certificates: AttestCertInfo[];
  trust_anchor_subject?: string;
  trust_anchor_fingerprint?: string;
}

export interface AttestationPolicy {
  enabled: boolean;
  boot_hash: string;
  boot_key_hash: string;
  boot_state: string;
  device_locked: boolean;
  min_security_level: string;
  set_at: string;
}

export type PairedDeviceType = 'phone' | 'extension' | 'agent';

export interface PairedDevice {
  name: string;
  address: string;
  paired: string;
  securityLevel: string;
  attestationStatus: string;
  lastAttestation: string | null;
  isDefault: boolean;
  isBackend: boolean;
  attestation: DeviceAttestation | null;
  policy: AttestationPolicy | null;
  type: PairedDeviceType;
}

export interface PairingState {
  connected: boolean;
  deviceName: string | null;
  deviceAddress: string | null;
  securityLevel: string | null;
  signalStrength: number | null;
  scanning: boolean;
  devices: PairedDevice[];
  connectedSince: string | null;
}

const initialState: PairingState = {
  connected: false,
  deviceName: null,
  deviceAddress: null,
  securityLevel: null,
  signalStrength: null,
  scanning: false,
  devices: [],
  connectedSince: null,
};

export const pairingState = writable<PairingState>(initialState);

// Keep phoneState as alias for backward compatibility during transition.
export const phoneState = pairingState;

export const isPhoneConnected = derived(pairingState, ($s) => $s.connected);
export const connectedDevice = derived(pairingState, ($s) =>
  $s.connected ? { name: $s.deviceName, address: $s.deviceAddress } : null
);
export const isScanning = derived(pairingState, ($s) => $s.scanning);
export const pairedDevices = derived(pairingState, ($s) => $s.devices);
export const deviceCount = derived(pairingState, ($s) => $s.devices.length);

export function setConnected(name: string, address: string, securityLevel: string): void {
  pairingState.update((s) => ({
    ...s,
    connected: true,
    deviceName: name,
    deviceAddress: address,
    securityLevel,
    connectedSince: new Date().toISOString(),
  }));
}

export function setDisconnected(): void {
  pairingState.update((s) => ({
    ...s,
    connected: false,
    deviceName: null,
    deviceAddress: null,
    securityLevel: null,
    signalStrength: null,
    connectedSince: null,
  }));
}

export function setScanning(value: boolean): void {
  pairingState.update((s) => ({ ...s, scanning: value }));
}

export function setDevices(devices: PairedDevice[]): void {
  pairingState.update((s) => ({ ...s, devices }));
}

export function updateSignalStrength(dbm: number): void {
  pairingState.update((s) => ({ ...s, signalStrength: dbm }));
}

export function addDevice(device: PairedDevice): void {
  pairingState.update((s) => ({
    ...s,
    devices: [...s.devices, device],
  }));
}

export function removeDevice(address: string): void {
  pairingState.update((s) => ({
    ...s,
    devices: s.devices.filter((d) => d.address !== address),
  }));
}

export function updateDeviceConnection(name: string, connected: boolean): void {
  pairingState.update((s) => ({
    ...s,
    devices: s.devices.map((d) =>
      d.name === name
        ? { ...d, attestationStatus: connected ? 'connected' : 'disconnected' }
        : d
    ),
  }));
}

export function updateDeviceAttestation(address: string, attestation: DeviceAttestation): void {
  pairingState.update((s) => ({
    ...s,
    devices: s.devices.map((d) =>
      d.address === address
        ? { ...d, attestation, lastAttestation: attestation.attest_time, attestationStatus: attestation.verified ? 'verified' : 'unverified' }
        : d
    ),
  }));
}

export function updateDevicePolicy(address: string, policy: AttestationPolicy | null): void {
  pairingState.update((s) => ({
    ...s,
    devices: s.devices.map((d) =>
      d.address === address ? { ...d, policy } : d
    ),
  }));
}

export function updateDeviceBackend(name: string, isBackend: boolean): void {
  pairingState.update((s) => ({
    ...s,
    devices: s.devices.map((d) =>
      d.name === name ? { ...d, isBackend } : d
    ),
  }));
}
