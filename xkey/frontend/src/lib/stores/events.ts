import { writable } from 'svelte/store';
import { pairingState, updateDeviceAttestation, updateDeviceConnection } from './pairing';
import type { DeviceAttestation } from './pairing';
import { addKey, removeKey } from './keys';
import { addBridgeAuthentication, setBridgeStatus, setCredentials } from './fido2';
import { addNotification } from './notifications';
import { setTouchPending, clearTouchPending } from './touch';
import { setSetupComplete } from './app';
import { setProgress } from './wizard';
import type { SetupProgressStep } from './wizard';
import type { BridgeStatus, BridgeAuthentication, FIDO2Credential } from './fido2';
import type { KeyEntry } from './keys';
import { isWailsAvailable, callBackend } from '$lib/api/backend';
import * as wailsRuntimeModule from '../../wailsjs/runtime/runtime';
import type { BackendFIDO2Credential } from '$lib/api/backend';
import { setAuthMode, setPolicyVerified, setTamperDetected } from './auth';
import type { AuthMode } from '$lib/types/setup';

/** Whether the application is in the process of shutting down. */
export const shuttingDown = writable<boolean>(false);

/** Counter that increments on extension:paired / extension:unpaired events. */
export const extensionPairingChanged = writable<number>(0);

/** Whether the application is locked (global app lock). */
export const appLocked = writable<boolean>(false);

/**
 * Event listener setup for Wails runtime events.
 *
 * The Wails runtime module (../../wailsjs/runtime/runtime) is auto-generated
 * during the Wails build process. In development without Wails, these listeners
 * are registered as stubs that can be activated when the runtime becomes available.
 */

type EventCallback = (data: unknown) => void;

interface WailsRuntime {
  EventsOn(event: string, callback: EventCallback): void;
}

let wailsRuntime: WailsRuntime | null = null;

function on(event: string, callback: EventCallback): void {
  if (wailsRuntime) {
    wailsRuntime.EventsOn(event, callback);
  } else {
    console.warn(`[events] Cannot register listener for "${event}": Wails runtime not available`);
  }
}

export async function setupEventListeners(): Promise<void> {
  try {
    wailsRuntime = wailsRuntimeModule as unknown as WailsRuntime;
    console.log('[events] Wails runtime loaded, registering event listeners');
  } catch {
    // Wails runtime not available (development mode outside Wails)
    // Event listeners will be no-ops until the runtime is loaded
    wailsRuntime = null;
  }

  on('phone:connected', (data) => {
    const payload = data as { name: string; address: string; securityLevel: string };
    pairingState.update((s) => ({
      ...s,
      connected: true,
      deviceName: payload.name,
      deviceAddress: payload.address,
      securityLevel: payload.securityLevel,
      connectedSince: new Date().toISOString(),
    }));
    updateDeviceConnection(payload.name, true);
    addNotification('success', `Connected to ${payload.name}`);
  });

  on('phone:disconnected', (_data) => {
    let deviceName: string | null = null;
    pairingState.subscribe((s) => { deviceName = s.deviceName; })();
    if (deviceName) {
      updateDeviceConnection(deviceName, false);
    }
    pairingState.update((s) => ({
      ...s,
      connected: false,
      deviceName: null,
      deviceAddress: null,
      securityLevel: null,
      signalStrength: null,
      connectedSince: null,
    }));
    if (deviceName) {
      addNotification('info', `Disconnected from ${deviceName}`);
    }
  });

  on('key:created', (data) => {
    const key = data as KeyEntry;
    addKey(key);
    addNotification('success', `Key created: ${key.alias}`);
  });

  on('key:deleted', (data) => {
    const payload = data as { id: string; alias: string };
    removeKey(payload.id);
    addNotification('info', `Key deleted: ${payload.alias}`);
  });

  on('key:used', (data) => {
    const payload = data as { keyAlias: string; operation: string };
    addNotification('info', `Key used: ${payload.keyAlias} (${payload.operation})`);
  });

  on('fido2:bridge_started', (data) => {
    const status = data as BridgeStatus;
    setBridgeStatus(status);
    addNotification('success', 'FIDO2 phone bridge started');
  });

  on('fido2:bridge_stopped', (_data) => {
    setBridgeStatus({
      running: false,
      deviceName: null,
      connectionType: null,
      uptime: 0,
      recentAuthentications: [],
    });
    addNotification('info', 'FIDO2 phone bridge stopped');
  });

  on('fido2:authentication', (data) => {
    const auth = data as BridgeAuthentication;
    addBridgeAuthentication(auth);
    const statusText = auth.success ? 'successful' : 'failed';
    const type = auth.success ? 'success' : 'error';
    addNotification(type as 'success' | 'error', `Authentication ${statusText}: ${auth.relyingParty}`);
  });

  on('attestation:result', (data) => {
    const evt = data as { type: string; payload: { device_name: string; success: boolean; details: string; attestation?: DeviceAttestation; address?: string }; time: string };
    const payload = evt.payload || data as { device_name: string; success: boolean; details: string; attestation?: DeviceAttestation; address?: string };
    const deviceName = payload.device_name || (data as any).deviceName;
    const success = payload.success ?? (data as any).success;
    const type = success ? 'success' : 'warning';
    addNotification(type as 'success' | 'warning', `Attestation ${success ? 'passed' : 'failed'}: ${deviceName}`);

    // Update the phone store with attestation data if provided
    if (payload.attestation && payload.address) {
      updateDeviceAttestation(payload.address, payload.attestation);
    }
  });

  on('settings:changed', (_data) => {
    addNotification('info', 'Settings updated');
  });

  on('server:connected', (data) => {
    const payload = data as { protocol: string; address: string; version: string };
    addNotification('success', `Connected to ${payload.address} via ${payload.protocol}`);
  });

  on('server:disconnected', (_data) => {
    addNotification('info', 'Disconnected from server');
  });

  on('server:error', (data) => {
    const payload = data as { message: string; operation: string };
    addNotification('error', `Server error: ${payload.message}`);
  });

  on('fido2:credential_created', async (_data) => {
    // Re-fetch the full credential list from the backend to ensure consistency.
    if (isWailsAvailable()) {
      const creds = await callBackend<BackendFIDO2Credential[]>('FIDO2Service', 'ListCredentials');
      if (creds && creds.length > 0) {
        setCredentials(creds.map((c): FIDO2Credential => ({
          id: c.id,
          relyingPartyId: c.relying_party_id,
          relyingPartyName: c.relying_party,
          userName: c.user_name,
          userDisplayName: c.user_display_name,
          algorithm: c.algorithm || '',
          keyType: c.key_type || '',
          credProtect: c.cred_protect || 0,
          backendType: c.backend_type || 'software',
          useCount: c.use_count || 0,
          discoverable: c.discoverable ?? false,
          created: c.created_at,
          lastUsed: c.last_used || null,
        })));
      }
    }
    const payload = _data as { relying_party?: string; user_name?: string };
    const rpName = payload.relying_party || 'Unknown';
    addNotification('success', `New credential registered: ${rpName}`);
  });

  on('fido2:touch_required', (data) => {
    const payload = data as { operation: string; rp_id: string; rp_name: string; user_name: string };
    setTouchPending(payload);
    addNotification('warning', `Touch required: ${payload.rp_name || payload.rp_id} (${payload.operation})`);
  });

  on('fido2:touch_resolved', (_data) => {
    clearTouchPending();
  });

  on('setup:progress', (data) => {
    const evt = data as { payload?: SetupProgressStep } & SetupProgressStep;
    const payload = evt.payload || evt;
    setProgress(payload);
  });

  on('setup:completed', (_data) => {
    setSetupComplete(true);
    addNotification('success', 'Setup wizard completed successfully');
  });

  on('setup:skipped', (_data) => {
    addNotification('info', 'Setup wizard skipped');
  });

  on('policy:violation', (data) => {
    const evt = data as { type: string; payload: { device_name: string; mismatches: Record<string, string>; message: string }; time: string };
    const payload = evt.payload || data as { device_name: string; mismatches: Record<string, string>; message: string };
    const deviceName = payload.device_name || 'Unknown device';
    const message = payload.message || 'Attestation policy violation';
    const mismatches = payload.mismatches || {};

    const details = Object.entries(mismatches)
      .map(([field, desc]) => `${field}: ${desc}`)
      .join('; ');

    const fullMessage = details
      ? `${message} (${deviceName}) — ${details}`
      : `${message} (${deviceName})`;

    addNotification('error', fullMessage);
  });

  on('auth:mode_changed', (data) => {
    const payload = data as { mode: string };
    setAuthMode(payload.mode as AuthMode);
  });

  on('policy:tamper_detected', (data) => {
    const payload = data as { fields?: string[] };
    setTamperDetected(true);
    const fieldList = payload.fields?.join(', ') || 'unknown fields';
    addNotification('error', `Policy tamper detected: ${fieldList}`);
  });

  on('setup:so_provisioned', (_data) => {
    addNotification('success', 'SO provisioning completed');
  });

  on('setup:user_onboarded', (_data) => {
    setSetupComplete(true);
    addNotification('success', 'User onboarding completed');
  });

  on('app:shutting_down', () => {
    shuttingDown.set(true);
  });

  on('app:locked', () => {
    appLocked.set(true);
  });

  on('app:unlocked', () => {
    appLocked.set(false);
  });

  on('extension:paired', (data) => {
    const payload = data as { payload?: { origin?: string } } & { origin?: string };
    const origin = payload.payload?.origin || payload.origin || '';
    extensionPairingChanged.update((n) => n + 1);
    addNotification('success', `Extension paired: ${origin}`);
  });

  on('extension:unpaired', () => {
    extensionPairingChanged.update((n) => n + 1);
    addNotification('info', 'Extension unpaired');
  });
}
