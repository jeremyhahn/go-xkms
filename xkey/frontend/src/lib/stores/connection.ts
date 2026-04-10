import { writable, derived } from 'svelte/store';
import { callBackend, callBackendVoid } from '$lib/api/backend';
import type { ConnectionInfo } from '$lib/api/backend';

export interface ConnectionState {
  state: 'disconnected' | 'connecting' | 'connected' | 'error';
  protocol: string;
  address: string;
  tls: boolean;
  version: string;
  error: string;
}

const defaultState: ConnectionState = {
  state: 'disconnected',
  protocol: '',
  address: '',
  tls: false,
  version: '',
  error: '',
};

export const connectionState = writable<ConnectionState>(defaultState);
export const isServerConnected = derived(connectionState, ($s) => $s.state === 'connected');

export async function connect(
  protocol: string,
  address: string,
  tlsEnabled: boolean,
  tlsSkipVerify: boolean,
  caFile: string
): Promise<ConnectionInfo | null> {
  connectionState.update((s) => ({ ...s, state: 'connecting', error: '' }));
  const result = await callBackend<ConnectionInfo>(
    'ConnectionService',
    'Connect',
    protocol,
    address,
    tlsEnabled,
    tlsSkipVerify,
    caFile
  );
  if (result) {
    connectionState.set({
      state: result.state as ConnectionState['state'],
      protocol: result.protocol,
      address: result.address,
      tls: result.tls,
      version: result.version || '',
      error: result.error || '',
    });
  } else {
    connectionState.update((s) => ({
      ...s,
      state: 'error',
      error: 'Connection failed',
    }));
  }
  return result;
}

export async function disconnect(): Promise<void> {
  await callBackendVoid('ConnectionService', 'Disconnect');
  connectionState.set(defaultState);
}

export async function refreshConnectionInfo(): Promise<void> {
  const info = await callBackend<ConnectionInfo>('ConnectionService', 'GetConnectionInfo');
  if (info) {
    connectionState.set({
      state: info.state as ConnectionState['state'],
      protocol: info.protocol,
      address: info.address,
      tls: info.tls,
      version: info.version || '',
      error: info.error || '',
    });
  }
}
