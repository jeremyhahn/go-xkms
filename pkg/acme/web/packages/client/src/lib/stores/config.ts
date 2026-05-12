import { writable } from 'svelte/store';
import type { ClientConfig, ClientConfigUpdate } from '@trustedca/shared/api/types';
import { clientApi } from '../api/client-api';
import { notifyError, notifySuccess } from '@trustedca/shared/stores/notifications';

export const clientConfig = writable<ClientConfig | null>(null);
export const configLoading = writable(false);

export async function fetchConfig(): Promise<void> {
  configLoading.set(true);
  try {
    const cfg = await clientApi.getConfig();
    clientConfig.set(cfg);
  } catch (e) {
    notifyError(`Failed to fetch configuration: ${(e as Error).message}`);
  } finally {
    configLoading.set(false);
  }
}

export async function saveConfig(update: ClientConfigUpdate): Promise<void> {
  configLoading.set(true);
  try {
    await clientApi.updateConfig(update);
    // Re-fetch to pick up the server-authoritative state after the update.
    const cfg = await clientApi.getConfig();
    clientConfig.set(cfg);
    notifySuccess('Configuration saved');
  } catch (e) {
    notifyError(`Failed to save configuration: ${(e as Error).message}`);
  } finally {
    configLoading.set(false);
  }
}
