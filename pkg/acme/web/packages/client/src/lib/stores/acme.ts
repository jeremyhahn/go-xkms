import { writable } from 'svelte/store';
import type { RenewalStatus, RenewalConfig } from '@trustedca/shared/api/types';
import { clientApi } from '../api/client-api';
import { notifyError } from '@trustedca/shared/stores/notifications';

export const accountUrl = writable<string | null>(null);
export const accountStatus = writable<string>('');
export const renewalStatus = writable<RenewalStatus | null>(null);
export const renewalConfig = writable<RenewalConfig | null>(null);
export const acmeLoading = writable(false);

export async function fetchRenewalStatus(): Promise<void> {
  acmeLoading.set(true);
  try {
    const status = await clientApi.getRenewalStatus();
    renewalStatus.set(status);
  } catch (e) {
    notifyError(`Failed to fetch renewal status: ${(e as Error).message}`);
  } finally {
    acmeLoading.set(false);
  }
}

export async function fetchRenewalConfig(): Promise<void> {
  try {
    const cfg = await clientApi.getRenewalConfig();
    renewalConfig.set(cfg);
  } catch (e) {
    notifyError(`Failed to fetch renewal config: ${(e as Error).message}`);
  }
}
