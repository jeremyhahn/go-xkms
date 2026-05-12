import { writable } from 'svelte/store';
import type { CAStatus, CAStats } from '@trustedca/shared/api/types';
import { adminApi } from '../api/admin-api';
import { notifyError } from '@trustedca/shared/stores/notifications';

export const caStatus = writable<CAStatus | null>(null);
export const caStats = writable<CAStats | null>(null);
export const statusLoading = writable(false);

export async function fetchStatus(): Promise<void> {
  statusLoading.set(true);
  try {
    const [status, stats] = await Promise.all([
      adminApi.getStatus(),
      adminApi.getStats(),
    ]);
    caStatus.set(status);
    caStats.set(stats);
  } catch (e) {
    notifyError(`Failed to fetch CA status: ${(e as Error).message}`);
  } finally {
    statusLoading.set(false);
  }
}
