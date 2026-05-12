import { writable } from 'svelte/store';
import type { AccountInfo, ListAccountsParams, Pagination } from '@trustedca/shared/api/types';
import { adminApi } from '../api/admin-api';
import { notifyError } from '@trustedca/shared/stores/notifications';

export const accounts = writable<AccountInfo[]>([]);
export const accountsPagination = writable<Pagination | null>(null);
export const accountsLoading = writable(false);

export async function fetchAccounts(params?: ListAccountsParams): Promise<void> {
  accountsLoading.set(true);
  try {
    const res = await adminApi.listAccounts(params) as any;
    accounts.set(res.items ?? res.data ?? []);
    accountsPagination.set(res.pagination ?? { page: res.page ?? 1, per_page: res.per_page ?? 20, total: res.total ?? 0 });
  } catch (e) {
    notifyError(`Failed to fetch accounts: ${(e as Error).message}`);
  } finally {
    accountsLoading.set(false);
  }
}
