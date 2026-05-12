import { writable } from 'svelte/store';
import type { TenantInfo, Pagination } from '@trustedca/shared/api/types';
import { adminApi } from '../api/admin-api';
import { notifyError } from '@trustedca/shared/stores/notifications';

export const tenants = writable<TenantInfo[]>([]);
export const tenantsPagination = writable<Pagination | null>(null);
export const tenantsLoading = writable(false);
export const selectedTenant = writable<TenantInfo | null>(null);

export async function fetchTenants(params?: { page?: number; per_page?: number; status?: string }): Promise<void> {
  tenantsLoading.set(true);
  try {
    const res = await adminApi.listTenants(params) as any;
    tenants.set(res.items ?? res.data ?? []);
    tenantsPagination.set(res.pagination ?? { page: res.page ?? 1, per_page: res.per_page ?? 20, total: res.total ?? 0 });
  } catch (e) {
    notifyError(`Failed to fetch tenants: ${(e as Error).message}`);
  } finally {
    tenantsLoading.set(false);
  }
}

export async function fetchTenant(id: string): Promise<void> {
  tenantsLoading.set(true);
  try {
    const tenant = await adminApi.getTenant(id);
    selectedTenant.set(tenant);
  } catch (e) {
    notifyError(`Failed to fetch tenant: ${(e as Error).message}`);
  } finally {
    tenantsLoading.set(false);
  }
}
