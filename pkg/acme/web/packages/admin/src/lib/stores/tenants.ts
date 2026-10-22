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
    const res = await adminApi.listTenants(params);
    tenants.set(res.tenants ?? []);
    tenantsPagination.set({
      page: res.pagination.page,
      per_page: res.pagination.page_size,
      total: res.pagination.total,
    });
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
