import { writable } from 'svelte/store';
import type { OrderInfo, Pagination } from '@trustedca/shared/api/types';
import { adminApi } from '../api/admin-api';
import { notifyError } from '@trustedca/shared/stores/notifications';

export const orders = writable<OrderInfo[]>([]);
export const ordersPagination = writable<Pagination | null>(null);
export const ordersLoading = writable(false);
export const selectedOrder = writable<OrderInfo | null>(null);

export async function fetchOrders(params?: {
  page?: number;
  per_page?: number;
  status?: string;
  account_id?: number;
}): Promise<void> {
  ordersLoading.set(true);
  try {
    const res = await adminApi.listOrders(params) as any;
    orders.set(res.items ?? res.data ?? []);
    ordersPagination.set(res.pagination ?? { page: res.page ?? 1, per_page: res.per_page ?? 20, total: res.total ?? 0 });
  } catch (e) {
    notifyError(`Failed to fetch orders: ${(e as Error).message}`);
  } finally {
    ordersLoading.set(false);
  }
}

export async function fetchOrder(id: string): Promise<void> {
  ordersLoading.set(true);
  try {
    const order = await adminApi.getOrder(id);
    selectedOrder.set(order);
  } catch (e) {
    notifyError(`Failed to fetch order: ${(e as Error).message}`);
  } finally {
    ordersLoading.set(false);
  }
}
