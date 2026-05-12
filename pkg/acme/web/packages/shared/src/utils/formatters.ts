/**
 * Formatting utilities for dates, bytes, certificates and other display values.
 */

/** Format an ISO date string for display. */
export function formatDate(iso: string | undefined | null): string {
  if (!iso) return '-';
  try {
    return new Date(iso).toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  } catch {
    return iso;
  }
}

/** Format an ISO date string with time. */
export function formatDateTime(iso: string | undefined | null): string {
  if (!iso) return '-';
  try {
    return new Date(iso).toLocaleString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return iso;
  }
}

/** Return a human-readable relative time string (e.g. "3 days ago"). */
export function formatRelativeTime(iso: string | undefined | null): string {
  if (!iso) return '-';
  const date = new Date(iso);
  const now = new Date();
  const diffMs = date.getTime() - now.getTime();
  const diffDays = Math.round(diffMs / (1000 * 60 * 60 * 24));

  if (diffDays === 0) return 'today';
  if (diffDays === 1) return 'tomorrow';
  if (diffDays === -1) return 'yesterday';
  if (diffDays > 0) return `in ${diffDays} days`;
  return `${Math.abs(diffDays)} days ago`;
}

/** Calculate days remaining until a date. */
export function daysRemaining(iso: string | undefined | null): number | null {
  if (!iso) return null;
  const date = new Date(iso);
  const now = new Date();
  return Math.ceil((date.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
}

/** Format a byte count as a human-readable string. */
export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const k = 1024;
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  const value = bytes / Math.pow(k, i);
  return `${value.toFixed(i > 0 ? 1 : 0)} ${units[i]}`;
}

/** Truncate a serial number for display. */
export function formatSerial(serial: string | undefined | null): string {
  if (!serial) return '-';
  if (serial.length <= 16) return serial;
  return `${serial.slice(0, 8)}...${serial.slice(-8)}`;
}

/** Format a certificate subject for display. */
export function formatSubject(subject: string | undefined | null): string {
  if (!subject) return '-';
  // Extract CN from DN string like "CN=example.com,O=Org,..."
  const cnMatch = subject.match(/CN=([^,]+)/i);
  return cnMatch ? cnMatch[1] : subject;
}

/** Format a number with thousands separators. */
export function formatNumber(n: number | undefined | null): string {
  if (n === undefined || n === null) return '-';
  return n.toLocaleString();
}

/** Capitalise the first letter of a string. */
export function capitalize(s: string): string {
  if (!s) return '';
  return s.charAt(0).toUpperCase() + s.slice(1);
}
