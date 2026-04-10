/**
 * Formatting utilities for the xKey Desktop GUI.
 */

const SECOND = 1000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
const WEEK = 7 * DAY;
const MONTH = 30 * DAY;
const YEAR = 365 * DAY;

/**
 * Formats a date as a human-readable relative time string.
 * For example: "2 minutes ago", "just now", "3 days ago".
 */
export function formatRelativeTime(date: Date | string | number): string {
  const target = date instanceof Date ? date : new Date(date);
  const now = Date.now();
  const diff = now - target.getTime();

  if (diff < 0) {
    return 'just now';
  }

  if (diff < MINUTE) {
    const seconds = Math.floor(diff / SECOND);
    return seconds <= 5 ? 'just now' : `${seconds} seconds ago`;
  }

  if (diff < HOUR) {
    const minutes = Math.floor(diff / MINUTE);
    return minutes === 1 ? '1 minute ago' : `${minutes} minutes ago`;
  }

  if (diff < DAY) {
    const hours = Math.floor(diff / HOUR);
    return hours === 1 ? '1 hour ago' : `${hours} hours ago`;
  }

  if (diff < WEEK) {
    const days = Math.floor(diff / DAY);
    if (days === 1) return 'yesterday';
    return `${days} days ago`;
  }

  if (diff < MONTH) {
    const weeks = Math.floor(diff / WEEK);
    return weeks === 1 ? '1 week ago' : `${weeks} weeks ago`;
  }

  if (diff < YEAR) {
    const months = Math.floor(diff / MONTH);
    return months === 1 ? '1 month ago' : `${months} months ago`;
  }

  const years = Math.floor(diff / YEAR);
  return years === 1 ? '1 year ago' : `${years} years ago`;
}

/**
 * Formats a date as a localized date/time string.
 * For example: "Jan 15, 2025 2:30 PM"
 */
export function formatDateTime(date: Date | string | number): string {
  const target = date instanceof Date ? date : new Date(date);
  return target.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    hour12: true,
  });
}

/**
 * Formats a date as a localized date-only string.
 * For example: "Jan 15, 2025"
 */
export function formatDate(date: Date | string | number): string {
  const target = date instanceof Date ? date : new Date(date);
  return target.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

/**
 * Formats a date as a localized time-only string.
 * For example: "2:30 PM"
 */
export function formatTime(date: Date | string | number): string {
  const target = date instanceof Date ? date : new Date(date);
  return target.toLocaleTimeString('en-US', {
    hour: 'numeric',
    minute: '2-digit',
    hour12: true,
  });
}

/**
 * Formats a hex fingerprint string into grouped display.
 * For example: "AB:CD:EF:12:34:56:78:90"
 */
export function formatFingerprint(hex: string): string {
  const cleaned = hex.replace(/[^a-fA-F0-9]/g, '').toUpperCase();
  const groups: string[] = [];
  for (let i = 0; i < cleaned.length; i += 2) {
    groups.push(cleaned.substring(i, i + 2));
  }
  return groups.join(':');
}

/**
 * Formats a TOTP code with space-separated grouping.
 * For example: "123456" becomes "123 456", "12345678" becomes "1234 5678".
 */
export function formatTOTPCode(code: string): string {
  const cleaned = code.replace(/\s/g, '');
  if (cleaned.length <= 4) return cleaned;
  if (cleaned.length === 6) {
    return `${cleaned.substring(0, 3)} ${cleaned.substring(3)}`;
  }
  if (cleaned.length === 8) {
    return `${cleaned.substring(0, 4)} ${cleaned.substring(4)}`;
  }
  const mid = Math.ceil(cleaned.length / 2);
  return `${cleaned.substring(0, mid)} ${cleaned.substring(mid)}`;
}

/**
 * Truncates a string in the middle, preserving start and end.
 * For example: truncateMiddle("abcdefghij", 8) returns "abc...ij"
 */
export function truncateMiddle(str: string, maxLen: number): string {
  if (str.length <= maxLen) return str;
  if (maxLen < 5) return str.substring(0, maxLen);
  const ellipsis = '...';
  const charsToShow = maxLen - ellipsis.length;
  const frontChars = Math.ceil(charsToShow / 2);
  const backChars = Math.floor(charsToShow / 2);
  return str.substring(0, frontChars) + ellipsis + str.substring(str.length - backChars);
}

/**
 * Formats a byte count as a human-readable size string.
 * For example: 1536 becomes "1.5 KB", 1048576 becomes "1.0 MB".
 */
export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const base = 1024;
  const unitIndex = Math.min(Math.floor(Math.log(bytes) / Math.log(base)), units.length - 1);
  const value = bytes / Math.pow(base, unitIndex);
  return unitIndex === 0 ? `${bytes} B` : `${value.toFixed(1)} ${units[unitIndex]}`;
}

/**
 * Formats a duration in milliseconds as a human-readable string.
 * For example: 8100000 becomes "2h 15m", 45000 becomes "45s".
 */
export function formatDuration(ms: number): string {
  if (ms < SECOND) return `${ms}ms`;

  const parts: string[] = [];
  let remaining = ms;

  const days = Math.floor(remaining / DAY);
  if (days > 0) {
    parts.push(`${days}d`);
    remaining -= days * DAY;
  }

  const hours = Math.floor(remaining / HOUR);
  if (hours > 0) {
    parts.push(`${hours}h`);
    remaining -= hours * HOUR;
  }

  const minutes = Math.floor(remaining / MINUTE);
  if (minutes > 0) {
    parts.push(`${minutes}m`);
    remaining -= minutes * MINUTE;
  }

  if (parts.length === 0) {
    const seconds = Math.floor(remaining / SECOND);
    parts.push(`${seconds}s`);
  }

  return parts.join(' ');
}
