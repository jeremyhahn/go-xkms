/**
 * Form validation helpers.
 */

export interface ValidationResult {
  valid: boolean;
  message: string;
}

const VALID: ValidationResult = { valid: true, message: '' };

function invalid(message: string): ValidationResult {
  return { valid: false, message };
}

/** Validate that a value is not empty. */
export function required(value: string | undefined | null, label?: string): ValidationResult {
  if (!value || value.trim().length === 0) {
    return invalid(`${label ?? 'This field'} is required`);
  }
  return VALID;
}

/** Validate minimum string length. */
export function minLength(value: string, min: number, label?: string): ValidationResult {
  if (value.length < min) {
    return invalid(`${label ?? 'Value'} must be at least ${min} characters`);
  }
  return VALID;
}

/** Validate maximum string length. */
export function maxLength(value: string, max: number, label?: string): ValidationResult {
  if (value.length > max) {
    return invalid(`${label ?? 'Value'} must be at most ${max} characters`);
  }
  return VALID;
}

/** Validate that a value is a valid email address. */
export function email(value: string): ValidationResult {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!re.test(value)) {
    return invalid('Invalid email address');
  }
  return VALID;
}

/** Validate that a value is a valid domain name. */
export function domain(value: string): ValidationResult {
  const re = /^(\*\.)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/;
  if (!re.test(value)) {
    return invalid('Invalid domain name');
  }
  return VALID;
}

/** Validate a positive integer. */
export function positiveInteger(value: string | number, label?: string): ValidationResult {
  const n = typeof value === 'string' ? parseInt(value, 10) : value;
  if (isNaN(n) || n < 1 || !Number.isInteger(n)) {
    return invalid(`${label ?? 'Value'} must be a positive integer`);
  }
  return VALID;
}

/** Validate that a value matches a regex pattern. */
export function pattern(value: string, regex: RegExp, message: string): ValidationResult {
  if (!regex.test(value)) {
    return invalid(message);
  }
  return VALID;
}

/** Validate a slug-style identifier (lowercase, alphanumeric, hyphens). */
export function slug(value: string, label?: string): ValidationResult {
  const re = /^[a-z0-9][a-z0-9-]*[a-z0-9]$/;
  if (value.length < 2) {
    return invalid(`${label ?? 'ID'} must be at least 2 characters`);
  }
  if (!re.test(value)) {
    return invalid(`${label ?? 'ID'} must contain only lowercase letters, numbers, and hyphens`);
  }
  return VALID;
}

/** Run multiple validators and return the first failure, or success. */
export function compose(...results: ValidationResult[]): ValidationResult {
  for (const r of results) {
    if (!r.valid) return r;
  }
  return VALID;
}
