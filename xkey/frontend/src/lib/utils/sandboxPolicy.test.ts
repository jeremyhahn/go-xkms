import { describe, it, expect } from 'vitest';
import { validateSandboxPolicy, SAFE_DEFAULT_SANDBOX_POLICY } from './sandboxPolicy';

describe('validateSandboxPolicy', () => {
  it('accepts the safe default policy unchanged', () => {
    const result = validateSandboxPolicy(SAFE_DEFAULT_SANDBOX_POLICY);
    expect(result.valid).toBe(true);
    expect(result.policy).toBe(SAFE_DEFAULT_SANDBOX_POLICY);
    expect(result.reason).toBeUndefined();
  });

  it('accepts an empty policy as valid (caller applies its own default)', () => {
    const result = validateSandboxPolicy('');
    expect(result.valid).toBe(true);
    expect(result.policy).toBe('');
  });

  it('refuses allow-scripts combined with allow-same-origin', () => {
    const result = validateSandboxPolicy('allow-same-origin allow-scripts allow-forms allow-popups');
    expect(result.valid).toBe(false);
    expect(result.policy).toBe(SAFE_DEFAULT_SANDBOX_POLICY);
    expect(result.reason).toMatch(/allow-scripts/);
    expect(result.reason).toMatch(/allow-same-origin/);
  });

  it('refuses the dangerous combination regardless of token order', () => {
    const result = validateSandboxPolicy('allow-scripts allow-same-origin');
    expect(result.valid).toBe(false);
    expect(result.policy).toBe(SAFE_DEFAULT_SANDBOX_POLICY);
  });

  it('allows allow-scripts without allow-same-origin', () => {
    // A srcdoc frame without allow-same-origin has a unique opaque origin,
    // so allow-scripts alone cannot reach window.parent.
    const result = validateSandboxPolicy('allow-scripts allow-forms');
    expect(result.valid).toBe(true);
    expect(result.policy).toBe('allow-scripts allow-forms');
  });

  it('allows allow-same-origin without allow-scripts', () => {
    // Without allow-scripts, no script in the previewed response ever runs.
    const result = validateSandboxPolicy('allow-same-origin allow-forms');
    expect(result.valid).toBe(true);
    expect(result.policy).toBe('allow-same-origin allow-forms');
  });

  it.each([
    'allow-top-navigation',
    'allow-top-navigation-by-user-activation',
    'allow-top-navigation-to-custom-protocols',
    'allow-popups-to-escape-sandbox',
    'allow-modals',
  ])('refuses forbidden directive %s outright', (directive) => {
    const result = validateSandboxPolicy(`allow-forms ${directive}`);
    expect(result.valid).toBe(false);
    expect(result.policy).toBe(SAFE_DEFAULT_SANDBOX_POLICY);
    expect(result.reason).toContain(directive);
  });

  it('is tolerant of extra whitespace between tokens', () => {
    const result = validateSandboxPolicy('  allow-forms   allow-popups  ');
    expect(result.valid).toBe(true);
  });

  it('does not refuse an unrecognized directive it has no opinion on', () => {
    const result = validateSandboxPolicy('allow-forms allow-downloads');
    expect(result.valid).toBe(true);
    expect(result.policy).toBe('allow-forms allow-downloads');
  });
});
