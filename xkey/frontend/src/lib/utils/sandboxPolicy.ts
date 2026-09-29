/**
 * Validation for the API Explorer response-preview iframe `sandbox`
 * attribute (go-xkms#1274).
 *
 * The preview renders arbitrary, untrusted HTML fetched from whatever URL
 * the user points the API Explorer at via `srcdoc`. A `srcdoc` frame with
 * `allow-same-origin` shares the parent document's origin, so a policy that
 * combines it with `allow-scripts` lets script in the fetched HTML reach
 * `window.parent` -- including the Wails runtime bindings
 * (`parent.go.services.*`, e.g. `OIDCService.ExecuteScript`, which shells
 * out). That combination is refused unconditionally, regardless of who set
 * it: the user's own config (Settings) or an enterprise policy override.
 *
 * A handful of other directives are refused outright because they let the
 * preview escape its role (navigate the top-level app window, spawn modal
 * dialogs that block the app, or hop out of a nested sandbox) without
 * needing `allow-same-origin` at all.
 */

/** The safe fallback policy applied whenever validation fails. */
export const SAFE_DEFAULT_SANDBOX_POLICY = 'allow-forms allow-popups';

/** Directives that are never permitted in the API Explorer preview policy. */
const FORBIDDEN_DIRECTIVES = new Set([
  'allow-top-navigation',
  'allow-top-navigation-by-user-activation',
  'allow-top-navigation-to-custom-protocols',
  'allow-popups-to-escape-sandbox',
  'allow-modals',
]);

export interface SandboxPolicyValidation {
  /** Whether the input policy was accepted unchanged. */
  valid: boolean;
  /** The policy to use: the input when valid, SAFE_DEFAULT_SANDBOX_POLICY otherwise. */
  policy: string;
  /** Present only when valid is false; explains what was refused and why. */
  reason?: string;
}

/**
 * Validates an iframe sandbox policy string intended for the API Explorer
 * response preview. Returns the policy unchanged when it is safe, or the
 * safe default policy plus a human-readable reason when it is not.
 */
export function validateSandboxPolicy(policy: string): SandboxPolicyValidation {
  const tokens = policy.trim().split(/\s+/).filter(Boolean);
  const tokenSet = new Set(tokens);

  if (tokenSet.has('allow-scripts') && tokenSet.has('allow-same-origin')) {
    return {
      valid: false,
      policy: SAFE_DEFAULT_SANDBOX_POLICY,
      reason:
        "The sandbox policy combines 'allow-scripts' and 'allow-same-origin'. " +
        'Together these let script in a previewed response escape the sandbox ' +
        "and reach xKey's own application bindings. Falling back to the safe default.",
    };
  }

  const forbidden = tokens.find((token) => FORBIDDEN_DIRECTIVES.has(token));
  if (forbidden) {
    return {
      valid: false,
      policy: SAFE_DEFAULT_SANDBOX_POLICY,
      reason:
        `The sandbox policy contains '${forbidden}', which is not permitted for the ` +
        'API Explorer preview. Falling back to the safe default.',
    };
  }

  return { valid: true, policy };
}
