"use strict";
// xKey AutoFill Extension - Content Script
//
// Injected into web pages to detect login forms, inject field icons,
// and fill credentials received from the background service worker.
//
// This file is self-contained (no ES module imports) because content
// scripts are injected by the browser, not loaded as modules.
/// <reference types="chrome" />
// ---------------------------------------------------------------------------
// Form detection
// ---------------------------------------------------------------------------
/** Username-like input selectors, ordered by specificity. */
const USERNAME_SELECTORS = [
    'input[autocomplete="username"]',
    'input[autocomplete="email"]',
    'input[name="username"]',
    'input[name="user"]',
    'input[name="login"]',
    'input[name="email"]',
    'input[id="username"]',
    'input[id="user"]',
    'input[id="login"]',
    'input[id="email"]',
    'input[type="email"]',
    'input[type="text"]',
];
/** TOTP / MFA input selectors. */
const TOTP_SELECTORS = [
    'input[autocomplete="one-time-code"]',
    'input[name*="totp"]',
    'input[name*="otp"]',
    'input[name*="mfa"]',
    'input[name*="2fa"]',
    'input[name*="verification"]',
    'input[name*="authenticator"]',
    'input[name*="passcode"]',
    'input[id*="totp"]',
    'input[id*="otp"]',
    'input[id*="mfa"]',
    'input[id*="passcode"]',
];
// ---------------------------------------------------------------------------
// Login context detection heuristic
// ---------------------------------------------------------------------------
/** Patterns in the page URL path that indicate a login page. */
const LOGIN_PATH_PATTERNS = [
    '/login',
    '/signin',
    '/sign-in',
    '/auth',
    '/sso',
    '/authenticate',
    '/session',
    '/account/login',
    '/oauth',
];
/** Button text patterns (lower-cased) that indicate a login submit action. */
const LOGIN_BUTTON_TEXT_PATTERNS = [
    'sign in',
    'log in',
    'login',
    'signin',
    'next',
    'continue',
    'submit',
    'verify',
];
/**
 * Determine whether a username input field sits in a "login context".
 *
 * A field is in a login context when ANY of these hold:
 *  - It lives inside a <form> element.
 *  - A submit-like button is nearby (same form or nearest container).
 *  - The page URL path contains a common login keyword.
 */
function isLoginContext(field) {
    // URL path heuristic.
    const pathname = window.location.pathname.toLowerCase();
    for (const pattern of LOGIN_PATH_PATTERNS) {
        if (pathname.includes(pattern))
            return true;
    }
    // Inside a <form> element.
    const form = field.closest('form');
    if (form)
        return true;
    // Look for a submit button in the nearest meaningful container.
    const container = field.closest('[role="form"], [role="dialog"], section, main, [class*="login"], [class*="auth"], [id*="login"], [id*="auth"]') ||
        field.parentElement;
    if (container && hasLoginButton(container))
        return true;
    return false;
}
/**
 * Check whether a container holds a submit-like button.
 */
function hasLoginButton(container) {
    // Explicit submit controls.
    const explicitSubmits = container.querySelectorAll('button[type="submit"], input[type="submit"]');
    if (explicitSubmits.length > 0)
        return true;
    // Buttons whose text matches a login keyword.
    const buttons = container.querySelectorAll('button, [role="button"]');
    for (const btn of buttons) {
        const text = (btn.textContent ?? '').trim().toLowerCase();
        for (const pattern of LOGIN_BUTTON_TEXT_PATTERNS) {
            if (text.includes(pattern))
                return true;
        }
    }
    return false;
}
// ---------------------------------------------------------------------------
// Form detection
// ---------------------------------------------------------------------------
/**
 * Detect login forms on the page by locating visible password fields
 * and their associated username fields.
 */
function detectForms() {
    const passwordFields = document.querySelectorAll('input[type="password"]:not([aria-hidden="true"])');
    const forms = [];
    for (const pwField of passwordFields) {
        // Skip hidden or invisible fields.
        if (!isVisible(pwField))
            continue;
        const usernameField = findUsernameField(pwField);
        forms.push({
            usernameField,
            passwordField: pwField,
            totpField: null,
            usernameOnly: false,
            totpOnly: false,
        });
    }
    return forms;
}
/**
 * Check if an element is visible in the page (not hidden, not zero-size).
 */
function isVisible(el) {
    if (el.offsetWidth === 0 && el.offsetHeight === 0)
        return false;
    const style = window.getComputedStyle(el);
    if (style.display === 'none' || style.visibility === 'hidden')
        return false;
    return true;
}
/**
 * Find the username field associated with a password field.
 *
 * Strategy 1: Look within the same <form> element.
 * Strategy 2: Walk backwards through preceding siblings/parents in the DOM.
 */
function findUsernameField(passwordField) {
    // Strategy 1: Same <form> element.
    const form = passwordField.closest('form');
    if (form) {
        const candidate = findUsernameInContainer(form, passwordField);
        if (candidate)
            return candidate;
    }
    // Strategy 2: Walk up to find a common container, then search within it.
    const container = passwordField.closest('div[class], section, main, body');
    if (container) {
        const candidate = findUsernameInContainer(container, passwordField);
        if (candidate)
            return candidate;
    }
    return null;
}
/**
 * Search for a username-like input within a container element that
 * appears before the given password field in DOM order.
 */
function findUsernameInContainer(container, passwordField) {
    const selectorStr = USERNAME_SELECTORS.join(',');
    const candidates = container.querySelectorAll(selectorStr);
    // Find candidates that precede the password field in DOM order.
    let bestCandidate = null;
    for (const candidate of candidates) {
        // Skip the password field itself.
        if (candidate === passwordField)
            continue;
        // Skip hidden fields.
        if (candidate.type === 'hidden' || !isVisible(candidate))
            continue;
        // Skip TOTP/OTP fields — they should not be treated as username inputs.
        if (isTOTPField(candidate))
            continue;
        // Must appear before the password field in document order.
        if (passwordField.compareDocumentPosition(candidate) & Node.DOCUMENT_POSITION_PRECEDING) {
            bestCandidate = candidate;
        }
    }
    return bestCandidate;
}
/**
 * Detect TOTP / MFA input fields on the page.
 */
function detectTOTPFields() {
    const selectorStr = TOTP_SELECTORS.join(',');
    const fields = document.querySelectorAll(selectorStr);
    return Array.from(fields).filter(isVisible);
}
/**
 * Check whether a specific input field matches any TOTP/OTP selector.
 */
function isTOTPField(field) {
    for (const sel of TOTP_SELECTORS) {
        if (field.matches(sel))
            return true;
    }
    return false;
}
/**
 * Detect standalone TOTP/OTP forms (fields that should get an xKey icon
 * for on-demand TOTP fill instead of auto-filling immediately).
 *
 * Returns DetectedForm entries with `totpOnly: true` so the icon click
 * handler knows to call fillTOTP() rather than requestCredentials().
 */
function detectTOTPForms() {
    const totpFields = detectTOTPFields();
    const forms = [];
    for (const field of totpFields) {
        // Skip if already has an xKey icon.
        if (field.dataset.xkeyIcon === 'true')
            continue;
        forms.push({
            usernameField: null,
            passwordField: null,
            totpField: field,
            usernameOnly: false,
            totpOnly: true,
        });
    }
    return forms;
}
/**
 * Detect username-only login forms (no visible password field on the page).
 *
 * This handles multi-step SPA login flows (e.g. Okta, Microsoft, Google)
 * where the username is collected first and the password field appears
 * only after submitting the username.
 *
 * Returns an empty array when password fields are already visible,
 * because password-bearing forms are handled by `detectForms()`.
 */
function detectUsernameOnlyForms() {
    // If any visible password field exists, defer to detectForms().
    const passwordFields = document.querySelectorAll('input[type="password"]:not([aria-hidden="true"])');
    for (const pwField of passwordFields) {
        if (isVisible(pwField))
            return [];
    }
    const forms = [];
    const selectorStr = USERNAME_SELECTORS.join(',');
    const candidates = document.querySelectorAll(selectorStr);
    for (const candidate of candidates) {
        if (candidate.type === 'hidden' || !isVisible(candidate))
            continue;
        // Skip fields that match TOTP selectors — these are OTP/MFA inputs,
        // not username fields (e.g. Google Authenticator OTP field on Okta).
        if (isTOTPField(candidate))
            continue;
        // Must be in a login context (inside form, near submit button, or login URL).
        if (!isLoginContext(candidate))
            continue;
        // Only inject on the first qualifying field to avoid duplicate icons.
        forms.push({
            usernameField: candidate,
            passwordField: null,
            totpField: null,
            usernameOnly: true,
            totpOnly: false,
        });
        break;
    }
    return forms;
}
// ---------------------------------------------------------------------------
// Field icon injection
// ---------------------------------------------------------------------------
/**
 * Compute the right offset for the xKey icon to avoid overlapping with
 * existing UI elements at the right edge of the input (e.g. password
 * reveal eye icons, clear buttons, suffix icons).
 *
 * Scans sibling elements in the parent wrapper that are positioned near
 * the right edge and vertically overlap the input, then returns a right
 * value that clears them.
 */
function computeIconRightOffset(target) {
    const MIN_RIGHT = 8;
    const ICON_GAP = 6;
    const wrapper = target.parentElement;
    if (!wrapper)
        return MIN_RIGHT;
    const wrapperRect = wrapper.getBoundingClientRect();
    const targetRect = target.getBoundingClientRect();
    // If rects have no dimensions yet (e.g. hidden), fall back.
    if (wrapperRect.width === 0 || targetRect.width === 0)
        return MIN_RIGHT;
    let maxOccupiedFromRight = 0;
    for (const child of wrapper.children) {
        if (child === target)
            continue;
        const el = child;
        if (el.classList?.contains('xkey-autofill-icon'))
            continue;
        if (el.offsetWidth === 0 || el.offsetHeight === 0)
            continue;
        const childRect = el.getBoundingClientRect();
        // Must vertically overlap the input field.
        if (childRect.top >= targetRect.bottom || childRect.bottom <= targetRect.top)
            continue;
        // Must be within 60px of the wrapper's right edge.
        const distFromRight = wrapperRect.right - childRect.right;
        if (distFromRight > 60)
            continue;
        // How far from the right edge does this element extend?
        const occupiedFromRight = wrapperRect.right - childRect.left;
        if (occupiedFromRight > maxOccupiedFromRight) {
            maxOccupiedFromRight = occupiedFromRight;
        }
    }
    if (maxOccupiedFromRight > MIN_RIGHT) {
        return maxOccupiedFromRight + ICON_GAP;
    }
    return MIN_RIGHT;
}
/**
 * Inject the xKey icon overlay on detected login fields.
 *
 * For password forms the icon is placed on BOTH the username and password
 * fields so the user can choose which credential to fill from either field.
 * For username-only forms the icon is placed on the username field.
 * Clicking the icon triggers a credential search against the xKey daemon.
 */
function injectFieldIcons(forms) {
    for (const form of forms) {
        if (form.totpOnly) {
            injectIconOnField(form.totpField, true, false, null);
        }
        else if (form.usernameOnly) {
            injectIconOnField(form.usernameField, false, true, form.usernameField);
        }
        else {
            // Standard form: icon on both username AND password fields.
            // Username icon: chooser fills username only (no PIN prompt).
            injectIconOnField(form.usernameField, false, true, form.usernameField);
            // Password icon: chooser fills both fields (with PIN + touch).
            injectIconOnField(form.passwordField, false, false, form.passwordField);
        }
    }
}
/**
 * Inject a single xKey icon on a target input field.
 *
 * @param target - The input field to attach the icon to.
 * @param isTOTP - True if this is a TOTP field (fills OTP code, not credentials).
 * @param usernameOnly - True if clicking should fill only the username (no PIN).
 * @param capturedField - Field reference captured at injection time for
 *   username-only fills (avoids re-detection after async round-trip).
 */
function injectIconOnField(target, isTOTP, usernameOnly, capturedField) {
    if (!target)
        return;
    if (target.dataset.xkeyIcon === 'true')
        return;
    const icon = document.createElement('div');
    icon.className = 'xkey-autofill-icon';
    icon.title = isTOTP ? 'Fill TOTP with xKey' : 'Fill with xKey';
    // SVG key icon (inline to avoid external resource loading).
    icon.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#666" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>`;
    // Compute right offset to avoid overlapping sibling UI (eye icons, etc.).
    const rightPx = computeIconRightOffset(target);
    icon.style.cssText = [
        'position: absolute',
        `right: ${rightPx}px`,
        'top: 50%',
        'transform: translateY(-50%)',
        'cursor: pointer',
        'z-index: 999999',
        'width: 24px',
        'height: 24px',
        'display: flex',
        'align-items: center',
        'justify-content: center',
        'opacity: 0.6',
        'transition: opacity 0.15s',
        'border-radius: 4px',
        'background: transparent',
    ].join(';');
    icon.addEventListener('mouseenter', () => {
        icon.style.opacity = '1';
        icon.style.background = 'rgba(0,0,0,0.04)';
    });
    icon.addEventListener('mouseleave', () => {
        icon.style.opacity = '0.6';
        icon.style.background = 'transparent';
    });
    icon.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (isTOTP) {
            fillTOTP(window.location.hostname);
        }
        else {
            requestCredentials(usernameOnly, capturedField);
        }
    });
    // Position the icon relative to the input's parent.
    const wrapper = target.parentElement;
    if (wrapper) {
        const wrapperStyle = window.getComputedStyle(wrapper);
        if (wrapperStyle.position === 'static') {
            wrapper.style.position = 'relative';
        }
        wrapper.appendChild(icon);
    }
    target.dataset.xkeyIcon = 'true';
}
// ---------------------------------------------------------------------------
// Waiting indicator (shown during CTAP2 challenge-response auth)
// ---------------------------------------------------------------------------
/**
 * Show a full-page waiting indicator while the user enters their PIN
 * and touches the xKey device. Uses a Shadow DOM for style isolation.
 *
 * Returns a dismiss function to remove the indicator.
 */
/**
 * Show a brief hint near the top of the page when the extension requires pairing.
 * Auto-dismisses after 4 seconds.
 */
function showPairingHint() {
    // Don't stack hints.
    if (document.getElementById('xkey-pairing-hint'))
        return;
    const host = document.createElement('div');
    host.id = 'xkey-pairing-hint';
    host.style.cssText = 'position:fixed;top:16px;right:16px;z-index:2147483647;pointer-events:auto;';
    const shadow = host.attachShadow({ mode: 'closed' });
    const card = document.createElement('div');
    card.style.cssText = 'background:#EEF2FF;border:1px solid #C7D2FE;border-radius:8px;padding:12px 16px;font-family:-apple-system,BlinkMacSystemFont,sans-serif;max-width:280px;box-shadow:0 4px 12px rgba(0,0,0,0.15);';
    const title = document.createElement('div');
    title.style.cssText = 'font-size:14px;font-weight:600;color:#3730A3;margin-bottom:4px;';
    title.textContent = 'xKey: Pairing Required';
    const body = document.createElement('div');
    body.style.cssText = 'font-size:12px;color:#4B5563;';
    body.textContent = 'Click the xKey extension icon in your toolbar to complete pairing.';
    card.append(title, body);
    shadow.appendChild(card);
    document.body.appendChild(host);
    setTimeout(() => host.remove(), 4000);
}
/**
 * Show a hint when the browser extension autofill is disabled in xKey settings.
 * Auto-dismisses after 5 seconds.
 */
function showDisabledHint() {
    if (document.getElementById('xkey-disabled-hint'))
        return;
    const host = document.createElement('div');
    host.id = 'xkey-disabled-hint';
    host.style.cssText = 'position:fixed;top:16px;right:16px;z-index:2147483647;pointer-events:auto;';
    const shadow = host.attachShadow({ mode: 'closed' });
    const card = document.createElement('div');
    card.style.cssText = 'background:#FEF3C7;border:1px solid #FCD34D;border-radius:8px;padding:12px 16px;font-family:-apple-system,BlinkMacSystemFont,sans-serif;max-width:300px;box-shadow:0 4px 12px rgba(0,0,0,0.15);';
    const title = document.createElement('div');
    title.style.cssText = 'font-size:14px;font-weight:600;color:#92400E;margin-bottom:4px;';
    title.textContent = 'xKey: AutoFill Disabled';
    const body = document.createElement('div');
    body.style.cssText = 'font-size:12px;color:#78350F;';
    body.textContent = 'Browser extension autofill is turned off. Open xKey \u2192 Settings \u2192 Browser to enable it.';
    card.append(title, body);
    shadow.appendChild(card);
    document.body.appendChild(host);
    setTimeout(() => host.remove(), 5000);
}
/**
 * Show a hint when the xKey app is locked (auto-lock or manual lock).
 * Auto-dismisses after 5 seconds.
 */
function showLockedHint() {
    if (document.getElementById('xkey-locked-hint'))
        return;
    const host = document.createElement('div');
    host.id = 'xkey-locked-hint';
    host.style.cssText = 'position:fixed;top:16px;right:16px;z-index:2147483647;pointer-events:auto;';
    const shadow = host.attachShadow({ mode: 'closed' });
    const card = document.createElement('div');
    card.style.cssText = 'background:#FEE2E2;border:1px solid #FCA5A5;border-radius:8px;padding:12px 16px;font-family:-apple-system,BlinkMacSystemFont,sans-serif;max-width:300px;box-shadow:0 4px 12px rgba(0,0,0,0.15);';
    const title = document.createElement('div');
    title.style.cssText = 'font-size:14px;font-weight:600;color:#991B1B;margin-bottom:4px;';
    title.textContent = 'xKey: App Locked';
    const body = document.createElement('div');
    body.style.cssText = 'font-size:12px;color:#7F1D1D;';
    body.textContent = 'xKey is locked. Unlock the app to use autofill.';
    card.append(title, body);
    shadow.appendChild(card);
    document.body.appendChild(host);
    setTimeout(() => host.remove(), 5000);
}
function showWaitingIndicator() {
    const host = document.createElement('div');
    host.id = 'xkey-waiting-host';
    host.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;z-index:2147483647;pointer-events:all;';
    const shadow = host.attachShadow({ mode: 'closed' });
    // Semi-transparent backdrop.
    const backdrop = document.createElement('div');
    backdrop.style.cssText = 'position:absolute;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.3);display:flex;align-items:center;justify-content:center;';
    // Centered card.
    const card = document.createElement('div');
    card.style.cssText = 'background:white;border-radius:12px;padding:24px 32px;box-shadow:0 8px 32px rgba(0,0,0,0.2);text-align:center;font-family:-apple-system,BlinkMacSystemFont,sans-serif;max-width:320px;';
    // Key icon (SVG).
    const icon = document.createElement('div');
    icon.innerHTML = '<svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#4F46E5" stroke-width="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>';
    // Text.
    const text = document.createElement('div');
    text.style.cssText = 'margin-top:12px;font-size:16px;font-weight:600;color:#1F2937;';
    text.textContent = 'Verify with xKey...';
    const subtext = document.createElement('div');
    subtext.style.cssText = 'margin-top:8px;font-size:13px;color:#6B7280;';
    subtext.textContent = 'Enter your PIN and touch to approve in the xKey app';
    // Cancel button.
    const cancel = document.createElement('button');
    cancel.style.cssText = 'margin-top:16px;padding:8px 20px;border:1px solid #D1D5DB;border-radius:6px;background:white;color:#374151;font-size:14px;cursor:pointer;';
    cancel.textContent = 'Cancel';
    cancel.onclick = dismiss;
    card.append(icon, text, subtext, cancel);
    backdrop.appendChild(card);
    shadow.appendChild(backdrop);
    document.body.appendChild(host);
    // Auto-dismiss after 45s (matches fill timeout).
    const timer = setTimeout(dismiss, 45000);
    function dismiss() {
        clearTimeout(timer);
        host.remove();
    }
    return dismiss;
}
// ---------------------------------------------------------------------------
// Credential filling
// ---------------------------------------------------------------------------
/**
 * Set a field's value in a way that triggers framework change detection
 * (React, Angular, Vue all trap the value setter differently).
 *
 * The technique uses the native HTMLInputElement.prototype.value setter
 * to bypass framework property overrides, then dispatches the event
 * sequence that React, Angular, and Vue listen to for state updates.
 */
function setFieldValue(field, value) {
    // Focus the field first — some frameworks only process input events
    // on the active element.
    field.focus();
    // Use the native HTMLInputElement value setter to bypass framework trapping.
    const nativeSetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
    if (nativeSetter) {
        nativeSetter.call(field, value);
    }
    else {
        field.value = value;
    }
    // Dispatch the full event sequence that frameworks expect:
    //   focus → input → change → blur
    // Use InputEvent for 'input' (React 16+ requires it for controlled inputs).
    field.dispatchEvent(new InputEvent('input', { bubbles: true, composed: true, inputType: 'insertText' }));
    field.dispatchEvent(new Event('change', { bubbles: true, composed: true }));
    field.dispatchEvent(new Event('blur', { bubbles: true, composed: true }));
}
/**
 * Request credentials from the background service worker for the
 * current domain.
 *
 * When `usernameOnly` is true (SPA multi-step flow), only the username
 * from the search result metadata is filled. No password is fetched or
 * cached — the password is retrieved via a fresh authenticated request
 * when the user clicks the icon on the password field.
 *
 * `targetField` is the field reference captured at icon-injection time
 * so that filling does not depend on re-detecting the form after the
 * async round-trip (the DOM may mutate during the request).
 */
async function requestCredentials(usernameOnly = false, targetField) {
    const domain = window.location.hostname;
    let response;
    try {
        response = await chrome.runtime.sendMessage({ type: 'search', domain });
    }
    catch (err) {
        console.error('[xKey] Failed to search credentials:', err);
        return;
    }
    // Guard: sendMessage can resolve to undefined when the service worker
    // doesn't respond or the message channel closes prematurely.
    if (!response || typeof response !== 'object') {
        console.error('[xKey] Empty or invalid response from background');
        return;
    }
    if (response.type === 'error') {
        console.error('[xKey]', response.message);
        const msg = response.message ?? '';
        if (msg.includes('extension disabled') || msg.includes('disabled')) {
            showDisabledHint();
        }
        else if (msg.includes('app is locked')) {
            showLockedHint();
        }
        return;
    }
    // Extension needs pairing — show a hint so the user knows to pair via the popup.
    if (response.type === 'pairing_status') {
        showPairingHint();
        return;
    }
    if (response.type === 'credentials') {
        const credentials = response.data ?? [];
        if (credentials.length === 0)
            return;
        if (credentials.length === 1) {
            if (usernameOnly) {
                fillUsernameFromSearch(credentials[0], targetField);
            }
            else {
                await fillCredential(credentials[0].id);
            }
        }
        else {
            showCredentialChooser(credentials, usernameOnly, targetField);
        }
    }
}
/**
 * Fill a specific credential into the first detected form on the page.
 *
 * This sends a `fill` request to the background service worker, which
 * forwards it to the xkey daemon. The daemon performs CTAP2 challenge-
 * response authentication (PIN + touch) before returning the password.
 * No credential data is cached in the content script.
 *
 * A waiting indicator overlay is shown while the user interacts with
 * the xKey app (PIN entry + touch to approve).
 */
async function fillCredential(id) {
    // Show the waiting indicator while the user authenticates.
    const dismissWaiting = showWaitingIndicator();
    let response;
    try {
        response = await chrome.runtime.sendMessage({ type: 'fill', id });
    }
    catch (err) {
        dismissWaiting();
        console.error('[xKey] Failed to fill credential:', err);
        return;
    }
    dismissWaiting();
    if (response.type === 'fill_result' && response.data) {
        const forms = detectForms();
        if (forms.length > 0) {
            const form = forms[0];
            if (form.usernameField && response.data.username) {
                setFieldValue(form.usernameField, response.data.username);
            }
            if (form.passwordField && response.data.password) {
                setFieldValue(form.passwordField, response.data.password);
            }
        }
    }
}
/**
 * Fill only the username from a search result's metadata.
 *
 * This uses the credential's public metadata (username) from the search
 * response — no `fill` request is made, so no password is fetched and
 * no PIN prompt occurs. The password will be retrieved via a separate
 * authenticated request when the user clicks the icon on the password
 * field in the next step.
 *
 * `targetField` is the field captured at icon-injection time. If the
 * field is still attached to the DOM it is used directly; otherwise we
 * fall back to re-detecting the form.
 */
function fillUsernameFromSearch(credential, targetField) {
    if (!credential.username)
        return;
    // Prefer the captured field reference (avoids re-detection failures
    // if the DOM mutated during the async search round-trip).
    let field = null;
    if (targetField && targetField.isConnected) {
        field = targetField;
    }
    else {
        // Try standard forms first (username field on a password form),
        // then fall back to username-only forms (SPA multi-step).
        const stdForms = detectForms();
        if (stdForms.length > 0 && stdForms[0].usernameField) {
            field = stdForms[0].usernameField;
        }
        else {
            const uoForms = detectUsernameOnlyForms();
            field = uoForms.length > 0 ? uoForms[0].usernameField : null;
        }
    }
    if (field) {
        setFieldValue(field, credential.username);
    }
}
/**
 * Fill a TOTP code into the first detected MFA field on the page.
 */
async function fillTOTP(domain) {
    let response;
    try {
        response = await chrome.runtime.sendMessage({ type: 'totp', domain });
    }
    catch (err) {
        console.error('[xKey] Failed to get TOTP:', err);
        return;
    }
    if (response.type === 'totp_result' && response.data) {
        const totpFields = detectTOTPFields();
        if (totpFields.length > 0) {
            setFieldValue(totpFields[0], response.data.code);
        }
    }
}
// ---------------------------------------------------------------------------
// Credential chooser dropdown
// ---------------------------------------------------------------------------
/**
 * Display a dropdown near the active login field allowing the user to
 * choose from multiple matching credentials.
 *
 * When `usernameOnly` is true the dropdown is anchored to the username
 * field and selecting a credential fills only the username.
 */
function showCredentialChooser(credentials, usernameOnly = false, targetField) {
    // Remove any existing chooser.
    removeChooser();
    // Prefer the captured field reference for anchoring — it was captured at
    // icon-injection time and avoids re-detection failures when the DOM mutates.
    let anchor = null;
    if (targetField && targetField.isConnected) {
        anchor = targetField;
    }
    else {
        let forms = detectForms();
        if (forms.length === 0) {
            forms = detectUsernameOnlyForms();
        }
        if (forms.length === 0)
            return;
        const form = forms[0];
        anchor = usernameOnly ? form.usernameField : (form.passwordField ?? form.usernameField);
    }
    if (!anchor)
        return;
    const rect = anchor.getBoundingClientRect();
    const chooser = document.createElement('div');
    chooser.className = 'xkey-chooser';
    chooser.style.cssText = [
        `position: fixed`,
        `left: ${rect.left}px`,
        `top: ${rect.bottom + 4}px`,
        `min-width: ${Math.max(rect.width, 200)}px`,
        `max-width: 400px`,
        `background: white`,
        `border: 1px solid #ccc`,
        `border-radius: 8px`,
        `box-shadow: 0 4px 12px rgba(0,0,0,0.15)`,
        `z-index: 999999`,
        `font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif`,
        `font-size: 14px`,
        `overflow: hidden`,
    ].join(';');
    // Header
    const header = document.createElement('div');
    header.style.cssText =
        'padding: 8px 14px; font-size: 11px; color: #999; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid #eee;';
    header.textContent = 'xKey Credentials';
    chooser.appendChild(header);
    for (const cred of credentials) {
        const item = document.createElement('div');
        item.style.cssText = [
            'padding: 10px 14px',
            'cursor: pointer',
            'display: flex',
            'flex-direction: column',
            'border-bottom: 1px solid #f0f0f0',
        ].join(';');
        const titleSpan = document.createElement('span');
        titleSpan.style.cssText = 'font-weight: 500; color: #1a1a1a;';
        titleSpan.textContent = cred.title || cred.username;
        const usernameSpan = document.createElement('span');
        usernameSpan.style.cssText = 'font-size: 12px; color: #666; margin-top: 2px;';
        usernameSpan.textContent = cred.username;
        item.appendChild(titleSpan);
        item.appendChild(usernameSpan);
        item.addEventListener('mouseenter', () => {
            item.style.background = '#f0f0f0';
        });
        item.addEventListener('mouseleave', () => {
            item.style.background = 'white';
        });
        item.addEventListener('click', () => {
            removeChooser();
            if (usernameOnly) {
                fillUsernameFromSearch(cred, targetField);
            }
            else {
                fillCredential(cred.id);
            }
        });
        chooser.appendChild(item);
    }
    document.body.appendChild(chooser);
    // Close on outside click (delayed to avoid immediate self-close).
    setTimeout(() => {
        document.addEventListener('click', outsideClickHandler);
        document.addEventListener('keydown', escKeyHandler);
    }, 0);
}
/**
 * Remove the credential chooser dropdown if present.
 */
function removeChooser() {
    const existing = document.querySelector('.xkey-chooser');
    if (existing) {
        existing.remove();
    }
    document.removeEventListener('click', outsideClickHandler);
    document.removeEventListener('keydown', escKeyHandler);
}
function outsideClickHandler(e) {
    const chooser = document.querySelector('.xkey-chooser');
    if (chooser && !chooser.contains(e.target)) {
        removeChooser();
    }
}
function escKeyHandler(e) {
    if (e.key === 'Escape') {
        removeChooser();
    }
}
// ---------------------------------------------------------------------------
// Handle fill requests from popup
// ---------------------------------------------------------------------------
chrome.runtime.onMessage.addListener((message, _sender, _sendResponse) => {
    if (message.type === 'fill_from_popup' && message.data) {
        const forms = detectForms();
        if (forms.length > 0) {
            const form = forms[0];
            if (form.usernameField && message.data.username) {
                setFieldValue(form.usernameField, message.data.username);
            }
            if (form.passwordField && message.data.password) {
                setFieldValue(form.passwordField, message.data.password);
            }
        }
    }
});
// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------
/**
 * Scan the page for login forms (including username-only SPA steps)
 * and inject xKey icons. Also check for TOTP fields and attempt
 * auto-fill.
 */
function initialize() {
    const forms = detectForms();
    if (forms.length > 0) {
        injectFieldIcons(forms);
    }
    else {
        // No password field visible -- try username-only detection.
        const usernameOnlyForms = detectUsernameOnlyForms();
        if (usernameOnlyForms.length > 0) {
            injectFieldIcons(usernameOnlyForms);
        }
    }
    // Check for TOTP / MFA fields (commonly on a second page after login).
    // Inject icons instead of auto-filling — the user may want a different
    // auth method (e.g. Okta FastPass) instead of the OTP code.
    const totpForms = detectTOTPForms();
    if (totpForms.length > 0) {
        injectFieldIcons(totpForms);
    }
}
// Run on DOM ready.
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initialize);
}
else {
    initialize();
}
// ---------------------------------------------------------------------------
// Debounced MutationObserver for SPA page changes
// ---------------------------------------------------------------------------
/** Timer handle for the debounced observer callback. */
let observerDebounceTimer = null;
/** Debounce interval in milliseconds for the MutationObserver callback. */
const OBSERVER_DEBOUNCE_MS = 150;
/**
 * Called (debounced) whenever the DOM mutates.
 *
 * 1. Detect password forms and inject icons (user clicks for fresh
 *    authenticated request with PIN prompt).
 * 2. If no password forms exist, detect username-only forms and inject
 *    icons on those.
 * 3. Detect TOTP fields for auto-fill.
 */
function onDOMMutation() {
    const forms = detectForms();
    if (forms.length > 0) {
        // Password field detected — inject the xKey icon. The user clicks
        // the icon to trigger a fresh authenticated request to xkey (with
        // PIN prompt) to retrieve the password.
        injectFieldIcons(forms);
    }
    else {
        // No password fields — try username-only detection for SPA
        // multi-step login flows (e.g. Okta, Microsoft, Google).
        const usernameOnlyForms = detectUsernameOnlyForms();
        if (usernameOnlyForms.length > 0) {
            injectFieldIcons(usernameOnlyForms);
        }
    }
    // TOTP / MFA — inject icons (user clicks to fill, not auto-fill).
    const totpForms = detectTOTPForms();
    if (totpForms.length > 0) {
        injectFieldIcons(totpForms);
    }
}
// Re-detect on dynamic page changes (SPAs, lazy-loaded forms).
const observer = new MutationObserver(() => {
    if (observerDebounceTimer !== null) {
        clearTimeout(observerDebounceTimer);
    }
    observerDebounceTimer = setTimeout(() => {
        observerDebounceTimer = null;
        onDOMMutation();
    }, OBSERVER_DEBOUNCE_MS);
});
// Start observing once the body is available.
const observeTarget = document.body || document.documentElement;
if (observeTarget) {
    observer.observe(observeTarget, {
        childList: true,
        subtree: true,
    });
}
//# sourceMappingURL=content.js.map