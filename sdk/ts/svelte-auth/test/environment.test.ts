import { describe, expect, it } from 'vitest';

// Node 25 and later define a global localStorage (the webstorage feature)
// that is undefined without --localstorage-file and shadows jsdom's, so the
// auth store's tests would read window.localStorage as undefined.
describe('test environment', () => {
  it('window.localStorage is the working jsdom Storage', () => {
    expect(window.localStorage).toBeInstanceOf(window.Storage);
    window.localStorage.setItem('environment-probe', 'v');
    expect(window.localStorage.getItem('environment-probe')).toBe('v');
    window.localStorage.removeItem('environment-probe');
  });
});
