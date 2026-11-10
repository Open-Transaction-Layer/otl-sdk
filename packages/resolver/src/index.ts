/**
 * `@otl/resolver` — HTTPS retrieval for the OTL Identity layer.
 *
 * The only package here that performs I/O. Everything it fetches is named by a
 * counterparty and served from infrastructure they control, so the guards in
 * `http.ts` are load-bearing rather than defensive habit.
 */

export * from './url.ts';
export * from './http.ts';
export * from './memory.ts';
export * from './resolve.ts';
export * from './whois.ts';
