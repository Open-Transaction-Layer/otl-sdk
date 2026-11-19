/**
 * `@otl/core` — protocol logic for the OTL Identity layer.
 *
 * Canonicalization, hashing and proof construction live here rather than in a
 * key provider, so that two backends can never drift on how a signature input
 * is built.
 */

export * from './errors.ts';
export * from './jcs.ts';
export * from './cryptosuite.ts';
export * from './proof.ts';
export * from './multihash.ts';
export * from './didwebvh/index.ts';
export * from './statuslist/index.ts';
export * from './signing.ts';
