/**
 * `@open-transaction-layer/jwe` — message encryption for the OTL Identity layer.
 *
 * JWE Compact Serialization with ECDH-ES and A256GCM. The envelope is
 * provisional because OTL spec 3.1.1 defines key types but no envelope, and
 * the construction is confidential but not sender-authenticated, so read the
 * package README before relying on it.
 */

export * from './errors.ts';
export * from './jwe.ts';
