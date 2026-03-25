// CipherBlock – Property-based tests for OpenPGP Adapter
// Test framework: Vitest with fast-check
// Source: src/openpgp-adapter.ts

import { describe, it, expect, beforeAll } from 'vitest';
import * as fc from 'fast-check';
import * as openpgp from 'openpgp';
import { OpenPGPAdapter } from './openpgp-adapter';
import { KeyImportError } from './errors';

// Make openpgp available globally so the adapter's lazy-loader finds it
beforeAll(() => {
  (globalThis as any).openpgp = openpgp;
});

const adapter = new OpenPGPAdapter();

// --- Helpers ---

/** Generate a fresh ECC key pair for testing. */
async function generateKeyPair(name: string, email: string) {
  const { publicKey, privateKey } = await openpgp.generateKey({
    type: 'ecc',
    curve: 'curve25519',
    userIDs: [{ name, email }],
    format: 'armored',
    passphrase: undefined,
  });
  return { publicKey, privateKey };
}

/**
 * Arbitrary that produces { name, email, publicKey, privateKey }.
 * We generate real OpenPGP keys from random name/email pairs.
 */
const keyPairArb = fc
  .record({
    name: fc.string({ minLength: 1, maxLength: 20 }).filter((s) => s.trim().length > 0 && !s.includes('<') && !s.includes('>')),
    email: fc.emailAddress(),
  })
  .map(async ({ name, email }) => {
    const pair = await generateKeyPair(name, email);
    return { name, email, ...pair };
  });

/**
 * Arbitrary for non-empty plaintext strings (no null bytes, printable).
 * OpenPGP handles arbitrary binary, but we test with printable text.
 */
const plaintextArb = fc
  .string({ minLength: 1, maxLength: 500 })
  .filter((s) => s.trim().length > 0);

/**
 * Arbitrary for strings that are definitely NOT valid armored OpenPGP keys.
 */
const invalidKeyArb = fc
  .string({ minLength: 0, maxLength: 200 })
  .filter(
    (s) =>
      !s.includes('-----BEGIN PGP PUBLIC KEY BLOCK-----') &&
      !s.includes('-----BEGIN PGP PRIVATE KEY BLOCK-----'),
  );

// --- Property Tests ---

describe('OpenPGP Adapter Property Tests', () => {

  // Feature: logseq-cipherblock, Property 1: Key import round-trip
  // Validates: Requirements 1.1, 1.2, 6.3, 6.4
  describe('Property 1: Key import round-trip', () => {
    it('importing a valid armored key preserves fingerprint, userID, type, and creationDate', async () => {
      await fc.assert(
        fc.asyncProperty(keyPairArb, async (keyPairPromise) => {
          const { name, email, publicKey, privateKey } = await keyPairPromise;

          // Test public key round-trip
          const parsedPublic = await adapter.parseKey(publicKey);
          expect(parsedPublic.fingerprint).toBeTruthy();
          expect(typeof parsedPublic.fingerprint).toBe('string');
          expect(parsedPublic.fingerprint.length).toBeGreaterThan(0);
          expect(parsedPublic.userID).toContain(name);
          expect(parsedPublic.userID).toContain(email);
          expect(parsedPublic.type).toBe('public');
          expect(parsedPublic.creationDate).toBeInstanceOf(Date);
          expect(parsedPublic.creationDate.getTime()).not.toBeNaN();

          // Verify the armored key is preserved (adapter trims whitespace)
          expect(parsedPublic.armoredKey).toBe(publicKey.trim());

          // Test private key round-trip
          const parsedPrivate = await adapter.parseKey(privateKey);
          expect(parsedPrivate.fingerprint).toBeTruthy();
          expect(parsedPrivate.fingerprint).toBe(parsedPublic.fingerprint); // same key pair
          expect(parsedPrivate.userID).toContain(name);
          expect(parsedPrivate.userID).toContain(email);
          expect(parsedPrivate.type).toBe('private');
          expect(parsedPrivate.creationDate).toBeInstanceOf(Date);
          expect(parsedPrivate.creationDate.getTime()).toBe(parsedPublic.creationDate.getTime());
        }),
        { numRuns: 100 },
      );
    });
  });

  // Feature: logseq-cipherblock, Property 3: Invalid key import produces error
  // Validates: Requirements 1.4
  describe('Property 3: Invalid key import produces error', () => {
    it('non-key strings cause parseKey to throw KeyImportError', async () => {
      await fc.assert(
        fc.asyncProperty(invalidKeyArb, async (invalidInput) => {
          await expect(adapter.parseKey(invalidInput)).rejects.toThrow(KeyImportError);
        }),
        { numRuns: 100 },
      );
    });
  });

  // Feature: logseq-cipherblock, Property 8: Encryption produces valid armored output
  // Validates: Requirements 3.2, 6.1
  describe('Property 8: Encryption produces valid armored output', () => {
    it('encrypted output starts with BEGIN PGP MESSAGE and ends with END PGP MESSAGE', async () => {
      // Pre-generate a single key pair to avoid generating 100 key pairs
      const { publicKey } = await generateKeyPair('TestUser', 'test@example.com');

      await fc.assert(
        fc.asyncProperty(plaintextArb, async (plaintext) => {
          const armored = await adapter.encrypt(plaintext, [publicKey]);
          const trimmed = armored.trim();
          expect(trimmed.startsWith('-----BEGIN PGP MESSAGE-----')).toBe(true);
          expect(trimmed.endsWith('-----END PGP MESSAGE-----')).toBe(true);
        }),
        { numRuns: 100 },
      );
    });
  });

  // Feature: logseq-cipherblock, Property 10: Encryption/decryption round-trip
  // Validates: Requirements 4.1, 6.5, 6.6
  describe('Property 10: Encryption/decryption round-trip', () => {
    it('encrypt then decrypt recovers original plaintext', async () => {
      // Pre-generate a single key pair to avoid generating 100 key pairs
      const { publicKey, privateKey } = await generateKeyPair('RoundTrip', 'roundtrip@example.com');

      await fc.assert(
        fc.asyncProperty(plaintextArb, async (plaintext) => {
          const armored = await adapter.encrypt(plaintext, [publicKey]);
          const decrypted = await adapter.decrypt(armored, privateKey);
          expect(decrypted).toBe(plaintext);
        }),
        { numRuns: 100 },
      );
    });
  });
});
