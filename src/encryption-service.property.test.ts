// CipherBlock – Property-based tests for Encryption Service
// Test framework: Vitest with fast-check
// Source: src/encryption-service.ts

import { describe, it, expect, beforeAll } from 'vitest';
import * as fc from 'fast-check';
import * as openpgp from 'openpgp';
import { EncryptionService } from './encryption-service';
import { OpenPGPAdapter } from './openpgp-adapter';
import type { IKeyStore, IOpenPGPAdapter } from './interfaces';
import type { StoredKey } from './types';

// Make openpgp available globally so the adapter's lazy-loader finds it
beforeAll(() => {
  (globalThis as any).openpgp = openpgp;
});

// --- Helpers ---

interface TestKeyPair {
  fingerprint: string;
  userID: string;
  publicKey: string;
  privateKey: string;
}

/** Pre-generated pool of key pairs to avoid generating keys in every iteration. */
const KEY_POOL_SIZE = 5;
let keyPool: TestKeyPair[] = [];

async function generateKeyPair(name: string, email: string): Promise<TestKeyPair> {
  const { publicKey, privateKey } = await openpgp.generateKey({
    type: 'ecc',
    curve: 'curve25519',
    userIDs: [{ name, email }],
    format: 'armored',
    passphrase: undefined,
  });
  const parsed = await openpgp.readKey({ armoredKey: publicKey });
  const fingerprint = parsed.getFingerprint();
  const userID = parsed.users[0]?.userID?.userID ?? `${name} <${email}>`;
  return { fingerprint, userID, publicKey, privateKey };
}

beforeAll(async () => {
  // Pre-generate a pool of key pairs for use across all property test iterations
  const promises = [];
  for (let i = 0; i < KEY_POOL_SIZE; i++) {
    promises.push(generateKeyPair(`User${i}`, `user${i}@test.com`));
  }
  keyPool = await Promise.all(promises);
}, 120_000);

/**
 * Arbitrary that picks a subset of 2..N key pairs from the pre-generated pool.
 * Returns at least 2 recipients for multi-recipient testing.
 */
const multiRecipientArb = fc
  .integer({ min: 2, max: KEY_POOL_SIZE })
  .map((count) => keyPool.slice(0, count));

/** Arbitrary for non-empty plaintext strings. */
const plaintextArb = fc
  .string({ minLength: 1, maxLength: 200 })
  .filter((s) => s.trim().length > 0);

/**
 * In-memory key store backed by a Map, using the real OpenPGPAdapter for parsing.
 */
function createInMemoryKeyStore(keys: TestKeyPair[]): IKeyStore {
  const storedKeys: StoredKey[] = keys.map((k) => ({
    fingerprint: k.fingerprint,
    userID: k.userID,
    type: 'public' as const,
    creationDate: new Date(),
    armoredKey: k.publicKey,
  }));

  return {
    importKey: async () => { throw new Error('not implemented'); },
    removeKey: async () => { throw new Error('not implemented'); },
    listKeys: async () => storedKeys,
    getKey: async (fp: string) => storedKeys.find((k) => k.fingerprint === fp) ?? null,
    getPublicKeys: async () => storedKeys,
    getPrivateKeys: async () => [],
  };
}

// --- Property Tests ---

describe('Encryption Service Property Tests', () => {
  const adapter = new OpenPGPAdapter();

  // Feature: logseq-cipherblock, Property 9: Multi-recipient independent decryption
  // Validates: Requirements 3.5
  describe('Property 9: Multi-recipient independent decryption', () => {
    it('encrypting for N recipients allows each to independently decrypt', async () => {
      await fc.assert(
        fc.asyncProperty(multiRecipientArb, plaintextArb, async (recipients, plaintext) => {
          const keyStore = createInMemoryKeyStore(recipients);
          const service = new EncryptionService(adapter, keyStore);

          const fingerprints = recipients.map((r) => r.fingerprint);
          const result = await service.encrypt(plaintext, fingerprints);

          // Each recipient should be able to independently decrypt
          for (const recipient of recipients) {
            const decrypted = await adapter.decrypt(
              result.armoredMessage,
              recipient.privateKey,
            );
            expect(decrypted).toBe(plaintext);
          }
        }),
        { numRuns: 100 },
      );
    });
  });

  // Feature: logseq-cipherblock, Property 16: Encryption success notification includes recipient count
  // Validates: Requirements 11.1
  describe('Property 16: Encryption success notification includes recipient count', () => {
    it('result recipientCount matches number of recipients provided', async () => {
      // Use a mock adapter and key store for this property — we only care about the count
      const recipientCountArb = fc.integer({ min: 1, max: KEY_POOL_SIZE });

      await fc.assert(
        fc.asyncProperty(recipientCountArb, plaintextArb, async (count, plaintext) => {
          const recipients = keyPool.slice(0, count);

          const mockAdapter: IOpenPGPAdapter = {
            parseKey: async () => { throw new Error('not used'); },
            encrypt: async () => '-----BEGIN PGP MESSAGE-----\nfake\n-----END PGP MESSAGE-----',
            decrypt: async () => '',
          };

          const mockKeyStore: IKeyStore = {
            importKey: async () => { throw new Error('not used'); },
            removeKey: async () => { throw new Error('not used'); },
            listKeys: async () => [],
            getKey: async (fp: string) => {
              const r = recipients.find((k) => k.fingerprint === fp);
              if (!r) return null;
              return {
                fingerprint: r.fingerprint,
                userID: r.userID,
                type: 'public' as const,
                creationDate: new Date(),
                armoredKey: r.publicKey,
              };
            },
            getPublicKeys: async () => [],
            getPrivateKeys: async () => [],
          };

          const service = new EncryptionService(mockAdapter, mockKeyStore);
          const fingerprints = recipients.map((r) => r.fingerprint);
          const result = await service.encrypt(plaintext, fingerprints);

          expect(result.recipientCount).toBe(count);
        }),
        { numRuns: 100 },
      );
    });
  });
});
