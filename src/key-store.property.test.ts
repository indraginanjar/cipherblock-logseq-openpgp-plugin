// CipherBlock – Property-based tests for Key Store
// Test framework: Vitest with fast-check
// Source: src/key-store.ts

import { describe, it, expect, beforeAll } from 'vitest';
import * as fc from 'fast-check';
import * as openpgp from 'openpgp';
import { KeyStore } from './key-store';
import { DuplicateKeyError } from './errors';
import type { IOpenPGPAdapter, IStorageAdapter } from './interfaces';
import type { ParsedKey } from './types';

// Make openpgp available globally so the adapter's lazy-loader finds it
beforeAll(() => {
  (globalThis as any).openpgp = openpgp;
});

// --- Pre-generated key fixtures ---

interface KeyFixture {
  name: string;
  email: string;
  publicKey: string;
  privateKey: string;
  fingerprint: string;
  userID: string;
  creationDate: Date;
}

const KEY_POOL_SIZE = 10;
let keyFixtures: KeyFixture[] = [];

beforeAll(async () => {
  const fixtures: KeyFixture[] = [];
  for (let i = 0; i < KEY_POOL_SIZE; i++) {
    const name = `User${i}`;
    const email = `user${i}@test.com`;
    const { publicKey, privateKey } = await openpgp.generateKey({
      type: 'ecc',
      curve: 'curve25519',
      userIDs: [{ name, email }],
      format: 'armored',
      passphrase: undefined,
    });
    // Parse to get fingerprint and creationDate
    const parsed = await openpgp.readKey({ armoredKey: publicKey });
    fixtures.push({
      name,
      email,
      publicKey,
      privateKey,
      fingerprint: parsed.getFingerprint(),
      userID: parsed.users[0]?.userID?.userID ?? '',
      creationDate: parsed.getCreationTime(),
    });
  }
  keyFixtures = fixtures;
});

// --- Mock factories ---

/**
 * Creates a real IOpenPGPAdapter that delegates to openpgp for parseKey.
 * This ensures the KeyStore receives realistic ParsedKey data.
 */
function createRealPgpAdapter(): IOpenPGPAdapter {
  return {
    async parseKey(armoredKey: string): Promise<ParsedKey> {
      const trimmed = armoredKey.trim();
      const isPublic = trimmed.includes('-----BEGIN PGP PUBLIC KEY BLOCK-----');
      if (isPublic) {
        const key = await openpgp.readKey({ armoredKey: trimmed });
        return {
          fingerprint: key.getFingerprint(),
          userID: key.users[0]?.userID?.userID ?? '',
          type: 'public',
          creationDate: key.getCreationTime(),
          armoredKey: trimmed,
        };
      } else {
        const key = await openpgp.readPrivateKey({ armoredKey: trimmed });
        return {
          fingerprint: key.getFingerprint(),
          userID: key.users[0]?.userID?.userID ?? '',
          type: 'private',
          creationDate: key.getCreationTime(),
          armoredKey: trimmed,
        };
      }
    },
    async encrypt() {
      return '';
    },
    async decrypt() {
      return '';
    },
  };
}

/**
 * Creates an in-memory IStorageAdapter backed by a Map.
 */
function createInMemoryStorage(): IStorageAdapter {
  const store = new Map<string, string>();
  return {
    async get(key: string) {
      return store.get(key) ?? null;
    },
    async set(key: string, value: string) {
      store.set(key, value);
    },
    async remove(key: string) {
      store.delete(key);
    },
  };
}

// --- Arbitraries ---

/** Arbitrary that picks a fixture index from the pre-generated pool. */
const fixtureIndexArb = fc.integer({ min: 0, max: KEY_POOL_SIZE - 1 });

/** Arbitrary that picks a non-empty subset of fixture indices (for multi-key tests). */
const fixtureSubsetArb = fc
  .uniqueArray(fixtureIndexArb, { minLength: 1, maxLength: KEY_POOL_SIZE })
  .filter((arr) => arr.length > 0);

/** Arbitrary for key type: 'public' or 'private'. */
const keyTypeArb = fc.constantFrom('public' as const, 'private' as const);

// --- Property Tests ---

describe('Key Store Property Tests', () => {

  // Feature: logseq-cipherblock, Property 2: Duplicate key import is idempotent
  // Validates: Requirements 1.3
  describe('Property 2: Duplicate key import is idempotent', () => {
    it('importing the same key twice results in one entry, second import rejected', async () => {
      await fc.assert(
        fc.asyncProperty(fixtureIndexArb, keyTypeArb, async (idx, keyType) => {
          const fixture = keyFixtures[idx];
          const armoredKey = keyType === 'public' ? fixture.publicKey : fixture.privateKey;

          const pgpAdapter = createRealPgpAdapter();
          const storage = createInMemoryStorage();
          const keyStore = new KeyStore(pgpAdapter, storage);

          // First import should succeed
          const imported = await keyStore.importKey(armoredKey);
          expect(imported.fingerprint).toBe(fixture.fingerprint);

          // Second import of the same key should throw DuplicateKeyError
          await expect(keyStore.importKey(armoredKey)).rejects.toThrow(DuplicateKeyError);

          // Store should contain exactly one entry
          const keys = await keyStore.listKeys();
          const matching = keys.filter(
            (k) => k.fingerprint === fixture.fingerprint && k.type === keyType,
          );
          expect(matching).toHaveLength(1);
        }),
        { numRuns: 100 },
      );
    });
  });

  // Feature: logseq-cipherblock, Property 4: Key removal removes from store
  // Validates: Requirements 1.5
  describe('Property 4: Key removal removes from store', () => {
    it('after removal, key no longer in list and list length decreases by one', async () => {
      await fc.assert(
        fc.asyncProperty(
          fixtureSubsetArb,
          keyTypeArb,
          async (indices, keyType) => {
            const pgpAdapter = createRealPgpAdapter();
            const storage = createInMemoryStorage();
            const keyStore = new KeyStore(pgpAdapter, storage);

            // Import all keys from the subset
            for (const idx of indices) {
              const fixture = keyFixtures[idx];
              const armoredKey = keyType === 'public' ? fixture.publicKey : fixture.privateKey;
              await keyStore.importKey(armoredKey);
            }

            const keysBefore = await keyStore.listKeys();
            expect(keysBefore).toHaveLength(indices.length);

            // Pick a random key to remove (first in the subset)
            const removeIdx = indices[0];
            const removeFingerprint = keyFixtures[removeIdx].fingerprint;

            await keyStore.removeKey(removeFingerprint);

            const keysAfter = await keyStore.listKeys();
            expect(keysAfter).toHaveLength(keysBefore.length - 1);

            // Removed key should not appear in the list
            const found = keysAfter.find((k) => k.fingerprint === removeFingerprint);
            expect(found).toBeUndefined();
          },
        ),
        { numRuns: 100 },
      );
    });
  });

  // Feature: logseq-cipherblock, Property 5: Key listing includes all required fields
  // Validates: Requirements 1.6
  describe('Property 5: Key listing includes all required fields', () => {
    it('every listed key has non-empty fingerprint, userID, valid type, valid creationDate', async () => {
      await fc.assert(
        fc.asyncProperty(
          fixtureSubsetArb,
          keyTypeArb,
          async (indices, keyType) => {
            const pgpAdapter = createRealPgpAdapter();
            const storage = createInMemoryStorage();
            const keyStore = new KeyStore(pgpAdapter, storage);

            // Import keys
            for (const idx of indices) {
              const fixture = keyFixtures[idx];
              const armoredKey = keyType === 'public' ? fixture.publicKey : fixture.privateKey;
              await keyStore.importKey(armoredKey);
            }

            const keys = await keyStore.listKeys();
            expect(keys).toHaveLength(indices.length);

            for (const key of keys) {
              // Non-empty fingerprint
              expect(key.fingerprint).toBeTruthy();
              expect(typeof key.fingerprint).toBe('string');
              expect(key.fingerprint.length).toBeGreaterThan(0);

              // Non-empty userID
              expect(key.userID).toBeTruthy();
              expect(typeof key.userID).toBe('string');
              expect(key.userID.length).toBeGreaterThan(0);

              // Valid type
              expect(['public', 'private']).toContain(key.type);

              // Valid creationDate
              expect(key.creationDate).toBeInstanceOf(Date);
              expect(key.creationDate.getTime()).not.toBeNaN();
              // Creation date should be a reasonable time (not epoch 0)
              expect(key.creationDate.getTime()).toBeGreaterThan(0);
            }
          },
        ),
        { numRuns: 100 },
      );
    });
  });
});
