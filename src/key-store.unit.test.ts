// CipherBlock – Unit tests for Key Store
// Test framework: Vitest
// Source: src/key-store.ts
// Validates: Requirements 1.1, 1.2, 1.3, 1.5, 1.6, 9.4

import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import * as openpgp from 'openpgp';
import { KeyStore } from './key-store';
import { DuplicateKeyError, KeyImportError } from './errors';
import type { IOpenPGPAdapter, IStorageAdapter } from './interfaces';
import type { ParsedKey } from './types';

// Make openpgp available globally so the adapter's lazy-loader finds it
beforeAll(() => {
  (globalThis as any).openpgp = openpgp;
});

// --- Fixtures ---

let publicKeyArmored: string;
let privateKeyArmored: string;
let keyFingerprint: string;
let keyUserID: string;

let publicKeyArmored2: string;
let privateKeyArmored2: string;
let keyFingerprint2: string;

beforeAll(async () => {
  // Key pair 1
  const kp1 = await openpgp.generateKey({
    type: 'ecc',
    curve: 'curve25519',
    userIDs: [{ name: 'Alice', email: 'alice@test.com' }],
    format: 'armored',
    passphrase: undefined,
  });
  publicKeyArmored = kp1.publicKey;
  privateKeyArmored = kp1.privateKey;
  const parsed1 = await openpgp.readKey({ armoredKey: kp1.publicKey });
  keyFingerprint = parsed1.getFingerprint();
  keyUserID = parsed1.users[0]?.userID?.userID ?? '';

  // Key pair 2
  const kp2 = await openpgp.generateKey({
    type: 'ecc',
    curve: 'curve25519',
    userIDs: [{ name: 'Bob', email: 'bob@test.com' }],
    format: 'armored',
    passphrase: undefined,
  });
  publicKeyArmored2 = kp2.publicKey;
  privateKeyArmored2 = kp2.privateKey;
  const parsed2 = await openpgp.readKey({ armoredKey: kp2.publicKey });
  keyFingerprint2 = parsed2.getFingerprint();
});

// --- Helpers ---

/** Real IOpenPGPAdapter that delegates to openpgp for parseKey. */
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

/** In-memory IStorageAdapter backed by a Map. */
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

// --- Tests ---

let pgpAdapter: IOpenPGPAdapter;
let storage: IStorageAdapter;
let keyStore: KeyStore;

beforeEach(() => {
  pgpAdapter = createRealPgpAdapter();
  storage = createInMemoryStorage();
  keyStore = new KeyStore(pgpAdapter, storage);
});

describe('Key Store Unit Tests', () => {
  // Req 1.1: Import a valid public key
  describe('importKey – valid public key', () => {
    it('should import a valid public key and return correct metadata', async () => {
      const result = await keyStore.importKey(publicKeyArmored);

      expect(result.fingerprint).toBe(keyFingerprint);
      expect(result.userID).toBe(keyUserID);
      expect(result.type).toBe('public');
      expect(result.creationDate).toBeInstanceOf(Date);
      expect(result.armoredKey).toBe(publicKeyArmored.trim());
    });
  });

  // Req 1.2: Import a valid private key
  describe('importKey – valid private key', () => {
    it('should import a valid private key and return correct metadata', async () => {
      const result = await keyStore.importKey(privateKeyArmored);

      expect(result.fingerprint).toBe(keyFingerprint);
      expect(result.userID).toBe(keyUserID);
      expect(result.type).toBe('private');
      expect(result.creationDate).toBeInstanceOf(Date);
      expect(result.armoredKey).toBe(privateKeyArmored.trim());
    });
  });

  // Req 1.3: Duplicate import rejection
  describe('importKey – duplicate rejection', () => {
    it('should throw DuplicateKeyError when importing the same public key twice', async () => {
      await keyStore.importKey(publicKeyArmored);
      await expect(keyStore.importKey(publicKeyArmored)).rejects.toThrow(DuplicateKeyError);
    });

    it('should throw DuplicateKeyError when importing the same private key twice', async () => {
      await keyStore.importKey(privateKeyArmored);
      await expect(keyStore.importKey(privateKeyArmored)).rejects.toThrow(DuplicateKeyError);
    });

    it('should allow importing both public and private key with the same fingerprint', async () => {
      await keyStore.importKey(publicKeyArmored);
      const priv = await keyStore.importKey(privateKeyArmored);
      expect(priv.fingerprint).toBe(keyFingerprint);
      expect(priv.type).toBe('private');

      const keys = await keyStore.listKeys();
      expect(keys).toHaveLength(2);
    });
  });

  // Req 1.5: Removal of existing key
  describe('removeKey – existing key', () => {
    it('should remove an imported key by fingerprint', async () => {
      await keyStore.importKey(publicKeyArmored);
      const keysBefore = await keyStore.listKeys();
      expect(keysBefore).toHaveLength(1);

      await keyStore.removeKey(keyFingerprint);

      const keysAfter = await keyStore.listKeys();
      expect(keysAfter).toHaveLength(0);
    });
  });

  // Req 1.5: Removal of non-existent key throws
  describe('removeKey – non-existent key', () => {
    it('should throw KeyImportError when removing a key that does not exist', async () => {
      await expect(keyStore.removeKey('nonexistent-fingerprint')).rejects.toThrow(KeyImportError);
    });
  });

  // Req 1.6: Listing empty store returns empty array
  describe('listKeys – empty store', () => {
    it('should return an empty array when no keys have been imported', async () => {
      const keys = await keyStore.listKeys();
      expect(keys).toEqual([]);
    });
  });

  // Req 1.6: getPublicKeys / getPrivateKeys filtering
  describe('getPublicKeys / getPrivateKeys filtering', () => {
    it('should return only public keys from getPublicKeys', async () => {
      await keyStore.importKey(publicKeyArmored);
      await keyStore.importKey(privateKeyArmored);
      await keyStore.importKey(publicKeyArmored2);

      const publicKeys = await keyStore.getPublicKeys();
      expect(publicKeys).toHaveLength(2);
      expect(publicKeys.every((k) => k.type === 'public')).toBe(true);
    });

    it('should return only private keys from getPrivateKeys', async () => {
      await keyStore.importKey(publicKeyArmored);
      await keyStore.importKey(privateKeyArmored);
      await keyStore.importKey(privateKeyArmored2);

      const privateKeys = await keyStore.getPrivateKeys();
      expect(privateKeys).toHaveLength(2);
      expect(privateKeys.every((k) => k.type === 'private')).toBe(true);
    });

    it('should return empty array from getPublicKeys when only private keys exist', async () => {
      await keyStore.importKey(privateKeyArmored);

      const publicKeys = await keyStore.getPublicKeys();
      expect(publicKeys).toEqual([]);
    });

    it('should return empty array from getPrivateKeys when only public keys exist', async () => {
      await keyStore.importKey(publicKeyArmored);

      const privateKeys = await keyStore.getPrivateKeys();
      expect(privateKeys).toEqual([]);
    });
  });
});
