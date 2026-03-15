// CipherBlock – Key Store implementation

import type { IKeyStore, IOpenPGPAdapter, IStorageAdapter } from './interfaces';
import type { StoredKey, PersistedKeyEntry } from './types';
import { DuplicateKeyError, KeyImportError } from './errors';

const STORAGE_KEY = 'cipherblock:keys';

/**
 * Manages imported OpenPGP keys with persistent storage.
 * Keys are serialized as PersistedKeyEntry[] JSON via the storage adapter.
 */
export class KeyStore implements IKeyStore {
  constructor(
    private readonly pgpAdapter: IOpenPGPAdapter,
    private readonly storage: IStorageAdapter,
  ) {}

  async importKey(armoredKey: string): Promise<StoredKey> {
    const parsed = await this.pgpAdapter.parseKey(armoredKey);
    const keys = await this.loadKeys();

    if (keys.some((k) => k.fingerprint === parsed.fingerprint && k.type === parsed.type)) {
      throw new DuplicateKeyError(`${parsed.type} key already exists: ${parsed.fingerprint}`);
    }

    const storedKey: StoredKey = {
      fingerprint: parsed.fingerprint,
      userID: parsed.userID,
      type: parsed.type,
      creationDate: parsed.creationDate,
      armoredKey: parsed.armoredKey,
    };

    keys.push(storedKey);
    await this.saveKeys(keys);
    return storedKey;
  }

  async removeKey(fingerprint: string): Promise<void> {
    const keys = await this.loadKeys();
    const index = keys.findIndex((k) => k.fingerprint === fingerprint);

    if (index === -1) {
      throw new KeyImportError(`Key not found: ${fingerprint}`);
    }

    keys.splice(index, 1);
    await this.saveKeys(keys);
  }

  async listKeys(): Promise<StoredKey[]> {
    return this.loadKeys();
  }

  async getKey(fingerprint: string): Promise<StoredKey | null> {
    const keys = await this.loadKeys();
    return keys.find((k) => k.fingerprint === fingerprint) ?? null;
  }

  async getPublicKeys(): Promise<StoredKey[]> {
    const keys = await this.loadKeys();
    return keys.filter((k) => k.type === 'public');
  }

  async getPrivateKeys(): Promise<StoredKey[]> {
    const keys = await this.loadKeys();
    return keys.filter((k) => k.type === 'private');
  }

  private async loadKeys(): Promise<StoredKey[]> {
    const raw = await this.storage.get(STORAGE_KEY);
    if (!raw) {
      return [];
    }

    const entries: PersistedKeyEntry[] = JSON.parse(raw);
    return entries.map((e) => ({
      fingerprint: e.fingerprint,
      userID: e.userID,
      type: e.type,
      creationDate: new Date(e.creationDate),
      armoredKey: e.armoredKey,
    }));
  }

  private async saveKeys(keys: StoredKey[]): Promise<void> {
    const entries: PersistedKeyEntry[] = keys.map((k) => ({
      fingerprint: k.fingerprint,
      userID: k.userID,
      type: k.type,
      creationDate: k.creationDate.toISOString(),
      armoredKey: k.armoredKey,
    }));
    await this.storage.set(STORAGE_KEY, JSON.stringify(entries));
  }
}
