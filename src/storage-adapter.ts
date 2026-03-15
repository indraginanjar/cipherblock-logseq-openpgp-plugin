// CipherBlock – Storage Adapter wrapping Logseq plugin storage API

import type { IStorageAdapter } from './interfaces';

/**
 * Wraps the Logseq plugin storage API (logseq.Storage) to conform to IStorageAdapter.
 * Provides get, set, and remove operations for persistent key-value storage.
 */
export class StorageAdapter implements IStorageAdapter {
  async get(key: string): Promise<string | null> {
    const value = await logseq.Storage.getItem(key);
    if (value === undefined || value === null) {
      return null;
    }
    return String(value);
  }

  async set(key: string, value: string): Promise<void> {
    await logseq.Storage.setItem(key, value);
  }

  async remove(key: string): Promise<void> {
    await logseq.Storage.removeItem(key);
  }
}
