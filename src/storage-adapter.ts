// CipherBlock – Storage Adapter wrapping Logseq plugin storage API

import type { IStorageAdapter } from './interfaces';

/**
 * Wraps the Logseq plugin storage API (logseq.Storage) to conform to IStorageAdapter.
 * Provides get, set, and remove operations for persistent key-value storage.
 */
export class StorageAdapter implements IStorageAdapter {
  async get(key: string): Promise<string | null> {
    try {
      const exists = await logseq.FileStorage.hasItem(key);
      if (!exists) return null;
      const value = await logseq.FileStorage.getItem(key);
      if (value === undefined || value === null) {
        return null;
      }
      return String(value);
    } catch {
      return null;
    }
  }

  async set(key: string, value: string): Promise<void> {
    await logseq.FileStorage.setItem(key, value);
  }

  async remove(key: string): Promise<void> {
    try {
      await logseq.FileStorage.removeItem(key);
    } catch {
      // Ignore removal errors for non-existent keys
    }
  }
}
