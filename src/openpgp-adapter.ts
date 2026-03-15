// CipherBlock – OpenPGP Adapter
// Thin wrapper around OpenPGP.js, isolating the crypto library from business logic.
// OpenPGP.js is lazy-loaded on first use to avoid blocking plugin startup.

import { KeyImportError } from './errors';
import type { IOpenPGPAdapter } from './interfaces';
import type { ParsedKey } from './types';

/** Check if an error message indicates an expired key. */
function isExpiredKeyError(msg: string): boolean {
  const lower = msg.toLowerCase();
  return lower.includes('expired') || lower.includes('expir');
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
let _openpgp: any = null;
let _loadPromise: Promise<any> | null = null;

/** Lazy-load openpgp by injecting a script tag at runtime. */
async function getOpenPGP(): Promise<any> {
  if (_openpgp) return _openpgp;

  // Check if already loaded globally (e.g. by another call or index.html)
  if ((globalThis as any).openpgp) {
    _openpgp = (globalThis as any).openpgp;
    return _openpgp;
  }

  // Also check the parent window (Logseq main frame)
  try {
    if ((parent as any).openpgp) {
      _openpgp = (parent as any).openpgp;
      return _openpgp;
    }
  } catch {
    // cross-origin access may fail, ignore
  }

  // Deduplicate concurrent load requests
  if (_loadPromise) return _loadPromise;

  _loadPromise = new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = 'https://unpkg.com/openpgp@5.11.2/dist/openpgp.min.js';
    script.onload = () => {
      _openpgp = (globalThis as any).openpgp;
      if (_openpgp) {
        resolve(_openpgp);
      } else {
        _loadPromise = null;
        reject(new Error('openpgp global not found after script load'));
      }
    };
    script.onerror = () => {
      _loadPromise = null;
      reject(new Error('Failed to load openpgp library from CDN'));
    };
    document.head.appendChild(script);
  });

  return _loadPromise;
}

export class OpenPGPAdapter implements IOpenPGPAdapter {
  async parseKey(armoredKey: string): Promise<ParsedKey> {
    const openpgp = await getOpenPGP();
    if (!armoredKey || typeof armoredKey !== 'string') {
      throw new KeyImportError('Failed to import key: input is empty or not a string');
    }

    const trimmed = armoredKey.trim();

    const isPublicArmor = trimmed.includes('-----BEGIN PGP PUBLIC KEY BLOCK-----');
    const isPrivateArmor = trimmed.includes('-----BEGIN PGP PRIVATE KEY BLOCK-----');

    if (!isPublicArmor && !isPrivateArmor) {
      throw new KeyImportError('Failed to import key: not a valid armored OpenPGP key');
    }

    try {
      if (isPublicArmor) {
        const key = await openpgp.readKey({ armoredKey: trimmed });
        return this.extractKeyMetadata(key, 'public', trimmed);
      } else {
        const key = await openpgp.readPrivateKey({ armoredKey: trimmed });
        return this.extractKeyMetadata(key, 'private', trimmed);
      }
    } catch (err) {
      if (err instanceof KeyImportError) {
        throw err;
      }
      throw new KeyImportError(
        `Failed to import key: ${err instanceof Error ? err.message : 'unknown error'}`,
        err instanceof Error ? err : undefined,
      );
    }
  }

  async encrypt(plaintext: string, recipientKeys: string[]): Promise<string> {
    const openpgp = await getOpenPGP();
    const publicKeys = await Promise.all(
      recipientKeys.map(async (armoredKey) => {
        try {
          return await openpgp.readKey({ armoredKey });
        } catch (err) {
          throw new KeyImportError(
            `Failed to read recipient key: ${err instanceof Error ? err.message : 'unknown error'}`,
            err instanceof Error ? err : undefined,
          );
        }
      }),
    );

    const message = await openpgp.createMessage({ text: plaintext });

    try {
      const encrypted = await openpgp.encrypt({
        message,
        encryptionKeys: publicKeys,
      });
      return encrypted as string;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (isExpiredKeyError(msg)) {
        throw new KeyImportError(
          'Recipient key is expired. Extend it with: gpg --edit-key <email> → expire → save, then re-export and re-import.',
          err instanceof Error ? err : undefined,
        );
      }
      throw err;
    }
  }

  async decrypt(armoredMessage: string, privateKey: string, passphrase?: string): Promise<string> {
    const openpgp = await getOpenPGP();
    const message = await openpgp.readMessage({ armoredMessage });

    let decryptionKey = await openpgp.readPrivateKey({ armoredKey: privateKey });

    if (passphrase) {
      decryptionKey = await openpgp.decryptKey({
        privateKey: decryptionKey,
        passphrase,
      });
    }

    const { data } = await openpgp.decrypt({
      message,
      decryptionKeys: decryptionKey,
    });

    return data as string;
  }

  private extractKeyMetadata(
    key: { getFingerprint(): string; users: Array<{ userID?: { userID?: string } }>; getCreationTime(): Date },
    type: 'public' | 'private',
    armoredKey: string,
  ): ParsedKey {
    const fingerprint = key.getFingerprint();
    const userID = key.users[0]?.userID?.userID ?? '';
    const creationDate = key.getCreationTime();

    return {
      fingerprint,
      userID,
      type,
      creationDate,
      armoredKey,
    };
  }
}
