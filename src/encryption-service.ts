// CipherBlock – Encryption Service

import { EmptyBlockError, NoKeysError } from './errors';
import type { IEncryptionService, IOpenPGPAdapter, IKeyStore } from './interfaces';
import type { EncryptionResult } from './types';

/** Encrypts plaintext for selected recipients using OpenPGP. */
export class EncryptionService implements IEncryptionService {
  constructor(
    private readonly pgpAdapter: IOpenPGPAdapter,
    private readonly keyStore: IKeyStore,
  ) {}

  async encrypt(plaintext: string, recipientFingerprints: string[]): Promise<EncryptionResult> {
    if (!plaintext || plaintext.trim().length === 0) {
      throw new EmptyBlockError('Cannot encrypt an empty block');
    }

    if (!recipientFingerprints || recipientFingerprints.length === 0) {
      throw new NoKeysError('No recipients provided');
    }

    const armoredPublicKeys: string[] = [];

    for (const fingerprint of recipientFingerprints) {
      const storedKey = await this.keyStore.getKey(fingerprint);
      if (!storedKey) {
        throw new NoKeysError(`Key not found for fingerprint: ${fingerprint}`);
      }
      armoredPublicKeys.push(storedKey.armoredKey);
    }

    const armoredMessage = await this.pgpAdapter.encrypt(plaintext, armoredPublicKeys);

    return {
      armoredMessage,
      recipientCount: recipientFingerprints.length,
    };
  }
}
