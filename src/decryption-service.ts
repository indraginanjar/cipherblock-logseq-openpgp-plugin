// CipherBlock – Decryption Service

import {
  InvalidCiphertextError,
  NoKeysError,
  KeyMismatchError,
  PassphraseError,
  DecryptionError,
} from './errors';
import type { IDecryptionService, IOpenPGPAdapter, IKeyStore } from './interfaces';
import type { DecryptionResult } from './types';

const MAX_PASSPHRASE_ATTEMPTS = 3;

/** Decrypts armored PGP messages using a private key from the Key Store. */
export class DecryptionService implements IDecryptionService {
  constructor(
    private readonly pgpAdapter: IOpenPGPAdapter,
    private readonly keyStore: IKeyStore,
  ) {}

  async decrypt(
    armoredMessage: string,
    privateKeyFingerprint: string,
    passphraseProvider?: () => Promise<string>,
  ): Promise<DecryptionResult> {
    if (!armoredMessage?.includes('-----BEGIN PGP MESSAGE-----')) {
      throw new InvalidCiphertextError('Block does not contain encrypted content');
    }

    const storedKey = await this.keyStore.getKey(privateKeyFingerprint);
    if (!storedKey) {
      throw new NoKeysError('Import a private key first');
    }

    return this.attemptDecryption(armoredMessage, storedKey.armoredKey, passphraseProvider);
  }

  private async attemptDecryption(
    armoredMessage: string,
    armoredKey: string,
    passphraseProvider?: () => Promise<string>,
  ): Promise<DecryptionResult> {
    try {
      const plaintext = await this.pgpAdapter.decrypt(armoredMessage, armoredKey);
      return { plaintext };
    } catch (error: unknown) {
      return this.handleDecryptionError(error, armoredMessage, armoredKey, passphraseProvider);
    }
  }

  private async handleDecryptionError(
    error: unknown,
    armoredMessage: string,
    armoredKey: string,
    passphraseProvider?: () => Promise<string>,
  ): Promise<DecryptionResult> {
    const errorMessage = error instanceof Error ? error.message : String(error);
    const cause = error instanceof Error ? error : undefined;

    if (this.isPassphraseNeeded(errorMessage) && passphraseProvider) {
      return this.decryptWithPassphrase(armoredMessage, armoredKey, passphraseProvider);
    }

    if (this.isPassphraseNeeded(errorMessage)) {
      throw new PassphraseError('Decryption cancelled: incorrect passphrase', cause);
    }

    if (this.isKeyMismatch(errorMessage)) {
      throw new KeyMismatchError('Decryption failed: no matching key', cause);
    }

    throw new DecryptionError('Decryption failed', cause);
  }

  private async decryptWithPassphrase(
    armoredMessage: string,
    armoredKey: string,
    passphraseProvider: () => Promise<string>,
  ): Promise<DecryptionResult> {
    for (let attempt = 0; attempt < MAX_PASSPHRASE_ATTEMPTS; attempt++) {
      const passphrase = await passphraseProvider();

      try {
        const plaintext = await this.pgpAdapter.decrypt(armoredMessage, armoredKey, passphrase);
        return { plaintext };
      } catch (error: unknown) {
        this.throwIfNotPassphraseError(error);
      }
    }

    throw new PassphraseError('Decryption cancelled: incorrect passphrase');
  }

  private throwIfNotPassphraseError(error: unknown): void {
    const errorMessage = error instanceof Error ? error.message : String(error);
    const cause = error instanceof Error ? error : undefined;

    if (this.isKeyMismatch(errorMessage)) {
      throw new KeyMismatchError('Decryption failed: no matching key', cause);
    }

    if (!this.isPassphraseNeeded(errorMessage)) {
      throw new DecryptionError('Decryption failed', cause);
    }
  }

  private isPassphraseNeeded(errorMessage: string): boolean {
    const lower = errorMessage.toLowerCase();
    return lower.includes('incorrect key passphrase') || lower.includes('passphrase');
  }

  private isKeyMismatch(errorMessage: string): boolean {
    const lower = errorMessage.toLowerCase();
    return lower.includes('session key decryption failed') || lower.includes('no matching key');
  }
}
