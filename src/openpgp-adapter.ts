// CipherBlock – OpenPGP Adapter
// Thin wrapper around OpenPGP.js, isolating the crypto library from business logic.

import * as openpgp from 'openpgp';
import { KeyImportError } from './errors';
import type { IOpenPGPAdapter } from './interfaces';
import type { ParsedKey } from './types';

export class OpenPGPAdapter implements IOpenPGPAdapter {
  async parseKey(armoredKey: string): Promise<ParsedKey> {
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

    const encrypted = await openpgp.encrypt({
      message,
      encryptionKeys: publicKeys,
    });

    return encrypted as string;
  }

  async decrypt(armoredMessage: string, privateKey: string, passphrase?: string): Promise<string> {
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
    key: openpgp.Key | openpgp.PrivateKey,
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
