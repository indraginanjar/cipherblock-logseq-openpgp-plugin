// CipherBlock – Vault Service

import { EmptyBlockError } from './errors';
import type {
  IVaultService,
  IEncryptionService,
  ISettingsManager,
  IMetadataWriter,
  IKeyStore,
} from './interfaces';
import type { VaultResult, EncryptionMetadata } from './types';

/** Orchestrates vault page creation: generates hex ID, creates page, inserts encrypted sub-block, replaces original block with vault link. */
export class VaultService implements IVaultService {
  constructor(
    private readonly encryptionService: IEncryptionService,
    private readonly settingsManager: ISettingsManager,
    private readonly metadataWriter: IMetadataWriter,
    private readonly keyStore: IKeyStore,
  ) {}

  /** Generate a random hex string of the given length (minimum 8 characters). */
  generateHex(length: number): string {
    const byteCount = Math.max(Math.ceil(length / 2), 4);
    const bytes = new Uint8Array(byteCount);
    crypto.getRandomValues(bytes);
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  async encryptToVault(
    blockUuid: string,
    plaintext: string,
    recipientFingerprints: string[],
  ): Promise<VaultResult> {
    if (!plaintext || plaintext.trim().length === 0) {
      throw new EmptyBlockError('Cannot encrypt an empty block');
    }

    // Generate vault page name
    const hex = this.generateHex(8);
    const vaultPageName = `Vault-${hex}`;

    // Encrypt plaintext
    const encryptionResult = await this.encryptionService.encrypt(
      plaintext,
      recipientFingerprints,
    );

    // Create vault page
    await logseq.Editor.createPage(vaultPageName);

    // Get first block of the page and insert armored message as sub-block
    const blocks = await logseq.Editor.getPageBlocksTree(vaultPageName);
    const firstBlock = blocks[0];
    const insertedBlock = await logseq.Editor.insertBlock(
      firstBlock.uuid,
      encryptionResult.armoredMessage,
      { sibling: false },
    );

    // Write metadata if enabled
    const settings = this.settingsManager.getSettings();
    if (settings.metadataEnabled && insertedBlock) {
      const metadata = await this.buildMetadata(
        recipientFingerprints,
        encryptionResult.recipientCount,
      );
      await this.metadataWriter.writeMetadata(
        insertedBlock.uuid,
        metadata,
        settings.metadataMode,
      );
    }

    // Replace original block with vault link
    const vaultLink = `[[${vaultPageName}]]`;
    await logseq.Editor.updateBlock(blockUuid, vaultLink);

    return { vaultPageName, vaultLink };
  }

  private async buildMetadata(
    recipientFingerprints: string[],
    recipientCount: number,
  ): Promise<EncryptionMetadata> {
    const recipientUserIDs: string[] = [];
    let keyAlgorithm = 'unknown';

    for (const fingerprint of recipientFingerprints) {
      const key = await this.keyStore.getKey(fingerprint);
      if (key) {
        recipientUserIDs.push(key.userID);
      } else {
        recipientUserIDs.push(fingerprint);
      }
    }

    return {
      recipientFingerprints,
      recipientUserIDs,
      encryptedAt: new Date().toISOString(),
      keyAlgorithm,
      recipientCount,
    };
  }
}
