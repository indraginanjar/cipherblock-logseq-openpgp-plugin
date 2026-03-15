// CipherBlock – Metadata Writer

import type { IMetadataWriter } from './interfaces';
import type { EncryptionMetadata, MetadataMode } from './types';

/** Writes encryption metadata to a block as Logseq properties or child blocks. */
export class MetadataWriter implements IMetadataWriter {
  async writeMetadata(
    blockUuid: string,
    metadata: EncryptionMetadata,
    mode: MetadataMode,
  ): Promise<void> {
    if (metadata.recipientCount !== metadata.recipientFingerprints.length) {
      throw new Error(
        `recipientCount (${metadata.recipientCount}) does not match recipientFingerprints length (${metadata.recipientFingerprints.length})`,
      );
    }

    if (mode === 'attributes') {
      await this.writeAttributes(blockUuid, metadata);
    } else {
      await this.writeSubBlocks(blockUuid, metadata);
    }
  }

  private async writeAttributes(
    blockUuid: string,
    metadata: EncryptionMetadata,
  ): Promise<void> {
    const block = await logseq.Editor.getBlock(blockUuid);
    if (!block) {
      throw new Error(`Block not found: ${blockUuid}`);
    }

    const properties = [
      `encrypted-by:: ${metadata.recipientFingerprints.join(', ')}`,
      `encrypted-by-uid:: ${metadata.recipientUserIDs.join(', ')}`,
      `encrypted-at:: ${metadata.encryptedAt}`,
      `encryption-algo:: ${metadata.keyAlgorithm}`,
      `recipient-count:: ${metadata.recipientCount}`,
    ].join('\n');

    const updatedContent = `${block.content}\n${properties}`;
    await logseq.Editor.updateBlock(blockUuid, updatedContent);
  }

  private async writeSubBlocks(
    blockUuid: string,
    metadata: EncryptionMetadata,
  ): Promise<void> {
    const entries = [
      `encrypted-by: ${metadata.recipientFingerprints.join(', ')}`,
      `encrypted-by-uid: ${metadata.recipientUserIDs.join(', ')}`,
      `encrypted-at: ${metadata.encryptedAt}`,
      `encryption-algo: ${metadata.keyAlgorithm}`,
      `recipient-count: ${metadata.recipientCount}`,
    ];

    for (const entry of entries) {
      await logseq.Editor.insertBlock(blockUuid, entry, { sibling: false });
    }
  }
}
