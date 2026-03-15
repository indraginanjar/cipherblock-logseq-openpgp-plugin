// CipherBlock – Output Handler

import { ClipboardError } from './errors';
import type { IOutputHandler } from './interfaces';
import type { OutputMode } from './types';

/** Places encryption/decryption results according to the active output mode. */
export class OutputHandler implements IOutputHandler {
  async placeResult(blockUuid: string, resultText: string, mode: OutputMode): Promise<string | null> {
    switch (mode) {
      case 'replace':
        await logseq.Editor.updateBlock(blockUuid, resultText);
        return blockUuid;

      case 'sibling': {
        const block = await logseq.Editor.insertBlock(blockUuid, resultText, { sibling: true });
        return block?.uuid ?? null;
      }

      case 'sub-block': {
        const block = await logseq.Editor.insertBlock(blockUuid, resultText, { sibling: false });
        return block?.uuid ?? null;
      }

      case 'clipboard':
        try {
          await navigator.clipboard.writeText(resultText);
        } catch (err) {
          throw new ClipboardError(
            'Failed to copy to clipboard',
            err instanceof Error ? err : undefined,
          );
        }
        return null;
    }
  }
}
