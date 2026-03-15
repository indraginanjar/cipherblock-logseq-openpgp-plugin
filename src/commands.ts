// CipherBlock – Command Module
// Registers slash commands, context menu items, and orchestrates encrypt/decrypt/vault flows.

import type {
  IKeyStore,
  IEncryptionService,
  IDecryptionService,
  IVaultService,
  IOutputHandler,
  IMetadataWriter,
} from './interfaces';
import type { EncryptionMetadata } from './types';
import { SettingsManager } from './settings-manager';
import { showRecipientDialog, showKeySelectionDialog, showPassphrasePrompt } from './ui';
import { handleError } from './error-handler';

/** Dependencies required by the command module. */
export interface CommandDeps {
  keyStore: IKeyStore;
  encryptionService: IEncryptionService;
  decryptionService: IDecryptionService;
  vaultService: IVaultService;
  outputHandler: IOutputHandler;
  settingsManager: SettingsManager;
  metadataWriter: IMetadataWriter;
}

/**
 * Extract the armored PGP message from block text.
 * Returns the armored message string (including headers) or null if not found.
 */
function extractArmoredMessage(text: string): string | null {
  const beginMarker = '-----BEGIN PGP MESSAGE-----';
  const endMarker = '-----END PGP MESSAGE-----';
  const beginIdx = text.indexOf(beginMarker);
  const endIdx = text.indexOf(endMarker);
  if (beginIdx === -1 || endIdx === -1 || endIdx < beginIdx) {
    return null;
  }
  return text.slice(beginIdx, endIdx + endMarker.length);
}

/**
 * Register all CipherBlock slash commands and context menu items.
 * Wires up encrypt, decrypt, and vault flows with full error handling.
 */
export function registerCommands(deps: CommandDeps): void {
  const {
    keyStore,
    encryptionService,
    decryptionService,
    vaultService,
    outputHandler,
    settingsManager,
    metadataWriter,
  } = deps;

  // --- Encrypt flow (shared logic) ---
  async function encryptBlock(blockUuid: string): Promise<void> {
    const block = await logseq.Editor.getBlock(blockUuid);
    if (!block) return;

    const blockText = block.content;

    const publicKeys = await keyStore.getPublicKeys();
    if (publicKeys.length === 0) {
      logseq.UI.showMsg('Import a public key first', 'error');
      return;
    }

    const settings = settingsManager.getSettings();
    const dialogResult = await showRecipientDialog(publicKeys, settings.outputMode);
    if (!dialogResult) return;

    const { recipients, outputMode } = dialogResult;

    const encryptionResult = await encryptionService.encrypt(blockText, recipients);
    await outputHandler.placeResult(blockUuid, encryptionResult.armoredMessage, outputMode);

    // Write metadata if enabled
    if (settings.metadataEnabled) {
      const metadata = await buildEncryptionMetadata(recipients, keyStore);
      await metadataWriter.writeMetadata(blockUuid, metadata, settings.metadataMode);
    }

    logseq.UI.showMsg(`Encrypted for ${encryptionResult.recipientCount} recipient(s)`, 'success');
  }

  // --- Decrypt flow (shared logic) ---
  async function decryptBlock(blockUuid: string): Promise<void> {
    const block = await logseq.Editor.getBlock(blockUuid);
    if (!block) return;

    const blockText = block.content;
    const armoredMessage = extractArmoredMessage(blockText);
    if (!armoredMessage) {
      logseq.UI.showMsg('Block does not contain encrypted content', 'error');
      return;
    }

    const privateKeys = await keyStore.getPrivateKeys();
    if (privateKeys.length === 0) {
      logseq.UI.showMsg('Import a private key first', 'error');
      return;
    }

    const settings = await settingsManager.getSettingsWithAutoDefault();
    let fingerprint = settings.defaultKeyFingerprint;

    if (!fingerprint) {
      // Multiple keys, no default — prompt user
      const selected = await showKeySelectionDialog(privateKeys);
      if (!selected) return;
      fingerprint = selected;
    }

    const passphraseProvider = () => showPassphrasePrompt();

    const decryptionResult = await decryptionService.decrypt(
      armoredMessage,
      fingerprint,
      passphraseProvider,
    );

    await outputHandler.placeResult(blockUuid, decryptionResult.plaintext, settings.outputMode);
    logseq.UI.showMsg('Decryption successful', 'success');
  }

  // --- Vault flow (shared logic) ---
  async function encryptToVault(blockUuid: string): Promise<void> {
    const block = await logseq.Editor.getBlock(blockUuid);
    if (!block) return;

    const blockText = block.content;

    const publicKeys = await keyStore.getPublicKeys();
    if (publicKeys.length === 0) {
      logseq.UI.showMsg('Import a public key first', 'error');
      return;
    }

    const settings = settingsManager.getSettings();
    const dialogResult = await showRecipientDialog(publicKeys, settings.outputMode);
    if (!dialogResult) return;

    const { recipients } = dialogResult;

    const vaultResult = await vaultService.encryptToVault(blockUuid, blockText, recipients);
    logseq.UI.showMsg(`Encrypted to ${vaultResult.vaultPageName}`, 'success');
  }

  // --- Register slash commands ---
  logseq.Editor.registerSlashCommand('encrypt-block', async (e) => {
    try {
      await encryptBlock(e.uuid);
    } catch (error) {
      handleError(error);
    }
  });

  logseq.Editor.registerSlashCommand('decrypt-block', async (e) => {
    try {
      await decryptBlock(e.uuid);
    } catch (error) {
      handleError(error);
    }
  });

  logseq.Editor.registerSlashCommand('encrypt-to-vault', async (e) => {
    try {
      await encryptToVault(e.uuid);
    } catch (error) {
      handleError(error);
    }
  });

  // --- Register context menu items ---
  logseq.Editor.registerBlockContextMenuItem('Encrypt Block', async (e) => {
    try {
      await encryptBlock(e.uuid);
    } catch (error) {
      handleError(error);
    }
  });

  logseq.Editor.registerBlockContextMenuItem('Decrypt Block', async (e) => {
    try {
      await decryptBlock(e.uuid);
    } catch (error) {
      handleError(error);
    }
  });

  logseq.Editor.registerBlockContextMenuItem('Encrypt to Vault', async (e) => {
    try {
      await encryptToVault(e.uuid);
    } catch (error) {
      handleError(error);
    }
  });
}

/**
 * Build EncryptionMetadata by looking up user IDs from the key store.
 */
async function buildEncryptionMetadata(
  recipientFingerprints: string[],
  keyStore: IKeyStore,
): Promise<EncryptionMetadata> {
  const recipientUserIDs: string[] = [];
  let keyAlgorithm = 'unknown';

  for (const fingerprint of recipientFingerprints) {
    const key = await keyStore.getKey(fingerprint);
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
    recipientCount: recipientFingerprints.length,
  };
}
