// CipherBlock – Unit tests for Command Module
// Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 11.1, 11.2, 11.4, 11.5, 14.2, 9.4

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { CommandDeps } from './commands';
import type { StoredKey, PluginSettings, EncryptionResult, DecryptionResult, VaultResult, EncryptionMetadata, MetadataMode } from './types';
import type { IKeyStore, IEncryptionService, IDecryptionService, IVaultService, IOutputHandler, IMetadataWriter } from './interfaces';
import { SettingsManager } from './settings-manager';

// --- Mock UI module ---
vi.mock('./ui', () => ({
  showRecipientDialog: vi.fn(),
  showKeySelectionDialog: vi.fn(),
  showPassphrasePrompt: vi.fn(),
  showImportKeyDialog: vi.fn(),
  showKeyManagerDialog: vi.fn(),
}));

vi.mock('./error-handler', () => ({
  handleError: vi.fn(),
}));

import { showRecipientDialog, showKeySelectionDialog } from './ui';
import { handleError } from './error-handler';

// --- Logseq global mock ---
const slashCommands = new Map<string, Function>();
const contextMenuItems = new Map<string, Function>();

const mockShowMsg = vi.fn().mockResolvedValue(undefined);

(globalThis as any).logseq = {
  Editor: {
    registerSlashCommand: vi.fn((name: string, handler: Function) => {
      slashCommands.set(name, handler);
    }),
    registerBlockContextMenuItem: vi.fn((name: string, handler: Function) => {
      contextMenuItems.set(name, handler);
    }),
    getBlock: vi.fn(),
  },
  UI: {
    showMsg: mockShowMsg,
  },
  settings: {} as Record<string, unknown>,
  useSettingsSchema: vi.fn(),
  onSettingsChanged: vi.fn(),
};

// --- Helpers ---
function makePublicKey(fp = 'AAAA', uid = 'Alice'): StoredKey {
  return { fingerprint: fp, userID: uid, type: 'public', creationDate: new Date(), armoredKey: 'pub' };
}

function makePrivateKey(fp = 'BBBB', uid = 'Bob'): StoredKey {
  return { fingerprint: fp, userID: uid, type: 'private', creationDate: new Date(), armoredKey: 'priv' };
}

function defaultSettings(overrides: Partial<PluginSettings> = {}): PluginSettings {
  return {
    defaultKeyFingerprint: null,
    outputMode: 'replace',
    passphraseCachingEnabled: false,
    metadataEnabled: false,
    metadataMode: 'attributes',
    ...overrides,
  };
}

function createMockDeps(): CommandDeps {
  const keyStore: IKeyStore = {
    importKey: vi.fn(),
    removeKey: vi.fn(),
    listKeys: vi.fn().mockResolvedValue([]),
    getKey: vi.fn().mockResolvedValue(null),
    getPublicKeys: vi.fn().mockResolvedValue([]),
    getPrivateKeys: vi.fn().mockResolvedValue([]),
  };

  const encryptionService: IEncryptionService = {
    encrypt: vi.fn().mockResolvedValue({ armoredMessage: '-----BEGIN PGP MESSAGE-----\ntest\n-----END PGP MESSAGE-----', recipientCount: 1 } as EncryptionResult),
  };

  const decryptionService: IDecryptionService = {
    decrypt: vi.fn().mockResolvedValue({ plaintext: 'decrypted text' } as DecryptionResult),
  };

  const vaultService: IVaultService = {
    encryptToVault: vi.fn().mockResolvedValue({ vaultPageName: 'Vault-abcd1234', vaultLink: '[[Vault-abcd1234]]' } as VaultResult),
  };

  const outputHandler: IOutputHandler = {
    placeResult: vi.fn().mockResolvedValue('result-block-uuid'),
  };

  const metadataWriter: IMetadataWriter = {
    writeMetadata: vi.fn().mockResolvedValue(undefined),
  };

  // Create a real SettingsManager but spy on its methods
  const settingsManager = new SettingsManager(keyStore);
  vi.spyOn(settingsManager, 'getSettings').mockReturnValue(defaultSettings());
  vi.spyOn(settingsManager, 'getSettingsWithAutoDefault').mockResolvedValue(defaultSettings());

  return {
    keyStore,
    encryptionService,
    decryptionService,
    vaultService,
    outputHandler,
    settingsManager,
    metadataWriter,
  };
}

describe('Command Module', () => {
  let deps: CommandDeps;

  beforeEach(() => {
    vi.clearAllMocks();
    slashCommands.clear();
    contextMenuItems.clear();
    (logseq as any).settings = {};
    deps = createMockDeps();
  });

  // Lazy import to allow mocks to be set up first
  async function register() {
    const { registerCommands } = await import('./commands');
    registerCommands(deps);
  }

  // --- Registration tests (Req 8.1, 8.2, 8.3) ---

  describe('slash command registration', () => {
    it('registers encrypt, decrypt, and vault slash commands', async () => {
      await register();
      expect(logseq.Editor.registerSlashCommand).toHaveBeenCalledWith('🔒 Encrypt Block', expect.any(Function));
      expect(logseq.Editor.registerSlashCommand).toHaveBeenCalledWith('🔓 Decrypt Block', expect.any(Function));
      expect(logseq.Editor.registerSlashCommand).toHaveBeenCalledWith('🔒 Encrypt to Vault', expect.any(Function));
    });
  });

  describe('context menu item registration', () => {
    it('registers Encrypt Block, Decrypt Block, and Encrypt to Vault context menu items', async () => {
      await register();
      expect(logseq.Editor.registerBlockContextMenuItem).toHaveBeenCalledWith('Encrypt Block', expect.any(Function));
      expect(logseq.Editor.registerBlockContextMenuItem).toHaveBeenCalledWith('Decrypt Block', expect.any(Function));
      expect(logseq.Editor.registerBlockContextMenuItem).toHaveBeenCalledWith('Encrypt to Vault', expect.any(Function));
    });
  });

  // --- Encrypt flow tests (Req 8.4, 11.1, 11.4, 14.2) ---

  describe('encrypt flow', () => {
    it('triggers recipient dialog when public keys exist', async () => {
      const pubKey = makePublicKey();
      vi.mocked(deps.keyStore.getPublicKeys).mockResolvedValue([pubKey]);
      vi.mocked(showRecipientDialog).mockResolvedValue({ recipients: [pubKey.fingerprint], outputMode: 'replace' });
      vi.mocked(logseq.Editor.getBlock).mockResolvedValue({ uuid: 'block-1', content: 'Hello secret' } as any);

      await register();
      const handler = slashCommands.get('🔒 Encrypt Block')!;
      await handler({ uuid: 'block-1' });

      expect(showRecipientDialog).toHaveBeenCalledWith([pubKey], 'replace');
    });

    it('calls MetadataWriter when metadataEnabled is true', async () => {
      const pubKey = makePublicKey('FP1', 'Alice');
      vi.mocked(deps.keyStore.getPublicKeys).mockResolvedValue([pubKey]);
      vi.mocked(deps.keyStore.getKey).mockResolvedValue(pubKey);
      vi.mocked(showRecipientDialog).mockResolvedValue({ recipients: ['FP1'], outputMode: 'replace' });
      vi.mocked(logseq.Editor.getBlock).mockResolvedValue({ uuid: 'block-1', content: 'Secret data' } as any);
      vi.mocked(deps.settingsManager.getSettings).mockReturnValue(defaultSettings({ metadataEnabled: true, metadataMode: 'attributes' }));

      await register();
      const handler = slashCommands.get('🔒 Encrypt Block')!;
      await handler({ uuid: 'block-1' });

      expect(deps.metadataWriter.writeMetadata).toHaveBeenCalledWith(
        'result-block-uuid',
        expect.objectContaining({
          recipientFingerprints: ['FP1'],
          recipientCount: 1,
        }),
        'attributes',
      );
    });

    it('skips MetadataWriter when metadataEnabled is false', async () => {
      const pubKey = makePublicKey();
      vi.mocked(deps.keyStore.getPublicKeys).mockResolvedValue([pubKey]);
      vi.mocked(showRecipientDialog).mockResolvedValue({ recipients: [pubKey.fingerprint], outputMode: 'replace' });
      vi.mocked(logseq.Editor.getBlock).mockResolvedValue({ uuid: 'block-1', content: 'Secret data' } as any);
      vi.mocked(deps.settingsManager.getSettings).mockReturnValue(defaultSettings({ metadataEnabled: false }));

      await register();
      const handler = slashCommands.get('🔒 Encrypt Block')!;
      await handler({ uuid: 'block-1' });

      expect(deps.metadataWriter.writeMetadata).not.toHaveBeenCalled();
    });

    it('shows success notification with recipient count', async () => {
      const pubKey = makePublicKey();
      vi.mocked(deps.keyStore.getPublicKeys).mockResolvedValue([pubKey]);
      vi.mocked(showRecipientDialog).mockResolvedValue({ recipients: [pubKey.fingerprint], outputMode: 'replace' });
      vi.mocked(logseq.Editor.getBlock).mockResolvedValue({ uuid: 'block-1', content: 'Hello' } as any);
      vi.mocked(deps.encryptionService.encrypt).mockResolvedValue({ armoredMessage: 'cipher', recipientCount: 1 });

      await register();
      const handler = slashCommands.get('🔒 Encrypt Block')!;
      await handler({ uuid: 'block-1' });

      expect(mockShowMsg).toHaveBeenCalledWith('Encrypted for 1 recipient(s)', 'success');
    });
  });

  // --- Decrypt flow tests (Req 8.5, 11.2) ---

  describe('decrypt flow', () => {
    const armoredBlock = '-----BEGIN PGP MESSAGE-----\ndata\n-----END PGP MESSAGE-----';

    it('uses default key when set', async () => {
      const privKey = makePrivateKey('DEFAULT_FP');
      vi.mocked(deps.keyStore.getPrivateKeys).mockResolvedValue([privKey]);
      vi.mocked(deps.settingsManager.getSettingsWithAutoDefault).mockResolvedValue(
        defaultSettings({ defaultKeyFingerprint: 'DEFAULT_FP' }),
      );
      vi.mocked(logseq.Editor.getBlock).mockResolvedValue({ uuid: 'block-2', content: armoredBlock } as any);

      await register();
      const handler = slashCommands.get('🔓 Decrypt Block')!;
      await handler({ uuid: 'block-2' });

      expect(deps.decryptionService.decrypt).toHaveBeenCalledWith(
        armoredBlock,
        'DEFAULT_FP',
        expect.any(Function),
      );
      expect(showKeySelectionDialog).not.toHaveBeenCalled();
    });

    it('prompts key selection when no default and multiple keys', async () => {
      const key1 = makePrivateKey('KEY1', 'Alice');
      const key2 = makePrivateKey('KEY2', 'Bob');
      vi.mocked(deps.keyStore.getPrivateKeys).mockResolvedValue([key1, key2]);
      vi.mocked(deps.settingsManager.getSettingsWithAutoDefault).mockResolvedValue(
        defaultSettings({ defaultKeyFingerprint: null }),
      );
      vi.mocked(showKeySelectionDialog).mockResolvedValue('KEY2');
      vi.mocked(logseq.Editor.getBlock).mockResolvedValue({ uuid: 'block-2', content: armoredBlock } as any);

      await register();
      const handler = slashCommands.get('🔓 Decrypt Block')!;
      await handler({ uuid: 'block-2' });

      expect(showKeySelectionDialog).toHaveBeenCalledWith([key1, key2]);
      expect(deps.decryptionService.decrypt).toHaveBeenCalledWith(
        armoredBlock,
        'KEY2',
        expect.any(Function),
      );
    });

    it('shows success notification after decryption', async () => {
      const privKey = makePrivateKey('FP');
      vi.mocked(deps.keyStore.getPrivateKeys).mockResolvedValue([privKey]);
      vi.mocked(deps.settingsManager.getSettingsWithAutoDefault).mockResolvedValue(
        defaultSettings({ defaultKeyFingerprint: 'FP' }),
      );
      vi.mocked(logseq.Editor.getBlock).mockResolvedValue({ uuid: 'block-2', content: armoredBlock } as any);

      await register();
      const handler = slashCommands.get('🔓 Decrypt Block')!;
      await handler({ uuid: 'block-2' });

      expect(mockShowMsg).toHaveBeenCalledWith('Decryption successful', 'success');
    });
  });

  // --- Error / edge case tests (Req 11.4, 11.5) ---

  describe('error notifications', () => {
    it('shows warning when block is empty on encrypt', async () => {
      vi.mocked(logseq.Editor.getBlock).mockResolvedValue({ uuid: 'block-3', content: '' } as any);

      await register();
      const handler = slashCommands.get('🔒 Encrypt Block')!;
      await handler({ uuid: 'block-3' });

      expect(mockShowMsg).toHaveBeenCalledWith('No block content to encrypt', 'warning');
      expect(deps.encryptionService.encrypt).not.toHaveBeenCalled();
    });

    it('shows warning when no public keys exist on encrypt', async () => {
      vi.mocked(logseq.Editor.getBlock).mockResolvedValue({ uuid: 'block-4', content: 'Some text' } as any);
      vi.mocked(deps.keyStore.getPublicKeys).mockResolvedValue([]);

      await register();
      const handler = slashCommands.get('🔒 Encrypt Block')!;
      await handler({ uuid: 'block-4' });

      expect(mockShowMsg).toHaveBeenCalledWith(expect.stringContaining('Import a public key'), 'warning');
    });

    it('shows warning when no private keys exist on decrypt', async () => {
      const armoredBlock = '-----BEGIN PGP MESSAGE-----\ndata\n-----END PGP MESSAGE-----';
      vi.mocked(logseq.Editor.getBlock).mockResolvedValue({ uuid: 'block-5', content: armoredBlock } as any);
      vi.mocked(deps.keyStore.getPrivateKeys).mockResolvedValue([]);

      await register();
      const handler = slashCommands.get('🔓 Decrypt Block')!;
      await handler({ uuid: 'block-5' });

      expect(mockShowMsg).toHaveBeenCalledWith(expect.stringContaining('Import a private key'), 'warning');
    });

    it('shows warning when block does not contain encrypted content on decrypt', async () => {
      vi.mocked(logseq.Editor.getBlock).mockResolvedValue({ uuid: 'block-6', content: 'Just plain text' } as any);

      await register();
      const handler = slashCommands.get('🔓 Decrypt Block')!;
      await handler({ uuid: 'block-6' });

      expect(mockShowMsg).toHaveBeenCalledWith('Block does not contain encrypted content', 'warning');
    });
  });

  // --- Vault flow success notification ---

  describe('vault flow', () => {
    it('shows success notification after vault encryption', async () => {
      const pubKey = makePublicKey();
      vi.mocked(deps.keyStore.getPublicKeys).mockResolvedValue([pubKey]);
      vi.mocked(showRecipientDialog).mockResolvedValue({ recipients: [pubKey.fingerprint], outputMode: 'replace' });
      vi.mocked(logseq.Editor.getBlock).mockResolvedValue({ uuid: 'block-7', content: 'Vault me' } as any);

      await register();
      const handler = slashCommands.get('🔒 Encrypt to Vault')!;
      await handler({ uuid: 'block-7' });

      expect(mockShowMsg).toHaveBeenCalledWith('Encrypted to Vault-abcd1234', 'success');
    });
  });
});
