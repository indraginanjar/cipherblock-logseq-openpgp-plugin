// CipherBlock – Property-based tests for Command Module
// Test framework: Vitest with fast-check
// Source: src/commands.ts

// Feature: logseq-cipherblock, Property 7: Default key selection logic
// Validates: Requirements 2.3, 2.4

import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as fc from 'fast-check';
import type { CommandDeps } from './commands';
import type {
  IKeyStore,
  IEncryptionService,
  IDecryptionService,
  IVaultService,
  IOutputHandler,
  IMetadataWriter,
} from './interfaces';
import type { StoredKey, PluginSettings, OutputMode, MetadataMode } from './types';
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

import { showKeySelectionDialog } from './ui';

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

// --- Arbitraries ---

const fingerprintArb = fc.hexaString({ minLength: 16, maxLength: 40 }).map((s) => s.toUpperCase());

const userIdArb = fc
  .tuple(fc.string({ minLength: 1, maxLength: 20 }), fc.emailAddress())
  .map(([name, email]) => `${name} <${email}>`);

const privateKeyArb = fc.tuple(fingerprintArb, userIdArb).map(
  ([fingerprint, userID]): StoredKey => ({
    fingerprint,
    userID,
    type: 'private',
    creationDate: new Date(),
    armoredKey: `-----BEGIN PGP PRIVATE KEY BLOCK-----\nfake-${fingerprint}\n-----END PGP PRIVATE KEY BLOCK-----`,
  }),
);

// --- Helpers ---

const ARMORED_BLOCK = '-----BEGIN PGP MESSAGE-----\ndata\n-----END PGP MESSAGE-----';

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
    encrypt: vi.fn().mockResolvedValue({ armoredMessage: 'cipher', recipientCount: 1 }),
  };

  const decryptionService: IDecryptionService = {
    decrypt: vi.fn().mockResolvedValue({ plaintext: 'decrypted text' }),
  };

  const vaultService: IVaultService = {
    encryptToVault: vi.fn().mockResolvedValue({ vaultPageName: 'Vault-abc', vaultLink: '[[Vault-abc]]' }),
  };

  const outputHandler: IOutputHandler = {
    placeResult: vi.fn().mockResolvedValue('result-uuid'),
  };

  const metadataWriter: IMetadataWriter = {
    writeMetadata: vi.fn().mockResolvedValue(undefined),
  };

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

// --- Property Tests ---

describe('Command Module Property Tests', () => {
  let deps: CommandDeps;

  beforeEach(() => {
    vi.clearAllMocks();
    slashCommands.clear();
    contextMenuItems.clear();
    (logseq as any).settings = {};
    deps = createMockDeps();
  });

  async function register() {
    const { registerCommands } = await import('./commands');
    registerCommands(deps);
  }

  // Feature: logseq-cipherblock, Property 7: Default key selection logic
  // Validates: Requirements 2.3, 2.4
  describe('Property 7: Default key selection logic', () => {
    it('when a default key is configured, it is used directly without prompting for key selection', async () => {
      await fc.assert(
        fc.asyncProperty(privateKeyArb, async (privateKey) => {
          // Reset mocks for each iteration
          vi.clearAllMocks();
          slashCommands.clear();
          contextMenuItems.clear();
          deps = createMockDeps();

          // Configure: one private key available, default key is set
          vi.mocked(deps.keyStore.getPrivateKeys).mockResolvedValue([privateKey]);
          vi.mocked(deps.settingsManager.getSettingsWithAutoDefault).mockResolvedValue(
            defaultSettings({ defaultKeyFingerprint: privateKey.fingerprint }),
          );
          vi.mocked(logseq.Editor.getBlock).mockResolvedValue({
            uuid: 'block-1',
            content: ARMORED_BLOCK,
          } as any);

          await register();
          const handler = slashCommands.get('🔓 Decrypt Block')!;
          await handler({ uuid: 'block-1' });

          // Default key should be used — no key selection dialog shown
          expect(showKeySelectionDialog).not.toHaveBeenCalled();
          expect(deps.decryptionService.decrypt).toHaveBeenCalledWith(
            ARMORED_BLOCK,
            privateKey.fingerprint,
            expect.any(Function),
          );
        }),
        { numRuns: 100 },
      );
    });

    it('when multiple keys exist with no default, key selection dialog is prompted', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.array(privateKeyArb, { minLength: 2, maxLength: 5 }),
          async (privateKeys) => {
            // Ensure unique fingerprints
            const seen = new Set<string>();
            const uniqueKeys = privateKeys.filter((k) => {
              if (seen.has(k.fingerprint)) return false;
              seen.add(k.fingerprint);
              return true;
            });
            if (uniqueKeys.length < 2) return; // skip if dedup reduced below 2

            // Reset mocks for each iteration
            vi.clearAllMocks();
            slashCommands.clear();
            contextMenuItems.clear();
            deps = createMockDeps();

            const selectedKey = uniqueKeys[0];

            // Configure: multiple private keys, no default
            vi.mocked(deps.keyStore.getPrivateKeys).mockResolvedValue(uniqueKeys);
            vi.mocked(deps.settingsManager.getSettingsWithAutoDefault).mockResolvedValue(
              defaultSettings({ defaultKeyFingerprint: null }),
            );
            vi.mocked(showKeySelectionDialog).mockResolvedValue(selectedKey.fingerprint);
            vi.mocked(logseq.Editor.getBlock).mockResolvedValue({
              uuid: 'block-1',
              content: ARMORED_BLOCK,
            } as any);

            await register();
            const handler = slashCommands.get('🔓 Decrypt Block')!;
            await handler({ uuid: 'block-1' });

            // Key selection dialog should have been shown with all private keys
            expect(showKeySelectionDialog).toHaveBeenCalledWith(uniqueKeys);
            // The user-selected key should be passed to decrypt
            expect(deps.decryptionService.decrypt).toHaveBeenCalledWith(
              ARMORED_BLOCK,
              selectedKey.fingerprint,
              expect.any(Function),
            );
          },
        ),
        { numRuns: 100 },
      );
    });
  });
});
