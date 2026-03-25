// CipherBlock – Unit tests for Main Entry / Bootstrap
// Requirements: 9.1, 9.4

import { describe, it, expect, vi, beforeEach } from 'vitest';

// --- Mock all imported modules to isolate bootstrap logic ---

vi.mock('./openpgp-adapter', () => ({
  OpenPGPAdapter: vi.fn().mockImplementation(() => ({})),
}));

vi.mock('./storage-adapter', () => ({
  StorageAdapter: vi.fn().mockImplementation(() => ({})),
}));

vi.mock('./key-store', () => ({
  KeyStore: vi.fn().mockImplementation(() => ({})),
}));

vi.mock('./settings-manager', () => ({
  SettingsManager: vi.fn().mockImplementation(() => ({
    registerSchema: vi.fn(),
  })),
}));

vi.mock('./encryption-service', () => ({
  EncryptionService: vi.fn().mockImplementation(() => ({})),
}));

vi.mock('./decryption-service', () => ({
  DecryptionService: vi.fn().mockImplementation(() => ({})),
}));

vi.mock('./output-handler', () => ({
  OutputHandler: vi.fn().mockImplementation(() => ({})),
}));

vi.mock('./metadata-writer', () => ({
  MetadataWriter: vi.fn().mockImplementation(() => ({})),
}));

vi.mock('./vault-service', () => ({
  VaultService: vi.fn().mockImplementation(() => ({})),
}));

vi.mock('./commands', () => ({
  registerCommands: vi.fn(),
}));



// --- Logseq global mock ---

let readyCallback: Function | null = null;

beforeEach(() => {
  vi.clearAllMocks();
  readyCallback = null;

  (globalThis as any).logseq = {
    ready: vi.fn((cb: Function) => {
      readyCallback = cb;
      return Promise.resolve(cb()).catch(() => {});
    }),
    useSettingsSchema: vi.fn(),
    settings: {},
    onSettingsChanged: vi.fn(),
    Editor: {
      registerSlashCommand: vi.fn(),
      registerBlockContextMenuItem: vi.fn(),
    },
    UI: {
      showMsg: vi.fn().mockResolvedValue(undefined),
    },
  };
});

describe('Main Entry / Bootstrap', () => {
  async function loadMain() {
    // Dynamic import so mocks are in place before module executes
    // Reset module registry to re-execute top-level code
    vi.resetModules();

    // Re-apply mocks after resetModules
    vi.doMock('./openpgp-adapter', () => ({
      OpenPGPAdapter: vi.fn().mockImplementation(() => ({})),
    }));
    vi.doMock('./storage-adapter', () => ({
      StorageAdapter: vi.fn().mockImplementation(() => ({})),
    }));
    vi.doMock('./key-store', () => ({
      KeyStore: vi.fn().mockImplementation(() => ({})),
    }));
    vi.doMock('./settings-manager', () => ({
      SettingsManager: vi.fn().mockImplementation(() => ({
        registerSchema: vi.fn(),
      })),
    }));
    vi.doMock('./encryption-service', () => ({
      EncryptionService: vi.fn().mockImplementation(() => ({})),
    }));
    vi.doMock('./decryption-service', () => ({
      DecryptionService: vi.fn().mockImplementation(() => ({})),
    }));
    vi.doMock('./output-handler', () => ({
      OutputHandler: vi.fn().mockImplementation(() => ({})),
    }));
    vi.doMock('./metadata-writer', () => ({
      MetadataWriter: vi.fn().mockImplementation(() => ({})),
    }));
    vi.doMock('./vault-service', () => ({
      VaultService: vi.fn().mockImplementation(() => ({})),
    }));
    vi.doMock('./commands', () => ({
      registerCommands: vi.fn(),
    }));

    await import('./main');

    // Re-import mocked modules to get the same references
    const { SettingsManager: SM } = await import('./settings-manager');
    const { registerCommands: RC } = await import('./commands');
    const { KeyStore: KS } = await import('./key-store');
    const { OpenPGPAdapter: OA } = await import('./openpgp-adapter');
    const { StorageAdapter: SA } = await import('./storage-adapter');
    const { EncryptionService: ES } = await import('./encryption-service');
    const { DecryptionService: DS } = await import('./decryption-service');
    const { OutputHandler: OH } = await import('./output-handler');
    const { MetadataWriter: MW } = await import('./metadata-writer');
    const { VaultService: VS } = await import('./vault-service');

    return {
      SettingsManager: SM,
      registerCommands: RC,
      KeyStore: KS,
      OpenPGPAdapter: OA,
      StorageAdapter: SA,
      EncryptionService: ES,
      DecryptionService: DS,
      OutputHandler: OH,
      MetadataWriter: MW,
      VaultService: VS,
    };
  }

  // Validates: Requirement 9.1
  it('calls logseq.ready to bootstrap the plugin', async () => {
    await loadMain();
    expect(logseq.ready).toHaveBeenCalledWith(expect.any(Function));
  });

  // Validates: Requirement 9.1
  it('registers the settings schema during bootstrap', async () => {
    const mocks = await loadMain();
    // SettingsManager was constructed and registerSchema was called
    expect(mocks.SettingsManager).toHaveBeenCalled();
    const instance = vi.mocked(mocks.SettingsManager).mock.results[0]?.value;
    expect(instance.registerSchema).toHaveBeenCalled();
  });

  // Validates: Requirement 9.4
  it('calls registerCommands with all required dependencies', async () => {
    const mocks = await loadMain();
    expect(mocks.registerCommands).toHaveBeenCalledTimes(1);
    expect(mocks.registerCommands).toHaveBeenCalledWith(
      expect.objectContaining({
        keyStore: expect.any(Object),
        encryptionService: expect.any(Object),
        decryptionService: expect.any(Object),
        vaultService: expect.any(Object),
        outputHandler: expect.any(Object),
        settingsManager: expect.any(Object),
        metadataWriter: expect.any(Object),
      }),
    );
  });

  // Validates: Requirement 9.1
  it('instantiates all core modules during bootstrap', async () => {
    const mocks = await loadMain();
    expect(mocks.OpenPGPAdapter).toHaveBeenCalledTimes(1);
    expect(mocks.StorageAdapter).toHaveBeenCalledTimes(1);
    expect(mocks.KeyStore).toHaveBeenCalledTimes(1);
    expect(mocks.SettingsManager).toHaveBeenCalledTimes(1);
    expect(mocks.EncryptionService).toHaveBeenCalledTimes(1);
    expect(mocks.DecryptionService).toHaveBeenCalledTimes(1);
    expect(mocks.OutputHandler).toHaveBeenCalledTimes(1);
    expect(mocks.MetadataWriter).toHaveBeenCalledTimes(1);
    expect(mocks.VaultService).toHaveBeenCalledTimes(1);
  });

  // Validates: Requirement 9.1 - dependency injection wiring
  it('wires KeyStore with OpenPGPAdapter and StorageAdapter', async () => {
    const mocks = await loadMain();
    const ksCall = vi.mocked(mocks.KeyStore).mock.calls[0];
    // KeyStore receives pgpAdapter and storageAdapter as constructor args
    expect(ksCall).toHaveLength(2);
  });

  // Validates: Requirement 9.1 - settings schema registered before commands
  it('registers settings schema before registering commands', async () => {
    const callOrder: string[] = [];

    vi.resetModules();

    vi.doMock('./openpgp-adapter', () => ({
      OpenPGPAdapter: vi.fn().mockImplementation(() => ({})),
    }));
    vi.doMock('./storage-adapter', () => ({
      StorageAdapter: vi.fn().mockImplementation(() => ({})),
    }));
    vi.doMock('./key-store', () => ({
      KeyStore: vi.fn().mockImplementation(() => ({})),
    }));
    vi.doMock('./settings-manager', () => ({
      SettingsManager: vi.fn().mockImplementation(() => ({
        registerSchema: vi.fn(() => {
          callOrder.push('registerSchema');
        }),
      })),
    }));
    vi.doMock('./encryption-service', () => ({
      EncryptionService: vi.fn().mockImplementation(() => ({})),
    }));
    vi.doMock('./decryption-service', () => ({
      DecryptionService: vi.fn().mockImplementation(() => ({})),
    }));
    vi.doMock('./output-handler', () => ({
      OutputHandler: vi.fn().mockImplementation(() => ({})),
    }));
    vi.doMock('./metadata-writer', () => ({
      MetadataWriter: vi.fn().mockImplementation(() => ({})),
    }));
    vi.doMock('./vault-service', () => ({
      VaultService: vi.fn().mockImplementation(() => ({})),
    }));
    vi.doMock('./commands', () => ({
      registerCommands: vi.fn(() => {
        callOrder.push('registerCommands');
      }),
    }));

    await import('./main');

    expect(callOrder).toEqual(['registerSchema', 'registerCommands']);
  });
});
