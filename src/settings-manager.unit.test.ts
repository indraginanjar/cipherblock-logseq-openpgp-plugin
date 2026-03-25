// CipherBlock – Unit tests for Settings Module
// Test framework: Vitest
// Source: src/settings-manager.ts

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { SettingsManager, settingsSchema } from './settings-manager';
import type { IKeyStore } from './interfaces';
import type { PluginSettings } from './types';

// --- Logseq API mock setup (mirrors pattern from settings-manager.property.test.ts) ---

let mockSettings: Record<string, unknown> = {};
let settingsChangedCallbacks: Array<(newSettings: Record<string, unknown>) => void> = [];

beforeEach(() => {
  mockSettings = {};
  settingsChangedCallbacks = [];

  (globalThis as any).logseq = {
    useSettingsSchema: vi.fn(),
    get settings() {
      return mockSettings;
    },
    set settings(val: Record<string, unknown>) {
      mockSettings = val;
    },
    onSettingsChanged: vi.fn((cb: (newSettings: Record<string, unknown>) => void) => {
      settingsChangedCallbacks.push(cb);
    }),
    updateSettings: vi.fn((newSettings: Record<string, unknown>) => {
      mockSettings = { ...mockSettings, ...newSettings };
      for (const cb of settingsChangedCallbacks) {
        cb(mockSettings);
      }
    }),
  };
});

// --- Mock KeyStore factory ---

function createMockKeyStore(privateKeys: any[] = []): IKeyStore {
  return {
    importKey: vi.fn(),
    removeKey: vi.fn(),
    listKeys: vi.fn(async () => privateKeys),
    getKey: vi.fn(),
    getPublicKeys: vi.fn(async () => []),
    getPrivateKeys: vi.fn(async () => privateKeys),
  };
}

// --- Unit Tests ---

// Validates: Requirements 7.1, 7.2, 7.3, 7.4
describe('Settings schema structure', () => {
  it('contains all expected setting keys', () => {
    const keys = settingsSchema.map((s) => s.key);
    expect(keys).toContain('defaultKeyFingerprint');
    expect(keys).toContain('outputMode');
    expect(keys).toContain('passphraseCachingEnabled');
    expect(keys).toContain('metadataEnabled');
    expect(keys).toContain('metadataMode');
  });

  it('defaultKeyFingerprint is a string type', () => {
    const entry = settingsSchema.find((s) => s.key === 'defaultKeyFingerprint');
    expect(entry).toBeDefined();
    expect(entry!.type).toBe('string');
  });

  it('outputMode is an enum with four choices', () => {
    const entry = settingsSchema.find((s) => s.key === 'outputMode');
    expect(entry).toBeDefined();
    expect(entry!.type).toBe('enum');
    expect((entry as any).enumChoices).toEqual(['replace', 'sibling', 'sub-block', 'clipboard']);
  });

  it('passphraseCachingEnabled is a boolean type', () => {
    const entry = settingsSchema.find((s) => s.key === 'passphraseCachingEnabled');
    expect(entry).toBeDefined();
    expect(entry!.type).toBe('boolean');
  });

  // Validates: Requirement 14.1
  it('metadataEnabled is a boolean type', () => {
    const entry = settingsSchema.find((s) => s.key === 'metadataEnabled');
    expect(entry).toBeDefined();
    expect(entry!.type).toBe('boolean');
  });

  // Validates: Requirement 14.3
  it('metadataMode is an enum with attributes and sub-blocks choices', () => {
    const entry = settingsSchema.find((s) => s.key === 'metadataMode');
    expect(entry).toBeDefined();
    expect(entry!.type).toBe('enum');
    expect((entry as any).enumChoices).toEqual(['attributes', 'sub-blocks']);
  });
});

// Validates: Requirements 14.1, 14.3
describe('Settings default values', () => {
  it('metadataEnabled defaults to false', () => {
    const entry = settingsSchema.find((s) => s.key === 'metadataEnabled');
    expect(entry!.default).toBe(false);
  });

  it('metadataMode defaults to attributes', () => {
    const entry = settingsSchema.find((s) => s.key === 'metadataMode');
    expect(entry!.default).toBe('attributes');
  });

  it('outputMode defaults to replace', () => {
    const entry = settingsSchema.find((s) => s.key === 'outputMode');
    expect(entry!.default).toBe('replace');
  });

  it('passphraseCachingEnabled defaults to false', () => {
    const entry = settingsSchema.find((s) => s.key === 'passphraseCachingEnabled');
    expect(entry!.default).toBe(false);
  });

  it('defaultKeyFingerprint defaults to empty string', () => {
    const entry = settingsSchema.find((s) => s.key === 'defaultKeyFingerprint');
    expect(entry!.default).toBe('');
  });
});

describe('SettingsManager.registerSchema', () => {
  it('calls logseq.useSettingsSchema with the settings schema', () => {
    const keyStore = createMockKeyStore();
    const manager = new SettingsManager(keyStore);

    manager.registerSchema();

    expect((globalThis as any).logseq.useSettingsSchema).toHaveBeenCalledWith(settingsSchema);
  });
});

describe('SettingsManager.getSettings', () => {
  it('returns correct defaults when logseq.settings is empty', () => {
    mockSettings = {};
    const keyStore = createMockKeyStore();
    const manager = new SettingsManager(keyStore);

    const settings = manager.getSettings();

    expect(settings.defaultKeyFingerprint).toBeNull();
    expect(settings.outputMode).toBe('replace');
    expect(settings.passphraseCachingEnabled).toBe(false);
    expect(settings.metadataEnabled).toBe(false);
    expect(settings.metadataMode).toBe('attributes');
  });

  it('reads configured values from logseq.settings', () => {
    mockSettings = {
      defaultKeyFingerprint: 'abc123',
      outputMode: 'clipboard',
      passphraseCachingEnabled: true,
      metadataEnabled: true,
      metadataMode: 'sub-blocks',
    };
    const keyStore = createMockKeyStore();
    const manager = new SettingsManager(keyStore);

    const settings = manager.getSettings();

    expect(settings.defaultKeyFingerprint).toBe('abc123');
    expect(settings.outputMode).toBe('clipboard');
    expect(settings.passphraseCachingEnabled).toBe(true);
    expect(settings.metadataEnabled).toBe(true);
    expect(settings.metadataMode).toBe('sub-blocks');
  });

  it('treats empty defaultKeyFingerprint as null', () => {
    mockSettings = { defaultKeyFingerprint: '' };
    const keyStore = createMockKeyStore();
    const manager = new SettingsManager(keyStore);

    const settings = manager.getSettings();

    expect(settings.defaultKeyFingerprint).toBeNull();
  });
});

// Validates: Requirements 14.8
describe('SettingsManager.onSettingsChanged', () => {
  it('fires callback when settings change', () => {
    const keyStore = createMockKeyStore();
    const manager = new SettingsManager(keyStore);
    mockSettings = {
      defaultKeyFingerprint: '',
      outputMode: 'replace',
      passphraseCachingEnabled: false,
      metadataEnabled: false,
      metadataMode: 'attributes',
    };

    const received: PluginSettings[] = [];
    manager.onSettingsChanged((s) => received.push(s));

    // Simulate settings change via Logseq API
    (globalThis as any).logseq.updateSettings({
      outputMode: 'sibling',
      metadataEnabled: true,
      metadataMode: 'sub-blocks',
    });

    expect(received).toHaveLength(1);
    expect(received[0].outputMode).toBe('sibling');
    expect(received[0].metadataEnabled).toBe(true);
    expect(received[0].metadataMode).toBe('sub-blocks');
  });

  it('fires callback multiple times for multiple changes', () => {
    const keyStore = createMockKeyStore();
    const manager = new SettingsManager(keyStore);
    mockSettings = {};

    const received: PluginSettings[] = [];
    manager.onSettingsChanged((s) => received.push(s));

    (globalThis as any).logseq.updateSettings({ outputMode: 'clipboard' });
    (globalThis as any).logseq.updateSettings({ metadataEnabled: true });

    expect(received).toHaveLength(2);
  });

  it('registers callback via logseq.onSettingsChanged', () => {
    const keyStore = createMockKeyStore();
    const manager = new SettingsManager(keyStore);

    manager.onSettingsChanged(() => {});

    expect((globalThis as any).logseq.onSettingsChanged).toHaveBeenCalled();
  });
});
