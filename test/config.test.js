/**
 * Tests for config loading
 */

import { test } from 'node:test';
import assert from 'node:assert';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { loadConfig } from '../src/utils/config.js';

test('loadConfig supports YAML files', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'subconverter-config-'));
  const configPath = path.join(tempDir, 'pref.yml');
  const yamlContent = [
    'excludeRemarks:',
    '  - 过期',
    'appendProxyType: true',
    'clashOptions:',
    '  port: 7890',
    ''
  ].join('\n');

  try {
    fs.writeFileSync(configPath, yamlContent, 'utf-8');
    const config = loadConfig(configPath);

    assert.deepStrictEqual(config.excludeRemarks, ['过期']);
    assert.strictEqual(config.appendProxyType, true);
    assert.strictEqual(config.clashOptions.port, 7890);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('loadConfig supports JSON files', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'subconverter-config-'));
  const configPath = path.join(tempDir, 'pref.json');
  const jsonContent = JSON.stringify({
    includeRemarks: ['香港'],
    appendProxyType: false,
    surgeOptions: { version: 4 }
  }, null, 2);

  try {
    fs.writeFileSync(configPath, jsonContent, 'utf-8');
    const config = loadConfig(configPath);

    assert.deepStrictEqual(config.includeRemarks, ['香港']);
    assert.strictEqual(config.appendProxyType, false);
    assert.strictEqual(config.surgeOptions.version, 4);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('loadConfig throws on invalid YAML', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'subconverter-config-'));
  const configPath = path.join(tempDir, 'pref.yml');
  const yamlContent = [
    'rules: [',
    '  - MATCH',
    '  - [',
    ''
  ].join('\n');

  try {
    fs.writeFileSync(configPath, yamlContent, 'utf-8');
    assert.throws(() => loadConfig(configPath), /Failed to parse YAML config/);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});
