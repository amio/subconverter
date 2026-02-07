/**
 * Cloudflare Worker tests
 */

import { test } from 'node:test';
import assert from 'node:assert';
import worker from '../worker/index.js';

const subscription = 'ss://YWVzLTI1Ni1nY206dGVzdA==@192.168.1.1:8388#WorkerTest';

test('worker applies custom config to clash output', async () => {
  const subscriptionUrl = 'https://example.com/subscription';
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input) => {
    if (input === subscriptionUrl) {
      return new Response(subscription);
    }
    throw new Error(`Unexpected fetch: ${input}`);
  };

  try {
    const request = new Request(
      `https://worker.example.com/?url=${encodeURIComponent(subscriptionUrl)}&target=clash`
    );
    const response = await worker.fetch(request);
    const text = await response.text();

    assert.strictEqual(response.status, 200);
    assert.ok(text.includes('allow-lan: true'));
    assert.ok(text.includes('port: 7890'));
  } finally {
    globalThis.fetch = originalFetch;
  }
});
