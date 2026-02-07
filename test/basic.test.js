/**
 * Basic tests for subconverter
 */

import { test } from 'node:test';
import assert from 'node:assert';
import { parse, subconvert } from '../src/index.js';
import { parseShadowsocks } from '../src/parsers/shadowsocks.js';
import { parseShadowsocksR } from '../src/parsers/shadowsocksr.js';
import { parseVMess } from '../src/parsers/vmess.js';
import { parseTrojan } from '../src/parsers/trojan.js';

test('parseShadowsocks - SIP002 format', () => {
  const link = 'ss://YWVzLTI1Ni1nY206dGVzdA==@192.168.1.1:8388#Test';
  const proxy = parseShadowsocks(link);
  
  assert.strictEqual(proxy.type, 'ss');
  assert.strictEqual(proxy.server, '192.168.1.1');
  assert.strictEqual(proxy.port, 8388);
  assert.strictEqual(proxy.cipher, 'aes-256-gcm');
  assert.strictEqual(proxy.password, 'test');
  assert.strictEqual(proxy.name, 'Test');
});

test('parseShadowsocksR', () => {
  const link = 'ssr://MTkyLjE2OC4xLjE6ODM4ODphdXRoX2FlczEyOF9tZDU6YWVzLTI1Ni1jZmI6dGxzMS4yX3RpY2tldF9hdXRoOmRHVnpkQS8_cmVtYXJrcz1WR1Z6ZEE';
  const proxy = parseShadowsocksR(link);
  
  assert.strictEqual(proxy.type, 'ssr');
  assert.strictEqual(proxy.server, '192.168.1.1');
  assert.strictEqual(proxy.port, 8388);
  assert.strictEqual(proxy.name, 'Test');
});

test('parseVMess', () => {
  const config = {
    v: '2',
    ps: 'VMess Test',
    add: '192.168.1.1',
    port: '443',
    id: 'b8be1234-5678-90ab-cdef-1234567890ab',
    aid: '0',
    net: 'ws',
    type: 'none',
    host: 'example.com',
    path: '/path',
    tls: 'tls'
  };
  
  const link = `vmess://${Buffer.from(JSON.stringify(config)).toString('base64')}`;
  const proxy = parseVMess(link);
  
  assert.strictEqual(proxy.type, 'vmess');
  assert.strictEqual(proxy.server, '192.168.1.1');
  assert.strictEqual(proxy.port, 443);
  assert.strictEqual(proxy.uuid, 'b8be1234-5678-90ab-cdef-1234567890ab');
  assert.strictEqual(proxy.network, 'ws');
  assert.strictEqual(proxy.tls, true);
});

test('parseTrojan', () => {
  const link = 'trojan://password123@192.168.1.1:443?sni=example.com#TrojanTest';
  const proxy = parseTrojan(link);
  
  assert.strictEqual(proxy.type, 'trojan');
  assert.strictEqual(proxy.server, '192.168.1.1');
  assert.strictEqual(proxy.port, 443);
  assert.strictEqual(proxy.password, 'password123');
  assert.strictEqual(proxy.sni, 'example.com');
  assert.strictEqual(proxy.name, 'TrojanTest');
});

test('parse subscription with multiple proxies', () => {
  const subscription = `ss://YWVzLTI1Ni1nY206dGVzdA==@192.168.1.1:8388#Test1
trojan://password@192.168.1.2:443#Test2`;
  
  const proxies = parse(subscription);
  
  assert.strictEqual(proxies.length, 2);
  assert.strictEqual(proxies[0].type, 'ss');
  assert.strictEqual(proxies[1].type, 'trojan');
});

test('subconvert to mixed format', () => {
  const subscription = 'ss://YWVzLTI1Ni1nY206dGVzdA==@192.168.1.1:8388#Test';
  const result = subconvert(subscription, 'mixed');
  
  assert.ok(result.includes('ss://'));
  assert.ok(result.includes('Test'));
});

test('subconvert to clash format', () => {
  const subscription = 'ss://YWVzLTI1Ni1nY206dGVzdA==@192.168.1.1:8388#Test';
  const result = subconvert(subscription, 'clash');
  
  assert.ok(result.includes('proxies:'));
  assert.ok(result.includes('proxy-groups:'));
});

test('subconvert to v2ray format', () => {
  const subscription = 'ss://YWVzLTI1Ni1nY206dGVzdA==@192.168.1.1:8388#Test';
  const result = subconvert(subscription, 'v2ray');
  
  const config = JSON.parse(result);
  assert.ok(config.inbounds);
  assert.ok(config.outbounds);
  assert.ok(config.routing);
});

test('subconvert with invalid input throws error', () => {
  assert.throws(() => {
    subconvert('', 'clash');
  }, /Invalid subscription string/);
});

test('subconvert with invalid target throws error', () => {
  const subscription = 'ss://YWVzLTI1Ni1nY206dGVzdA==@192.168.1.1:8388#Test';
  
  assert.throws(() => {
    subconvert(subscription, 'invalid');
  }, /Unsupported target format/);
});
