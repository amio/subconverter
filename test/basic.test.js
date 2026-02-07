/**
 * Basic tests for subconverter
 */

import { test } from 'node:test';
import assert from 'node:assert';
import { mergeAndConvert, parse, parseMixedSubscription, subconvert } from '../src/index.js';
import { parseShadowsocks } from '../src/parsers/shadowsocks.js';
import { parseShadowsocksR } from '../src/parsers/shadowsocksr.js';
import { parseVMess } from '../src/parsers/vmess.js';
import { parseTrojan } from '../src/parsers/trojan.js';

const targetSsLink = 'ss://YWVzLTI1Ni1nY206dGVzdA==@10.0.0.1:8388#TargetSS';
const targetSsrLink = 'ssr://MTkyLjE2OC4xLjE6ODM4ODphdXRoX2FlczEyOF9tZDU6YWVzLTI1Ni1jZmI6dGxzMS4yX3RpY2tldF9hdXRoOmRHVnpkQS8_cmVtYXJrcz1WR0Z5WjJWMFUxTlM';
const targetVmessConfig = {
  v: '2',
  ps: 'TargetVMess',
  add: '10.0.0.3',
  port: '8443',
  id: 'b8be1234-5678-90ab-cdef-1234567890ab',
  aid: '0',
  net: 'ws',
  type: 'none',
  host: 'vmess.example.com',
  path: '/ws',
  tls: 'tls'
};
const targetVmessLink = `vmess://${Buffer.from(JSON.stringify(targetVmessConfig)).toString('base64')}`;
const targetTrojanLink = 'trojan://password123@10.0.0.4:443?sni=example.com#TargetTrojan';
const targetSubscription = [
  targetSsLink,
  targetSsrLink,
  targetVmessLink,
  targetTrojanLink
].join('\n');

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
  const proxy = parseShadowsocksR(targetSsrLink);
  
  assert.strictEqual(proxy.type, 'ssr');
  assert.strictEqual(proxy.server, '192.168.1.1');
  assert.strictEqual(proxy.port, 8388);
  assert.strictEqual(proxy.name, 'TargetSSR');
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

test('parse base64 subscription with comments', () => {
  const rawSubscription = `# comment
ss://YWVzLTI1Ni1nY206dGVzdA==@192.168.1.1:8388#Test1

trojan://password@192.168.1.2:443#Test2`;
  const encoded = Buffer.from(rawSubscription, 'utf-8').toString('base64');
  const proxies = parse(encoded);
  
  assert.strictEqual(proxies.length, 2);
  assert.strictEqual(proxies[0].name, 'Test1');
  assert.strictEqual(proxies[1].name, 'Test2');
});

test('parse mixed subscription with base64 segments', () => {
  const first = 'ss://YWVzLTI1Ni1nY206dGVzdA==@192.168.1.1:8388#Mixed1';
  const second = Buffer.from('trojan://password@192.168.1.2:443#Mixed2', 'utf-8').toString('base64');
  const proxies = parseMixedSubscription(`${first}|${second}`);
  
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

test('subconvert to clashr format', () => {
  const result = subconvert(targetSubscription, 'clashr', { outputJson: true });
  const config = JSON.parse(result);
  
  assert.strictEqual(config.proxies.length, 4);
  assert.ok(config['proxy-groups'].some(group => group.proxies.includes('TargetSS')));
});

test('subconvert to surge format', () => {
  const result = subconvert(targetSubscription, 'surge');
  
  assert.ok(result.includes('[Proxy]'));
  assert.ok(result.includes('TargetSS = ss,'));
  assert.ok(result.includes('TargetVMess = custom,'));
  assert.ok(result.includes('TargetTrojan = trojan,'));
});

test('subconvert to quanx format', () => {
  const result = subconvert(targetSubscription, 'quanx');
  
  assert.ok(result.includes('[server_local]'));
  assert.ok(result.includes('tag=TargetSS'));
  assert.ok(result.includes('tag=TargetVMess'));
  assert.ok(result.includes('tag=TargetTrojan'));
});

test('subconvert to singbox format', () => {
  const result = subconvert(targetSubscription, 'singbox');
  const config = JSON.parse(result);
  const tags = config.outbounds.map(outbound => outbound.tag);
  
  assert.ok(tags.includes('TargetSS'));
  assert.ok(tags.includes('TargetVMess'));
  assert.ok(tags.includes('TargetTrojan'));
});

test('subconvert to ss format', () => {
  const result = subconvert(targetSubscription, 'ss');
  const proxy = parseShadowsocks(result.trim());
  
  assert.strictEqual(proxy.name, 'TargetSS');
  assert.strictEqual(proxy.server, '10.0.0.1');
});

test('subconvert to ssr format', () => {
  const result = subconvert(targetSubscription, 'ssr');
  const proxy = parseShadowsocksR(result.trim());
  
  assert.strictEqual(proxy.name, 'TargetSSR');
  assert.strictEqual(proxy.protocol, 'auth_aes128_md5');
});

test('subconvert to vmess format', () => {
  const result = subconvert(targetSubscription, 'vmess');
  const proxy = parseVMess(result.trim());
  
  assert.strictEqual(proxy.name, 'TargetVMess');
  assert.strictEqual(proxy.network, 'ws');
});

test('subconvert to trojan format', () => {
  const result = subconvert(targetSubscription, 'trojan');
  const proxy = parseTrojan(result.trim());
  
  assert.strictEqual(proxy.name, 'TargetTrojan');
  assert.strictEqual(proxy.sni, 'example.com');
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

test('mergeAndConvert returns json with combined proxies', () => {
  const sub1 = 'ss://YWVzLTI1Ni1nY206dGVzdA==@192.168.1.1:8388#Merge1';
  const sub2 = 'ss://YWVzLTI1Ni1nY206dGVzdA==@192.168.1.2:8389#Merge2';
  const result = mergeAndConvert([sub1, sub2], 'clash', { outputJson: true });
  const config = JSON.parse(result);
  
  assert.strictEqual(config.proxies.length, 2);
  assert.ok(config.proxies.some(proxy => proxy.name === 'Merge1'));
  assert.ok(config.proxies.some(proxy => proxy.name === 'Merge2'));
});
