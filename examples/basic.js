/**
 * Basic example of using subconverter
 */

import { subconvert, parse } from '../src/index.js';

// Example subscription content with various proxy types
const exampleSubscription = `ss://YWVzLTI1Ni1nY206dGVzdHBhc3N3b3Jk@example.com:8388#SS-Example
ssr://ZXhhbXBsZS5jb206ODM4ODphdXRoX2FlczEyOF9tZDU6YWVzLTI1Ni1jZmI6dGxzMS4yX3RpY2tldF9hdXRoOmRHVnpkSEJoYzNOM2IzSmsvP3JlbWFya3M9VTFOU0xVVjRZVzF3YkdVJnByb3RvcGFyYW09Jm9iZnNwYXJhbT0
vmess://eyJ2IjoiMiIsInBzIjoiVk1lc3MtRXhhbXBsZSIsImFkZCI6ImV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiYjhiZTEyMzQtNTY3OC05MGFiLWNkZWYtMTIzNDU2Nzg5MGFiIiwiYWlkIjoiMCIsIm5ldCI6IndzIiwidHlwZSI6Im5vbmUiLCJob3N0IjoiZXhhbXBsZS5jb20iLCJwYXRoIjoiL3BhdGgiLCJ0bHMiOiJ0bHMifQ==
trojan://password123@example.com:443?sni=example.com#Trojan-Example`;

console.log('=== Subconverter JavaScript Example ===\n');

// 1. Parse subscription to see proxy objects
console.log('1. Parsing subscription...');
const proxies = parse(exampleSubscription);
console.log(`Found ${proxies.length} proxies:`);
proxies.forEach((proxy, index) => {
  console.log(`  ${index + 1}. ${proxy.name} (${proxy.type}) - ${proxy.server}:${proxy.port}`);
});
console.log();

// 2. Convert to Clash format
console.log('2. Converting to Clash format...');
try {
  const clashConfig = subconvert(exampleSubscription, 'clash');
  console.log('Clash configuration generated:');
  console.log(clashConfig.substring(0, 500) + '...\n');
} catch (e) {
  console.error('Error:', e.message);
}

// 3. Convert to Surge format
console.log('3. Converting to Surge format...');
try {
  const surgeConfig = subconvert(exampleSubscription, 'surge');
  console.log('Surge configuration generated:');
  console.log(surgeConfig.substring(0, 500) + '...\n');
} catch (e) {
  console.error('Error:', e.message);
}

// 4. Convert to Quantumult X format
console.log('4. Converting to Quantumult X format...');
try {
  const quanxConfig = subconvert(exampleSubscription, 'quanx');
  console.log('Quantumult X configuration generated:');
  console.log(quanxConfig.substring(0, 500) + '...\n');
} catch (e) {
  console.error('Error:', e.message);
}

// 5. Convert to V2Ray format
console.log('5. Converting to V2Ray format...');
try {
  const v2rayConfig = subconvert(exampleSubscription, 'v2ray');
  console.log('V2Ray configuration generated:');
  console.log(v2rayConfig.substring(0, 500) + '...\n');
} catch (e) {
  console.error('Error:', e.message);
}

// 6. Convert to SingBox format
console.log('6. Converting to SingBox format...');
try {
  const singboxConfig = subconvert(exampleSubscription, 'singbox');
  console.log('SingBox configuration generated:');
  console.log(singboxConfig.substring(0, 500) + '...\n');
} catch (e) {
  console.error('Error:', e.message);
}

// 7. Generate raw SS links
console.log('7. Generating Shadowsocks links...');
try {
  const ssLinks = subconvert(exampleSubscription, 'ss');
  console.log('Shadowsocks links:');
  console.log(ssLinks + '\n');
} catch (e) {
  console.error('Error:', e.message);
}

// 8. Generate mixed links (all types)
console.log('8. Generating mixed format links...');
try {
  const mixedLinks = subconvert(exampleSubscription, 'mixed');
  console.log('Mixed links:');
  console.log(mixedLinks + '\n');
} catch (e) {
  console.error('Error:', e.message);
}

// 9. Custom options example
console.log('9. Converting to Clash with custom options...');
try {
  const customClash = subconvert(exampleSubscription, 'clash', {
    clashOptions: {
      port: 7890,
      socksPort: 7891,
      allowLan: true,
      mode: 'rule',
      groups: [
        {
          name: 'Proxy',
          type: 'select',
          proxies: ['auto', 'DIRECT']
        },
        {
          name: 'auto',
          type: 'url-test',
          proxies: proxies.map(p => p.name),
          url: 'http://www.gstatic.com/generate_204',
          interval: 300
        }
      ],
      rules: [
        'DOMAIN-SUFFIX,google.com,Proxy',
        'DOMAIN-SUFFIX,github.com,Proxy',
        'GEOIP,CN,DIRECT',
        'MATCH,Proxy'
      ]
    }
  });
  console.log('Custom Clash configuration generated successfully\n');
} catch (e) {
  console.error('Error:', e.message);
}

console.log('=== Example Complete ===');
