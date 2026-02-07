/**
 * Unified subscription parser
 * Parses subscription strings and returns an array of proxy objects
 */

import { base64Decode } from '../utils/base64.js';
import { parseShadowsocks } from './shadowsocks.js';
import { parseShadowsocksR } from './shadowsocksr.js';
import { parseVMess } from './vmess.js';
import { parseTrojan } from './trojan.js';

/**
 * Parse a single proxy link
 * @param {string} link - Proxy link
 * @returns {Object|null} Parsed proxy object or null
 */
function parseProxyLink(link) {
  if (!link || typeof link !== 'string') {
    return null;
  }
  
  link = link.trim();
  
  // Dispatch to appropriate parser based on protocol
  if (link.startsWith('ss://')) {
    return parseShadowsocks(link);
  } else if (link.startsWith('ssr://')) {
    return parseShadowsocksR(link);
  } else if (link.startsWith('vmess://')) {
    return parseVMess(link);
  } else if (link.startsWith('trojan://')) {
    return parseTrojan(link);
  }
  
  return null;
}

/**
 * Parse subscription content
 * @param {string} content - Subscription content (can be base64 or plain text)
 * @returns {Array} Array of parsed proxy objects
 */
export function parseSubscription(content) {
  if (!content || typeof content !== 'string') {
    return [];
  }
  
  content = content.trim();
  
  // Try to decode as base64 first
  let decoded = content;
  try {
    // Check if it's base64 encoded
    if (!/^(ss|ssr|vmess|trojan):\/\//i.test(content)) {
      decoded = base64Decode(content);
    }
  } catch (e) {
    // Not base64, use as-is
    decoded = content;
  }
  
  // Split by newlines and parse each link
  const lines = decoded.split(/\r?\n/);
  const proxies = [];
  
  for (const line of lines) {
    const trimmedLine = line.trim();
    if (!trimmedLine || trimmedLine.startsWith('#')) {
      // Skip empty lines and comments
      continue;
    }
    
    const proxy = parseProxyLink(trimmedLine);
    if (proxy) {
      proxies.push(proxy);
    }
  }
  
  return proxies;
}

/**
 * Parse mixed format subscription (multiple links separated by | or newlines)
 * @param {string} content - Mixed format content
 * @returns {Array} Array of parsed proxy objects
 */
export function parseMixedSubscription(content) {
  if (!content || typeof content !== 'string') {
    return [];
  }
  
  // Split by | first (for URL-encoded multi-subscription format)
  const subscriptions = content.split('|');
  const allProxies = [];
  
  for (const sub of subscriptions) {
    const proxies = parseSubscription(sub.trim());
    allProxies.push(...proxies);
  }
  
  return allProxies;
}

export { parseProxyLink };
