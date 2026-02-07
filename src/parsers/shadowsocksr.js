/**
 * ShadowsocksR (SSR) link parser
 * Format: ssr://base64(server:port:protocol:method:obfs:base64(password)/?params)
 */

import { base64UrlDecode } from '../utils/base64.js';

/**
 * Parse ShadowsocksR link
 * @param {string} link - SSR link (ssr://...)
 * @returns {Object|null} Parsed proxy object or null if invalid
 */
export function parseShadowsocksR(link) {
  if (!link || !link.startsWith('ssr://')) {
    return null;
  }
  
  try {
    // Remove ssr:// prefix and decode
    const decoded = base64UrlDecode(link.substring(6));
    
    // Split into main part and query params
    const [mainPart, queryPart] = decoded.split('/?');
    
    // Parse main part: server:port:protocol:method:obfs:password_base64
    const parts = mainPart.split(':');
    if (parts.length < 6) {
      return null;
    }
    
    const server = parts[0];
    const port = parseInt(parts[1]) || 443;
    const protocol = parts[2];
    const method = parts[3];
    const obfs = parts[4];
    const passwordBase64 = parts.slice(5).join(':');
    
    // Decode password
    const password = base64UrlDecode(passwordBase64);
    
    // Parse query parameters
    const params = {};
    if (queryPart) {
      const pairs = queryPart.split('&');
      for (const pair of pairs) {
        const [key, value] = pair.split('=');
        if (key && value) {
          params[key] = base64UrlDecode(value);
        }
      }
    }
    
    const remark = params.remarks || params.remark || `${server}:${port}`;
    const protocolParam = params.protoparam || '';
    const obfsParam = params.obfsparam || '';
    const group = params.group || '';
    
    return {
      type: 'ssr',
      name: remark,
      server,
      port,
      password,
      cipher: method,
      protocol,
      protocolParam,
      obfs,
      obfsParam,
      group,
      udp: true
    };
  } catch (e) {
    console.error('Failed to parse SSR link:', e);
    return null;
  }
}
