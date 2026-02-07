/**
 * Shadowsocks (SS) link parser
 * Format: ss://base64(method:password)@server:port#remark
 * Or: ss://base64(method:password@server:port)#remark
 */

import { base64Decode, base64UrlDecode } from '../utils/base64.js';

/**
 * Parse Shadowsocks link
 * @param {string} link - SS link (ss://...)
 * @returns {Object|null} Parsed proxy object or null if invalid
 */
export function parseShadowsocks(link) {
  if (!link || !link.startsWith('ss://')) {
    return null;
  }
  
  try {
    // Remove ss:// prefix
    link = link.substring(5);
    
    // Extract remark (after #)
    let remark = '';
    const hashIndex = link.indexOf('#');
    if (hashIndex !== -1) {
      remark = decodeURIComponent(link.substring(hashIndex + 1));
      link = link.substring(0, hashIndex);
    }
    
    // Try to parse SIP002 format first (method:password@server:port)
    let method, password, server, port, plugin, pluginOpts;
    
    if (link.includes('@')) {
      // SIP002 format: base64(method:password)@server:port or method:password@server:port
      const atIndex = link.lastIndexOf('@');
      let userInfo = link.substring(0, atIndex);
      const serverInfo = link.substring(atIndex + 1);
      
      // Try to decode userInfo if it's base64
      try {
        const decoded = base64UrlDecode(userInfo);
        if (decoded.includes(':')) {
          userInfo = decoded;
        }
      } catch (e) {
        // Not base64, use as-is
      }
      
      // Parse method:password
      const colonIndex = userInfo.indexOf(':');
      if (colonIndex === -1) {
        return null;
      }
      method = userInfo.substring(0, colonIndex);
      password = userInfo.substring(colonIndex + 1);
      
      // Parse server:port and optional plugin
      const parts = serverInfo.split('/?');
      const serverPort = parts[0].split(':');
      server = serverPort[0];
      port = parseInt(serverPort[1]) || 443;
      
      // Parse plugin options if present
      if (parts[1]) {
        const params = new URLSearchParams(parts[1]);
        plugin = params.get('plugin');
        if (plugin) {
          // Parse plugin name and options
          const pluginParts = plugin.split(';');
          plugin = pluginParts[0];
          pluginOpts = pluginParts.slice(1).join(';');
        }
      }
    } else {
      // Legacy format: base64(method:password@server:port)
      const decoded = base64UrlDecode(link);
      
      // Parse: method:password@server:port
      const atIndex = decoded.lastIndexOf('@');
      if (atIndex === -1) {
        return null;
      }
      
      const userInfo = decoded.substring(0, atIndex);
      const serverInfo = decoded.substring(atIndex + 1);
      
      const colonIndex = userInfo.indexOf(':');
      if (colonIndex === -1) {
        return null;
      }
      
      method = userInfo.substring(0, colonIndex);
      password = userInfo.substring(colonIndex + 1);
      
      const serverPort = serverInfo.split(':');
      server = serverPort[0];
      port = parseInt(serverPort[1]) || 443;
    }
    
    return {
      type: 'ss',
      name: remark || `${server}:${port}`,
      server,
      port,
      password,
      cipher: method,
      plugin: plugin || '',
      pluginOpts: pluginOpts || '',
      udp: true
    };
  } catch (e) {
    console.error('Failed to parse SS link:', e);
    return null;
  }
}
