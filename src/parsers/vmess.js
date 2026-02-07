/**
 * VMess link parser
 * Format: vmess://base64(json)
 */

import { base64UrlDecode } from '../utils/base64.js';

/**
 * Parse VMess link
 * @param {string} link - VMess link (vmess://...)
 * @returns {Object|null} Parsed proxy object or null if invalid
 */
export function parseVMess(link) {
  if (!link || !link.startsWith('vmess://')) {
    return null;
  }
  
  try {
    // Remove vmess:// prefix and decode
    const decoded = base64UrlDecode(link.substring(8));
    const config = JSON.parse(decoded);
    
    // Extract basic info
    const server = config.add || config.address || '';
    const port = parseInt(config.port) || 443;
    const uuid = config.id || '';
    const alterId = parseInt(config.aid || config.alterId || 0);
    const cipher = config.scy || config.cipher || 'auto';
    
    // Network type (tcp, ws, http, h2, grpc, quic)
    const network = config.net || config.network || 'tcp';
    
    // TLS settings
    const tls = config.tls === 'tls' || config.tls === true;
    const sni = config.sni || config.host || '';
    const allowInsecure = config.skip_cert_verify || config.allowInsecure || false;
    
    // Transport settings
    const transportOpts = {};
    
    // WebSocket settings
    if (network === 'ws') {
      transportOpts.path = config.path || '/';
      transportOpts.headers = {
        Host: config.host || ''
      };
    }
    
    // HTTP/2 settings
    if (network === 'h2' || network === 'http') {
      transportOpts.path = config.path || '/';
      transportOpts.host = config.host ? [config.host] : [];
    }
    
    // gRPC settings
    if (network === 'grpc') {
      transportOpts.serviceName = config.path || '';
      transportOpts.mode = config.type || 'gun';
    }
    
    // QUIC settings
    if (network === 'quic') {
      transportOpts.security = config.host || 'none';
      transportOpts.key = config.path || '';
      transportOpts.type = config.type || 'none';
    }
    
    // TCP settings
    if (network === 'tcp') {
      transportOpts.type = config.type || 'none';
      if (config.type === 'http') {
        transportOpts.headers = {
          Host: config.host || ''
        };
        transportOpts.path = config.path || '/';
      }
    }
    
    const remark = config.ps || config.remark || `${server}:${port}`;
    
    return {
      type: 'vmess',
      name: remark,
      server,
      port,
      uuid,
      alterId,
      cipher,
      network,
      tls,
      sni,
      allowInsecure,
      ...transportOpts,
      udp: true
    };
  } catch (e) {
    console.error('Failed to parse VMess link:', e);
    return null;
  }
}
