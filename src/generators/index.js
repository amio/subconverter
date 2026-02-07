/**
 * Unified generator module
 * Exports all generators
 */

import { generateClash } from './clash.js';
import { generateSurge } from './surge.js';
import { generateQuantumultX } from './quantumultx.js';
import { generateV2Ray } from './v2ray.js';
import { generateSingBox } from './singbox.js';
import { generateLinks } from './links.js';

export {
  generateClash,
  generateSurge,
  generateQuantumultX,
  generateV2Ray,
  generateSingBox,
  generateLinks
};

/**
 * Generate configuration based on target type
 * @param {Array} proxies - Array of proxy objects
 * @param {string} target - Target format
 * @param {Object} options - Generation options
 * @returns {string|Object} Generated configuration
 */
export function generate(proxies, target, options = {}) {
  if (!proxies || proxies.length === 0) {
    throw new Error('No proxies provided');
  }
  
  switch (target.toLowerCase()) {
    case 'clash':
    case 'clashr':
      return generateClash(proxies, options);
      
    case 'surge':
      return generateSurge(proxies, options);
      
    case 'quanx':
    case 'quantumultx':
      return generateQuantumultX(proxies, options);
      
    case 'v2ray':
      return generateV2Ray(proxies, options);
      
    case 'singbox':
      return generateSingBox(proxies, options);
      
    case 'ss':
      return generateLinks(proxies, 'ss');
      
    case 'ssr':
      return generateLinks(proxies, 'ssr');
      
    case 'vmess':
      return generateLinks(proxies, 'vmess');
      
    case 'trojan':
      return generateLinks(proxies, 'trojan');
      
    case 'mixed':
      return generateLinks(proxies, 'mixed');
      
    default:
      throw new Error(`Unsupported target format: ${target}`);
  }
}
