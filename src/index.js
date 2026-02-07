/**
 * Subconverter JavaScript Library
 * Main entry point
 */

import yaml from 'js-yaml';
import { parseSubscription, parseMixedSubscription } from './parsers/index.js';
import { generate } from './generators/index.js';

/**
 * Convert subscription to target format
 * @param {string} subscriptionString - Subscription content (base64 or plain text with proxy links)
 * @param {string} target - Target format (clash/clashr/surge/quanx/v2ray/ss/ssr/trojan/mixed/singbox)
 * @param {Object} options - Conversion options
 * @param {Object} options.clashOptions - Clash-specific options
 * @param {Object} options.surgeOptions - Surge-specific options
 * @param {Object} options.v2rayOptions - V2Ray-specific options
 * @param {Object} options.singboxOptions - SingBox-specific options
 * @param {boolean} options.outputJson - Output as JSON for structured formats (default: false)
 * @returns {string} Converted subscription content
 */
export function subconvert(subscriptionString, target, options = {}) {
  if (!subscriptionString || typeof subscriptionString !== 'string') {
    throw new Error('Invalid subscription string');
  }
  
  if (!target || typeof target !== 'string') {
    throw new Error('Invalid target format');
  }
  
  // Parse subscription
  const proxies = parseSubscription(subscriptionString);
  
  if (proxies.length === 0) {
    throw new Error('No valid proxies found in subscription');
  }
  
  // Get format-specific options
  const formatOptions = options[`${target.toLowerCase()}Options`] || {};
  
  // Generate output
  const result = generate(proxies, target, formatOptions);
  
  // Format output based on target type
  const outputJson = options.outputJson === true;
  
  if (typeof result === 'string') {
    return result;
  }
  
  // For structured formats (Clash, V2Ray, SingBox), convert to appropriate string format
  switch (target.toLowerCase()) {
    case 'clash':
    case 'clashr':
      return outputJson ? JSON.stringify(result, null, 2) : yaml.dump(result);
      
    case 'v2ray':
    case 'singbox':
      return JSON.stringify(result, null, 2);
      
    default:
      return JSON.stringify(result, null, 2);
  }
}

/**
 * Parse subscription without conversion
 * Useful for inspecting proxy content
 * @param {string} subscriptionString - Subscription content
 * @returns {Array} Array of parsed proxy objects
 */
export function parse(subscriptionString) {
  return parseSubscription(subscriptionString);
}

/**
 * Convert multiple subscriptions merged together
 * @param {Array<string>} subscriptions - Array of subscription strings
 * @param {string} target - Target format
 * @param {Object} options - Conversion options
 * @returns {string} Converted subscription content
 */
export function mergeAndConvert(subscriptions, target, options = {}) {
  if (!Array.isArray(subscriptions) || subscriptions.length === 0) {
    throw new Error('Invalid subscriptions array');
  }
  
  // Parse all subscriptions and merge
  const allProxies = [];
  for (const sub of subscriptions) {
    const proxies = parseSubscription(sub);
    allProxies.push(...proxies);
  }
  
  if (allProxies.length === 0) {
    throw new Error('No valid proxies found in subscriptions');
  }
  
  // Generate output
  const formatOptions = options[`${target.toLowerCase()}Options`] || {};
  const result = generate(allProxies, target, formatOptions);
  
  // Format output
  const outputJson = options.outputJson === true;
  
  if (typeof result === 'string') {
    return result;
  }
  
  switch (target.toLowerCase()) {
    case 'clash':
    case 'clashr':
      return outputJson ? JSON.stringify(result, null, 2) : yaml.dump(result);
      
    case 'v2ray':
    case 'singbox':
      return JSON.stringify(result, null, 2);
      
    default:
      return JSON.stringify(result, null, 2);
  }
}

// Export parsers and generators for advanced usage
export * from './parsers/index.js';
export * from './generators/index.js';

// Default export
export default {
  subconvert,
  parse,
  mergeAndConvert
};
