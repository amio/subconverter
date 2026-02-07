/**
 * Base64 encoding/decoding utilities
 * Works in both Node.js and browser environments
 */

// Check if running in Node.js or browser
const isNode = typeof process !== 'undefined' && 
               process.versions != null && 
               process.versions.node != null;

/**
 * Decode base64 string to UTF-8 string
 * @param {string} str - Base64 encoded string
 * @returns {string} Decoded UTF-8 string
 */
export function base64Decode(str) {
  if (!str) return '';
  
  // Remove whitespace and padding
  str = str.trim().replace(/\s/g, '');
  
  if (isNode) {
    return Buffer.from(str, 'base64').toString('utf-8');
  } else {
    try {
      return decodeURIComponent(escape(atob(str)));
    } catch (e) {
      // Fallback for invalid base64
      return atob(str);
    }
  }
}

/**
 * Encode UTF-8 string to base64
 * @param {string} str - UTF-8 string
 * @returns {string} Base64 encoded string
 */
export function base64Encode(str) {
  if (!str) return '';
  
  if (isNode) {
    return Buffer.from(str, 'utf-8').toString('base64');
  } else {
    try {
      return btoa(unescape(encodeURIComponent(str)));
    } catch (e) {
      return btoa(str);
    }
  }
}

/**
 * URL-safe base64 decode
 * @param {string} str - URL-safe base64 string
 * @returns {string} Decoded string
 */
export function base64UrlDecode(str) {
  if (!str) return '';
  
  // Convert URL-safe base64 to standard base64
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  
  // Add padding if needed
  const pad = str.length % 4;
  if (pad) {
    str += '='.repeat(4 - pad);
  }
  
  return base64Decode(str);
}

/**
 * URL-safe base64 encode
 * @param {string} str - String to encode
 * @returns {string} URL-safe base64 string
 */
export function base64UrlEncode(str) {
  if (!str) return '';
  
  return base64Encode(str)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}
