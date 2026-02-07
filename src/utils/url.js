/**
 * URL parsing utilities
 */

/**
 * Parse query string into object
 * @param {string} query - Query string (with or without leading ?)
 * @returns {Object} Parsed query parameters
 */
export function parseQuery(query) {
  if (!query) return {};
  
  // Remove leading ? if present
  query = query.replace(/^\?/, '');
  
  const params = {};
  const pairs = query.split('&');
  
  for (const pair of pairs) {
    const [key, value] = pair.split('=').map(decodeURIComponent);
    if (key) {
      params[key] = value || '';
    }
  }
  
  return params;
}

/**
 * Build query string from object
 * @param {Object} params - Query parameters object
 * @returns {string} Query string (without leading ?)
 */
export function buildQuery(params) {
  if (!params || typeof params !== 'object') return '';
  
  return Object.entries(params)
    .filter(([_, value]) => value !== undefined && value !== null)
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
    .join('&');
}

/**
 * Parse URL into components
 * @param {string} urlString - URL string
 * @returns {Object} URL components
 */
export function parseUrl(urlString) {
  try {
    const url = new URL(urlString);
    return {
      protocol: url.protocol.replace(':', ''),
      hostname: url.hostname,
      port: url.port,
      pathname: url.pathname,
      search: url.search,
      hash: url.hash,
      query: parseQuery(url.search),
      href: url.href
    };
  } catch (e) {
    // Fallback for non-standard URLs
    const match = urlString.match(/^([^:]+):\/\/([^\/\?#]+)(.*)$/);
    if (match) {
      const [, protocol, host, rest] = match;
      const [hostname, port] = host.split(':');
      const [pathname, search] = rest.split('?');
      
      return {
        protocol,
        hostname,
        port: port || '',
        pathname: pathname || '',
        search: search ? `?${search}` : '',
        hash: '',
        query: parseQuery(search),
        href: urlString
      };
    }
    
    throw new Error(`Invalid URL: ${urlString}`);
  }
}
