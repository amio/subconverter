/**
 * Quantumult X format generator
 * Generates Quantumult X configuration
 */

/**
 * Convert proxy to Quantumult X format
 * @param {Object} proxy - Proxy object
 * @returns {string|null} QuantumultX proxy line
 */
function proxyToQuantumultX(proxy) {
  const tag = proxy.name;
  
  switch (proxy.type) {
    case 'ss': {
      let ssLine = `shadowsocks=${proxy.server}:${proxy.port}, method=${proxy.cipher}, password=${proxy.password}, tag=${tag}`;
      if (proxy.plugin) {
        if (proxy.plugin === 'obfs-local' || proxy.plugin.includes('obfs')) {
          // Parse obfs plugin opts
          const opts = parseObfsOpts(proxy.pluginOpts);
          ssLine += `, obfs=${opts.obfs || 'http'}`;
          if (opts['obfs-host']) {
            ssLine += `, obfs-host=${opts['obfs-host']}`;
          }
          if (opts['obfs-uri']) {
            ssLine += `, obfs-uri=${opts['obfs-uri']}`;
          }
        }
      }
      if (proxy.udp !== false) {
        ssLine += ', udp-relay=true';
      }
      return ssLine;
    }
      
    case 'ssr':
      return `shadowsocks=${proxy.server}:${proxy.port}, method=${proxy.cipher}, password=${proxy.password}, ssr-protocol=${proxy.protocol}, ssr-protocol-param=${proxy.protocolParam || ''}, obfs=${proxy.obfs}, obfs-host=${proxy.obfsParam || ''}, tag=${tag}`;
      
    case 'vmess': {
      let vmessLine = `vmess=${proxy.server}:${proxy.port}, method=${proxy.cipher || 'auto'}, password=${proxy.uuid}, tag=${tag}`;
      if (proxy.tls) {
        vmessLine += ', tls=true';
      }
      if (proxy.sni) {
        vmessLine += `, tls-host=${proxy.sni}`;
      }
      if (proxy.allowInsecure) {
        vmessLine += ', tls-verification=false';
      }
      if (proxy.network === 'ws') {
        vmessLine += `, obfs=ws, obfs-uri=${proxy.path || '/'}`;
        if (proxy.headers && proxy.headers.Host) {
          vmessLine += `, obfs-host=${proxy.headers.Host}`;
        }
      } else if (proxy.network === 'h2') {
        vmessLine += `, obfs=http, obfs-uri=${proxy.path || '/'}`;
      }
      return vmessLine;
    }
      
    case 'trojan': {
      let trojanLine = `trojan=${proxy.server}:${proxy.port}, password=${proxy.password}, tag=${tag}`;
      if (proxy.sni) {
        trojanLine += `, tls-host=${proxy.sni}`;
      }
      if (proxy.allowInsecure) {
        trojanLine += ', tls-verification=false';
      }
      if (proxy.network === 'ws') {
        trojanLine += `, obfs=ws, obfs-uri=${proxy.path || '/'}`;
      }
      return trojanLine;
    }
      
    default:
      return null;
  }
}

/**
 * Parse obfs plugin options
 * @param {string} opts - Plugin options string
 * @returns {Object} Parsed options
 */
function parseObfsOpts(opts) {
  if (!opts) return {};
  
  const result = {};
  const pairs = opts.split(';');
  
  for (const pair of pairs) {
    const [key, value] = pair.split('=');
    if (key) {
      result[key.trim()] = value ? value.trim() : true;
    }
  }
  
  return result;
}

/**
 * Generate Quantumult X configuration
 * @param {Array} proxies - Array of proxy objects
 * @param {Object} options - Generation options
 * @returns {string} QuantumultX configuration string
 */
export function generateQuantumultX(proxies, options = {}) {
  const { rules = [] } = options;
  
  const lines = [];
  
  // Server section
  lines.push('[server_local]');
  for (const proxy of proxies) {
    const line = proxyToQuantumultX(proxy);
    if (line) {
      lines.push(line);
    }
  }
  lines.push('');
  
  // Filter section (proxy groups)
  lines.push('[filter_local]');
  if (rules.length > 0) {
    lines.push(...rules);
  } else {
    lines.push('host-suffix, google.com, proxy');
    lines.push('geoip, cn, direct');
    lines.push('final, proxy');
  }
  lines.push('');
  
  return lines.join('\n');
}
