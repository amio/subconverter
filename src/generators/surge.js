/**
 * Surge format generator
 * Generates Surge configuration (INI-like format)
 */

/**
 * Convert proxy to Surge format
 * @param {Object} proxy - Proxy object
 * @returns {string|null} Surge proxy line
 */
function proxyToSurge(proxy) {
  const name = proxy.name;
  
  switch (proxy.type) {
    case 'ss':
      let ssLine = `${name} = ss, ${proxy.server}, ${proxy.port}, encrypt-method=${proxy.cipher}, password=${proxy.password}`;
      if (proxy.udp !== false) {
        ssLine += ', udp-relay=true';
      }
      if (proxy.plugin) {
        ssLine += `, obfs=${proxy.plugin}`;
        if (proxy.pluginOpts) {
          ssLine += `, obfs-opts=${proxy.pluginOpts}`;
        }
      }
      return ssLine;
      
    case 'vmess':
      // Surge doesn't natively support VMess, convert to note
      return `${name} = custom, ${proxy.server}, ${proxy.port}, vmess, ${proxy.uuid}, encrypt-method=${proxy.cipher || 'auto'}`;
      
    case 'trojan':
      let trojanLine = `${name} = trojan, ${proxy.server}, ${proxy.port}, password=${proxy.password}`;
      if (proxy.sni) {
        trojanLine += `, sni=${proxy.sni}`;
      }
      if (proxy.allowInsecure) {
        trojanLine += ', skip-cert-verify=true';
      }
      if (proxy.udp !== false) {
        trojanLine += ', udp-relay=true';
      }
      return trojanLine;
      
    default:
      return null;
  }
}

/**
 * Generate Surge configuration
 * @param {Array} proxies - Array of proxy objects
 * @param {Object} options - Generation options
 * @returns {string} Surge configuration string
 */
export function generateSurge(proxies, options = {}) {
  const {
    version = 4,
    groups = [],
    rules = []
  } = options;
  
  const lines = [];
  
  // Header
  lines.push('[General]');
  lines.push('loglevel = notify');
  lines.push('bypass-system = true');
  lines.push('skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, localhost, *.local');
  lines.push('bypass-tun = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12');
  lines.push('dns-server = system, 223.5.5.5, 114.114.114.114');
  lines.push('');
  
  // Proxy section
  lines.push('[Proxy]');
  for (const proxy of proxies) {
    const line = proxyToSurge(proxy);
    if (line) {
      lines.push(line);
    }
  }
  lines.push('');
  
  // Proxy Group section
  lines.push('[Proxy Group]');
  if (groups.length > 0) {
    lines.push(...groups);
  } else {
    // Default proxy group
    const proxyNames = proxies.map(p => p.name).join(', ');
    lines.push(`Proxy = select, ${proxyNames}`);
  }
  lines.push('');
  
  // Rule section
  lines.push('[Rule]');
  if (rules.length > 0) {
    lines.push(...rules);
  } else {
    // Default rules
    lines.push('DOMAIN-SUFFIX,google.com,Proxy');
    lines.push('GEOIP,CN,DIRECT');
    lines.push('FINAL,Proxy');
  }
  lines.push('');
  
  return lines.join('\n');
}
