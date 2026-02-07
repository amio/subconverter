/**
 * Clash format generator
 * Generates Clash YAML configuration
 */

/**
 * Convert proxy to Clash format
 * @param {Object} proxy - Proxy object
 * @returns {Object} Clash proxy object
 */
function proxyToClash(proxy) {
  const base = {
    name: proxy.name,
    server: proxy.server,
    port: proxy.port,
    udp: proxy.udp !== false
  };
  
  switch (proxy.type) {
    case 'ss':
      return {
        ...base,
        type: 'ss',
        cipher: proxy.cipher,
        password: proxy.password,
        ...(proxy.plugin && {
          plugin: proxy.plugin,
          'plugin-opts': parsePluginOpts(proxy.pluginOpts)
        })
      };
      
    case 'ssr':
      return {
        ...base,
        type: 'ssr',
        cipher: proxy.cipher,
        password: proxy.password,
        protocol: proxy.protocol,
        obfs: proxy.obfs,
        'protocol-param': proxy.protocolParam || '',
        'obfs-param': proxy.obfsParam || ''
      };
      
    case 'vmess':
      return {
        ...base,
        type: 'vmess',
        uuid: proxy.uuid,
        alterId: proxy.alterId || 0,
        cipher: proxy.cipher || 'auto',
        tls: proxy.tls || false,
        'skip-cert-verify': proxy.allowInsecure || false,
        ...(proxy.sni && { servername: proxy.sni }),
        network: proxy.network || 'tcp',
        ...(proxy.network === 'ws' && {
          'ws-opts': {
            path: proxy.path || '/',
            headers: proxy.headers || {}
          }
        }),
        ...(proxy.network === 'h2' && {
          'h2-opts': {
            path: proxy.path || '/',
            host: proxy.host || []
          }
        }),
        ...(proxy.network === 'grpc' && {
          'grpc-opts': {
            'grpc-service-name': proxy.serviceName || ''
          }
        })
      };
      
    case 'trojan':
      return {
        ...base,
        type: 'trojan',
        password: proxy.password,
        sni: proxy.sni || proxy.server,
        'skip-cert-verify': proxy.allowInsecure || false,
        ...(proxy.network && proxy.network !== 'tcp' && {
          network: proxy.network,
          ...(proxy.network === 'ws' && {
            'ws-opts': {
              path: proxy.path || '/',
              headers: proxy.headers || {}
            }
          }),
          ...(proxy.network === 'grpc' && {
            'grpc-opts': {
              'grpc-service-name': proxy.serviceName || ''
            }
          })
        })
      };
      
    default:
      return null;
  }
}

/**
 * Parse plugin options string into object
 * @param {string} opts - Plugin options string
 * @returns {Object} Plugin options object
 */
function parsePluginOpts(opts) {
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
 * Generate Clash configuration
 * @param {Array} proxies - Array of proxy objects
 * @param {Object} options - Generation options
 * @returns {Object} Clash configuration object
 */
export function generateClash(proxies, options = {}) {
  const {
    port = 7890,
    socksPort = 7891,
    allowLan = false,
    mode = 'rule',
    logLevel = 'info',
    externalController = '127.0.0.1:9090',
    groups = [],
    rules = [],
    extraGroups = [],
    extraRules = []
  } = options;
  
  // Convert all proxies
  const clashProxies = proxies
    .map(proxy => proxyToClash(proxy))
    .filter(proxy => proxy !== null);
  
  // Create default proxy groups if not provided
  const baseProxyGroups = groups.length > 0 ? groups : [
    {
      name: 'PROXY',
      type: 'select',
      proxies: ['auto', ...clashProxies.map(p => p.name)]
    },
    {
      name: 'auto',
      type: 'url-test',
      proxies: clashProxies.map(p => p.name),
      url: 'http://www.gstatic.com/generate_204',
      interval: 300
    }
  ];
  const proxyGroups = extraGroups.length > 0
    ? [...baseProxyGroups, ...extraGroups]
    : baseProxyGroups;
  
  // Create default rules if not provided
  const baseRules = rules.length > 0 ? rules : [
    'MATCH,PROXY'
  ];
  const clashRules = extraRules.length > 0
    ? [...extraRules, ...baseRules]
    : baseRules;
  
  return {
    port,
    'socks-port': socksPort,
    'allow-lan': allowLan,
    mode,
    'log-level': logLevel,
    'external-controller': externalController,
    proxies: clashProxies,
    'proxy-groups': proxyGroups,
    rules: clashRules
  };
}
