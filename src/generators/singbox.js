/**
 * SingBox format generator
 * Generates SingBox JSON configuration
 */

/**
 * Convert proxy to SingBox outbound format
 * @param {Object} proxy - Proxy object
 * @returns {Object|null} SingBox outbound object
 */
function proxyToSingBox(proxy) {
  const tag = proxy.name;
  
  switch (proxy.type) {
    case 'ss':
      return {
        tag,
        type: 'shadowsocks',
        server: proxy.server,
        server_port: proxy.port,
        method: proxy.cipher,
        password: proxy.password,
        ...(proxy.plugin && {
          plugin: proxy.plugin,
          plugin_opts: proxy.pluginOpts
        })
      };
      
    case 'vmess':
      return {
        tag,
        type: 'vmess',
        server: proxy.server,
        server_port: proxy.port,
        uuid: proxy.uuid,
        alter_id: proxy.alterId || 0,
        security: proxy.cipher || 'auto',
        tls: proxy.tls ? {
          enabled: true,
          server_name: proxy.sni || proxy.server,
          insecure: proxy.allowInsecure || false
        } : undefined,
        transport: proxy.network !== 'tcp' ? {
          type: proxy.network,
          ...(proxy.network === 'ws' && {
            path: proxy.path || '/',
            headers: proxy.headers || {}
          }),
          ...(proxy.network === 'h2' && {
            path: proxy.path || '/',
            host: proxy.host || []
          }),
          ...(proxy.network === 'grpc' && {
            service_name: proxy.serviceName || ''
          })
        } : undefined
      };
      
    case 'trojan':
      return {
        tag,
        type: 'trojan',
        server: proxy.server,
        server_port: proxy.port,
        password: proxy.password,
        tls: {
          enabled: true,
          server_name: proxy.sni || proxy.server,
          insecure: proxy.allowInsecure || false
        },
        transport: proxy.network && proxy.network !== 'tcp' ? {
          type: proxy.network,
          ...(proxy.network === 'ws' && {
            path: proxy.path || '/',
            headers: proxy.headers || {}
          }),
          ...(proxy.network === 'grpc' && {
            service_name: proxy.serviceName || ''
          })
        } : undefined
      };
      
    default:
      return null;
  }
}

/**
 * Generate SingBox configuration
 * @param {Array} proxies - Array of proxy objects
 * @param {Object} options - Generation options
 * @returns {Object} SingBox configuration object
 */
export function generateSingBox(proxies, options = {}) {
  const {
    port = 2080,
    inboundTag = 'mixed-in'
  } = options;
  
  // Convert all proxies to outbounds
  const outbounds = proxies
    .map(proxy => proxyToSingBox(proxy))
    .filter(outbound => outbound !== null);
  
  // Add selector outbound
  outbounds.unshift({
    tag: 'proxy',
    type: 'selector',
    outbounds: outbounds.map(o => o.tag),
    default: outbounds[0]?.tag || 'direct'
  });
  
  // Add direct and block outbounds
  outbounds.push(
    {
      tag: 'direct',
      type: 'direct'
    },
    {
      tag: 'block',
      type: 'block'
    }
  );
  
  return {
    log: {
      level: 'info'
    },
    inbounds: [
      {
        tag: inboundTag,
        type: 'mixed',
        listen: '127.0.0.1',
        listen_port: port
      }
    ],
    outbounds,
    route: {
      rules: [
        {
          geosite: 'cn',
          outbound: 'direct'
        },
        {
          geoip: ['cn', 'private'],
          outbound: 'direct'
        }
      ],
      final: 'proxy',
      auto_detect_interface: true
    }
  };
}
