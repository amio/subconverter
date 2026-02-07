/**
 * V2Ray format generator (JSON format)
 * Generates V2Ray configuration
 */

/**
 * Convert proxy to V2Ray outbound format
 * @param {Object} proxy - Proxy object
 * @returns {Object|null} V2Ray outbound object
 */
function proxyToV2Ray(proxy) {
  const tag = proxy.name;
  
  switch (proxy.type) {
    case 'ss':
      return {
        tag,
        protocol: 'shadowsocks',
        settings: {
          servers: [{
            address: proxy.server,
            port: proxy.port,
            method: proxy.cipher,
            password: proxy.password
          }]
        }
      };
      
    case 'vmess':
      return {
        tag,
        protocol: 'vmess',
        settings: {
          vnext: [{
            address: proxy.server,
            port: proxy.port,
            users: [{
              id: proxy.uuid,
              alterId: proxy.alterId || 0,
              security: proxy.cipher || 'auto'
            }]
          }]
        },
        streamSettings: {
          network: proxy.network || 'tcp',
          security: proxy.tls ? 'tls' : 'none',
          ...(proxy.tls && {
            tlsSettings: {
              serverName: proxy.sni || proxy.server,
              allowInsecure: proxy.allowInsecure || false
            }
          }),
          ...(proxy.network === 'ws' && {
            wsSettings: {
              path: proxy.path || '/',
              headers: proxy.headers || {}
            }
          }),
          ...(proxy.network === 'h2' && {
            httpSettings: {
              path: proxy.path || '/',
              host: proxy.host || []
            }
          }),
          ...(proxy.network === 'grpc' && {
            grpcSettings: {
              serviceName: proxy.serviceName || ''
            }
          })
        }
      };
      
    case 'trojan':
      return {
        tag,
        protocol: 'trojan',
        settings: {
          servers: [{
            address: proxy.server,
            port: proxy.port,
            password: proxy.password
          }]
        },
        streamSettings: {
          network: proxy.network || 'tcp',
          security: 'tls',
          tlsSettings: {
            serverName: proxy.sni || proxy.server,
            allowInsecure: proxy.allowInsecure || false
          },
          ...(proxy.network === 'ws' && {
            wsSettings: {
              path: proxy.path || '/',
              headers: proxy.headers || {}
            }
          }),
          ...(proxy.network === 'grpc' && {
            grpcSettings: {
              serviceName: proxy.serviceName || ''
            }
          })
        }
      };
      
    default:
      return null;
  }
}

/**
 * Generate V2Ray configuration
 * @param {Array} proxies - Array of proxy objects
 * @param {Object} options - Generation options
 * @returns {Object} V2Ray configuration object
 */
export function generateV2Ray(proxies, options = {}) {
  const {
    port = 1080,
    inboundTag = 'socks-in',
    outboundTag = 'proxy'
  } = options;
  
  // Convert all proxies to outbounds
  const outbounds = proxies
    .map(proxy => proxyToV2Ray(proxy))
    .filter(outbound => outbound !== null);
  
  // Add direct and block outbounds
  outbounds.push(
    {
      tag: 'direct',
      protocol: 'freedom',
      settings: {}
    },
    {
      tag: 'block',
      protocol: 'blackhole',
      settings: {}
    }
  );
  
  return {
    log: {
      loglevel: 'warning'
    },
    inbounds: [
      {
        tag: inboundTag,
        port,
        protocol: 'socks',
        settings: {
          auth: 'noauth',
          udp: true
        }
      }
    ],
    outbounds,
    routing: {
      domainStrategy: 'IPIfNonMatch',
      rules: [
        {
          type: 'field',
          outboundTag: 'direct',
          domain: ['geosite:cn']
        },
        {
          type: 'field',
          outboundTag: 'direct',
          ip: ['geoip:cn', 'geoip:private']
        }
      ]
    }
  };
}
