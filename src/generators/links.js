/**
 * Raw proxy link generators
 * Generate original proxy link format (ss://, ssr://, vmess://, trojan://)
 */

import { base64Encode, base64UrlEncode } from '../utils/base64.js';

/**
 * Generate Shadowsocks link
 * @param {Object} proxy - Proxy object
 * @returns {string} SS link
 */
function generateSSLink(proxy) {
  // SIP002 format: ss://base64(method:password)@server:port#remark
  const userInfo = `${proxy.cipher}:${proxy.password}`;
  const encoded = base64UrlEncode(userInfo);
  const remark = encodeURIComponent(proxy.name);
  
  let link = `ss://${encoded}@${proxy.server}:${proxy.port}`;
  
  // Add plugin if present
  if (proxy.plugin) {
    const pluginStr = proxy.pluginOpts 
      ? `${proxy.plugin};${proxy.pluginOpts}`
      : proxy.plugin;
    link += `/?plugin=${encodeURIComponent(pluginStr)}`;
  }
  
  link += `#${remark}`;
  return link;
}

/**
 * Generate ShadowsocksR link
 * @param {Object} proxy - Proxy object
 * @returns {string} SSR link
 */
function generateSSRLink(proxy) {
  // Format: ssr://base64(server:port:protocol:method:obfs:base64(password)/?params)
  const passwordBase64 = base64UrlEncode(proxy.password);
  
  let main = `${proxy.server}:${proxy.port}:${proxy.protocol}:${proxy.cipher}:${proxy.obfs}:${passwordBase64}`;
  
  const params = [];
  params.push(`remarks=${base64UrlEncode(proxy.name)}`);
  if (proxy.protocolParam) {
    params.push(`protoparam=${base64UrlEncode(proxy.protocolParam)}`);
  }
  if (proxy.obfsParam) {
    params.push(`obfsparam=${base64UrlEncode(proxy.obfsParam)}`);
  }
  if (proxy.group) {
    params.push(`group=${base64UrlEncode(proxy.group)}`);
  }
  
  if (params.length > 0) {
    main += `/?${params.join('&')}`;
  }
  
  return `ssr://${base64UrlEncode(main)}`;
}

/**
 * Generate VMess link
 * @param {Object} proxy - Proxy object
 * @returns {string} VMess link
 */
function generateVMessLink(proxy) {
  const config = {
    v: '2',
    ps: proxy.name,
    add: proxy.server,
    port: String(proxy.port),
    id: proxy.uuid,
    aid: String(proxy.alterId || 0),
    net: proxy.network || 'tcp',
    type: 'none',
    host: '',
    path: '',
    tls: proxy.tls ? 'tls' : '',
    sni: proxy.sni || '',
    scy: proxy.cipher || 'auto'
  };
  
  if (proxy.network === 'ws') {
    config.path = proxy.path || '/';
    config.host = proxy.headers?.Host || '';
  } else if (proxy.network === 'h2') {
    config.path = proxy.path || '/';
    config.host = Array.isArray(proxy.host) ? proxy.host.join(',') : (proxy.host || '');
  } else if (proxy.network === 'grpc') {
    config.path = proxy.serviceName || '';
    config.type = proxy.mode || 'gun';
  }
  
  const json = JSON.stringify(config);
  return `vmess://${base64Encode(json)}`;
}

/**
 * Generate Trojan link
 * @param {Object} proxy - Proxy object
 * @returns {string} Trojan link
 */
function generateTrojanLink(proxy) {
  let link = `trojan://${proxy.password}@${proxy.server}:${proxy.port}`;
  
  const params = [];
  
  if (proxy.sni && proxy.sni !== proxy.server) {
    params.push(`sni=${encodeURIComponent(proxy.sni)}`);
  }
  
  if (proxy.allowInsecure) {
    params.push('allowInsecure=1');
  }
  
  if (proxy.network && proxy.network !== 'tcp') {
    params.push(`type=${proxy.network}`);
    
    if (proxy.network === 'ws') {
      if (proxy.path) {
        params.push(`path=${encodeURIComponent(proxy.path)}`);
      }
      if (proxy.headers?.Host) {
        params.push(`host=${encodeURIComponent(proxy.headers.Host)}`);
      }
    } else if (proxy.network === 'grpc') {
      if (proxy.serviceName) {
        params.push(`serviceName=${encodeURIComponent(proxy.serviceName)}`);
      }
    }
  }
  
  if (params.length > 0) {
    link += `?${params.join('&')}`;
  }
  
  link += `#${encodeURIComponent(proxy.name)}`;
  return link;
}

/**
 * Generate proxy links
 * @param {Array} proxies - Array of proxy objects
 * @param {string} type - Output type (ss, ssr, vmess, trojan, mixed)
 * @returns {string} Generated links (newline separated)
 */
export function generateLinks(proxies, type = 'mixed') {
  const links = [];
  
  for (const proxy of proxies) {
    let link = null;
    
    if (type === 'mixed' || type === proxy.type) {
      switch (proxy.type) {
        case 'ss':
          link = generateSSLink(proxy);
          break;
        case 'ssr':
          link = generateSSRLink(proxy);
          break;
        case 'vmess':
          link = generateVMessLink(proxy);
          break;
        case 'trojan':
          link = generateTrojanLink(proxy);
          break;
      }
    }
    
    if (link) {
      links.push(link);
    }
  }
  
  return links.join('\n');
}
