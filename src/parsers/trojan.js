/**
 * Trojan link parser
 * Format: trojan://password@server:port?params#remark
 */

/**
 * Parse Trojan link
 * @param {string} link - Trojan link (trojan://...)
 * @returns {Object|null} Parsed proxy object or null if invalid
 */
export function parseTrojan(link) {
  if (!link || !link.startsWith('trojan://')) {
    return null;
  }
  
  try {
    // Remove trojan:// prefix
    link = link.substring(9);
    
    // Extract remark (after #)
    let remark = '';
    const hashIndex = link.indexOf('#');
    if (hashIndex !== -1) {
      remark = decodeURIComponent(link.substring(hashIndex + 1));
      link = link.substring(0, hashIndex);
    }
    
    // Extract query params (after ?)
    let queryParams = {};
    const queryIndex = link.indexOf('?');
    if (queryIndex !== -1) {
      const queryString = link.substring(queryIndex + 1);
      link = link.substring(0, queryIndex);
      
      // Parse query params
      const params = new URLSearchParams(queryString);
      queryParams = Object.fromEntries(params.entries());
    }
    
    // Parse password@server:port
    const atIndex = link.lastIndexOf('@');
    if (atIndex === -1) {
      return null;
    }
    
    const password = link.substring(0, atIndex);
    const serverPort = link.substring(atIndex + 1).split(':');
    const server = serverPort[0];
    const port = parseInt(serverPort[1]) || 443;
    
    // Parse transport settings
    const network = queryParams.type || 'tcp';
    const sni = queryParams.sni || queryParams.peer || server;
    const allowInsecure = queryParams.allowInsecure === '1' || 
                          queryParams.skip_cert_verify === '1';
    
    // WebSocket settings
    const wsOpts = {};
    if (network === 'ws') {
      wsOpts.path = queryParams.path || '/';
      wsOpts.headers = {
        Host: queryParams.host || server
      };
    }
    
    // gRPC settings
    const grpcOpts = {};
    if (network === 'grpc') {
      grpcOpts.serviceName = queryParams.serviceName || queryParams.path || '';
      grpcOpts.mode = queryParams.mode || 'gun';
    }
    
    return {
      type: 'trojan',
      name: remark || `${server}:${port}`,
      server,
      port,
      password,
      network,
      sni,
      allowInsecure,
      ...(network === 'ws' ? wsOpts : {}),
      ...(network === 'grpc' ? grpcOpts : {}),
      udp: true
    };
  } catch (e) {
    console.error('Failed to parse Trojan link:', e);
    return null;
  }
}
