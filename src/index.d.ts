/**
 * TypeScript definitions for subconverter
 */

export type ProxyType = 'ss' | 'ssr' | 'vmess' | 'trojan';

export type TargetFormat = 
  | 'clash'
  | 'clashr'
  | 'surge'
  | 'quanx'
  | 'quantumultx'
  | 'v2ray'
  | 'singbox'
  | 'ss'
  | 'ssr'
  | 'vmess'
  | 'trojan'
  | 'mixed';

export interface ProxyBase {
  type: ProxyType;
  name: string;
  server: string;
  port: number;
  udp?: boolean;
}

export interface ShadowsocksProxy extends ProxyBase {
  type: 'ss';
  cipher: string;
  password: string;
  plugin?: string;
  pluginOpts?: string;
}

export interface ShadowsocksRProxy extends ProxyBase {
  type: 'ssr';
  cipher: string;
  password: string;
  protocol: string;
  protocolParam?: string;
  obfs: string;
  obfsParam?: string;
  group?: string;
}

export interface VMessProxy extends ProxyBase {
  type: 'vmess';
  uuid: string;
  alterId?: number;
  cipher?: string;
  network?: string;
  tls?: boolean;
  sni?: string;
  allowInsecure?: boolean;
  path?: string;
  headers?: Record<string, string>;
  host?: string | string[];
  serviceName?: string;
  mode?: string;
}

export interface TrojanProxy extends ProxyBase {
  type: 'trojan';
  password: string;
  network?: string;
  sni?: string;
  allowInsecure?: boolean;
  path?: string;
  headers?: Record<string, string>;
  serviceName?: string;
}

export type Proxy = ShadowsocksProxy | ShadowsocksRProxy | VMessProxy | TrojanProxy;

export interface ClashProxyGroup {
  name: string;
  type: 'select' | 'url-test' | 'fallback' | 'load-balance';
  proxies: string[];
  url?: string;
  interval?: number;
  tolerance?: number;
  strategy?: string;
}

export interface ClashOptions {
  port?: number;
  socksPort?: number;
  allowLan?: boolean;
  mode?: 'rule' | 'global' | 'direct';
  logLevel?: 'info' | 'warning' | 'error' | 'debug' | 'silent';
  externalController?: string;
  groups?: ClashProxyGroup[];
  rules?: string[];
}

export interface SurgeOptions {
  version?: number;
  groups?: string[];
  rules?: string[];
}

export interface V2RayOptions {
  port?: number;
  inboundTag?: string;
  outboundTag?: string;
}

export interface SingBoxOptions {
  port?: number;
  inboundTag?: string;
}

export interface ConversionOptions {
  clashOptions?: ClashOptions;
  surgeOptions?: SurgeOptions;
  v2rayOptions?: V2RayOptions;
  singboxOptions?: SingBoxOptions;
  extraGroups?: ClashProxyGroup[];
  extraRules?: string[];
  outputJson?: boolean;
}

/**
 * Convert subscription to target format
 * @param subscriptionString - Subscription content (base64 or plain text with proxy links)
 * @param target - Target format
 * @param options - Conversion options
 * @returns Converted subscription content
 */
export function subconvert(
  subscriptionString: string,
  target: TargetFormat,
  options?: ConversionOptions
): string;

/**
 * Parse subscription without conversion
 * @param subscriptionString - Subscription content
 * @returns Array of parsed proxy objects
 */
export function parse(subscriptionString: string): Proxy[];

/**
 * Convert multiple subscriptions merged together
 * @param subscriptions - Array of subscription strings
 * @param target - Target format
 * @param options - Conversion options
 * @returns Converted subscription content
 */
export function mergeAndConvert(
  subscriptions: string[],
  target: TargetFormat,
  options?: ConversionOptions
): string;

// Parsers
export function parseShadowsocks(link: string): ShadowsocksProxy | null;
export function parseShadowsocksR(link: string): ShadowsocksRProxy | null;
export function parseVMess(link: string): VMessProxy | null;
export function parseTrojan(link: string): TrojanProxy | null;
export function parseSubscription(content: string): Proxy[];
export function parseMixedSubscription(content: string): Proxy[];

// Generators
export function generateClash(proxies: Proxy[], options?: ClashOptions): object;
export function generateSurge(proxies: Proxy[], options?: SurgeOptions): string;
export function generateQuantumultX(proxies: Proxy[], options?: any): string;
export function generateV2Ray(proxies: Proxy[], options?: V2RayOptions): object;
export function generateSingBox(proxies: Proxy[], options?: SingBoxOptions): object;
export function generateLinks(proxies: Proxy[], type?: string): string;
export function generate(proxies: Proxy[], target: TargetFormat, options?: any): string | object;

// Default export
declare const _default: {
  subconvert: typeof subconvert;
  parse: typeof parse;
  mergeAndConvert: typeof mergeAndConvert;
};

export default _default;
