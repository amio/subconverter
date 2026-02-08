/**
 * Configuration file loader and parser
 * Supports JSON format for simplicity
 */

import fs from 'fs';
import path from 'path';
import yaml from 'js-yaml';

/**
 * Default configuration
 */
export const defaultConfig = {
  // Filtering options
  excludeRemarks: [],  // Regex patterns to exclude nodes
  includeRemarks: [],  // Regex patterns to include nodes (if set, only matching nodes are included)
  
  // Proxy group configuration
  groups: [],
  
  // Rules configuration
  rules: [],
  
  // Format-specific options
  clashOptions: {},
  surgeOptions: {},
  quanxOptions: {},
  v2rayOptions: {},
  singboxOptions: {},
  
  // Output options
  appendProxyType: false,  // Append proxy type to node name
  outputJson: false        // Output as JSON for structured formats
};

/**
 * Load configuration from file
 * @param {string} configPath - Path to config file (JSON format)
 * @returns {Object} Parsed configuration object
 */
export function loadConfig(configPath) {
  if (!configPath) {
    return { ...defaultConfig };
  }
  
  try {
    const displayPath = path.basename(configPath);
    let content;
    try {
      content = fs.readFileSync(configPath, 'utf-8');
    } catch (error) {
      throw new Error(`Failed to read config file: ${displayPath} - ${error.message}`);
    }
    const lowerPath = configPath.toLowerCase();
    const isYaml = lowerPath.endsWith('.yml') || lowerPath.endsWith('.yaml');
    let rawConfig;
    try {
      rawConfig = isYaml ? yaml.load(content) : JSON.parse(content);
    } catch (error) {
      throw new Error(`Failed to parse ${isYaml ? 'YAML' : 'JSON'} config: ${displayPath} - ${error.message}`);
    }
    let receivedType;
    if (Array.isArray(rawConfig)) {
      receivedType = 'array';
    } else if (rawConfig === null) {
      receivedType = 'null';
    } else {
      receivedType = typeof rawConfig;
    }
    if (receivedType !== 'object') {
      throw new Error(`Config file must contain a top-level object, received: ${receivedType}`);
    }
    const config = rawConfig;
    
    // Merge with defaults
    return {
      ...defaultConfig,
      ...config,
      clashOptions: { ...defaultConfig.clashOptions, ...(config.clashOptions || {}) },
      surgeOptions: { ...defaultConfig.surgeOptions, ...(config.surgeOptions || {}) },
      quanxOptions: { ...defaultConfig.quanxOptions, ...(config.quanxOptions || {}) },
      v2rayOptions: { ...defaultConfig.v2rayOptions, ...(config.v2rayOptions || {}) },
      singboxOptions: { ...defaultConfig.singboxOptions, ...(config.singboxOptions || {}) }
    };
  } catch (error) {
    throw new Error(`Failed to load config file: ${error.message}`);
  }
}

/**
 * Filter proxies based on configuration
 * @param {Array} proxies - Array of proxy objects
 * @param {Object} config - Configuration object
 * @returns {Array} Filtered proxies
 */
export function filterProxies(proxies, config) {
  let filtered = [...proxies];
  
  // Apply exclude patterns
  if (config.excludeRemarks && config.excludeRemarks.length > 0) {
    const excludePatterns = config.excludeRemarks.map(pattern => new RegExp(pattern, 'i'));
    filtered = filtered.filter(proxy => {
      return !excludePatterns.some(pattern => pattern.test(proxy.name));
    });
  }
  
  // Apply include patterns (if specified, only matching proxies are kept)
  if (config.includeRemarks && config.includeRemarks.length > 0) {
    const includePatterns = config.includeRemarks.map(pattern => new RegExp(pattern, 'i'));
    filtered = filtered.filter(proxy => {
      return includePatterns.some(pattern => pattern.test(proxy.name));
    });
  }
  
  // Append proxy type if configured
  if (config.appendProxyType) {
    filtered = filtered.map(proxy => ({
      ...proxy,
      name: `[${proxy.type.toUpperCase()}] ${proxy.name}`
    }));
  }
  
  return filtered;
}

/**
 * Get format-specific options from config
 * @param {Object} config - Configuration object
 * @param {string} target - Target format
 * @returns {Object} Format-specific options
 */
export function getFormatOptions(config, target) {
  const targetLower = target.toLowerCase();
  const optionsKey = `${targetLower}Options`;
  
  const options = {
    ...(config[optionsKey] || {})
  };
  
  // Add groups if configured
  if (config.groups && config.groups.length > 0) {
    options.groups = config.groups;
  }
  
  // Add rules if configured
  if (config.rules && config.rules.length > 0) {
    options.rules = config.rules;
  }
  
  return options;
}
