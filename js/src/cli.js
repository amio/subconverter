#!/usr/bin/env node

/**
 * Command-line interface for subconverter
 * Usage: subconverter --url <subscription-url> --target <format> [options]
 */

import { subconvert, parse } from './index.js';
import { generate } from './generators/index.js';
import { loadConfig, filterProxies, getFormatOptions } from './utils/config.js';
import fs from 'fs';
import https from 'https';
import http from 'http';
import { fileURLToPath } from 'url';
import path from 'path';
import yaml from 'js-yaml';

// Parse command-line arguments
function parseArgs() {
  const args = process.argv.slice(2);
  const options = {
    url: null,
    target: null,
    output: null,
    config: null,
    help: false
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    
    if (arg === '--help' || arg === '-h') {
      options.help = true;
    } else if (arg === '--url' || arg === '-u') {
      options.url = args[++i];
    } else if (arg === '--target' || arg === '-t') {
      options.target = args[++i];
    } else if (arg === '--output' || arg === '-o') {
      options.output = args[++i];
    } else if (arg === '--config' || arg === '-c') {
      options.config = args[++i];
    }
  }

  return options;
}

// Show help message
function showHelp() {
  console.log(`
Subconverter CLI - Convert proxy subscriptions between formats

Usage: subconverter --url <subscription-url> --target <format> [options]

Options:
  -u, --url <url>       Subscription URL or file path to convert (required)
  -t, --target <format> Target format (required)
                        Supported: clash, clashr, surge, quanx, v2ray,
                                   ss, ssr, trojan, mixed, singbox
  -o, --output <file>   Output file path (default: stdout)
  -c, --config <file>   Configuration file for advanced options (JSON format)
  -h, --help           Show this help message

Examples:
  # Convert to Clash and output to file
  subconverter --url "https://example.com/sub" --target clash --output clash.yaml

  # Convert local file to Surge
  subconverter --url ./subscription.txt --target surge

  # Use config file for advanced options
  subconverter -u ./sub.txt -t clash -c config.json -o clash.yaml

  # Convert to V2Ray JSON format
  subconverter -u "https://example.com/sub" -t v2ray -o v2ray.json

Supported target formats:
  clash, clashr  - Clash YAML configuration
  surge          - Surge configuration
  quanx          - Quantumult X configuration
  v2ray          - V2Ray JSON configuration
  singbox        - SingBox JSON configuration
  ss, ssr        - Shadowsocks/ShadowsocksR links
  trojan         - Trojan links
  mixed          - Mixed format (all proxy types)

Config file format (JSON):
  {
    "excludeRemarks": ["regex_pattern"],
    "includeRemarks": ["regex_pattern"],
    "appendProxyType": false,
    "groups": [...],
    "rules": [...],
    "clashOptions": { "port": 7890, ... },
    "surgeOptions": { ... }
  }

See documentation for full config schema.
`);
}

// Fetch URL content
function fetchUrl(url) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https:') ? https : http;
    
    // Set a timeout and follow redirects
    const request = client.get(url, {
      timeout: 10000,
      headers: {
        'User-Agent': 'subconverter-cli/1.0'
      }
    }, (res) => {
      // Handle redirects
      if (res.statusCode === 301 || res.statusCode === 302) {
        fetchUrl(res.headers.location).then(resolve).catch(reject);
        return;
      }

      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode}: ${res.statusMessage}`));
        return;
      }

      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });

      res.on('end', () => {
        resolve(data);
      });
    });

    request.on('error', (err) => {
      reject(err);
    });

    request.on('timeout', () => {
      request.destroy();
      reject(new Error('Request timeout'));
    });
  });
}

// Load content from URL or file
async function loadContent(urlOrPath) {
  // Check if it's a URL
  if (urlOrPath.startsWith('http://') || urlOrPath.startsWith('https://')) {
    return await fetchUrl(urlOrPath);
  }
  
  // Otherwise treat as file path
  try {
    return fs.readFileSync(urlOrPath, 'utf-8');
  } catch (err) {
    throw new Error(`Failed to read file: ${err.message}`);
  }
}

// Main function
async function main() {
  const options = parseArgs();

  if (options.help) {
    showHelp();
    process.exit(0);
  }

  if (!options.url) {
    console.error('Error: --url parameter is required\n');
    showHelp();
    process.exit(1);
  }

  if (!options.target) {
    console.error('Error: --target parameter is required\n');
    showHelp();
    process.exit(1);
  }

  try {
    // Load configuration if provided
    let config = null;
    if (options.config) {
      console.error(`Loading configuration from: ${options.config}`);
      config = loadConfig(options.config);
    }
    
    // Load subscription content
    const isUrl = options.url.startsWith('http://') || options.url.startsWith('https://');
    console.error(`${isUrl ? 'Fetching' : 'Loading'} subscription from: ${options.url}`);
    const subscriptionContent = await loadContent(options.url);
    
    // Parse subscription
    console.error(`Parsing subscription...`);
    const proxies = parse(subscriptionContent);
    console.error(`Found ${proxies.length} proxies`);
    
    // Apply filters if config is provided
    let filteredProxies = proxies;
    if (config) {
      filteredProxies = filterProxies(proxies, config);
      if (filteredProxies.length !== proxies.length) {
        console.error(`After filtering: ${filteredProxies.length} proxies`);
      }
    }
    
    if (filteredProxies.length === 0) {
      throw new Error('No proxies left after filtering');
    }
    
    // Get format options from config
    const formatOptions = config ? getFormatOptions(config, options.target) : {};
    
    // Convert subscription
    console.error(`Converting to ${options.target} format...`);
    
    // Build full options object
    const conversionOptions = {
      [`${options.target.toLowerCase()}Options`]: formatOptions,
      outputJson: config ? config.outputJson : false
    };
    
    // Convert using filtered proxies directly by calling generate
    let result = generate(filteredProxies, options.target, formatOptions);
    
    // Format output based on target type
    if (typeof result !== 'string') {
      switch (options.target.toLowerCase()) {
        case 'clash':
        case 'clashr':
          result = conversionOptions.outputJson ? JSON.stringify(result, null, 2) : yaml.dump(result);
          break;
        case 'v2ray':
        case 'singbox':
          result = JSON.stringify(result, null, 2);
          break;
        default:
          result = JSON.stringify(result, null, 2);
      }
    }

    // Output result
    if (options.output) {
      fs.writeFileSync(options.output, result, 'utf-8');
      console.error(`Successfully saved to: ${options.output}`);
    } else {
      console.log(result);
    }

    process.exit(0);
  } catch (error) {
    console.error(`Error: ${error.message}`);
    process.exit(1);
  }
}

main();
