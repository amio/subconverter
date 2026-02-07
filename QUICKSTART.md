# JavaScript Library Quick Start

This directory contains a pure JavaScript implementation of subconverter that can be used in both Node.js and browser environments.

## What is this?

This is a standalone JavaScript library that extracts the core conversion functionality from the C++ subconverter implementation. It provides a simple API to convert between various proxy subscription formats without needing to run a server.

It also includes a **command-line interface (CLI)** for quick conversions.

## Features

- 🔄 **Convert between formats**: Clash, Surge, Quantumult X, V2Ray, SingBox, and raw proxy links
- 📦 **Parse multiple protocols**: SS, SSR, VMess, Trojan
- 🌐 **Universal**: Works in Node.js and browsers
- 🎯 **Simple API**: `subconvert(subscriptionString, target, options)`
- 💻 **CLI Tool**: Command-line interface for quick conversions
- 📝 **TypeScript support**: Full type definitions included

## Installation

```bash
cd js
npm install
```

## Quick Start with CLI

```bash
# Run CLI tool directly
node src/cli.js --url "https://example.com/sub" --target clash

# Or install globally and use anywhere
npm install -g .
subconverter --url ./subscription.txt --target surge --output surge.conf

# Get help
node src/cli.js --help
```

## Quick Example (Library)

```javascript
import { subconvert } from './src/index.js';

// Your subscription content
const subscription = `
ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@example.com:8388#Example
vmess://eyJ2IjoiMiIsInBzIjoi...
`;

// Convert to Clash format
const clashConfig = subconvert(subscription, 'clash');
console.log(clashConfig);
```

## Supported Formats

### Input (Source)
- Shadowsocks (SS)
- ShadowsocksR (SSR)  
- VMess
- Trojan
- Base64-encoded subscriptions

### Output (Target)
- `clash` / `clashr` - Clash YAML
- `surge` - Surge config
- `quanx` - Quantumult X
- `v2ray` - V2Ray JSON
- `singbox` - SingBox JSON
- `ss` / `ssr` / `trojan` - Raw links
- `mixed` - All proxy links

## Running Tests

```bash
npm test
```

## Running Example

```bash
npm run example
```

## Documentation

See the full documentation in:
- [README.md](./README.md) - English documentation
- [README-cn.md](./README-cn.md) - 中文文档

## API Overview

```javascript
// Main conversion function
subconvert(subscriptionString, target, options)

// Parse subscription to proxy objects
parse(subscriptionString)

// Merge multiple subscriptions
mergeAndConvert(subscriptions, target, options)
```

## File Structure

```
js/
├── src/
│   ├── index.js              # Main entry point
│   ├── index.d.ts            # TypeScript definitions
│   ├── parsers/              # Protocol parsers
│   │   ├── index.js          # Unified parser
│   │   ├── shadowsocks.js    # SS parser
│   │   ├── shadowsocksr.js   # SSR parser
│   │   ├── vmess.js          # VMess parser
│   │   └── trojan.js         # Trojan parser
│   ├── generators/           # Format generators
│   │   ├── index.js          # Unified generator
│   │   ├── clash.js          # Clash generator
│   │   ├── surge.js          # Surge generator
│   │   ├── quantumultx.js    # QuanX generator
│   │   ├── v2ray.js          # V2Ray generator
│   │   ├── singbox.js        # SingBox generator
│   │   └── links.js          # Raw link generator
│   └── utils/                # Utility functions
│       ├── base64.js         # Base64 encoding/decoding
│       └── url.js            # URL parsing
├── test/                     # Test files
├── examples/                 # Usage examples
├── package.json              # NPM package config
└── README.md                 # Full documentation
```

## Differences from C++ Version

This JavaScript implementation focuses on the core conversion logic:

✅ **Included:**
- All protocol parsers (SS, SSR, VMess, Trojan)
- All format generators (Clash, Surge, QuanX, V2Ray, SingBox)
- Basic template support
- Subscription parsing and merging

❌ **Not included:**
- HTTP server functionality (use the C++ version for this)
- External config file downloading
- Rule providers and remote rules
- Advanced filtering and scripting
- Gist upload functionality

For server-based usage with full features, use the C++ implementation. This JS library is best for:
- Client-side conversion in web apps
- CLI tools and scripts
- Embedded conversion in other applications
- Learning and experimentation

## License

GPL-3.0 (same as main project)
