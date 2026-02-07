# Subconverter JavaScript Library

JavaScript implementation of subconverter - converts between various proxy subscription formats.

## Features

- ✅ **Multiple Input Formats**: SS, SSR, VMess, Trojan
- ✅ **Multiple Output Formats**: Clash, Surge, Quantumult X, V2Ray, SingBox, and raw links
- ✅ **Universal**: Works in both Node.js and browser environments
- ✅ **CLI Tool**: Command-line interface for quick conversions
- ✅ **Template Support**: Supports configuration templates and customization
- ✅ **Zero Dependencies** (except js-yaml for YAML output)

## Supported Formats

### Input (Source)
- Shadowsocks (SS)
- ShadowsocksR (SSR)
- VMess
- Trojan
- Base64-encoded subscription lists
- Plain text proxy links

### Output (Target)
- `clash` / `clashr` - Clash YAML configuration
- `surge` - Surge configuration
- `quanx` / `quantumultx` - Quantumult X configuration
- `v2ray` - V2Ray JSON configuration
- `singbox` - SingBox JSON configuration
- `ss` - Shadowsocks links
- `ssr` - ShadowsocksR links
- `trojan` - Trojan links
- `mixed` - Mixed format (all proxy links)

## Installation

```bash
npm install subconverter
```

Or for browser usage, include the script directly.

## Command-Line Usage

The library includes a CLI tool for quick conversions:

```bash
# Install globally to use the CLI
npm install -g subconverter

# Or use npx without installation
npx subconverter --url "https://example.com/sub" --target clash

# Convert subscription from URL to Clash format
subconverter --url "https://example.com/sub" --target clash --output clash.yaml

# Convert local file to Surge
subconverter --url ./subscription.txt --target surge

# Short flags
subconverter -u "https://example.com/sub" -t v2ray -o v2ray.json

# Print to stdout (default)
subconverter -u ./subscription.txt -t mixed
```

### CLI Options

```
-u, --url <url>       Subscription URL or file path to convert (required)
-t, --target <format> Target format (required)
                      Supported: clash, clashr, surge, quanx, v2ray,
                                 ss, ssr, trojan, mixed, singbox
-o, --output <file>   Output file path (default: stdout)
-c, --config <file>   Configuration file for advanced options (JSON format)
-h, --help           Show help message
```

### Advanced Configuration

Use `-c` or `--config` to specify a JSON configuration file for advanced options:

```bash
# Filter nodes and customize output
subconverter -u subscription.txt -t clash -c config.json -o clash.yaml
```

**Config file features:**
- Filter proxies by name patterns (include/exclude)
- Append proxy type to node names
- Define custom proxy groups
- Configure routing rules
- Set format-specific options

See [CONFIG_GUIDE.md](./CONFIG_GUIDE.md) for complete configuration documentation.

**Example config.json:**
```json
{
  "excludeRemarks": ["到期", "过期"],
  "appendProxyType": true,
  "groups": [
    {
      "name": "Proxy",
      "type": "select",
      "proxies": ["auto", "DIRECT"]
    }
  ],
  "rules": [
    "DOMAIN-SUFFIX,google.com,Proxy",
    "GEOIP,CN,DIRECT"
  ],
  "clashOptions": {
    "port": 8080
  }
}
```

## Library Usage

### Basic Usage

```javascript
import { subconvert } from 'subconverter';

// Your subscription content (base64 or plain text with proxy links)
const subscriptionString = `
ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@example.com:8388#Example
vmess://eyJ2IjoiMiIsInBzIjoi...
`;

// Convert to Clash format
const clashConfig = subconvert(subscriptionString, 'clash');
console.log(clashConfig);

// Convert to Surge format
const surgeConfig = subconvert(subscriptionString, 'surge');
console.log(surgeConfig);

// Convert to V2Ray format
const v2rayConfig = subconvert(subscriptionString, 'v2ray');
console.log(v2rayConfig);
```

### Advanced Usage with Options

```javascript
import { subconvert } from 'subconverter';

const subscriptionString = '...'; // Your subscription

// Clash with custom options
const clashConfig = subconvert(subscriptionString, 'clash', {
  clashOptions: {
    port: 7890,
    socksPort: 7891,
    allowLan: true,
    mode: 'rule',
    logLevel: 'info',
    groups: [
      {
        name: 'Proxy',
        type: 'select',
        proxies: ['auto', 'DIRECT']
      }
    ],
    rules: [
      'DOMAIN-SUFFIX,google.com,Proxy',
      'GEOIP,CN,DIRECT',
      'MATCH,Proxy'
    ]
  }
});

// Output as JSON instead of YAML for Clash
const clashJson = subconvert(subscriptionString, 'clash', {
  outputJson: true
});
```

### Parse Subscription Without Conversion

```javascript
import { parse } from 'subconverter';

// Parse and inspect proxies
const proxies = parse(subscriptionString);
console.log(proxies);
// [
//   {
//     type: 'ss',
//     name: 'Example',
//     server: 'example.com',
//     port: 8388,
//     cipher: 'aes-256-gcm',
//     password: 'password'
//   },
//   ...
// ]
```

### Merge Multiple Subscriptions

```javascript
import { mergeAndConvert } from 'subconverter';

const subscriptions = [
  'ss://...', // Subscription 1
  'vmess://...', // Subscription 2
  'trojan://...' // Subscription 3
];

const merged = mergeAndConvert(subscriptions, 'clash');
console.log(merged);
```

### Node.js Example

```javascript
import { subconvert } from 'subconverter';
import fs from 'fs';

// Read subscription from file
const subscription = fs.readFileSync('subscription.txt', 'utf-8');

// Convert to Clash
const clashConfig = subconvert(subscription, 'clash');

// Write to file
fs.writeFileSync('clash.yaml', clashConfig);
```

### Browser Example

```html
<!DOCTYPE html>
<html>
<head>
  <title>Subconverter Demo</title>
</head>
<body>
  <textarea id="input" rows="10" cols="50" placeholder="Paste subscription here"></textarea>
  <br>
  <select id="target">
    <option value="clash">Clash</option>
    <option value="surge">Surge</option>
    <option value="quanx">Quantumult X</option>
    <option value="v2ray">V2Ray</option>
    <option value="singbox">SingBox</option>
  </select>
  <button onclick="convert()">Convert</button>
  <br>
  <textarea id="output" rows="20" cols="50" readonly></textarea>

  <script type="module">
    import { subconvert } from './src/index.js';
    
    window.convert = function() {
      const input = document.getElementById('input').value;
      const target = document.getElementById('target').value;
      
      try {
        const result = subconvert(input, target);
        document.getElementById('output').value = result;
      } catch (e) {
        alert('Error: ' + e.message);
      }
    };
  </script>
</body>
</html>
```

## API Reference

### `subconvert(subscriptionString, target, options)`

Converts subscription to target format.

**Parameters:**
- `subscriptionString` (string): Subscription content (base64 or plain text)
- `target` (string): Target format (`clash`, `surge`, `quanx`, `v2ray`, `ss`, `ssr`, `trojan`, `mixed`, `singbox`)
- `options` (object, optional): Conversion options
  - `clashOptions`: Clash-specific options (port, groups, rules, etc.)
  - `surgeOptions`: Surge-specific options
  - `v2rayOptions`: V2Ray-specific options
  - `singboxOptions`: SingBox-specific options
  - `outputJson`: Output as JSON for structured formats (default: false)

**Returns:** Converted subscription string

### `parse(subscriptionString)`

Parses subscription without conversion.

**Parameters:**
- `subscriptionString` (string): Subscription content

**Returns:** Array of proxy objects

### `mergeAndConvert(subscriptions, target, options)`

Merges multiple subscriptions and converts to target format.

**Parameters:**
- `subscriptions` (Array<string>): Array of subscription strings
- `target` (string): Target format
- `options` (object, optional): Conversion options

**Returns:** Converted subscription string

## Proxy Object Structure

Each parsed proxy has the following structure:

```javascript
{
  type: 'ss' | 'ssr' | 'vmess' | 'trojan',
  name: string,        // Display name
  server: string,      // Server address
  port: number,        // Server port
  
  // Type-specific fields
  // For SS:
  cipher: string,
  password: string,
  plugin: string,
  pluginOpts: string,
  
  // For SSR:
  cipher: string,
  password: string,
  protocol: string,
  protocolParam: string,
  obfs: string,
  obfsParam: string,
  
  // For VMess:
  uuid: string,
  alterId: number,
  cipher: string,
  network: string,
  tls: boolean,
  sni: string,
  // ... transport-specific fields
  
  // For Trojan:
  password: string,
  sni: string,
  network: string
}
```

## Development

```bash
# Install dependencies
npm install

# Run tests
npm test

# Run examples
npm run example
```

## License

GPL-3.0

## Related

- [subconverter](https://github.com/tindy2013/subconverter) - Original C++ implementation
