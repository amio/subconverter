# Configuration File Guide

The CLI supports advanced configuration through JSON config files using the `-c` or `--config` option.

## Config File Structure

```json
{
  "excludeRemarks": ["pattern1", "pattern2"],
  "includeRemarks": ["pattern1", "pattern2"],
  "appendProxyType": false,
  "groups": [...],
  "rules": [...],
  "clashOptions": {...},
  "surgeOptions": {...},
  "quanxOptions": {...},
  "v2rayOptions": {...},
  "singboxOptions": {...},
  "outputJson": false
}
```

## Configuration Options

### Filtering Options

#### excludeRemarks
- **Type**: Array of strings (regex patterns)
- **Description**: Exclude proxies whose names match any of these patterns
- **Example**: `["到期", "剩余流量", "过期", "官网"]`

#### includeRemarks
- **Type**: Array of strings (regex patterns)
- **Description**: Only include proxies whose names match these patterns. If empty, all proxies (not excluded) are included.
- **Example**: `["香港", "美国", "日本"]`

#### appendProxyType
- **Type**: Boolean
- **Description**: Prepend proxy type prefix like `[SS]`, `[VMess]`, `[Trojan]` to proxy names
- **Default**: `false`

### Proxy Groups Configuration

#### groups
- **Type**: Array of group objects
- **Description**: Define proxy groups for formats that support them (Clash, Surge)
- **Example**:
```json
{
  "groups": [
    {
      "name": "Proxy",
      "type": "select",
      "proxies": ["auto", "DIRECT"]
    },
    {
      "name": "auto",
      "type": "url-test",
      "url": "http://www.gstatic.com/generate_204",
      "interval": 300,
      "tolerance": 150
    },
    {
      "name": "fallback",
      "type": "fallback",
      "url": "http://www.gstatic.com/generate_204",
      "interval": 300
    }
  ]
}
```

**Group Types**:
- `select`: Manual selection
- `url-test`: Automatic selection based on URL testing
- `fallback`: Use first available proxy
- `load-balance`: Distribute traffic across proxies

**Common Group Options**:
- `name`: Group name (required)
- `type`: Group type (required)
- `proxies`: Array of proxy names or nested group names
- `url`: Test URL (for url-test and fallback)
- `interval`: Test interval in seconds
- `tolerance`: Tolerance in milliseconds (for url-test)

### Rules Configuration

#### rules
- **Type**: Array of strings
- **Description**: Define routing rules
- **Example**:
```json
{
  "rules": [
    "DOMAIN-SUFFIX,google.com,Proxy",
    "DOMAIN-SUFFIX,github.com,Proxy",
    "DOMAIN-KEYWORD,youtube,Proxy",
    "IP-CIDR,192.168.0.0/16,DIRECT",
    "GEOIP,CN,DIRECT",
    "MATCH,Proxy"
  ]
}
```

**Rule Types**:
- `DOMAIN`: Exact domain match
- `DOMAIN-SUFFIX`: Domain suffix match
- `DOMAIN-KEYWORD`: Domain keyword match
- `IP-CIDR`: IP CIDR block
- `GEOIP`: GeoIP database match
- `MATCH`: Catch-all rule (should be last)

### Format-Specific Options

#### clashOptions
Options specific to Clash format:
```json
{
  "clashOptions": {
    "port": 7890,
    "socksPort": 7891,
    "allowLan": false,
    "mode": "rule",
    "logLevel": "info",
    "externalController": "127.0.0.1:9090"
  }
}
```

#### surgeOptions
Options specific to Surge format:
```json
{
  "surgeOptions": {
    "version": 4
  }
}
```

#### v2rayOptions
Options specific to V2Ray format:
```json
{
  "v2rayOptions": {
    "port": 1080,
    "inboundTag": "socks-in",
    "outboundTag": "proxy"
  }
}
```

#### singboxOptions
Options specific to SingBox format:
```json
{
  "singboxOptions": {
    "port": 2080,
    "inboundTag": "mixed-in"
  }
}
```

### Output Options

#### outputJson
- **Type**: Boolean
- **Description**: For formats that support both JSON and other formats (like Clash), output as JSON instead
- **Default**: `false`

## Complete Example

```json
{
  "excludeRemarks": [
    "到期",
    "剩余流量",
    "过期时间",
    "官网"
  ],
  "includeRemarks": [],
  "appendProxyType": true,
  "groups": [
    {
      "name": "Proxy",
      "type": "select",
      "proxies": ["auto", "fallback", "DIRECT"]
    },
    {
      "name": "auto",
      "type": "url-test",
      "url": "http://www.gstatic.com/generate_204",
      "interval": 300,
      "tolerance": 150
    },
    {
      "name": "fallback",
      "type": "fallback",
      "url": "http://www.gstatic.com/generate_204",
      "interval": 300
    }
  ],
  "rules": [
    "DOMAIN-SUFFIX,google.com,Proxy",
    "DOMAIN-SUFFIX,googleapis.com,Proxy",
    "DOMAIN-SUFFIX,github.com,Proxy",
    "DOMAIN-SUFFIX,youtube.com,Proxy",
    "DOMAIN-SUFFIX,twitter.com,Proxy",
    "DOMAIN-SUFFIX,facebook.com,Proxy",
    "GEOIP,CN,DIRECT",
    "MATCH,Proxy"
  ],
  "clashOptions": {
    "port": 7890,
    "socksPort": 7891,
    "allowLan": false,
    "mode": "rule",
    "logLevel": "info"
  },
  "outputJson": false
}
```

## Usage Examples

### Basic usage with config
```bash
subconverter -u subscription.txt -t clash -c config.json -o output.yaml
```

### Filter out expired nodes
```bash
# config.json
{
  "excludeRemarks": ["到期", "过期"]
}

subconverter -u sub.txt -t clash -c config.json
```

### Include only specific regions
```bash
# config.json
{
  "includeRemarks": ["香港", "美国", "日本"]
}

subconverter -u sub.txt -t clash -c config.json
```

### Add proxy type prefixes
```bash
# config.json
{
  "appendProxyType": true
}

subconverter -u sub.txt -t mixed -c config.json
# Output: [SS] Node1, [VMess] Node2, etc.
```

### Custom port and rules
```bash
# config.json
{
  "clashOptions": {
    "port": 8080
  },
  "rules": [
    "DOMAIN-SUFFIX,google.com,Proxy",
    "GEOIP,CN,DIRECT",
    "MATCH,Proxy"
  ]
}

subconverter -u sub.txt -t clash -c config.json
```
