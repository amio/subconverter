# subconverter-js

[subconverter](https://github.com/tindy2013/subconverter) 的 JavaScript 实现（含 CLI 和 Worker） - 在各种代理订阅格式之间进行转换。

## 特性

- ✅ **多种输入格式**：SS、SSR、VMess、Trojan
- ✅ **多种输出格式**：Clash、Surge、Quantumult X、V2Ray、SingBox 及原始链接
- ✅ **通用兼容**：支持 Node.js 和浏览器环境
- ✅ **命令行工具**：提供 CLI 工具快速转换
- ✅ **模板支持**：支持配置模板和自定义
- ✅ **零依赖**（除了用于 YAML 输出的 js-yaml）

## 支持的格式

### 输入（源）
- Shadowsocks (SS)
- ShadowsocksR (SSR)
- VMess
- Trojan
- Base64 编码的订阅列表
- 纯文本代理链接

### 输出（目标）
- `clash` / `clashr` - Clash YAML 配置
- `surge` - Surge 配置
- `quanx` / `quantumultx` - Quantumult X 配置
- `v2ray` - V2Ray JSON 配置
- `singbox` - SingBox JSON 配置
- `ss` - Shadowsocks 链接
- `ssr` - ShadowsocksR 链接
- `trojan` - Trojan 链接
- `mixed` - 混合格式（所有代理链接）

## 安装

```bash
npm install subconverter-js
```

或在浏览器中直接引入脚本。

## Cloudflare Workers

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/amio/subconverter-js)

Worker 入口位于 `worker/index.js`，可在其中修改 `CUSTOM_CONFIG` 来应用自定义转换配置。

部署后请求示例：

```
https://<your-worker>.workers.dev/?url=https://example.com/subscription&target=clash
```

## 命令行使用

该库包含一个 CLI 工具用于快速转换：

```bash
# 全局安装以使用 CLI
npm install -g subconverter-js

# 或使用 npx 无需安装
npx subconverter-js --url "https://example.com/sub" --target clash

# 从 URL 转换订阅到 Clash 格式
subconverter --url "https://example.com/sub" --target clash --output clash.yaml

# 转换本地文件到 Surge
subconverter --url ./subscription.txt --target surge

# 使用短标志
subconverter -u "https://example.com/sub" -t v2ray -o v2ray.json

# 打印到标准输出（默认）
subconverter -u ./subscription.txt -t mixed
```

### CLI 选项

```
-u, --url <url>       订阅 URL 或文件路径（必需）
-t, --target <format> 目标格式（必需）
                      支持：clash、clashr、surge、quanx、v2ray、
                           ss、ssr、trojan、mixed、singbox
-o, --output <file>   输出文件路径（默认：标准输出）
-c, --config <file>   高级选项配置文件（JSON 格式）
-h, --help           显示帮助信息
```

### 高级配置

使用 `-c` 或 `--config` 指定 JSON 配置文件以实现高级选项：

```bash
# 过滤节点并自定义输出
subconverter -u subscription.txt -t clash -c config.json -o clash.yaml
```

**配置文件功能：**
- 按名称模式过滤代理（包含/排除）
- 为节点名称添加代理类型前缀
- 定义自定义代理组
- 配置路由规则
- 设置格式特定选项

完整配置文档请参见 [CONFIG_GUIDE.md](./CONFIG_GUIDE.md)。

**示例 config.json：**
```json
{
  "excludeRemarks": ["到期", "过期"],
  "appendProxyType": true,
  "groups": [
    {
      "name": "代理",
      "type": "select",
      "proxies": ["自动选择", "DIRECT"]
    }
  ],
  "extraGroups": [],
  "rules": [
    "DOMAIN-SUFFIX,google.com,代理",
    "GEOIP,CN,DIRECT"
  ],
  "extraRules": [],
  "clashOptions": {
    "port": 8080
  }
}
```

## 库使用方法

### 基本用法

```javascript
import { subconvert } from 'subconverter-js';

// 你的订阅内容（base64 或包含代理链接的纯文本）
const subscriptionString = `
ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@example.com:8388#示例
vmess://eyJ2IjoiMiIsInBzIjoi...
`;

// 转换为 Clash 格式
const clashConfig = subconvert(subscriptionString, 'clash');
console.log(clashConfig);

// 转换为 Surge 格式
const surgeConfig = subconvert(subscriptionString, 'surge');
console.log(surgeConfig);

// 转换为 V2Ray 格式
const v2rayConfig = subconvert(subscriptionString, 'v2ray');
console.log(v2rayConfig);
```

### 带选项的高级用法

```javascript
import { subconvert } from 'subconverter-js';

const subscriptionString = '...'; // 你的订阅

// 使用自定义选项生成 Clash
const clashConfig = subconvert(subscriptionString, 'clash', {
  clashOptions: {
    port: 7890,
    socksPort: 7891,
    allowLan: true,
    mode: 'rule',
    logLevel: 'info',
    groups: [
      {
        name: '代理',
        type: 'select',
        proxies: ['自动选择', 'DIRECT']
      }
    ],
    rules: [
      'DOMAIN-SUFFIX,google.com,代理',
      'GEOIP,CN,DIRECT',
      'MATCH,代理'
    ]
  }
});

// 对于 Clash 输出 JSON 而不是 YAML
const clashJson = subconvert(subscriptionString, 'clash', {
  outputJson: true
});
```

### 解析订阅但不转换

```javascript
import { parse } from 'subconverter-js';

// 解析并检查代理
const proxies = parse(subscriptionString);
console.log(proxies);
// [
//   {
//     type: 'ss',
//     name: '示例',
//     server: 'example.com',
//     port: 8388,
//     cipher: 'aes-256-gcm',
//     password: 'password'
//   },
//   ...
// ]
```

### 合并多个订阅

```javascript
import { mergeAndConvert } from 'subconverter-js';

const subscriptions = [
  'ss://...', // 订阅 1
  'vmess://...', // 订阅 2
  'trojan://...' // 订阅 3
];

const merged = mergeAndConvert(subscriptions, 'clash');
console.log(merged);
```

### Node.js 示例

```javascript
import { subconvert } from 'subconverter-js';
import fs from 'fs';

// 从文件读取订阅
const subscription = fs.readFileSync('subscription.txt', 'utf-8');

// 转换为 Clash
const clashConfig = subconvert(subscription, 'clash');

// 写入文件
fs.writeFileSync('clash.yaml', clashConfig);
```

### 浏览器示例

```html
<!DOCTYPE html>
<html>
<head>
  <title>Subconverter 演示</title>
</head>
<body>
  <textarea id="input" rows="10" cols="50" placeholder="在此粘贴订阅"></textarea>
  <br>
  <select id="target">
    <option value="clash">Clash</option>
    <option value="surge">Surge</option>
    <option value="quanx">Quantumult X</option>
    <option value="v2ray">V2Ray</option>
    <option value="singbox">SingBox</option>
  </select>
  <button onclick="convert()">转换</button>
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
        alert('错误: ' + e.message);
      }
    };
  </script>
</body>
</html>
```

## API 参考

### `subconvert(subscriptionString, target, options)`

将订阅转换为目标格式。

**参数：**
- `subscriptionString` (string): 订阅内容（base64 或纯文本）
- `target` (string): 目标格式（`clash`、`surge`、`quanx`、`v2ray`、`ss`、`ssr`、`trojan`、`mixed`、`singbox`）
- `options` (object, 可选): 转换选项
  - `clashOptions`: Clash 特定选项（端口、分组、规则等）
  - `surgeOptions`: Surge 特定选项
  - `v2rayOptions`: V2Ray 特定选项
  - `singboxOptions`: SingBox 特定选项
  - `outputJson`: 对于结构化格式输出为 JSON（默认：false）

**返回：** 转换后的订阅字符串

### `parse(subscriptionString)`

解析订阅但不转换。

**参数：**
- `subscriptionString` (string): 订阅内容

**返回：** 代理对象数组

### `mergeAndConvert(subscriptions, target, options)`

合并多个订阅并转换为目标格式。

**参数：**
- `subscriptions` (Array<string>): 订阅字符串数组
- `target` (string): 目标格式
- `options` (object, 可选): 转换选项

**返回：** 转换后的订阅字符串

## 代理对象结构

每个解析的代理具有以下结构：

```javascript
{
  type: 'ss' | 'ssr' | 'vmess' | 'trojan',
  name: string,        // 显示名称
  server: string,      // 服务器地址
  port: number,        // 服务器端口
  
  // 类型特定字段
  // 对于 SS：
  cipher: string,
  password: string,
  plugin: string,
  pluginOpts: string,
  
  // 对于 SSR：
  cipher: string,
  password: string,
  protocol: string,
  protocolParam: string,
  obfs: string,
  obfsParam: string,
  
  // 对于 VMess：
  uuid: string,
  alterId: number,
  cipher: string,
  network: string,
  tls: boolean,
  sni: string,
  // ... 传输层特定字段
  
  // 对于 Trojan：
  password: string,
  sni: string,
  network: string
}
```

## 开发

```bash
# 安装依赖
npm install

# 运行测试
npm test

# 运行示例
npm run example
```

## 许可证

GPL-3.0

## 相关项目

- [subconverter](https://github.com/tindy2013/subconverter) - 原始 C++ 实现
