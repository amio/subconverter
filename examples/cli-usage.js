/**
 * CLI Usage Examples
 * 
 * This file demonstrates various ways to use the subconverter CLI
 */

// Example 1: Convert local subscription file to Clash format
// node src/cli.js --url ./subscription.txt --target clash

// Example 2: Convert local file to Surge and save to file
// node src/cli.js --url ./subscription.txt --target surge --output surge.conf

// Example 3: Fetch from URL and convert to V2Ray JSON
// node src/cli.js --url "https://example.com/subscription" --target v2ray --output v2ray.json

// Example 4: Convert to Quantumult X (short flags)
// node src/cli.js -u ./subscription.txt -t quanx -o quanx.conf

// Example 5: Convert to SingBox
// node src/cli.js -u ./subscription.txt -t singbox -o singbox.json

// Example 6: Generate mixed proxy links (all formats)
// node src/cli.js -u ./subscription.txt -t mixed

// Example 7: Generate only Shadowsocks links
// node src/cli.js -u ./subscription.txt -t ss

// Example 8: Print to stdout (default)
// node src/cli.js -u ./subscription.txt -t clash

console.log('CLI examples loaded. Run the commands above to see the CLI in action.');
console.log('For help: node src/cli.js --help');
