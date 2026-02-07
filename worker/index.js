import { subconvert } from '../src/index.js';

const DEFAULT_TARGET = 'clash';
const JSON_TARGETS = new Set(['v2ray', 'singbox']);

const CUSTOM_CONFIG = {
  clashOptions: {
    port: 7890,
    allowLan: true,
    mode: 'rule',
    logLevel: 'info'
  },
  outputJson: false
};

function getContentType(target, outputJson) {
  if (outputJson || JSON_TARGETS.has(target)) {
    return 'application/json; charset=utf-8';
  }
  return 'text/plain; charset=utf-8';
}

export default {
  async fetch(request) {
    const { searchParams } = new URL(request.url);
    const subscriptionUrl = searchParams.get('url');
    if (!subscriptionUrl) {
      return new Response('Missing url parameter.', { status: 400 });
    }

    const target = (searchParams.get('target') || DEFAULT_TARGET).toLowerCase();

    let subscriptionResponse;
    try {
      subscriptionResponse = await fetch(subscriptionUrl);
    } catch (error) {
      return new Response('Failed to fetch subscription.', { status: 502 });
    }

    if (!subscriptionResponse.ok) {
      return new Response(`Failed to fetch subscription: ${subscriptionResponse.status}`, { status: 502 });
    }

    const subscriptionString = await subscriptionResponse.text();

    try {
      const result = subconvert(subscriptionString, target, CUSTOM_CONFIG);
      return new Response(result, {
        headers: {
          'content-type': getContentType(target, CUSTOM_CONFIG.outputJson)
        }
      });
    } catch (error) {
      return new Response(`Conversion failed: ${error.message}`, { status: 400 });
    }
  }
};
