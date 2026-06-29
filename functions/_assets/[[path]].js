const API_HOST    = 'eu.i.posthog.com';
const ASSETS_HOST = 'eu-assets.i.posthog.com';

const STRIP_REQ = new Set(['cookie', 'origin', 'referer', 'user-agent']);
const STRIP_RESP = new Set(['set-cookie', 'server', 'x-powered-by', 'x-served-by', 'x-cache']);

export async function onRequest(context) {
  const url = new URL(context.request.url);
  const parts = url.pathname.split('/').filter(Boolean);
  const upstreamPath = '/' + parts.slice(1).join('/');





  if (upstreamPath.endsWith('.map')) {
    return new Response('', { status: 404 });
  }

  const isStatic = upstreamPath.startsWith('/static/');
  const upstreamHost = isStatic ? ASSETS_HOST : API_HOST;
  const upstreamUrl = `https://${upstreamHost}${upstreamPath}${url.search}`;


  const headers = new Headers();
  for (const [k, v] of context.request.headers.entries()) {
    if (STRIP_REQ.has(k.toLowerCase())) continue;
    headers.set(k, v);
  }
  headers.set('host', upstreamHost);
  headers.set('user-agent', 'Mozilla/5.0 (compatible; assetfetch/1.0)');









  const clientIp = context.request.headers.get('cf-connecting-ip');
  if (clientIp) {
    headers.set('x-forwarded-for', clientIp);
  }

  const init = {
    method: context.request.method,
    headers,
    redirect: 'manual',
  };
  if (!['GET', 'HEAD', 'OPTIONS'].includes(context.request.method)) {
    init.body = context.request.body;
  }

  let response;
  try {
    response = await fetch(upstreamUrl, init);
  } catch (e) {
    return new Response('{}', {
      status: 502,
      headers: { 'Content-Type': 'application/json' },
    });
  }


  const respHeaders = new Headers();
  for (const [k, v] of response.headers.entries()) {
    if (STRIP_RESP.has(k.toLowerCase())) continue;
    respHeaders.set(k, v);
  }
  respHeaders.set('Access-Control-Allow-Origin', '*');
  respHeaders.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  respHeaders.set('Access-Control-Allow-Headers', 'Content-Type, X-Requested-With, X-PostHog-Token');




  const ctype = (respHeaders.get('content-type') || '').toLowerCase();



  const isJs = upstreamPath.endsWith('.js') || ctype.includes('javascript') || ctype.includes('typescript');
  if (isJs) {
    const text = await response.text();
    const stripped = text.replace(/\/[\/*][#@]\s*sourceMappingURL=\S+\s*\*?\/?\s*$/gm, '');
    respHeaders.delete('content-length');
    respHeaders.set('content-type', 'application/javascript; charset=utf-8');
    return new Response(stripped, {
      status: response.status,
      statusText: response.statusText,
      headers: respHeaders,
    });
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: respHeaders,
  });
}

export async function onRequestOptions() {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Requested-With, X-PostHog-Token',
      'Access-Control-Max-Age': '86400',
    },
  });
}
