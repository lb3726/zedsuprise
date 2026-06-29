const COOKIE = "__gate_session";
const TTL_SECONDS = 48 * 60 * 60;

const SEC = {
  "content-security-policy":
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://www.clarity.ms https://*.clarity.ms https://eu-assets.i.posthog.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https://*.clarity.ms https://eu.i.posthog.com https://eu-assets.i.posthog.com; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'",
  "x-frame-options": "DENY",
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
  "strict-transport-security": "max-age=31536000",
};

const EXPECTED = [
  "7b2be7904201cc52ca13e9185c669903df2446dbe1d6bfb8ca58861239914bbd",
  "96f584736f5ea8d837c465dcd7a897a1c13864a35f220adfdada0e133aa85b62",
];

const NOT_FOUND_HTML = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow">
<title>404 &mdash; Not found</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{min-height:100vh;min-height:100dvh;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:32px;color:#e6efff;background:radial-gradient(900px 620px at 50% 30%,rgba(201,163,98,.10),transparent 60%),linear-gradient(180deg,#0a0e16,#090c12);font-family:Georgia,'Times New Roman',serif;-webkit-font-smoothing:antialiased}
.code{font-size:clamp(76px,19vw,160px);line-height:1;color:#c9a362;letter-spacing:.02em;filter:drop-shadow(0 0 42px rgba(201,163,98,.25))}
.msg{margin-top:12px;font-size:clamp(16px,3.4vw,23px);font-style:italic;opacity:.86}
.sub{margin-top:28px;font-family:ui-monospace,'Courier New',monospace;font-size:12px;letter-spacing:.26em;text-transform:uppercase}
.sub a{color:#c9a362;text-decoration:none;border-bottom:1px solid rgba(201,163,98,.4);padding-bottom:3px;transition:color .2s}
.sub a:hover{color:#e0c486}
</style></head>
<body>
<div class="code">404</div>
<div class="msg">This page doesn&rsquo;t exist.</div>
<div class="sub"><a href="/">Back to the start</a></div>
</body></html>`;
function notFoundResponse() {
  return new Response(NOT_FOUND_HTML, {
    status: 404,
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-robots-tag": "noindex, nofollow" },
  });
}

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  if (url.pathname === "/preview" || url.pathname.startsWith("/preview/") ||
      url.pathname === "/lore" || url.pathname.startsWith("/lore/")) {
    return notFoundResponse();
  }

  if (env.SITE_PUBLIC === "1" || env.SITE_PUBLIC === "true") {
    if (url.pathname === "/auth.json" ||
        /^\/(scripts|\.github)\//i.test(url.pathname) ||
        /\.(py|md|toml|ya?ml|lock)$/i.test(url.pathname)) {
      return notFoundResponse();
    }
    const res = await context.next();
    const ct = res.headers.get("content-type") || "";
    if (env.PUBLIC_SECRET && ct.includes("text/html")) {
      return new HTMLRewriter().on("head", new PublicUnlockInjector(env.PUBLIC_SECRET)).transform(res);
    }
    return res;
  }

  if (url.pathname.startsWith("/_assets")) {
    return context.next();
  }

  if (url.pathname === "/__gate" && request.method === "POST") {
    return handleGate(request, env);
  }

  if (url.pathname === "/auth.json") return context.next();

  const __scope = await sessionScope(request, env);
  if (__scope) {
    const res = await context.next();
    const ct = res.headers.get("content-type") || "";
    if (ct.includes("text/html")) {
      return new HTMLRewriter().on("body", new HandoffInjector()).transform(res);
    }
    return res;
  }

  const accept = request.headers.get("accept") || "";
  if (request.method === "GET" && accept.includes("text/html")) {
    return new Response(gatePage(url), {
      status: 200,
      headers: {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
        "x-robots-tag": "noindex, nofollow",
        ...SEC,
      },
    });
  }
  return new Response("Forbidden", { status: 403, headers: { "cache-control": "no-store", ...SEC } });
}

async function handleGate(request, env) {
  if (!env.GATE_SIGNING_SECRET) return json({ ok: false, error: "gate_not_configured" }, 500);
  let body;
  try { body = await request.json(); } catch (_) { return json({ ok: false }, 400); }
  const proof = String((body && body.proof) || "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(proof)) return json({ ok: false }, 400);

  const check = await sha256hex(hexToBytes(proof));
  if (!EXPECTED.includes(check)) return json({ ok: false }, 401);

  const scope = "main";
  const cookie = await makeCookie(env.GATE_SIGNING_SECRET, scope);
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
      "set-cookie": `${COOKIE}=${cookie}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${TTL_SECONDS}`,
    },
  });
}

async function makeCookie(secret, scope) {
  const exp = Math.floor(Date.now() / 1000) + TTL_SECONDS;
  const payload = b64url(new TextEncoder().encode(String(exp) + "." + (scope || "main")));
  const sig = await hmac(secret, payload);
  return `${payload}.${sig}`;
}

async function sessionScope(request, env) {
  if (!env.GATE_SIGNING_SECRET) return null;
  const raw = readCookie(request, COOKIE);
  if (!raw || raw.indexOf(".") < 0) return null;
  const [payload, sig] = raw.split(".");
  const expect = await hmac(env.GATE_SIGNING_SECRET, payload);
  if (!timingSafeEqual(sig, expect)) return null;
  try {
    const dec = new TextDecoder().decode(b64urlToBytes(payload));
    const dot = dec.indexOf(".");
    const exp = parseInt(dot < 0 ? dec : dec.slice(0, dot), 10);
    if (!(Number.isFinite(exp) && exp > Math.floor(Date.now() / 1000))) return null;
    return dot < 0 ? "main" : (dec.slice(dot + 1) || "main");
  } catch (_) { return null; }
}

async function hmac(secret, msg) {
  const k = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", k, new TextEncoder().encode(msg));
  return b64url(new Uint8Array(sig));
}

async function sha256hex(bytes) {
  const d = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

const HANDOFF = `
<script>
(function(){
  try {
    var u = sessionStorage.getItem('__gate_u');
    var p = sessionStorage.getItem('__gate_p');
    if (!p) return;
    sessionStorage.removeItem('__gate_u');
    sessionStorage.removeItem('__gate_p');
    var ov = document.createElement('div');
    ov.setAttribute('style','position:fixed;inset:0;z-index:2147483647;background:#070d18;display:flex;align-items:center;justify-content:center;transition:opacity .45s ease');
    ov.innerHTML = '<div style="width:34px;height:34px;border:3px solid rgba(201,163,98,.22);border-top-color:#c9a362;border-radius:50%;animation:gspin .8s linear infinite"></div><style>@keyframes gspin{to{transform:rotate(360deg)}}</style>';
    (function mount(){ if(document.body){ document.body.appendChild(ov); } else { setTimeout(mount,10); } })();
    var tries = 0;
    (function go(){
      var g = document.getElementById('gate'); if (g) g.style.visibility = 'hidden';
      var uf = document.getElementById('login-username') || document.getElementById('login-user');
      var pf = document.getElementById('login-password') || document.getElementById('login-pass');
      var fm = document.getElementById('login-form');
      if (pf && fm) {
        if (uf && u) uf.value = u;
        pf.value = p; p = null; u = null;
        if (fm.requestSubmit) fm.requestSubmit();
        else fm.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
      } else if (tries++ < 60) { setTimeout(go, 50); return; }
    })();
    var waited = 0;
    var iv = setInterval(function(){
      waited += 120;
      var sc = document.getElementById('site-content');
      var revealed = sc && getComputedStyle(sc).display !== 'none';
      if (revealed || waited > 8000) {
        clearInterval(iv);
        ov.style.opacity = '0';
        setTimeout(function(){ if (ov.parentNode) ov.parentNode.removeChild(ov); }, 480);
      }
    }, 120);
  } catch (e) {}
})();
</script>`;

class HandoffInjector {
  element(el) { el.append(HANDOFF, { html: true }); }
}

function publicUnlockSnippet(secret) {
  return `<style>/*pubhide*/#pin-gate{display:none!important}</style><script>/*pubunlock*/
(function(){try{
  window.__publicReveal=true;
  var SEC=${JSON.stringify(secret)};
  var ok=false; try{var c=JSON.parse(localStorage.getItem('__s')||'null'); ok=!!(c&&c.s===SEC);}catch(e){}
  if(!ok){ localStorage.setItem('__s',JSON.stringify({s:SEC,u:'guest',x:Date.now()+365*24*60*60*1000})); }
  try{ if(!sessionStorage.getItem('__b')) sessionStorage.setItem('__b',SEC); }catch(e){}
  try{ if(!sessionStorage.getItem('__u')) sessionStorage.setItem('__u','guest'); }catch(e){}
}catch(e){}})();
</script>`;
}

class PublicUnlockInjector {
  constructor(secret) { this.secret = secret; }
  element(el) { el.append(publicUnlockSnippet(this.secret), { html: true }); }
}

function gatePage(url) {
  const u0 = new URL(url);
  const prefill = (u0.searchParams.get("u") || "").replace(/[<>"&]/g, "");
  let dest = u0.pathname + u0.search;
  if (!dest.startsWith("/") || dest.startsWith("//") || dest.startsWith("/__gate")) dest = "/";
  const destJs = JSON.stringify(dest);
  return `<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow"><title>Private</title>
<meta property="og:title" content="A Surprise for Zed">
<meta property="og:type" content="website">
<meta property="og:url" content="https://zedsuprise.pages.dev/">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="A Surprise for Zed">
<style>
:root{--bg:#070d18;--ink:#f4ead8;--ink-soft:#b9c2d0;--gold:#c9a362;--line:rgba(255,255,255,.10)}
*{box-sizing:border-box}html,body{margin:0;height:100%}
body{background:var(--bg);color:var(--ink);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px}
.card{width:100%;max-width:360px;text-align:center}
.ey{font-size:11px;letter-spacing:.5em;text-transform:uppercase;color:var(--gold);opacity:.85;margin-bottom:18px}
h1{font-family:Georgia,'Times New Roman',serif;font-size:34px;font-weight:600;margin:0 0 6px}
.sub{color:var(--ink-soft);font-size:14px;margin-bottom:26px}
form{display:flex;flex-direction:column;gap:12px}
input{width:100%;padding:13px 14px;border-radius:10px;border:1px solid var(--line);background:rgba(255,255,255,.04);color:var(--ink);font-size:15px;outline:none}
input:focus{border-color:var(--gold)}
button{margin-top:4px;padding:13px;border-radius:10px;border:0;background:var(--gold);color:#13202f;font-weight:700;font-size:15px;letter-spacing:.04em;cursor:pointer}
button:disabled{opacity:.6;cursor:default}
.err{min-height:18px;color:#e98c8c;font-size:13px;margin-top:10px;opacity:0;transition:opacity .2s}
.err.show{opacity:1}
.hp{position:absolute;left:-9999px;width:1px;height:1px;opacity:0}
</style></head><body>
<div class="card">
  <div class="ey">&#10022;</div>
  <h1>Private</h1>
  <div class="sub">Sign in to continue</div>
  <form id="gate-form" autocomplete="off">
    <input id="g-user" type="text" placeholder="Username" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" value="${prefill}">
    <input id="g-extra" class="hp" type="text" tabindex="-1" autocomplete="off" aria-hidden="true">
    <input id="g-pass" type="password" placeholder="Password" autocomplete="off">
    <button id="g-btn" type="submit">Continue</button>
  </form>
  <div class="err" id="g-err">Incorrect username or password</div>
</div>
<script>
(function(){
  var GDEST=${destJs};
  var f=document.getElementById('gate-form'),u=document.getElementById('g-user'),
      p=document.getElementById('g-pass'),b=document.getElementById('g-btn'),
      e=document.getElementById('g-err'),hp=document.getElementById('g-extra');
  (u.value?p:u).focus();
  function fail(){e.classList.add('show');b.disabled=false;b.textContent='Continue';setTimeout(function(){e.classList.remove('show')},2600);}
  function b64(s){return Uint8Array.from(atob(s),function(c){return c.charCodeAt(0);});}
  function hex(buf){return Array.prototype.map.call(new Uint8Array(buf),function(x){return x.toString(16).padStart(2,'0');}).join('');}
  async function deriveProof(un,pw){
    var res=await fetch('/auth.json?t='+Date.now(),{cache:'no-cache'});
    if(!res.ok) return null;
    var users=((await res.json())||{}).users||[];
    var usr=users.find(function(x){return (x.username||'').toLowerCase()===un.toLowerCase();});
    if(!usr) return null;
    var mat=await crypto.subtle.importKey('raw',new TextEncoder().encode(pw),'PBKDF2',false,['deriveKey']);
    var key=await crypto.subtle.deriveKey({name:'PBKDF2',salt:b64(usr.salt),iterations:300000,hash:'SHA-256'},mat,{name:'AES-GCM',length:256},false,['decrypt']);
    var secretBytes=await crypto.subtle.decrypt({name:'AES-GCM',iv:b64(usr.iv)},key,b64(usr.wrapped));
    var secret=new TextDecoder().decode(secretBytes);
    var dig=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(secret));
    return {proof:hex(dig), secret:secret};
  }
  f.addEventListener('submit',function(ev){
    ev.preventDefault();
    if(hp.value){return;}
    var un=u.value.trim(),pw=p.value;
    if(!un||!pw){fail();return;}
    b.disabled=true;b.textContent='\\u2026';
    deriveProof(un,pw).then(function(res){
      if(!res){fail();return;}
      return fetch('/__gate',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({proof:res.proof})})
        .then(function(r){return r.json().catch(function(){return{ok:false};});})
        .then(function(j){
          if(j&&j.ok){
            try{
              localStorage.setItem('__s',JSON.stringify({s:res.secret,u:un,x:Date.now()+30*24*60*60*1000}));
              sessionStorage.setItem('__b',res.secret);
              sessionStorage.setItem('__u',un);
              sessionStorage.setItem('__gate_u',un);
              sessionStorage.setItem('__gate_p',pw);
            }catch(_){}
            un=null;pw=null;res=null;
            window.location.replace(GDEST);
          } else { fail(); }
        });
    }).catch(function(){fail();});
  });
})();
</script>
<script>
(function(c,l,a,r,i,t,y){c[a]=c[a]||function(){(c[a].q=c[a].q||[]).push(arguments)};t=l.createElement(r);t.async=1;t.src="https://www.clarity.ms/tag/"+i;y=l.getElementsByTagName(r)[0];y.parentNode.insertBefore(t,y);})(window,document,"clarity","script","wo679bg9qp");
!function(t,e){var o,n,p,r;e.__SV||(window.posthog=e,e._i=[],e.init=function(i,s,a){function g(t,e){var o=e.split(".");2==o.length&&(t=t[o[0]],e=o[1]),t[e]=function(){t.push([e].concat(Array.prototype.slice.call(arguments,0)))}}(p=t.createElement("script")).type="text/javascript",p.async=!0,p.src=s.api_host.replace(".i.posthog.com","-assets.i.posthog.com")+"/static/array.js",(r=t.getElementsByTagName("script")[0]).parentNode.insertBefore(p,r);var u=e;for(void 0!==a?u=e[a]=[]:a="posthog",u.people=u.people||[],u.toString=function(t){var e="posthog";return"posthog"!==a&&(e+="."+a),t||(e+=" (stub)"),e},u.people.toString=function(){return u.toString(1)+".people (stub)"},o="init capture register register_once unregister identify reset group set_config get_distinct_id opt_in_capturing opt_out_capturing".split(" "),n=0;n<o.length;n++)g(u,o[n]);e._i.push([i,s,a])},e.__SV=1)}(document,window.posthog||[]);
posthog.init('phc_wH3sNEB3KrzYR5qnEciqe6DZMo5CRNZmAVY2VkAyYSuT',{api_host:'/_assets',persistence:'memory',capture_pageview:false});
posthog.register({gate_page:true});
posthog.capture('gate_view',{path:location.pathname});
</script>
</body></html>`;
}

function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

function readCookie(request, name) {
  const c = request.headers.get("cookie") || "";
  for (const part of c.split(/;\s*/)) {
    const i = part.indexOf("=");
    if (i > -1 && part.slice(0, i) === name) return part.slice(i + 1);
  }
  return null;
}

function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}

function hexToBytes(h) {
  const arr = new Uint8Array(h.length / 2);
  for (let i = 0; i < arr.length; i++) arr[i] = parseInt(h.substr(i * 2, 2), 16);
  return arr;
}
function b64url(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlToBytes(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}
