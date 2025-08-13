// Worker v7 — DIRECT + PROXY + analytics blocker + URL rewriter (anchors/aggressive)
const SERVERS = new Set([
  ...Array.from({ length: 20 }, (_, i) => `us${i + 1}`),
  ...Array.from({ length: 20 }, (_, i) => `eu${i + 1}`),
]);

// ---------- utils ----------
function buildWrapperLink(currentReqUrl, absoluteTargetUrl) {
  const cur = new URL(currentReqUrl);
  const pairs = [];
  for (const [k, v] of cur.searchParams) {
    if (k.toLowerCase() === 'u') continue;
    pairs.push(`${encodeURIComponent(k)}=${encodeURIComponent(v)}`);
  }
  pairs.push(`u=${absoluteTargetUrl}`); // raw, sesuai contohmu
  return `${cur.origin}${cur.pathname}?${pairs.join('&')}`;
}
function shouldIgnore(raw) {
  if (!raw) return true;
  const low = raw.trim().toLowerCase();
  return (
    low.startsWith('#') ||
    low.startsWith('javascript:') ||
    low.startsWith('mailto:') ||
    low.startsWith('tel:') ||
    low.startsWith('data:') ||
    low.startsWith('blob:')
  );
}
function isAlreadyWrapped(href, workerBase) {
  try {
    const u = new URL(href, workerBase);
    return u.origin === workerBase.origin &&
           u.pathname === workerBase.pathname &&
           u.searchParams.has('u');
  } catch { return false; }
}
function toAbsolute(raw, base) {
  try { return new URL(raw, base).href; } catch { return null; }
}
function rewriteSrcset(val, baseAbs, reqUrl) {
  // srcset: "url1 1x, url2 2x" — rewrite setiap URL
  return val.split(',')
    .map(part => {
      const seg = part.trim().split(/\s+/);
      if (!seg[0]) return part;
      const abs = toAbsolute(seg[0], baseAbs);
      if (!abs) return part;
      seg[0] = buildWrapperLink(reqUrl, abs);
      return seg.join(' ');
    })
    .join(', ');
}
function rewriteCssUrls(text, baseAbs, reqUrl) {
  return text.replace(/url\(\s*(['"]?)([^)'"]+)\1\s*\)/gi, (_m, q, u) => {
    if (shouldIgnore(u)) return _m;
    const abs = toAbsolute(u, baseAbs);
    if (!abs) return _m;
    return `url(${q}${buildWrapperLink(reqUrl, abs)}${q})`;
  });
}

// ---------- HTML transforms sebelum rewriter ----------
function transformHTMLString(html, { target, srv, blockAnalytics }) {
  const origin = new URL(target).origin;

  if (!/<base\s/i.test(html)) {
    const BASE = `<base href="${origin}/">`;
    html = html.replace(/<head[^>]*>/i, m => `${m}\n${BASE}`);
  }
  html = html.replace(/top\.location\s*=/gi, 'window.location=');

  const TAG = `<script>try{const U=new URL(location);
    if(!U.searchParams.get('srv')){
      U.searchParams.set('srv','${srv}');
      U.searchParams.set('u',${JSON.stringify(target)});
      history.replaceState(0,'',U);
    }}catch(e){}</script>`;
  html = html.replace(/<\/head>/i, TAG + '</head>');

  if (blockAnalytics) {
    const HOSTS = [
      'googletagmanager\\.com','google-analytics\\.com','doubleclick\\.net',
      'facebook\\.com\\/tr','connect\\.facebook\\.net',
      'static\\.hotjar\\.com','hotjar\\.com\\/c','clarity\\.ms','mc\\.yandex\\.ru',
      'hm\\.baidu\\.com','tiktok\\.com\\/i18n\\/pixel','snap\\.sc',
      '(?:cdn\\.)?segment\\.com','mixpanel\\.com','cdn\\.sentry\\.io',
      'plausible\\.io','matomo\\.(?:js|php)|\\/matomo\\.js|\\/piwik\\.js',
      'stats\\.wp\\.com','umami\\.js|umami\\.is',
    ];
    const HOSTS_RE = HOSTS.join('|');

    html = html.replace(
      new RegExp(`<script[^>]+src=["'][^"']*(?:${HOSTS_RE})[^"']*["'][^>]*>\\s*<\\/script>`, 'gi'), ''
    );
    html = html.replace(
      new RegExp(`<noscript>[\\s\\S]*?(?:<iframe[^>]+src=["'][^"']*(?:${HOSTS_RE})[^"']*["'][^>]*>)[\\s\\S]*?<\\/noscript>`, 'gi'), ''
    );
    const INLINE_SIGNS = [
      'googletagmanager\\.com','\\bdataLayer\\s*=','\\bdataLayer\\.push\\(','\\bgtag\\(','\\bga\\(',
      '\\bfbevents\\.js','\\bf(bq|\\.pixel)\\(','\\bhj\\(','\\bclarity\\(','\\bym\\(',
      '_hmt\\s*=|_hmt\\.push\\(','\\bplausible\\(','\\b_matrack\\(','\\b_sentry\\.',
    ];
    html = html.replace(
      new RegExp(`<script\\b[^>]*>[\\s\\S]*?(?:${INLINE_SIGNS.join('|')})[\\s\\S]*?<\\/script>`, 'gi'), ''
    );
    html = html.replace(new RegExp(`<img[^>]+src=["'][^"']*(?:${HOSTS_RE})[^"']*["'][^>]*>`, 'gi'), '');
    html = html.replace(new RegExp(`<link[^>]+(?:rel=["'](?:preconnect|dns-prefetch|preload)["']).*?(?:${HOSTS_RE})[^>]*>`, 'gi'), '');

    const STUBS = `<script>(function(){try{
      window.ga=window.ga||function(){};window.gtag=window.gtag||function(){};
      window.dataLayer=window.dataLayer||[];window.fbq=window.fbq||function(){};
      window.hj=window.hj||function(){};window.clarity=window.clarity||function(){};
      window.ym=window.ym||function(){};window._hmt=window._hmt||[];
      window.plausible=window.plausible||function(){};window._paq=window._paq||[];
    }catch(e){}})();</script>`;
    html = /<\/head>/i.test(html) ? html.replace(/<\/head>/i, STUBS + '</head>') : (STUBS + html);
  } else {
    const GA_STUB = `<script>(function(){try{
      window.ga=window.ga||function(){};window.dataLayer=window.dataLayer||[];
      window.gtag=window.gtag||function(){};
    }catch(e){}})();</script>`;
    html = /<\/head>/i.test(html) ? html.replace(/<\/head>/i, GA_STUB + '</head>') : (GA_STUB + html);
  }
  return html;
}

// ---------- HTMLRewriter: anchors only ----------
function rewriteAnchorsResponse(html, { reqUrl, targetOrigin, headers }) {
  const workerBase = new URL(reqUrl);
  const resIn = new Response(html, { status: 200, headers });
  return new HTMLRewriter().on('a[href]', {
    element(el) {
      const raw = el.getAttribute('href'); if (!raw || shouldIgnore(raw)) return;
      if (isAlreadyWrapped(raw, workerBase)) return;
      const abs = toAbsolute(raw, targetOrigin); if (!abs) return;
      el.setAttribute('href', buildWrapperLink(reqUrl, abs));
    }
  }).transform(resIn);
}

// ---------- HTMLRewriter: aggressive (atribut href/src/action/srcset/poster + style + style tag + meta refresh + svg) ----------
function rewriteAggressiveResponse(html, { reqUrl, targetUrl, headers }) {
  const workerBase = new URL(reqUrl);
  const targetOrigin = new URL(targetUrl).origin + '/';
  const baseAbs = new URL(targetUrl).href;

  const resIn = new Response(html, { status: 200, headers });
  const r = new HTMLRewriter()

    // href-like
    .on('a[href],area[href],link[href]', {
      element(el) {
        const raw = el.getAttribute('href'); if (!raw || shouldIgnore(raw)) return;
        if (isAlreadyWrapped(raw, workerBase)) return;
        const abs = toAbsolute(raw, targetOrigin); if (!abs) return;
        el.setAttribute('href', buildWrapperLink(reqUrl, abs));
      }
    })

    // src-like
    .on('img[src],script[src],iframe[src],video[src],audio[src],source[src],track[src],embed[src],input[src]', {
      element(el) {
        const raw = el.getAttribute('src'); if (!raw || shouldIgnore(raw)) return;
        if (isAlreadyWrapped(raw, workerBase)) return;
        const abs = toAbsolute(raw, targetOrigin); if (!abs) return;
        el.setAttribute('src', buildWrapperLink(reqUrl, abs));
      }
    })

    // object data
    .on('object[data]', {
      element(el) {
        const raw = el.getAttribute('data'); if (!raw || shouldIgnore(raw)) return;
        const abs = toAbsolute(raw, targetOrigin); if (!abs) return;
        el.setAttribute('data', buildWrapperLink(reqUrl, abs));
      }
    })

    // form action (PERINGATAN: submit POST tidak didukung di mode=direct)
    .on('form[action]', {
      element(el) {
        const raw = el.getAttribute('action'); if (!raw || shouldIgnore(raw)) return;
        const abs = toAbsolute(raw, targetOrigin); if (!abs) return;
        el.setAttribute('action', buildWrapperLink(reqUrl, abs));
      }
    })

    // srcset (img/source)
    .on('img[srcset],source[srcset]', {
      element(el) {
        const raw = el.getAttribute('srcset'); if (!raw) return;
        el.setAttribute('srcset', rewriteSrcset(raw, baseAbs, reqUrl));
      }
    })

    // poster (video)
    .on('video[poster]', {
      element(el) {
        const raw = el.getAttribute('poster'); if (!raw || shouldIgnore(raw)) return;
        const abs = toAbsolute(raw, targetOrigin); if (!abs) return;
        el.setAttribute('poster', buildWrapperLink(reqUrl, abs));
      }
    })

    // inline style="...url(...)..."
    .on('[style]', {
      element(el) {
        const raw = el.getAttribute('style'); if (!raw) return;
        el.setAttribute('style', rewriteCssUrls(raw, baseAbs, reqUrl));
      }
    })

    // <style>...</style>
    .on('style', {
      text(t) {
        t.replace(rewriteCssUrls(t.text, baseAbs, reqUrl));
      }
    })

    // <meta http-equiv="refresh" content="0; url=/...">
    .on('meta[http-equiv="refresh" i][content]', {
      element(el) {
        const c = el.getAttribute('content'); if (!c) return;
        const m = c.match(/url\s*=\s*([^;]+)/i);
        if (!m) return;
        const abs = toAbsolute(m[1].trim(), targetOrigin); if (!abs) return;
        el.setAttribute('content', c.replace(m[1], buildWrapperLink(reqUrl, abs)));
      }
    })

    // SVG <use href|xlink:href>
    .on('use[href], use[xlink\\:href]', {
      element(el) {
        const raw = el.getAttribute('href') || el.getAttribute('xlink:href');
        if (!raw || shouldIgnore(raw)) return;
        const abs = toAbsolute(raw, targetOrigin); if (!abs) return;
        const wrapped = buildWrapperLink(reqUrl, abs);
        if (el.hasAttribute('href')) el.setAttribute('href', wrapped);
        if (el.hasAttribute('xlink:href')) el.setAttribute('xlink:href', wrapped);
      }
    });

  return r.transform(resIn);
}

export default {
  async fetch(req) {
    const url = new URL(req.url);
    const mode = (url.searchParams.get('mode') || 'direct').toLowerCase();
    const target = url.searchParams.get('u');
    let srv = (url.searchParams.get('srv') || 'eu3').toLowerCase();
    if (!SERVERS.has(srv)) srv = 'eu3';

    const blockParam = (url.searchParams.get('block') || '').toLowerCase();
    const blockSet = new Set(blockParam.split(',').map(s => s.trim()).filter(Boolean));
    const blockAnalytics = blockSet.has('analytics') || blockSet.has('ana') || blockSet.has('tracker');

    const wrap = (url.searchParams.get('wrap') || 'anchors').toLowerCase();
    const aggressive = wrap === 'aggressive' || wrap === 'all' || wrap === 'attrs';

    if (!target || !/^https?:\/\//i.test(target)) {
      return new Response('Use ?u=https://…&srv=eu10 (optional) [&mode=direct|proxy] [&block=analytics] [&wrap=anchors|aggressive]', { status: 400 });
    }

    if (mode === 'direct') {
      const r = await fetch(target, {
        headers: {
          'referer': `https://${srv}.proxysite.com/`,
          'user-agent': req.headers.get('user-agent') || 'Mozilla/5.0',
          'accept-language': req.headers.get('accept-language') || 'id,en;q=0.8',
        },
        redirect: 'follow',
      });

      const h = new Headers(r.headers);
      const csp = h.get('content-security-policy') || '';
      if (csp) {
        const cleaned = csp.split(';').map(s => s.trim()).filter(s => !/^frame-ancestors\b/i.test(s)).join('; ');
        cleaned ? h.set('content-security-policy', cleaned) : h.delete('content-security-policy');
      }
      h.delete('x-frame-options');
      h.set('referrer-policy', 'no-referrer');
      h.set('x-content-type-options', 'nosniff');

      const ct = (h.get('content-type') || '').toLowerCase();
      let body;

      if (ct.includes('text/html')) {
        let html = await r.text();
        html = transformHTMLString(html, { target, srv, blockAnalytics });
        if (aggressive) {
          return rewriteAggressiveResponse(html, { reqUrl: req.url, targetUrl: target, headers: h });
        } else {
          const targetOrigin = new URL(target).origin + '/';
          return rewriteAnchorsResponse(html, { reqUrl: req.url, targetOrigin, headers: h });
        }
      }

      // Rewriter untuk CSS eksternal saat aggressive: rewrite url(...) di dalam CSS
      if (aggressive && ct.includes('text/css')) {
        const css = await r.text();
        const cssRe = rewriteCssUrls(css, new URL(target).href, req.url);
        return new Response(cssRe, { status: r.status, headers: h });
      }

      // lainnya: biarkan apa adanya
      return new Response(r.body, { status: r.status, headers: h });
    }

    // ---------- PROXY fallback ----------
    const jar = [];
    const pushSetCookies = (res) => {
      for (const [k, v] of res.headers) if (k.toLowerCase() === 'set-cookie') jar.push(v.split(';')[0]);
    };
    const cookie = () => jar.join('; ');
    const warm = await fetch(`https://${srv}.proxysite.com/`, { redirect: 'manual' });
    pushSetCookies(warm);

    const body = new URLSearchParams({ 'server-option': srv, d: target, allowCookies: '1' });
    const upd = await fetch(`https://${srv}.proxysite.com/includes/process.php?action=update`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        cookie: cookie(),
        referer: `https://${srv}.proxysite.com/`,
        'user-agent': req.headers.get('user-agent') || 'Mozilla/5.0',
      },
      body, redirect: 'manual',
    });
    pushSetCookies(upd);
    let loc = upd.headers.get('location') || '/';
    if (!loc.startsWith('http')) loc = `https://${srv}.proxysite.com${loc}`;

    const page = await fetch(loc, {
      headers: {
        cookie: cookie(),
        referer: `https://${srv}.proxysite.com/`,
        'user-agent': req.headers.get('user-agent') || 'Mozilla/5.0',
      },
      redirect: 'follow',
    });

    const h2 = new Headers(page.headers);
    h2.delete('x-frame-options');
    h2.delete('cross-origin-resource-policy');
    h2.delete('cross-origin-embedder-policy');
    h2.delete('cross-origin-opener-policy');
    h2.set('referrer-policy', 'no-referrer');
    h2.set('x-content-type-options', 'nosniff');

    const ct2 = (h2.get('content-type') || '').toLowerCase();
    if (ct2.includes('text/html')) {
      let html2 = await page.text();
      html2 = transformHTMLString(html2, { target, srv, blockAnalytics });
      if (aggressive) {
        return rewriteAggressiveResponse(html2, { reqUrl: req.url, targetUrl: target, headers: h2 });
      } else {
        const targetOrigin = new URL(target).origin + '/';
        return rewriteAnchorsResponse(html2, { reqUrl: req.url, targetOrigin, headers: h2 });
      }
    }
    if (aggressive && ct2.includes('text/css')) {
      const css = await page.text();
      const cssRe = rewriteCssUrls(css, new URL(target).href, req.url);
      return new Response(cssRe, { status: page.status, headers: h2 });
    }
    return new Response(page.body, { status: page.status, headers: h2 });
  }
};
