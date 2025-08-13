// Worker v8 — DIRECT only + analytics blocker + URL rewriter (anchors default, aggressive optional)
const SERVERS = new Set([
  ...Array.from({ length: 20 }, (_, i) => `us${i + 1}`),
  ...Array.from({ length: 20 }, (_, i) => `eu${i + 1}`),
]);

// ---------- utils ----------
function buildWrapperLink(currentReqUrl, absoluteTargetUrl) {
  const cur = new URL(currentReqUrl);
  const pairs = [];
  for (const [k, v] of cur.searchParams) {
    if (k.toLowerCase() === 'u') continue; // akan dioverride
    pairs.push(`${encodeURIComponent(k)}=${encodeURIComponent(v)}`);
  }
  // u disisipkan raw (tanpa encode keras) agar sesuai contoh kamu
  pairs.push(`u=${absoluteTargetUrl}`);
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
    return (
      u.origin === workerBase.origin &&
      u.pathname === workerBase.pathname &&
      u.searchParams.has('u')
    );
  } catch {
    return false;
  }
}

function toAbsolute(raw, base) {
  try { return new URL(raw, base).href; } catch { return null; }
}

function rewriteSrcset(val, baseAbs, reqUrl) {
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

// ---------- transform string (base tag, anti frame-buster, analytics blocker, tag penanda URL) ----------
function transformHTMLString(html, { target, srv, blockAnalytics }) {
  const origin = new URL(target).origin;

  // <base> agar URL relatif resolve ke origin target
  if (!/<base\s/i.test(html)) {
    const BASE = `<base href="${origin}/">`;
    html = html.replace(/<head[^>]*>/i, m => `${m}\n${BASE}`);
  }

  // jinakkan frame-buster sederhana
  html = html.replace(/top\.location\s*=/gi, 'window.location=');

  // sematkan penanda srv/u di address bar
  const TAG = `<script>try{const U=new URL(location);
    if(!U.searchParams.get('srv')){
      U.searchParams.set('srv','${srv}');
      U.searchParams.set('u',${JSON.stringify(target)});
      history.replaceState(0,'',U);
    }}catch(e){}</script>`;
  html = html.replace(/<\/head>/i, TAG + '</head>');

  // blokir analytics opsional
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

    // potong loader eksternal
    html = html.replace(
      new RegExp(`<script[^>]+src=["'][^"']*(?:${HOSTS_RE})[^"']*["'][^>]*>\\s*<\\/script>`, 'gi'), ''
    );
    // noscript/iframe tracker
    html = html.replace(
      new RegExp(`<noscript>[\\s\\S]*?(?:<iframe[^>]+src=["'][^"']*(?:${HOSTS_RE})[^"']*["'][^>]*>)[\\s\\S]*?<\\/noscript>`, 'gi'), ''
    );
    // inline snippet
    const INLINE_SIGNS = [
      'googletagmanager\\.com','\\bdataLayer\\s*=','\\bdataLayer\\.push\\(','\\bgtag\\(','\\bga\\(',
      '\\bfbevents\\.js','\\bf(bq|\\.pixel)\\(','\\bhj\\(','\\bclarity\\(','\\bym\\(',
      '_hmt\\s*=|_hmt\\.push\\(','\\bplausible\\(','\\b_matrack\\(','\\b_sentry\\.',
    ];
    html = html.replace(
      new RegExp(`<script\\b[^>]*>[\\s\\S]*?(?:${INLINE_SIGNS.join('|')})[\\s\\S]*?<\\/script>`, 'gi'), ''
    );
    // beacon / preconnect
    html = html.replace(new RegExp(`<img[^>]+src=["'][^"']*(?:${HOSTS_RE})[^"']*["'][^>]*>`, 'gi'), '');
    html = html.replace(new RegExp(`<link[^>]+(?:rel=["'](?:preconnect|dns-prefetch|preload)["']).*?(?:${HOSTS_RE})[^>]*>`, 'gi'), '');

    // stubs agar tidak ReferenceError
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
      const raw = el.getAttribute('href');
      if (!raw || shouldIgnore(raw)) return;

      // biarkan jika sudah wrapped
      if (isAlreadyWrapped(raw, workerBase)) return;

      // absolutkan relatif terhadap origin target
      const abs = toAbsolute(raw, targetOrigin);
      if (!abs) return;

      // bungkus
      el.setAttribute('href', buildWrapperLink(reqUrl, abs));
    }
  }).transform(resIn);
}

// ---------- HTMLRewriter: aggressive (href/src/action/srcset/poster + style + <style> + meta refresh + svg use) ----------
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

    // form action (catatan: submit POST bisa gagal karena same-origin/cookies)
    .on('form[action]', {
      element(el) {
        const raw = el.getAttribute('action'); if (!raw || shouldIgnore(raw)) return;
        const abs = toAbsolute(raw, targetOrigin); if (!abs) return;
        el.setAttribute('action', buildWrapperLink(reqUrl, abs));
      }
    })

    // srcset
    .on('img[srcset],source[srcset]', {
      element(el) {
        const raw = el.getAttribute('srcset'); if (!raw) return;
        el.setAttribute('srcset', rewriteSrcset(raw, baseAbs, reqUrl));
      }
    })

    // poster
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
    // "mode" diabaikan (kompatibel link lama). Selalu DIRECT.
    const target = url.searchParams.get('u');
    let srv = (url.searchParams.get('srv') || 'eu3').toLowerCase();
    if (!SERVERS.has(srv)) srv = 'eu3';

    const blockParam = (url.searchParams.get('block') || '').toLowerCase();
    const blockSet = new Set(blockParam.split(',').map(s => s.trim()).filter(Boolean));
    const blockAnalytics = blockSet.has('analytics') || blockSet.has('ana') || blockSet.has('tracker');

    const wrap = (url.searchParams.get('wrap') || 'anchors').toLowerCase();
    const aggressive = wrap === 'aggressive' || wrap === 'all' || wrap === 'attrs';

    if (!target || !/^https?:\/\//i.test(target)) {
      return new Response(
        'Use ?u=https://…&srv=eu10 (optional) [&block=analytics] [&wrap=anchors|aggressive]',
        { status: 400 }
      );
    }

    // ---------- DIRECT fetch ----------
    const r = await fetch(target, {
      headers: {
        'referer': `https://${srv}.proxysite.com/`,
        'user-agent': req.headers.get('user-agent') || 'Mozilla/5.0',
        'accept-language': req.headers.get('accept-language') || 'id,en;q=0.8',
      },
      redirect: 'follow',
    });

    // bersihkan header penghalang frame
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

    // HTML: transform + rewrite
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

    // CSS: jika aggressive, rewrite url(...) di dalam CSS
    if (aggressive && ct.includes('text/css')) {
      const css = await r.text();
      const cssRe = rewriteCssUrls(css, new URL(target).href, req.url);
      return new Response(cssRe, { status: r.status, headers: h });
    }

    // lainnya: passthrough
    return new Response(r.body, { status: r.status, headers: h });
  }
};
