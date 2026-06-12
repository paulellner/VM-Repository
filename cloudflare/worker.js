/**
 * VeloMatch Pro — Bike Save Worker
 *
 * Endpoints:
 *   GET  /setup?shop=velomatch.myshopify.com  → startet OAuth (einmalig)
 *   GET  /callback                            → tauscht Code gegen Token (einmalig)
 *   POST /save                                → speichert Bike via Admin API (App Proxy)
 *
 * Secrets (wrangler secret put <NAME>):
 *   SHOPIFY_CLIENT_ID      — Client ID aus dem Dev Dashboard
 *   SHOPIFY_CLIENT_SECRET  — Schlüssel aus dem Dev Dashboard
 *   SHOPIFY_ADMIN_TOKEN    — wird nach dem OAuth-Setup-Schritt gesetzt
 */

const API_VERSION = '2025-01';

async function hmacSHA256(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const buf = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifyProxySignature(params, secret) {
  const sig = params.get('signature');
  if (!sig) return false;
  const message = [...params.entries()]
    .filter(([k]) => k !== 'signature')
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join('');
  return (await hmacSHA256(secret, message)) === sig;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    /* ── SCHRITT A: OAuth starten ─────────────────────────────────────────── */
    if (url.pathname === '/setup') {
      const shop = url.searchParams.get('shop') || 'velomatch.myshopify.com';
      const redirectUri = encodeURIComponent(`${url.origin}/callback`);
      const oauthUrl =
        `https://${shop}/admin/oauth/authorize` +
        `?client_id=${env.SHOPIFY_CLIENT_ID}` +
        `&scope=write_customers` +
        `&redirect_uri=${redirectUri}` +
        `&state=setup`;
      return Response.redirect(oauthUrl, 302);
    }

    /* ── SCHRITT B: OAuth Callback — Token anzeigen ───────────────────────── */
    if (url.pathname === '/callback') {
      const code = url.searchParams.get('code');
      const shop = url.searchParams.get('shop');
      if (!code || !shop) {
        return new Response('Fehlende Parameter (code oder shop).', { status: 400 });
      }

      const tokenResp = await fetch(`https://${shop}/admin/oauth/access_token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_id:     env.SHOPIFY_CLIENT_ID,
          client_secret: env.SHOPIFY_CLIENT_SECRET,
          code,
        }),
      });
      const tokenData = await tokenResp.json();

      if (!tokenData.access_token) {
        return new Response(
          'Token-Anfrage fehlgeschlagen: ' + JSON.stringify(tokenData),
          { status: 500 }
        );
      }

      return new Response(
        `<!DOCTYPE html><html><body style="font-family:monospace;padding:32px">
        <h2>Setup abgeschlossen!</h2>
        <p>Kopiere diesen Token und fuehre dann aus:<br>
        <code>wrangler secret put SHOPIFY_ADMIN_TOKEN</code></p>
        <p style="background:#f0f0f0;padding:16px;word-break:break-all">
          <strong>${tokenData.access_token}</strong>
        </p>
        <p>Scopes: ${tokenData.scope}</p>
        </body></html>`,
        { headers: { 'Content-Type': 'text/html' } }
      );
    }

    /* ── HAUPTENDPOINT: Bike speichern (App Proxy POST /save) ─────────────── */
    if (request.method !== 'POST') {
      return Response.json({ error: 'Method not allowed' }, { status: 405 });
    }

    const valid = await verifyProxySignature(url.searchParams, env.SHOPIFY_CLIENT_SECRET);
    if (!valid) {
      return Response.json({ error: 'Invalid signature' }, { status: 403 });
    }

    const customerId = url.searchParams.get('logged_in_customer_id');
    if (!customerId) {
      return Response.json({ error: 'Not authenticated' }, { status: 401 });
    }

    let bike;
    try {
      const body = await request.json();
      bike = body.vm_bike;
    } catch {
      return Response.json({ error: 'Invalid request body' }, { status: 400 });
    }

    if (!bike || !bike.collectionTag) {
      return Response.json({ error: 'Invalid bike data' }, { status: 400 });
    }

    const shop = url.searchParams.get('shop');
    const note = JSON.stringify({ vm_bike: bike });

    const apiResp = await fetch(
      `https://${shop}/admin/api/${API_VERSION}/customers/${customerId}.json`,
      {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'X-Shopify-Access-Token': env.SHOPIFY_ADMIN_TOKEN,
        },
        body: JSON.stringify({ customer: { id: Number(customerId), note } }),
      }
    );

    if (!apiResp.ok) {
      const detail = await apiResp.text();
      console.error('Admin API error:', apiResp.status, detail);
      return Response.json({ error: 'Failed to save' }, { status: 500 });
    }

    return Response.json({ success: true });
  },
};
