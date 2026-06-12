/**
 * VeloMatch Pro — Bike Save Worker
 *
 * Shopify App Proxy endpoint: POST /apps/vm-pro/save
 * Shopify forwards the request here and injects:
 *   ?shop=velomatch.myshopify.com
 *   &logged_in_customer_id=<number>
 *   &signature=<hmac-sha256>
 *   &timestamp=<unix>
 *
 * Environment secrets (set via: wrangler secret put <NAME>):
 *   SHOPIFY_CLIENT_SECRET  — App client secret (for signature verification)
 *   SHOPIFY_ADMIN_TOKEN    — Admin API access token (from Custom App)
 */

const API_VERSION = '2025-01';

async function verifySignature(params, secret) {
  const sig = params.get('signature');
  if (!sig) return false;

  const message = [...params.entries()]
    .filter(([k]) => k !== 'signature')
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join('');

  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false, ['sign']
  );
  const buf = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  const hex = [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
  return hex === sig;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    /* Only accept POST */
    if (request.method !== 'POST') {
      return Response.json({ error: 'Method not allowed' }, { status: 405 });
    }

    /* Verify this is a genuine Shopify App Proxy call */
    const valid = await verifySignature(url.searchParams, env.SHOPIFY_CLIENT_SECRET);
    if (!valid) {
      return Response.json({ error: 'Invalid signature' }, { status: 403 });
    }

    /* Shopify adds logged_in_customer_id only for authenticated customers */
    const customerId = url.searchParams.get('logged_in_customer_id');
    if (!customerId) {
      return Response.json({ error: 'Not authenticated' }, { status: 401 });
    }

    /* Parse the bike payload */
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

    /* Write to customer.note via Admin API */
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
