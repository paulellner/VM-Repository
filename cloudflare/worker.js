/**
 * VeloMatch Pro — Worker
 *
 * Shopify OAuth (einmalig):
 *   GET /setup?shop=velomatch.myshopify.com
 *   GET /callback
 *
 * App Proxy Endpunkte:
 *   POST /save              → Rad in customer.note speichern
 *   GET  /strava/connect    → Strava OAuth starten
 *   GET  /strava/callback   → Token tauschen, Daten speichern
 *
 * Secrets:
 *   SHOPIFY_CLIENT_ID / SHOPIFY_CLIENT_SECRET / SHOPIFY_ADMIN_TOKEN
 *   STRAVA_CLIENT_ID  / STRAVA_CLIENT_SECRET
 */

const API_VERSION  = '2025-01';
const STRAVA_AUTH  = 'https://www.strava.com/oauth/authorize';
const STRAVA_TOKEN = 'https://www.strava.com/oauth/token';
const STRAVA_API   = 'https://www.strava.com/api/v3';

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

async function getNote(shop, customerId, token) {
  const r = await fetch(
    `https://${shop}/admin/api/${API_VERSION}/customers/${customerId}.json`,
    { headers: { 'X-Shopify-Access-Token': token } }
  );
  if (!r.ok) return {};
  const d = await r.json();
  try { return JSON.parse(d.customer?.note || '{}'); } catch { return {}; }
}

async function putNote(shop, customerId, token, note) {
  return fetch(
    `https://${shop}/admin/api/${API_VERSION}/customers/${customerId}.json`,
    {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'X-Shopify-Access-Token': token },
      body: JSON.stringify({ customer: { id: Number(customerId), note: JSON.stringify(note) } }),
    }
  );
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    /* ── A: Shopify OAuth starten ─────────────────────────────────────────── */
    if (url.pathname === '/setup') {
      const shop = url.searchParams.get('shop') || 'velomatch.myshopify.com';
      const redirectUri = encodeURIComponent(`${url.origin}/callback`);
      return Response.redirect(
        `https://${shop}/admin/oauth/authorize` +
        `?client_id=${env.SHOPIFY_CLIENT_ID}&scope=write_customers` +
        `&redirect_uri=${redirectUri}&state=setup`,
        302
      );
    }

    /* ── B: Shopify OAuth Callback ────────────────────────────────────────── */
    if (url.pathname === '/callback') {
      const code = url.searchParams.get('code');
      const shop = url.searchParams.get('shop');
      if (!code || !shop) return new Response('Fehlende Parameter', { status: 400 });

      const r = await fetch(`https://${shop}/admin/oauth/access_token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ client_id: env.SHOPIFY_CLIENT_ID, client_secret: env.SHOPIFY_CLIENT_SECRET, code }),
      });
      const td = await r.json();
      if (!td.access_token) return new Response('Token fehlgeschlagen: ' + JSON.stringify(td), { status: 500 });

      return new Response(
        `<!DOCTYPE html><html><body style="font-family:monospace;padding:32px">
        <h2>Setup abgeschlossen!</h2>
        <p>wrangler secret put SHOPIFY_ADMIN_TOKEN</p>
        <p style="background:#f0f0f0;padding:16px;word-break:break-all"><strong>${td.access_token}</strong></p>
        <p>Scopes: ${td.scope}</p></body></html>`,
        { headers: { 'Content-Type': 'text/html' } }
      );
    }

    /* ── C0: Strava-Profil lesen (App Proxy GET /strava/profile) ──────────── */
    if (url.pathname === '/strava/profile') {
      const valid = await verifyProxySignature(url.searchParams, env.SHOPIFY_CLIENT_SECRET);
      if (!valid) return Response.json({ error: 'Invalid signature' }, { status: 403 });

      const customerId = url.searchParams.get('logged_in_customer_id');
      if (!customerId) return Response.json({ connected: false }, { status: 401 });

      const shop = url.searchParams.get('shop');
      const note = await getNote(shop, customerId, env.SHOPIFY_ADMIN_TOKEN);
      if (!note.strava || !note.strava.athlete_id) {
        return Response.json({ connected: false });
      }

      /* Tokens bleiben serverseitig — nur Anzeige-Daten zurückgeben */
      const s = note.strava;
      return Response.json({
        connected:        true,
        connected_at:     s.connected_at,
        token_expires_at: s.token_expires_at,
        athlete:          s.athlete,
        profile:          s.profile,
      });
    }

    /* ── C: Strava verbinden (App Proxy GET /strava/connect) ──────────────── */
    if (url.pathname === '/strava/connect') {
      const valid = await verifyProxySignature(url.searchParams, env.SHOPIFY_CLIENT_SECRET);
      if (!valid) return Response.json({ error: 'Invalid signature' }, { status: 403 });

      const customerId = url.searchParams.get('logged_in_customer_id');
      const shop       = url.searchParams.get('shop');
      if (!customerId) return new Response('Nicht eingeloggt', { status: 401 });

      const state      = btoa(JSON.stringify({ customerId, shop }));
      const redirectUri = encodeURIComponent(`${url.origin}/strava/callback`);
      return Response.redirect(
        `${STRAVA_AUTH}?client_id=${env.STRAVA_CLIENT_ID}` +
        `&redirect_uri=${redirectUri}&response_type=code` +
        `&approval_prompt=force&scope=read,activity:read_all&state=${state}`,
        302
      );
    }

    /* ── D: Strava Callback ───────────────────────────────────────────────── */
    if (url.pathname === '/strava/callback') {
      const error    = url.searchParams.get('error');
      const code     = url.searchParams.get('code');
      const stateStr = url.searchParams.get('state');

      let state;
      try { state = JSON.parse(atob(stateStr || '')); } catch {
        return new Response('Ungültiger State', { status: 400 });
      }
      const { customerId, shop } = state;
      const dashUrl = `https://${shop}/pages/vm-pro-dashboard`;

      if (error === 'access_denied') return Response.redirect(dashUrl + '?strava=denied', 302);
      if (!code) return new Response('Fehlender Code', { status: 400 });

      /* Token tauschen */
      const tokenResp = await fetch(STRAVA_TOKEN, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_id:     env.STRAVA_CLIENT_ID,
          client_secret: env.STRAVA_CLIENT_SECRET,
          code,
          grant_type: 'authorization_code',
        }),
      });
      const td = await tokenResp.json();
      if (!td.access_token) return new Response('Strava-Auth fehlgeschlagen: ' + JSON.stringify(td), { status: 500 });

      /* Aktivitäten + Athleten-Stats parallel laden */
      const [actsResp, statsResp] = await Promise.all([
        fetch(`${STRAVA_API}/athlete/activities?per_page=30`, {
          headers: { 'Authorization': `Bearer ${td.access_token}` },
        }),
        fetch(`${STRAVA_API}/athletes/${td.athlete.id}/stats`, {
          headers: { 'Authorization': `Bearer ${td.access_token}` },
        }),
      ]);
      const [activities, athleteStats] = await Promise.all([actsResp.json(), statsResp.json()]);

      /* Fahr-Profil berechnen */
      const rideTypes = ['Ride', 'VirtualRide', 'MountainBikeRide', 'GravelRide', 'EBikeRide'];
      const rides = Array.isArray(activities) ? activities.filter(a => rideTypes.includes(a.type)) : [];
      const avgDist = rides.length
        ? Math.round(rides.reduce((s, a) => s + a.distance, 0) / rides.length / 100) / 10
        : null;
      const typeCounts = {};
      rides.forEach(a => { typeCounts[a.type] = (typeCounts[a.type] || 0) + 1; });
      const dominantType = Object.entries(typeCounts).sort((a, b) => b[1] - a[1])[0]?.[0] || null;

      /* In customer.note mergen (bestehende Daten nicht überschreiben) */
      const note = await getNote(shop, customerId, env.SHOPIFY_ADMIN_TOKEN);
      note.strava = {
        athlete_id:       td.athlete.id,
        access_token:     td.access_token,
        refresh_token:    td.refresh_token,
        token_expires_at: td.expires_at,
        connected_at:     new Date().toISOString(),
        athlete: {
          firstname: td.athlete.firstname,
          lastname:  td.athlete.lastname,
          profile:   td.athlete.profile_medium,
          city:      td.athlete.city,
          country:   td.athlete.country,
          weight:    td.athlete.weight,
          bikes: (td.athlete.bikes || []).map(b => ({
            id:          b.id,
            name:        b.name,
            distance_km: Math.round(b.distance / 1000),
          })),
        },
        profile: {
          dominant_ride_type:   dominantType,
          avg_ride_distance_km: avgDist,
          recent_rides:         rides.length,
          ytd_rides:            athleteStats.ytd_ride_totals?.count ?? null,
          ytd_distance_km:      athleteStats.ytd_ride_totals
            ? Math.round(athleteStats.ytd_ride_totals.distance / 1000)
            : null,
          all_time_rides:       athleteStats.all_ride_totals?.count   ?? null,
          all_time_distance_km: athleteStats.all_ride_totals
            ? Math.round(athleteStats.all_ride_totals.distance / 1000)
            : null,
          computed_at: new Date().toISOString(),
        },
      };

      const saveResp = await putNote(shop, customerId, env.SHOPIFY_ADMIN_TOKEN, note);
      if (!saveResp.ok) {
        console.error('Note save failed:', saveResp.status, await saveResp.text());
      }

      return Response.redirect(dashUrl + '?strava=connected', 302);
    }

    /* ── E: Bike speichern (App Proxy POST /save) ─────────────────────────── */
    if (request.method !== 'POST') {
      return Response.json({ error: 'Not found' }, { status: 404 });
    }

    const valid = await verifyProxySignature(url.searchParams, env.SHOPIFY_CLIENT_SECRET);
    if (!valid) return Response.json({ error: 'Invalid signature' }, { status: 403 });

    const customerId = url.searchParams.get('logged_in_customer_id');
    if (!customerId) return Response.json({ error: 'Not authenticated' }, { status: 401 });

    let bike;
    try {
      const b = await request.json();
      bike = b.vm_bike;
    } catch {
      return Response.json({ error: 'Invalid request body' }, { status: 400 });
    }
    if (!bike || !bike.collectionTag) return Response.json({ error: 'Invalid bike data' }, { status: 400 });

    const shop = url.searchParams.get('shop');
    const note = await getNote(shop, customerId, env.SHOPIFY_ADMIN_TOKEN);
    note.vm_bike = bike;

    const apiResp = await putNote(shop, customerId, env.SHOPIFY_ADMIN_TOKEN, note);
    if (!apiResp.ok) {
      const detail = await apiResp.text();
      console.error('Admin API error:', apiResp.status, detail);
      return Response.json({ error: 'Failed to save' }, { status: 500 });
    }

    return Response.json({ success: true });
  },
};
