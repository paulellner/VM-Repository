/**
 * VeloMatch Pro — Worker
 *
 * Shopify OAuth (einmalig):
 *   GET /setup?shop=velomatch.myshopify.com
 *   GET /callback
 *
 * App Proxy Endpunkte:
 *   POST /save              → Rad in customer.note speichern
 *   GET  /strava/connect    → Strava OAuth starten (nur Erst-Verbindung)
 *   GET  /strava/callback   → Token tauschen, Daten speichern
 *   GET  /strava/profile    → gespeicherte Daten lesen (Token bei Ablauf auto-refresh)
 *   GET  /strava/refresh    → Daten neu laden via refresh_token (ohne Re-Login)
 *
 * Secrets:
 *   SHOPIFY_CLIENT_ID / SHOPIFY_CLIENT_SECRET / SHOPIFY_ADMIN_TOKEN
 *   STRAVA_CLIENT_ID  / STRAVA_CLIENT_SECRET
 */

const API_VERSION  = '2025-01';
const STRAVA_AUTH  = 'https://www.strava.com/oauth/authorize';
const STRAVA_TOKEN = 'https://www.strava.com/oauth/token';
const STRAVA_API   = 'https://www.strava.com/api/v3';
const RIDE_TYPES   = ['Ride', 'VirtualRide', 'MountainBikeRide', 'GravelRide', 'EBikeRide'];

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

/* Athlet, Aktivitäten und Stats von Strava laden + Fahr-Profil berechnen.
   Wird sowohl beim Erst-Connect als auch beim Refresh genutzt. */
async function fetchStravaRecord(accessToken) {
  const athleteResp = await fetch(`${STRAVA_API}/athlete`, {
    headers: { 'Authorization': `Bearer ${accessToken}` },
  });
  const athlete = await athleteResp.json();
  if (!athlete || !athlete.id) throw new Error('Strava athlete fetch failed');

  const [actsResp, statsResp] = await Promise.all([
    fetch(`${STRAVA_API}/athlete/activities?per_page=30`, {
      headers: { 'Authorization': `Bearer ${accessToken}` },
    }),
    fetch(`${STRAVA_API}/athletes/${athlete.id}/stats`, {
      headers: { 'Authorization': `Bearer ${accessToken}` },
    }),
  ]);
  const activities   = await actsResp.json();
  const athleteStats = await statsResp.json();

  const rides = Array.isArray(activities) ? activities.filter(a => RIDE_TYPES.includes(a.type)) : [];
  const avgDist = rides.length
    ? Math.round(rides.reduce((s, a) => s + a.distance, 0) / rides.length / 100) / 10
    : null;
  const typeCounts = {};
  rides.forEach(a => { typeCounts[a.type] = (typeCounts[a.type] || 0) + 1; });
  const dominantType = Object.entries(typeCounts).sort((a, b) => b[1] - a[1])[0]?.[0] || null;

  return {
    athlete_id: athlete.id,
    athlete: {
      firstname: athlete.firstname,
      lastname:  athlete.lastname,
      profile:   athlete.profile_medium,
      city:      athlete.city,
      country:   athlete.country,
      weight:    athlete.weight,
      bikes: (athlete.bikes || []).map(b => ({
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
      all_time_rides:       athleteStats.all_ride_totals?.count ?? null,
      all_time_distance_km: athleteStats.all_ride_totals
        ? Math.round(athleteStats.all_ride_totals.distance / 1000)
        : null,
      computed_at: new Date().toISOString(),
    },
  };
}

/* Frischen Access-Token via refresh_token holen (kein erneuter Login nötig). */
async function refreshStravaToken(env, refreshToken) {
  const r = await fetch(STRAVA_TOKEN, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id:     env.STRAVA_CLIENT_ID,
      client_secret: env.STRAVA_CLIENT_SECRET,
      grant_type:    'refresh_token',
      refresh_token: refreshToken,
    }),
  });
  return r.json();
}

/* Token erneuern, Daten frisch laden und in der Notiz speichern.
   Gibt den aktualisierten strava-Block zurück oder null bei Fehler. */
async function refreshAndStore(env, shop, customerId, note) {
  const s = note.strava;
  if (!s || !s.refresh_token) return null;

  const tok = await refreshStravaToken(env, s.refresh_token);
  if (!tok.access_token) {
    console.error('Strava token refresh failed:', JSON.stringify(tok));
    return null;
  }

  const record = await fetchStravaRecord(tok.access_token);
  note.strava = {
    athlete_id:       record.athlete_id,
    access_token:     tok.access_token,
    refresh_token:    tok.refresh_token || s.refresh_token,
    token_expires_at: tok.expires_at,
    connected_at:     s.connected_at,             // ursprüngliches Verbindungsdatum bewahren
    refreshed_at:     new Date().toISOString(),
    athlete:          record.athlete,
    profile:          record.profile,
  };
  await putNote(shop, customerId, env.SHOPIFY_ADMIN_TOKEN, note);
  return note.strava;
}

function publicStrava(s) {
  return {
    connected:        true,
    connected_at:     s.connected_at,
    refreshed_at:     s.refreshed_at,
    token_expires_at: s.token_expires_at,
    athlete:          s.athlete,
    profile:          s.profile,
  };
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

    /* ── Bike lesen (App Proxy GET /bike) ─────────────────────────────────── */
    if (url.pathname === '/bike') {
      const valid = await verifyProxySignature(url.searchParams, env.SHOPIFY_CLIENT_SECRET);
      if (!valid) return Response.json({ error: 'Invalid signature' }, { status: 403 });

      const customerId = url.searchParams.get('logged_in_customer_id');
      if (!customerId) return Response.json({ bike: null }, { status: 401 });

      const shop = url.searchParams.get('shop');
      const note = await getNote(shop, customerId, env.SHOPIFY_ADMIN_TOKEN);
      return Response.json({ bike: note.vm_bike || null });
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

      let s = note.strava;
      /* Token abgelaufen (mit 2 Min. Puffer)? → automatisch erneuern, kein Re-Login. */
      if (s.token_expires_at && Date.now() / 1000 > s.token_expires_at - 120) {
        const refreshed = await refreshAndStore(env, shop, customerId, note);
        if (refreshed) s = refreshed;
      }
      return Response.json(publicStrava(s));
    }

    /* ── C1: Strava-Daten neu laden (App Proxy GET /strava/refresh) ───────── */
    if (url.pathname === '/strava/refresh') {
      const valid = await verifyProxySignature(url.searchParams, env.SHOPIFY_CLIENT_SECRET);
      if (!valid) return Response.json({ error: 'Invalid signature' }, { status: 403 });

      const customerId = url.searchParams.get('logged_in_customer_id');
      if (!customerId) return Response.json({ connected: false }, { status: 401 });

      const shop = url.searchParams.get('shop');
      const note = await getNote(shop, customerId, env.SHOPIFY_ADMIN_TOKEN);
      if (!note.strava || !note.strava.refresh_token) {
        return Response.json({ connected: false });
      }

      const refreshed = await refreshAndStore(env, shop, customerId, note);
      if (!refreshed) {
        /* Refresh fehlgeschlagen → alte Daten zurückgeben, Verbindung gilt als ungültig. */
        return Response.json({ connected: true, refresh_failed: true, ...publicStrava(note.strava) });
      }
      return Response.json(publicStrava(refreshed));
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

      /* Authorization Code gegen Tokens tauschen */
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

      const record = await fetchStravaRecord(td.access_token);

      /* In customer.note mergen (bestehende Daten wie vm_bike nicht überschreiben) */
      const note = await getNote(shop, customerId, env.SHOPIFY_ADMIN_TOKEN);
      const now  = new Date().toISOString();
      note.strava = {
        athlete_id:       record.athlete_id,
        access_token:     td.access_token,
        refresh_token:    td.refresh_token,
        token_expires_at: td.expires_at,
        connected_at:     now,
        refreshed_at:     now,
        athlete:          record.athlete,
        profile:          record.profile,
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
