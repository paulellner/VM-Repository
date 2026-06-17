/**
 * VeloMatch Pro — Worker
 *
 * Shopify OAuth (einmalig):
 *   GET /setup?shop=velomatch.myshopify.com
 *   GET /callback
 *
 * App Proxy Endpunkte:
 *   POST /save                  → Rad in customer.note speichern
 *   POST /cancel                → Abo-Kündigung beantragen
 *   GET  /bike                  → gespeichertes Rad lesen
 *   GET  /bike/health           → Verschleißstatus aller Komponenten
 *   POST /bike/health/reset     → Komponente als erneuert markieren
 *   GET  /strava/connect        → Strava OAuth starten
 *   GET  /strava/callback       → Token tauschen, Daten speichern
 *   GET  /strava/profile        → gespeicherte Daten lesen (auto-refresh)
 *   GET  /strava/refresh        → Daten neu laden via refresh_token
 *   GET  /strava/disconnect     → Strava trennen + Athleten-Slot freigeben
 *
 * Secrets:
 *   SHOPIFY_CLIENT_ID / SHOPIFY_CLIENT_SECRET / SHOPIFY_ADMIN_TOKEN
 *   STRAVA_CLIENT_ID  / STRAVA_CLIENT_SECRET
 */

const API_VERSION  = '2025-01';
const STRAVA_AUTH   = 'https://www.strava.com/oauth/authorize';
const STRAVA_TOKEN  = 'https://www.strava.com/oauth/token';
const STRAVA_DEAUTH = 'https://www.strava.com/oauth/deauthorize';
const STRAVA_API    = 'https://www.strava.com/api/v3';
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

/* ── Verschleiß-Modell ────────────────────────────────────────────────────────
   Basis-Intervalle aus Herstellerempfehlungen und Industrie-Richtwerten.
   Multiplikatoren bilden Fahrbedingungen ab (Nässe via Saison-Proxy,
   Watt aus Strava-Aktivitätsdaten, Höhenmeter für Bremsbel\u00e4ge).
   ─────────────────────────────────────────────────────────────────────────── */

const WEAR_COMPONENTS = [
  /* id             name                            maxKm  warnPct critPct mult       */
  { id: 'chain',      name: 'Kette',                maxKm: 2500,  warnPct: 0.70, critPct: 0.90, mult: 'overall',
    tip: 'Kettenverschlei\u00dflehre nutzen \u2014 ab 0,75 mm L\u00e4ngung sofort tauschen.' },
  { id: 'cassette',   name: 'Kassette',             maxKm: 8000,  warnPct: 0.70, critPct: 0.90, mult: 'overall',
    tip: 'Kassette sp\u00e4testens beim dritten Kettenwechsel erneuern.' },
  { id: 'brakepads',  name: 'Bremsbel\u00e4ge',        maxKm: 2500,  warnPct: 0.65, critPct: 0.85, mult: 'elev',
    tip: 'Disc-Bel\u00e4ge: Mindest-Materialst\u00e4rke 1,5 mm. Quietschen = sofort pr\u00fcfen.' },
  { id: 'cables',     name: 'Schalt- & Bremsz\u00fcge', maxKm: 10000, warnPct: 0.75, critPct: 0.90, mult: 'wet',
    tip: 'Bei z\u00f6gerlichem Schalten oder harten Schalthebeln Z\u00fcge + H\u00fcllen tauschen.' },
  { id: 'chainrings', name: 'Kettensterne',          maxKm: 15000, warnPct: 0.75, critPct: 0.90, mult: 'overall',
    tip: 'Abnutzung erkennbar an spitzen, schiefstehenden Z\u00e4hnen ("Haifischz\u00e4hne").' },
  { id: 'tires',      name: 'Bereifung',             maxKm: 4000,  warnPct: 0.65, critPct: 0.85, mult: 'none',
    tip: 'Hinterreifen verschlei\u00dft 2\u00d7 schneller. Bei Rissen im Profil sofort tauschen.' },
  /* Verbrauchsmittel */
  { id: 'chain_lube', name: 'Kettenpflege',          maxKm: 500,   warnPct: 0.60, critPct: 0.85, mult: 'lube',
    isConsumable: true,
    tip: 'Nasse Fahrten halbieren das Intervall. Kette bis zur n\u00e4chsten Fahrt einziehen lassen.' },
  { id: 'cleaner',    name: 'Reinigungsset',          maxRides: 5,  warnPct: 0.60, critPct: 0.90, mult: 'none',
    isConsumable: true, isRideBased: true,
    tip: 'Regelm\u00e4\u00dfige Reinigung verl\u00e4ngert die Lebensdauer aller Antriebsteile erheblich.' },
];

/* Fahrbedingungen aus den letzten 90 Tagen → Verschleißmultiplikatoren.
   Quellen: Saison (Nässeproxy), average_watts, total_elevation_gain.
   Für Räder ohne Powermeter wird powerFactor = 0 gesetzt (konservativ). */
function computeConditions(activities) {
  const outdoor = activities.filter(a =>
    ['Ride', 'MountainBikeRide', 'GravelRide'].includes(a.type) && !a.trainer
  );
  if (!outdoor.length) return { overall: 1.0, wet: 1.0, lube: 1.0, elev: 1.0, wet_pct: 0, avg_watts: null, elev_per_km: 0 };

  /* Nässeproxy: Fahrten in Monaten Okt–März (Mitteleuropa) */
  const wetRides = outdoor.filter(a => { const m = new Date(a.start_date).getMonth(); return m >= 9 || m <= 2; });
  const wetPct   = wetRides.length / outdoor.length;

  /* Leistungsfaktor: durchschnittliche Watt vs. Basis 150 W */
  const withPower  = outdoor.filter(a => a.average_watts > 0);
  const avgWatts   = withPower.length
    ? Math.round(withPower.reduce((s, a) => s + a.average_watts, 0) / withPower.length)
    : null;
  const powerFactor = avgWatts ? Math.min(0.30, Math.max(0, (avgWatts - 150) / 200)) : 0;

  /* Höhenfaktor: Bremsbel\u00e4ge verschleißen bei viel Bergfahrt schneller */
  const totDist    = outdoor.reduce((s, a) => s + a.distance, 0);
  const totElev    = outdoor.reduce((s, a) => s + (a.total_elevation_gain || 0), 0);
  const elevPerKm  = totDist > 0 ? Math.round(totElev / (totDist / 1000)) : 0;
  const elevFactor = Math.min(0.25, elevPerKm / 40);

  const wetFactor = wetPct * 0.50;
  const r2        = v => Math.round(v * 100) / 100;

  return {
    overall:     r2(1.0 + wetFactor + powerFactor + elevFactor),  /* Antrieb gesamt  */
    wet:         r2(1.0 + wetFactor),                              /* Züge (Korrosion)*/
    lube:        r2(1.0 + wetPct * 1.5),                          /* Schmiermittel   */
    elev:        r2(1.0 + elevFactor + wetFactor * 0.5),          /* Bremsbel\u00e4ge     */
    wet_pct:     Math.round(wetPct * 100),
    avg_watts:   avgWatts,
    elev_per_km: elevPerKm,
  };
}

/* Verschleiß aller Komponenten berechnen und in Status (green/yellow/red) umwandeln. */
function computeHealth(allTimeKm, allTimeRides, cond, bundles) {
  const b      = bundles   || {};
  const comps  = b.components || {};
  const startKm    = b.odometer_start_km ?? allTimeKm;
  const startRides = b.rides_start       ?? allTimeRides;

  const results = WEAR_COMPONENTS.map(def => {
    const state      = comps[def.id] || {};
    const resetKm    = state.reset_km    ?? startKm;
    const resetRides = state.reset_rides ?? startRides;

    let wearPct, kmSince, effectiveKm, kmLeft, ridesLeft;

    if (def.isRideBased) {
      const rSince = Math.max(0, allTimeRides - resetRides);
      wearPct   = Math.min(1, rSince / def.maxRides);
      ridesLeft = Math.max(0, def.maxRides - rSince);
    } else {
      const raw   = Math.max(0, allTimeKm - resetKm);
      const mult  = cond[def.mult] ?? 1.0;
      effectiveKm = Math.round(raw * mult);
      wearPct     = Math.min(1, effectiveKm / def.maxKm);
      kmSince     = raw;
      /* Rückrechnung in echte km, die der Fahrer noch hat */
      kmLeft      = mult > 0 ? Math.max(0, Math.round((def.maxKm - effectiveKm) / mult)) : 0;
    }

    const status = wearPct >= def.critPct ? 'red'
                 : wearPct >= def.warnPct ? 'yellow'
                 : 'green';

    return {
      id: def.id, name: def.name, status,
      wear_pct:        Math.round(wearPct * 100),
      km_since_reset:  kmSince    ?? null,
      effective_km:    effectiveKm ?? null,
      km_remaining:    kmLeft      ?? null,
      rides_remaining: ridesLeft   ?? null,
      reset_at:        state.reset_at ?? null,
      tip:             def.tip,
      is_consumable:   !!def.isConsumable,
      is_ride_based:   !!def.isRideBased,
      max_km:          def.maxKm    ?? null,
      max_rides:       def.maxRides ?? null,
    };
  });

  const statuses = results.map(r => r.status);
  const overall  = statuses.includes('red') ? 'red' : statuses.includes('yellow') ? 'yellow' : 'green';

  const alerts = results
    .filter(r => r.status !== 'green')
    .sort((a, b) => b.wear_pct - a.wear_pct)
    .map(r => ({
      level:   r.status,
      id:      r.id,
      name:    r.name,
      message: r.status === 'red'
        ? `${r.name} kurz vor Verschlei\u00dfgrenze \u2014 jetzt erneuern`
        : `${r.name} bald f\u00e4llig \u2014 bitte pr\u00fcfen`,
    }));

  return { components: results, overall_status: overall, alerts };
}

/* ─────────────────────────────────────────────────────────────────────────── */

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

    /* ── GET /bike/health — Verschleißstatus aller Komponenten ──────────────── */
    if (url.pathname === '/bike/health') {
      const valid = await verifyProxySignature(url.searchParams, env.SHOPIFY_CLIENT_SECRET);
      if (!valid) return Response.json({ error: 'Invalid signature' }, { status: 403 });

      const customerId = url.searchParams.get('logged_in_customer_id');
      if (!customerId) return Response.json({ ok: false, error: 'not_authenticated' }, { status: 401 });

      const shop = url.searchParams.get('shop');
      const note = await getNote(shop, customerId, env.SHOPIFY_ADMIN_TOKEN);

      /* Strava muss verbunden sein — liefert den Kilometerzähler */
      if (!note.strava?.profile) {
        return Response.json({ ok: false, error: 'strava_not_connected' });
      }

      /* Token erneuern falls abgelaufen */
      let s = note.strava;
      if (s.token_expires_at && Date.now() / 1000 > s.token_expires_at - 120) {
        const refreshed = await refreshAndStore(env, shop, customerId, note);
        if (refreshed) { s = refreshed; note.strava = refreshed; }
      }

      /* Aktivitäten (90 Tage) + aktuelle Gesamtstatistik parallel laden —
         so spiegeln sich neue Fahrten sofort im Verschleißstatus wider. */
      const since90 = Math.floor((Date.now() - 90 * 24 * 60 * 60 * 1000) / 1000);
      let acts = [];
      let allTimeKm    = s.profile?.all_time_distance_km ?? 0;
      let allTimeRides = s.profile?.all_time_rides        ?? 0;
      try {
        const [actsResp, statsResp] = await Promise.all([
          fetch(`${STRAVA_API}/athlete/activities?per_page=100&after=${since90}`,
            { headers: { Authorization: `Bearer ${s.access_token}` } }),
          fetch(`${STRAVA_API}/athletes/${s.athlete_id}/stats`,
            { headers: { Authorization: `Bearer ${s.access_token}` } }),
        ]);
        if (actsResp.ok) { acts = await actsResp.json(); if (!Array.isArray(acts)) acts = []; }
        if (statsResp.ok) {
          const stats = await statsResp.json();
          if (stats?.all_ride_totals) {
            allTimeKm    = Math.round((stats.all_ride_totals.distance ?? 0) / 1000);
            allTimeRides = stats.all_ride_totals.count ?? allTimeRides;
            /* Cache in customer.note aktualisieren (fire-and-forget) */
            if (note.strava?.profile) {
              note.strava.profile.all_time_distance_km = allTimeKm;
              note.strava.profile.all_time_rides       = allTimeRides;
              putNote(shop, customerId, env.SHOPIFY_ADMIN_TOKEN, note)
                .catch(e => console.error('Stats cache update failed:', e));
            }
          }
        }
      } catch (e) { console.error('Strava fetch failed:', e); }

      /* vm_bundles beim ersten Aufruf initialisieren */
      if (!note.vm_bundles) {
        note.vm_bundles = {
          initialized_at:    new Date().toISOString(),
          odometer_start_km: allTimeKm,
          rides_start:       allTimeRides,
          components:        {},
        };
        putNote(shop, customerId, env.SHOPIFY_ADMIN_TOKEN, note)
          .catch(e => console.error('vm_bundles init save failed:', e));
      }

      /* Noch keine Kalibrierung → Setup-Wizard im Client anzeigen */
      if (!note.vm_bundles.setup_done) {
        return Response.json({ ok: true, needs_setup: true, odometer_km: allTimeKm });
      }

      const cond   = computeConditions(acts);
      const health = computeHealth(allTimeKm, allTimeRides, cond, note.vm_bundles);

      return Response.json({
        ok:             true,
        odometer_km:    allTimeKm,
        odometer_rides: allTimeRides,
        conditions:     cond,
        ...health,
      });
    }

    /* ── POST /bike/health/reset — Komponente als erneuert markieren ─────────── */
    if (url.pathname === '/bike/health/reset') {
      const valid = await verifyProxySignature(url.searchParams, env.SHOPIFY_CLIENT_SECRET);
      if (!valid) return Response.json({ error: 'Invalid signature' }, { status: 403 });
      if (request.method !== 'POST') return Response.json({ error: 'Method not allowed' }, { status: 405 });

      const customerId = url.searchParams.get('logged_in_customer_id');
      if (!customerId) return Response.json({ error: 'not_authenticated' }, { status: 401 });

      let body;
      try { body = await request.json(); } catch {
        return Response.json({ error: 'bad_request' }, { status: 400 });
      }
      const { component_id } = body || {};
      if (!component_id) return Response.json({ error: 'missing component_id' }, { status: 400 });

      const def = WEAR_COMPONENTS.find(c => c.id === component_id);
      if (!def) return Response.json({ error: 'unknown_component' }, { status: 400 });

      const shop = url.searchParams.get('shop');
      const note = await getNote(shop, customerId, env.SHOPIFY_ADMIN_TOKEN);

      const allTimeKm    = note.strava?.profile?.all_time_distance_km ?? 0;
      const allTimeRides = note.strava?.profile?.all_time_rides        ?? 0;

      if (!note.vm_bundles)            note.vm_bundles            = {};
      if (!note.vm_bundles.components) note.vm_bundles.components = {};

      const resetAt = new Date().toISOString().split('T')[0];
      note.vm_bundles.components[component_id] = def.isRideBased
        ? { reset_rides: allTimeRides, reset_at: resetAt }
        : { reset_km: allTimeKm,       reset_at: resetAt };

      await putNote(shop, customerId, env.SHOPIFY_ADMIN_TOKEN, note);
      return Response.json({ ok: true, component_id, reset_at: resetAt });
    }

    /* ── POST /bike/setup — Erstkalibrierung speichern ─────────────────────── */
    if (url.pathname === '/bike/setup') {
      if (request.method !== 'POST') return Response.json({ error: 'Method not allowed' }, { status: 405 });
      const valid = await verifyProxySignature(url.searchParams, env.SHOPIFY_CLIENT_SECRET);
      if (!valid) return Response.json({ error: 'Invalid signature' }, { status: 403 });

      const customerId = url.searchParams.get('logged_in_customer_id');
      if (!customerId) return Response.json({ error: 'not_authenticated' }, { status: 401 });

      let body;
      try { body = await request.json(); } catch {
        return Response.json({ error: 'bad_request' }, { status: 400 });
      }
      const { bikeKm, chainKmSince, cassetteBrakepadsKmSince, cablesTiresChainringsKmSince } = body || {};

      const shop = url.searchParams.get('shop');
      const note = await getNote(shop, customerId, env.SHOPIFY_ADMIN_TOKEN);

      if (!note.strava?.profile) {
        return Response.json({ ok: false, error: 'strava_not_connected' });
      }

      let s = note.strava;
      if (s.token_expires_at && Date.now() / 1000 > s.token_expires_at - 120) {
        const refreshed = await refreshAndStore(env, shop, customerId, note);
        if (refreshed) { s = refreshed; note.strava = refreshed; }
      }

      const allTimeKm    = s.profile?.all_time_distance_km ?? 0;
      const allTimeRides = s.profile?.all_time_rides        ?? 0;
      const today        = new Date().toISOString().split('T')[0];

      const mkReset = km => ({ reset_km: Math.max(0, allTimeKm - (km || 0)), reset_at: today });

      if (!note.vm_bundles) note.vm_bundles = {};
      note.vm_bundles.setup_done        = true;
      note.vm_bundles.bike_total_km     = bikeKm ?? null;
      note.vm_bundles.strava_baseline_km = allTimeKm;
      note.vm_bundles.components = {
        chain:      mkReset(chainKmSince),
        cassette:   mkReset(cassetteBrakepadsKmSince),
        brakepads:  mkReset(cassetteBrakepadsKmSince),
        cables:     mkReset(cablesTiresChainringsKmSince),
        tires:      mkReset(cablesTiresChainringsKmSince),
        chainrings: mkReset(cablesTiresChainringsKmSince),
        chain_lube: mkReset(Math.min(Math.round((chainKmSince || 0) / 5), 400)),
        cleaner:    { reset_rides: Math.max(0, allTimeRides - 3), reset_at: today },
      };

      await putNote(shop, customerId, env.SHOPIFY_ADMIN_TOKEN, note);

      /* Aktivitäten für Verschleißmultiplikator laden */
      const since90 = Math.floor((Date.now() - 90 * 24 * 60 * 60 * 1000) / 1000);
      let acts = [];
      try {
        const r = await fetch(
          `${STRAVA_API}/athlete/activities?per_page=100&after=${since90}`,
          { headers: { Authorization: `Bearer ${s.access_token}` } }
        );
        if (r.ok) { acts = await r.json(); if (!Array.isArray(acts)) acts = []; }
      } catch (e) { console.error('Activities fetch failed:', e); }

      const cond   = computeConditions(acts);
      const health = computeHealth(allTimeKm, allTimeRides, cond, note.vm_bundles);

      return Response.json({
        ok:             true,
        odometer_km:    allTimeKm,
        odometer_rides: allTimeRides,
        conditions:     cond,
        ...health,
      });
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

    /* ── C2: Strava trennen / ausloggen (App Proxy GET /strava/disconnect) ── */
    if (url.pathname === '/strava/disconnect') {
      const valid = await verifyProxySignature(url.searchParams, env.SHOPIFY_CLIENT_SECRET);
      if (!valid) return Response.json({ error: 'Invalid signature' }, { status: 403 });

      const customerId = url.searchParams.get('logged_in_customer_id');
      if (!customerId) return Response.json({ connected: false }, { status: 401 });

      const shop = url.searchParams.get('shop');
      const note = await getNote(shop, customerId, env.SHOPIFY_ADMIN_TOKEN);

      if (note.strava) {
        /* Best-effort: Zugriff bei Strava widerrufen — gibt den Athleten-Slot frei. */
        let accessToken = note.strava.access_token;
        if (note.strava.token_expires_at &&
            Date.now() / 1000 > note.strava.token_expires_at - 120 &&
            note.strava.refresh_token) {
          const tok = await refreshStravaToken(env, note.strava.refresh_token);
          if (tok && tok.access_token) accessToken = tok.access_token;
        }
        if (accessToken) {
          try {
            await fetch(`${STRAVA_DEAUTH}?access_token=${encodeURIComponent(accessToken)}`, { method: 'POST' });
          } catch (e) { console.error('Strava deauthorize failed:', e); }
        }
        /* Strava-Block aus der Note entfernen (vm_bike bleibt erhalten). */
        delete note.strava;
        await putNote(shop, customerId, env.SHOPIFY_ADMIN_TOKEN, note);
      }

      return Response.json({ connected: false });
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

    /* ── F: Abo kündigen (App Proxy POST /cancel) ────────────────────────── */
    if (url.pathname === '/cancel') {
      if (request.method !== 'POST') return Response.json({ error: 'Method not allowed' }, { status: 405 });
      const valid = await verifyProxySignature(url.searchParams, env.SHOPIFY_CLIENT_SECRET);
      if (!valid) return Response.json({ error: 'Invalid signature' }, { status: 403 });

      const customerId = url.searchParams.get('logged_in_customer_id');
      if (!customerId) return Response.json({ error: 'not_authenticated' }, { status: 401 });

      const shop = url.searchParams.get('shop');

      /* Kundendaten holen (Note + Tags in einer Anfrage) */
      const custResp = await fetch(
        `https://${shop}/admin/api/${API_VERSION}/customers/${customerId}.json`,
        { headers: { 'X-Shopify-Access-Token': env.SHOPIFY_ADMIN_TOKEN } }
      );
      if (!custResp.ok) return Response.json({ error: 'customer_not_found' }, { status: 500 });

      const custData = await custResp.json();
      const customer = custData.customer;

      /* Note aktualisieren */
      let note = {};
      try { note = JSON.parse(customer.note || '{}'); } catch {}
      const now = new Date().toISOString();
      note.vm_pro = { ...(note.vm_pro || {}), cancel_requested_at: now };

      /* Tag hinzufügen (vm-pro-cancel-requested) damit der Shop-Inhaber es sieht */
      const existingTags = customer.tags || '';
      const tagList = existingTags.split(',').map(t => t.trim()).filter(Boolean);
      if (!tagList.includes('vm-pro-cancel-requested')) {
        tagList.push('vm-pro-cancel-requested');
      }

      const saveResp = await fetch(
        `https://${shop}/admin/api/${API_VERSION}/customers/${customerId}.json`,
        {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json', 'X-Shopify-Access-Token': env.SHOPIFY_ADMIN_TOKEN },
          body: JSON.stringify({
            customer: {
              id:   Number(customerId),
              note: JSON.stringify(note),
              tags: tagList.join(','),
            },
          }),
        }
      );

      if (!saveResp.ok) {
        console.error('Cancel save failed:', saveResp.status, await saveResp.text());
        return Response.json({ error: 'save_failed' }, { status: 500 });
      }

      return Response.json({ ok: true, cancel_requested_at: now });
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
