// ═══════════════════════════════════════════════════════════════
// Virtual Pitch — Cloudflare Worker
// ═══════════════════════════════════════════════════════════════

const CORS_ORIGIN = 'https://virtualpitching.vercel.app';
const ACCESS_TTL  = 60 * 60 * 6;   // 6 hours
const REFRESH_TTL = 60 * 60 * 24 * 30; // 30 days

// ── CORS ──────────────────────────────────────────────────────
function corsHeaders(origin) {
  const allowed = [CORS_ORIGIN, 'http://localhost:3000'];
  const o = allowed.includes(origin) ? origin : CORS_ORIGIN;
  return {
    'Access-Control-Allow-Origin': o,
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,PATCH,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-Client-Token',
    'Access-Control-Allow-Credentials': 'true',
  };
}

function json(data, status = 200, origin = CORS_ORIGIN) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
  });
}

function err(msg, status = 400, origin = CORS_ORIGIN) {
  return json({ error: msg }, status, origin);
}

// ── JWT ───────────────────────────────────────────────────────
async function signJWT(payload, secret, expiresIn) {
  const header  = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body    = btoa(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + expiresIn }));
  const data    = `${header}.${body}`;
  const key     = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig     = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  const b64sig  = btoa(String.fromCharCode(...new Uint8Array(sig)));
  return `${data}.${b64sig}`;
}

async function verifyJWT(token, secret) {
  try {
    const [header, body, sig] = token.split('.');
    const key    = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const valid  = await crypto.subtle.verify('HMAC', key, Uint8Array.from(atob(sig), c => c.charCodeAt(0)), new TextEncoder().encode(`${header}.${body}`));
    if (!valid) return null;
    const payload = JSON.parse(atob(body));
    if (payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}

// ── CLIENT TOKEN (Next.js → Worker HMAC) ─────────────────────
async function verifyClientToken(token, secret) {
  try {
    const [ts, sig] = token.split('.');
    if (Math.abs(Date.now() - Number(ts)) > 30000) return false;
    const key   = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    return crypto.subtle.verify('HMAC', key, Uint8Array.from(atob(sig), c => c.charCodeAt(0)), new TextEncoder().encode(ts));
  } catch { return false; }
}

// ── AUTH MIDDLEWARE ───────────────────────────────────────────
async function requireAuth(req, env) {
  const authHeader = req.headers.get('Authorization') || '';
  const token = authHeader.replace('Bearer ', '');
  if (!token) return null;
  const payload = await verifyJWT(token, env.JWT_SECRET);
  if (!payload) return null;
  const account = await env.DB.prepare('SELECT * FROM accounts WHERE id = ?').bind(payload.sub).first();
  if (!account || account.is_banned) return null;
  return account;
}

async function requireAdmin(req, env) {
  const authHeader = req.headers.get('Authorization') || '';
  const token = authHeader.replace('Bearer ', '');
  if (!token) return null;
  const payload = await verifyJWT(token, env.ADMIN_JWT_SECRET);
  if (!payload || payload.role !== 'admin') return null;
  return payload;
}

// ── ECONOMY HELPERS ───────────────────────────────────────────
async function addCoins(db, accountId, amount, type, note) {
  const bank = await db.prepare('SELECT coin_supply FROM bank WHERE id = 1').first();
  if (bank.coin_supply < amount) throw new Error('Bank insufficient funds');
  await db.batch([
    db.prepare('UPDATE accounts SET coins = coins + ?, updated_at = unixepoch() WHERE id = ?').bind(amount, accountId),
    db.prepare('UPDATE bank SET coin_supply = coin_supply - ?, coins_in_circulation = coins_in_circulation + ? WHERE id = 1').bind(amount, amount),
    db.prepare('INSERT INTO transactions (account_id, type, amount, direction, note) VALUES (?,?,?,?,?)').bind(accountId, type, amount, 'credit', note),
  ]);
}

async function deductCoins(db, accountId, amount, type, note) {
  const account = await db.prepare('SELECT coins FROM accounts WHERE id = ?').bind(accountId).first();
  if (!account || account.coins < amount) throw new Error('Insufficient coins');
  await db.batch([
    db.prepare('UPDATE accounts SET coins = coins - ?, updated_at = unixepoch() WHERE id = ?').bind(amount, accountId),
    db.prepare('UPDATE bank SET coins_in_circulation = coins_in_circulation - ? WHERE id = 1').bind(amount),
    db.prepare('INSERT INTO transactions (account_id, type, amount, direction, note) VALUES (?,?,?,?,?)').bind(accountId, type, amount, 'debit', note),
  ]);
}

async function taxToBank(db, amount) {
  await db.prepare('UPDATE bank SET coin_supply = coin_supply + ?, total_taxed_back = total_taxed_back + ? WHERE id = 1').bind(amount, amount).run();
}

// ── GRANT CARD ────────────────────────────────────────────────
async function grantCard(db, accountId, cardId, via) {
  const card = await db.prepare('SELECT * FROM cards WHERE id = ? AND is_active = 1').bind(cardId).first();
  if (!card) throw new Error('Card not found');
  if (card.current_supply >= card.max_supply) throw new Error('Card max supply reached');

  const existing = await db.prepare('SELECT id, quantity FROM user_cards WHERE account_id = ? AND card_id = ?').bind(accountId, cardId).first();

  if (existing) {
    await db.prepare('UPDATE user_cards SET quantity = quantity + 1 WHERE id = ?').bind(existing.id).run();
  } else {
    await db.prepare(
      'INSERT INTO user_cards (account_id, card_id, current_overall, obtained_via) VALUES (?,?,?,?)'
    ).bind(accountId, cardId, card.base_overall, via).run();
    await db.prepare('UPDATE cards SET holder_count = holder_count + 1 WHERE id = ?').bind(cardId).run();
  }

  await db.prepare('UPDATE cards SET current_supply = current_supply + 1 WHERE id = ?').bind(cardId).run();
  return card;
}

// ── NOTIFICATIONS ─────────────────────────────────────────────
async function notify(db, accountId, type, title, body, refType = null, refId = null) {
  await db.prepare(
    'INSERT INTO notifications (account_id, type, title, body, ref_type, ref_id) VALUES (?,?,?,?,?,?)'
  ).bind(accountId, type, title, body, refType, refId).run();
}

// ── SPIN LOGIC (pack type) ────────────────────────────────────
async function spinPack(db, packId, count, accountId) {
  const slots = await db.prepare('SELECT * FROM pack_cards WHERE pack_id = ?').bind(packId).all();
  if (!slots.results.length) throw new Error('Pack has no cards');

  const totalWeight = slots.results.reduce((s, r) => s + r.weight, 0);
  const results = [];

  for (let i = 0; i < count; i++) {
    let rand = Math.random() * totalWeight;
    let chosen = slots.results[slots.results.length - 1];
    for (const slot of slots.results) {
      rand -= slot.weight;
      if (rand <= 0) { chosen = slot; break; }
    }
    results.push(chosen);
  }
  return results;
}

// ── WHEEL SPIN LOGIC ──────────────────────────────────────────
async function spinWheel(db, packId, count, accountId) {
  // Check which grand prize slots user already won
  const wonSlots = await db.prepare(
    'SELECT slot_id FROM user_wheel_wins WHERE account_id = ? AND pack_id = ?'
  ).bind(accountId, packId).all();
  const wonIds = new Set(wonSlots.results.map(r => r.slot_id));

  // Get pity info
  const pack = await db.prepare('SELECT pity_threshold FROM packs WHERE id = ?').bind(packId).first();
  const pity = await db.prepare(
    'SELECT spin_count FROM user_wheel_pity WHERE account_id = ? AND pack_id = ?'
  ).bind(accountId, packId).first();

  let pityCount = pity ? pity.spin_count : 0;
  const results = [];

  // Get all slots (exclude grand prize if user already won it)
  const allSlots = await db.prepare('SELECT * FROM wheel_slots WHERE pack_id = ?').bind(packId).all();
  const available = allSlots.results.filter(s => !(s.is_grand_prize && wonIds.has(s.id)));

  for (let i = 0; i < count; i++) {
    pityCount++;

    // Force grand prize on pity threshold
    let chosen;
    if (pack.pity_threshold && pityCount >= pack.pity_threshold) {
      const grandPrize = available.find(s => s.is_grand_prize && !wonIds.has(s.id));
      if (grandPrize) {
        chosen = grandPrize;
        pityCount = 0;
      }
    }

    if (!chosen) {
      const pool = available.filter(s => !s.is_grand_prize || !wonIds.has(s.id));
      const totalWeight = pool.reduce((s, r) => s + r.weight, 0);
      let rand = Math.random() * totalWeight;
      chosen = pool[pool.length - 1];
      for (const slot of pool) {
        rand -= slot.weight;
        if (rand <= 0) { chosen = slot; break; }
      }
    }

    // If grand prize won, record it
    if (chosen.is_grand_prize) {
      wonIds.add(chosen.id);
      await db.prepare(
        'INSERT OR IGNORE INTO user_wheel_wins (account_id, pack_id, slot_id) VALUES (?,?,?)'
      ).bind(accountId, packId, chosen.id).run();
      pityCount = 0;
    }

    results.push(chosen);
  }

  // Update pity counter
  await db.prepare(
    'INSERT INTO user_wheel_pity (account_id, pack_id, spin_count) VALUES (?,?,?) ON CONFLICT(account_id, pack_id) DO UPDATE SET spin_count = ?, updated_at = unixepoch()'
  ).bind(accountId, packId, pityCount, pityCount).run();

  return results;
}

// ── PROCESS SPIN RESULTS ──────────────────────────────────────
async function processSpinResults(db, accountId, results, via) {
  const processed = [];
  for (const result of results) {
    if (result.reward_type === 'card' && result.card_id) {
      try {
        const card = await grantCard(db, accountId, result.card_id, via);
        processed.push({ type: 'card', card_id: result.card_id, name: card.name, rarity: card.rarity, quantity: result.quantity || 1 });
      } catch(e) {
        processed.push({ type: 'coins', amount: 500, note: 'Card unavailable — compensated' });
        await addCoins(db, accountId, 500, 'compensation', 'Card max supply hit');
      }
    } else if (result.reward_type === 'rank_up_card' && result.ruc_id) {
      const existing = await db.prepare(
        'SELECT id FROM user_rank_up_cards WHERE account_id = ? AND rank_up_card_id = ?'
      ).bind(accountId, result.ruc_id).first();
      if (existing) {
        await db.prepare('UPDATE user_rank_up_cards SET quantity = quantity + ? WHERE id = ?').bind(result.quantity || 1, existing.id).run();
      } else {
        await db.prepare('INSERT INTO user_rank_up_cards (account_id, rank_up_card_id, quantity) VALUES (?,?,?)').bind(accountId, result.ruc_id, result.quantity || 1).run();
      }
      const ruc = await db.prepare('SELECT name, rarity FROM rank_up_cards WHERE id = ?').bind(result.ruc_id).first();
      processed.push({ type: 'rank_up_card', ruc_id: result.ruc_id, name: ruc?.name, rarity: ruc?.rarity, quantity: result.quantity || 1 });
    } else if (result.reward_type === 'coins' && result.coins_amount) {
      await addCoins(db, accountId, result.coins_amount * (result.quantity || 1), 'spin_reward', 'Spin reward');
      processed.push({ type: 'coins', amount: result.coins_amount * (result.quantity || 1) });
    }
  }
  return processed;
}

// ── TEAM STRENGTH CALCULATOR ──────────────────────────────────
async function calcTeamStrength(db, teamId) {
  const slots = await db.prepare(`
    SELECT ts.slot_type, uc.current_overall
    FROM user_team_slots ts
    JOIN user_cards uc ON ts.user_card_id = uc.id
    WHERE ts.team_id = ? AND ts.user_card_id IS NOT NULL
  `).bind(teamId).all();

  const starters = slots.results.filter(s => s.slot_type === 'starting');
  const subs     = slots.results.filter(s => s.slot_type === 'sub');

  if (!starters.length) return 0;

  const xiSum  = starters.reduce((s, r) => s + r.current_overall, 0);
  const subSum = subs.reduce((s, r) => s + r.current_overall, 0);

  const xiScore  = xiSum;
  const subScore = subSum;
  const total    = xiScore + subScore;

  // Max possible: 130 * 19 = 2470
  const maxPossible = 130 * 19;
  const scaled = Math.round((total / maxPossible) * 10000);

  // Chemistry boost: +5% if starting XI is full (11 players)
  const boost = starters.length === 11 ? Math.round(scaled * 0.05) : 0;

  return Math.min(scaled + boost, 10000);
}

// ── PRICE FLUCTUATION (cron hourly) ──────────────────────────
async function runPriceFluctuation(db) {
  const cards = await db.prepare('SELECT * FROM cards WHERE is_active = 1').all();

  for (const card of cards.results) {
    const scarcity = card.holder_count / (card.listing_count + 1);
    let changePct = 0;

    if      (scarcity > 50) changePct = 2.5;
    else if (scarcity > 20) changePct = 1.4;
    else if (scarcity > 5)  changePct = 0.5;
    else if (scarcity < 0.5) changePct = -3.5;
    else if (scarcity < 2)  changePct = -1.2;

    if (changePct === 0) continue;

    const floor   = Math.round(card.base_price * 0.3);
    const ceiling = Math.round(card.base_price * 5);
    const maxMove = card.market_price * 0.25;

    let delta = Math.round(card.market_price * (changePct / 100));
    delta = Math.max(-maxMove, Math.min(maxMove, delta));

    let newPrice = card.market_price + delta;
    newPrice = Math.max(floor, Math.min(ceiling, newPrice));

    if (newPrice === card.market_price) continue;

    const actualPct = ((newPrice - card.market_price) / card.market_price) * 100;

    await db.batch([
      db.prepare('UPDATE cards SET market_price = ?, price_change_pct = ?, scarcity_ratio = ?, updated_at = unixepoch() WHERE id = ?')
        .bind(newPrice, actualPct, scarcity, card.id),
      db.prepare('INSERT INTO price_history (card_id, price, change_pct, trigger) VALUES (?,?,?,?)')
        .bind(card.id, newPrice, actualPct, 'cron'),
    ]);

    // Fire price alerts
    const alerts = await db.prepare(
      'SELECT * FROM price_alerts WHERE card_id = ? AND triggered = 0'
    ).bind(card.id).all();

    for (const alert of alerts.results) {
      const hit = (alert.direction === 'above' && newPrice >= alert.target_price) ||
                  (alert.direction === 'below' && newPrice <= alert.target_price);
      if (hit) {
        await db.prepare('UPDATE price_alerts SET triggered = 1 WHERE id = ?').bind(alert.id).run();
        await notify(db, alert.account_id, 'price_alert', 'Price Alert Triggered',
          `${card.name} is now ${newPrice} coins`, 'card', String(card.id));
      }
    }
  }
}

// ── LEADERBOARD CACHE (cron hourly) ──────────────────────────
async function rebuildLeaderboard(db, category) {
  const teams = await db.prepare(`
    SELECT ut.account_id, ut.strength, a.username, a.avatar_url
    FROM user_teams ut
    JOIN accounts a ON ut.account_id = a.id
    WHERE ut.category = ? AND ut.is_active = 1
    ORDER BY ut.strength DESC
    LIMIT 100
  `).bind(category).all();

  await db.prepare('DELETE FROM leaderboard_cache WHERE category = ?').bind(category).run();

  for (let i = 0; i < teams.results.length; i++) {
    const t = teams.results[i];
    await db.prepare(
      'INSERT OR REPLACE INTO leaderboard_cache (category, account_id, username, avatar_url, strength, rank) VALUES (?,?,?,?,?,?)'
    ).bind(category, t.account_id, t.username, t.avatar_url, t.strength, i + 1).run();
  }
}

// ── DAILY RESET (cron daily) ──────────────────────────────────
async function runDailyReset(db) {
  // Prune old price history — keep hourly for 7 days, then daily snapshots
  const sevenDaysAgo = Math.floor(Date.now() / 1000) - (7 * 24 * 60 * 60);
  await db.prepare(`
    DELETE FROM price_history
    WHERE recorded_at < ?
    AND id NOT IN (
      SELECT MIN(id) FROM price_history
      WHERE recorded_at < ?
      GROUP BY card_id, date(recorded_at, 'unixepoch')
    )
  `).bind(sevenDaysAgo, sevenDaysAgo).run();

  // Prune expired sessions
  await db.prepare('DELETE FROM sessions WHERE expires_at < unixepoch()').run();

  // Card of the day
  const featuredCard = await db.prepare(`
    SELECT id FROM cards WHERE is_active = 1 ORDER BY RANDOM() LIMIT 1
  `).first();
  if (featuredCard) {
    await db.prepare('UPDATE cards SET is_featured = 0').run();
    await db.prepare('UPDATE cards SET is_featured = 1, featured_date = date() WHERE id = ?').bind(featuredCard.id).run();
  }
}

// ═══════════════════════════════════════════════════════════════
// MAIN FETCH HANDLER
// ═══════════════════════════════════════════════════════════════
export default {
  async fetch(req, env) {
    const origin = req.headers.get('Origin') || CORS_ORIGIN;

    if (req.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    const url = new URL(req.url);
    const p   = url.pathname;
    const m   = req.method;

    // Verify client token for all non-auth, non-public routes
    const clientToken = req.headers.get('X-Client-Token');
    const isPublic = p.startsWith('/auth/') || p.startsWith('/public/');
    if (!isPublic && clientToken) {
      const valid = await verifyClientToken(clientToken, env.CLIENT_TOKEN_SECRET);
      if (!valid) return err('Invalid client token', 401, origin);
    }

    try {
      // ── AUTH ────────────────────────────────────────────────
      if (p === '/auth/google' && m === 'GET') {
        const state = crypto.randomUUID();
        const params = new URLSearchParams({
          client_id: env.GOOGLE_CLIENT_ID,
          redirect_uri: env.GOOGLE_REDIRECT_URI,
          response_type: 'code',
          scope: 'openid email profile',
          state,
        });
        return Response.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`, 302);
      }

      if (p === '/auth/google/callback' && m === 'GET') {
        const code = url.searchParams.get('code');
        if (!code) return err('Missing code', 400, origin);

        // Exchange code for tokens
        const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            code,
            client_id: env.GOOGLE_CLIENT_ID,
            client_secret: env.GOOGLE_CLIENT_SECRET,
            redirect_uri: env.GOOGLE_REDIRECT_URI,
            grant_type: 'authorization_code',
          }),
        });

        const tokenData = await tokenRes.json();
        if (!tokenData.id_token) return err('Google auth failed', 400, origin);

        // Decode Google ID token (unverified — for user info only, we trust Google's code exchange)
        const googlePayload = JSON.parse(atob(tokenData.id_token.split('.')[1]));
        const { sub: googleId, email, name, picture } = googlePayload;

        // Upsert account
        let account = await env.DB.prepare('SELECT * FROM accounts WHERE google_id = ?').bind(googleId).first();
        if (!account) {
          const bank = await env.DB.prepare('SELECT welcome_coins FROM bank WHERE id = 1').first();
          const newId = crypto.randomUUID();
          await env.DB.prepare(`
            INSERT INTO accounts (id, google_id, email, display_name, avatar_url, coins)
            VALUES (?,?,?,?,?,?)
          `).bind(newId, googleId, email, name, picture, bank.welcome_coins || 500).run();
          await env.DB.prepare('UPDATE bank SET coin_supply = coin_supply - ?, coins_in_circulation = coins_in_circulation + ? WHERE id = 1').bind(bank.welcome_coins || 500, bank.welcome_coins || 500).run();
          account = await env.DB.prepare('SELECT * FROM accounts WHERE id = ?').bind(newId).first();
        } else {
          await env.DB.prepare('UPDATE accounts SET display_name = ?, avatar_url = ?, updated_at = unixepoch() WHERE id = ?').bind(name, picture, account.id).run();
        }

        // Issue tokens
        const accessToken  = await signJWT({ sub: account.id, email: account.email }, env.JWT_SECRET, ACCESS_TTL);
        const refreshToken = await signJWT({ sub: account.id }, env.REFRESH_SECRET, REFRESH_TTL);

        await env.DB.prepare(
          'INSERT INTO sessions (account_id, refresh_token, expires_at) VALUES (?,?,?)'
        ).bind(account.id, refreshToken, Math.floor(Date.now() / 1000) + REFRESH_TTL).run();

        // Redirect to frontend with tokens
        const redirectUrl = new URL('/auth/callback', CORS_ORIGIN);
        redirectUrl.searchParams.set('access_token', accessToken);
        redirectUrl.searchParams.set('refresh_token', refreshToken);
        redirectUrl.searchParams.set('onboarded', account.onboarded ? '1' : '0');
        return Response.redirect(redirectUrl.toString(), 302);
      }

      if (p === '/auth/refresh' && m === 'POST') {
        const { refresh_token } = await req.json();
        if (!refresh_token) return err('Missing refresh token', 400, origin);
        const payload = await verifyJWT(refresh_token, env.REFRESH_SECRET);
        if (!payload) return err('Invalid refresh token', 401, origin);
        const session = await env.DB.prepare('SELECT * FROM sessions WHERE refresh_token = ?').bind(refresh_token).first();
        if (!session) return err('Session not found', 401, origin);
        const accessToken = await signJWT({ sub: payload.sub }, env.JWT_SECRET, ACCESS_TTL);
        return json({ access_token: accessToken }, 200, origin);
      }

      if (p === '/auth/logout' && m === 'POST') {
        const { refresh_token } = await req.json();
        if (refresh_token) {
          await env.DB.prepare('DELETE FROM sessions WHERE refresh_token = ?').bind(refresh_token).run();
        }
        return json({ ok: true }, 200, origin);
      }

      // ── ADMIN AUTH ──────────────────────────────────────────
      if (p === '/admin/login' && m === 'POST') {
        const { username, password } = await req.json();
        if (username !== env.ADMIN_USERNAME || password !== env.ADMIN_PASSWORD) {
          return err('Invalid credentials', 401, origin);
        }
        const token = await signJWT({ role: 'admin', sub: 'admin' }, env.ADMIN_JWT_SECRET, ACCESS_TTL);
        return json({ token }, 200, origin);
      }

      // ── PUBLIC ROUTES ───────────────────────────────────────
      if (p === '/public/stats' && m === 'GET') {
        const [bank, cardCount, userCount, spinCount, marketCount] = await Promise.all([
          env.DB.prepare('SELECT coins_in_circulation, coin_to_dollar_rate FROM bank WHERE id = 1').first(),
          env.DB.prepare('SELECT COUNT(*) as c FROM cards WHERE is_active = 1').first(),
          env.DB.prepare('SELECT COUNT(*) as c FROM accounts').first(),
          env.DB.prepare('SELECT SUM(count) as c FROM spin_history').first(),
          env.DB.prepare('SELECT COUNT(*) as c FROM market_listings WHERE status = ?').bind('active').first(),
        ]);
        return json({
          cards_in_circulation: bank.coins_in_circulation,
          total_cards: cardCount.c,
          active_players: userCount.c,
          total_spins: spinCount.c || 0,
          active_listings: marketCount.c,
          coin_to_dollar_rate: bank.coin_to_dollar_rate,
        }, 200, origin);
      }

      if (p === '/public/packs' && m === 'GET') {
        const packs = await env.DB.prepare(`
          SELECT id, name, category, type, image_url, hero_image_url, description,
                 cost_single, cost_ten, pity_threshold, starts_at, expires_at, sort_order
          FROM packs
          WHERE is_live = 1 AND (expires_at IS NULL OR expires_at > unixepoch())
          ORDER BY sort_order ASC, created_at DESC
        `).all();
        return json(packs.results, 200, origin);
      }

      if (p === '/public/cards' && m === 'GET') {
        const cat   = url.searchParams.get('category');
        const rarity = url.searchParams.get('rarity');
        const page  = parseInt(url.searchParams.get('page') || '1');
        const limit = Math.min(parseInt(url.searchParams.get('limit') || '20'), 50);
        const offset = (page - 1) * limit;

        let query = 'SELECT * FROM cards WHERE is_active = 1';
        const params = [];
        if (cat)    { query += ' AND category = ?'; params.push(cat); }
        if (rarity) { query += ' AND rarity = ?';   params.push(rarity); }
        query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
        params.push(limit, offset);

        const cards = await env.DB.prepare(query).bind(...params).all();
        return json({ cards: cards.results, page, limit }, 200, origin);
      }

      if (p === '/public/leaderboard' && m === 'GET') {
        const category = url.searchParams.get('category') || 'football';
        const board = await env.DB.prepare(
          'SELECT * FROM leaderboard_cache WHERE category = ? ORDER BY rank ASC LIMIT 50'
        ).bind(category).all();
        return json(board.results, 200, origin);
      }

      if (p === '/public/card' && m === 'GET') {
        const cardId = url.searchParams.get('id');
        if (!cardId) return err('Missing card id', 400, origin);
        const card = await env.DB.prepare('SELECT * FROM cards WHERE id = ?').bind(cardId).first();
        if (!card) return err('Card not found', 404, origin);
        return json(card, 200, origin);
      }

      if (p === '/public/card/history' && m === 'GET') {
        const cardId = url.searchParams.get('id');
        const range  = url.searchParams.get('range') || '7d';
        if (!cardId) return err('Missing card id', 400, origin);

        let since;
        const now = Math.floor(Date.now() / 1000);
        if (range === '24h') since = now - 86400;
        else if (range === '7d') since = now - 604800;
        else if (range === '30d') since = now - 2592000;
        else since = 0;

        const history = await env.DB.prepare(
          'SELECT price, change_pct, recorded_at FROM price_history WHERE card_id = ? AND recorded_at >= ? ORDER BY recorded_at ASC'
        ).bind(cardId, since).all();
        return json(history.results, 200, origin);
      }

      if (p === '/public/market' && m === 'GET') {
        const cardId = url.searchParams.get('card_id');
        const page   = parseInt(url.searchParams.get('page') || '1');
        const limit  = Math.min(parseInt(url.searchParams.get('limit') || '20'), 50);
        const offset = (page - 1) * limit;

        let query = `
          SELECT ml.*, c.name as card_name, c.rarity, c.category, c.image_url,
                 c.position, c.club, c.nation, c.series, c.anime_role,
                 a.username as seller_username, a.avatar_url as seller_avatar
          FROM market_listings ml
          JOIN cards c ON ml.card_id = c.id
          JOIN accounts a ON ml.seller_id = a.id
          WHERE ml.status = 'active'
        `;
        const params = [];
        if (cardId) { query += ' AND ml.card_id = ?'; params.push(cardId); }
        query += ' ORDER BY ml.listed_at DESC LIMIT ? OFFSET ?';
        params.push(limit, offset);

        const listings = await env.DB.prepare(query).bind(...params).all();
        return json({ listings: listings.results, page, limit }, 200, origin);
      }

      // ── USER ROUTES (all require auth) ──────────────────────
      const account = await requireAuth(req, env);
      if (!account && !p.startsWith('/admin') && !isPublic) {
        return err('Unauthorized', 401, origin);
      }

      // ── PROFILE ─────────────────────────────────────────────
      if (p === '/user/me' && m === 'GET') {
        const bank = await env.DB.prepare('SELECT coin_to_dollar_rate FROM bank WHERE id = 1').first();
        return json({ ...account, coin_to_dollar_rate: bank.coin_to_dollar_rate }, 200, origin);
      }

      if (p === '/user/onboard' && m === 'POST') {
        const { username } = await req.json();
        if (!username || username.length < 3) return err('Username too short', 400, origin);
        const exists = await env.DB.prepare('SELECT id FROM accounts WHERE username = ?').bind(username).first();
        if (exists) return err('Username taken', 409, origin);
        await env.DB.prepare('UPDATE accounts SET username = ?, onboarded = 1, updated_at = unixepoch() WHERE id = ?').bind(username, account.id).run();
        return json({ ok: true }, 200, origin);
      }

      if (p.startsWith('/user/profile/') && m === 'GET') {
        const username = p.split('/')[3];
        const profile = await env.DB.prepare(`
          SELECT id, username, display_name, avatar_url, xp, total_spins, total_wins, created_at
          FROM accounts WHERE username = ?
        `).bind(username).first();
        if (!profile) return err('User not found', 404, origin);

        const [cards, teams, achievements] = await Promise.all([
          env.DB.prepare('SELECT COUNT(*) as c FROM user_cards WHERE account_id = ?').bind(profile.id).first(),
          env.DB.prepare('SELECT * FROM user_teams WHERE account_id = ? AND is_active = 1').bind(profile.id).all(),
          env.DB.prepare(`
            SELECT ua.*, a.name, a.description, a.icon
            FROM user_achievements ua JOIN achievements a ON ua.achievement_id = a.id
            WHERE ua.account_id = ?
          `).bind(profile.id).all(),
        ]);

        return json({
          ...profile,
          card_count: cards.c,
          active_teams: teams.results,
          achievements: achievements.results,
        }, 200, origin);
      }

      // ── COLLECTION ──────────────────────────────────────────
      if (p === '/user/collection' && m === 'GET') {
        const cat    = url.searchParams.get('category');
        const page   = parseInt(url.searchParams.get('page') || '1');
        const limit  = Math.min(parseInt(url.searchParams.get('limit') || '20'), 50);
        const offset = (page - 1) * limit;
        const bank   = await env.DB.prepare('SELECT coin_to_dollar_rate FROM bank WHERE id = 1').first();

        let query = `
          SELECT uc.*, c.name, c.category, c.rarity, c.image_url, c.position,
                 c.club, c.nation, c.series, c.anime_role, c.potential,
                 c.market_price, c.base_price, c.price_change_pct
          FROM user_cards uc JOIN cards c ON uc.card_id = c.id
          WHERE uc.account_id = ?
        `;
        const params = [account.id];
        if (cat) { query += ' AND c.category = ?'; params.push(cat); }
        query += ' ORDER BY uc.obtained_at DESC LIMIT ? OFFSET ?';
        params.push(limit, offset);

        const cards = await env.DB.prepare(query).bind(...params).all();
        const totalValue = cards.results.reduce((s, c) => s + c.market_price, 0);
        const totalDollars = Math.floor(totalValue / bank.coin_to_dollar_rate);

        return json({ cards: cards.results, total_value: totalValue, total_dollars: totalDollars, page, limit }, 200, origin);
      }

      // ── TRIVIA ──────────────────────────────────────────────
      if (p === '/trivia/question' && m === 'GET') {
        const cat = url.searchParams.get('category');

        // Get questions user hasn't answered recently (last 24h)
        let query = `
          SELECT tq.* FROM trivia_questions tq
          WHERE tq.is_active = 1
          AND tq.id NOT IN (
            SELECT question_id FROM trivia_sessions
            WHERE account_id = ? AND answered_at > unixepoch() - 86400
          )
        `;
        const params = [account.id];
        if (cat) { query += ' AND tq.category = ?'; params.push(cat); }
        query += ' ORDER BY RANDOM() LIMIT 1';

        const question = await env.DB.prepare(query).bind(...params).first();
        if (!question) return err('No questions available', 404, origin);

        // Return question WITHOUT correct answer
        const { correct_option, reward_card_id, reward_ruc_id, ...safeQuestion } = question;
        return json(safeQuestion, 200, origin);
      }

      if (p === '/trivia/answer' && m === 'POST') {
        const { question_id, answer, elapsed_ms } = await req.json();
        if (!question_id || !answer) return err('Missing fields', 400, origin);

        const question = await env.DB.prepare('SELECT * FROM trivia_questions WHERE id = ? AND is_active = 1').bind(question_id).first();
        if (!question) return err('Question not found', 404, origin);

        // Check if already answered in last 24h
        const recent = await env.DB.prepare(
          'SELECT id FROM trivia_sessions WHERE account_id = ? AND question_id = ? AND answered_at > unixepoch() - 86400'
        ).bind(account.id, question_id).first();
        if (recent) return err('Already answered', 409, origin);

        const isCorrect = answer.toLowerCase() === question.correct_option.toLowerCase();

        // Calculate multiplier based on elapsed time
        let multiplier = 0;
        let reward = null;

        if (isCorrect) {
          const timerMs = question.timer_seconds * 1000;
          const elapsed = Math.max(0, elapsed_ms || 0);

          if (elapsed <= 1000) multiplier = 2.0;                // answered within 1 second
          else if (elapsed < timerMs) multiplier = 1.8;         // answered before timer ends
          else multiplier = 1.0;                                 // answered at zero

          if (question.reward_type === 'coins') {
            const earned = Math.round(question.reward_coins * multiplier);
            await addCoins(env.DB, account.id, earned, 'trivia', `Trivia correct ×${multiplier}`);
            reward = { type: 'coins', amount: earned, multiplier };
          } else if (question.reward_type === 'card' && question.reward_card_id) {
            try {
              const card = await grantCard(env.DB, account.id, question.reward_card_id, 'trivia');
              reward = { type: 'card', card_id: question.reward_card_id, name: card.name, rarity: card.rarity };
            } catch(e) {
              // Fallback to coins if card unavailable
              await addCoins(env.DB, account.id, question.reward_coins, 'trivia', 'Trivia card unavailable fallback');
              reward = { type: 'coins', amount: question.reward_coins, multiplier: 1.0 };
            }
          } else if (question.reward_type === 'rank_up_card' && question.reward_ruc_id) {
            const existing = await env.DB.prepare(
              'SELECT id FROM user_rank_up_cards WHERE account_id = ? AND rank_up_card_id = ?'
            ).bind(account.id, question.reward_ruc_id).first();
            if (existing) {
              await env.DB.prepare('UPDATE user_rank_up_cards SET quantity = quantity + 1 WHERE id = ?').bind(existing.id).run();
            } else {
              await env.DB.prepare('INSERT INTO user_rank_up_cards (account_id, rank_up_card_id, quantity) VALUES (?,?,1)').bind(account.id, question.reward_ruc_id).run();
            }
            const ruc = await env.DB.prepare('SELECT name FROM rank_up_cards WHERE id = ?').bind(question.reward_ruc_id).first();
            reward = { type: 'rank_up_card', ruc_id: question.reward_ruc_id, name: ruc?.name };
          }

          await env.DB.prepare('UPDATE accounts SET total_wins = total_wins + 1 WHERE id = ?').bind(account.id).run();
        }

        await env.DB.prepare(
          'INSERT INTO trivia_sessions (account_id, question_id, answered, is_correct, elapsed_ms, multiplier, coins_earned) VALUES (?,?,?,?,?,?,?)'
        ).bind(account.id, question_id, answer, isCorrect ? 1 : 0, elapsed_ms || 0, multiplier, reward?.amount || 0).run();

        await env.DB.prepare('UPDATE trivia_questions SET times_answered = times_answered + 1 WHERE id = ?').bind(question_id).run();
        if (isCorrect) {
          await env.DB.prepare('UPDATE trivia_questions SET times_correct = times_correct + 1 WHERE id = ?').bind(question_id).run();
        }

        return json({ correct: isCorrect, correct_option: question.correct_option, reward }, 200, origin);
      }

      // ── SPINS ────────────────────────────────────────────────
      if (p === '/spin' && m === 'POST') {
        const { pack_id, count } = await req.json();
        if (!pack_id) return err('Missing pack_id', 400, origin);

        const spinCount = count === 10 ? 11 : 1; // 10+1 bonus
        const pack = await env.DB.prepare('SELECT * FROM packs WHERE id = ? AND is_live = 1').bind(pack_id).first();
        if (!pack) return err('Pack not available', 404, origin);
        if (pack.expires_at && pack.expires_at < Math.floor(Date.now() / 1000)) return err('Pack expired', 400, origin);

        const cost = count === 10 ? pack.cost_ten : pack.cost_single;
        await deductCoins(env.DB, account.id, cost, 'spin', `Spun pack: ${pack.name}`);

        let rawResults;
        if (pack.type === 'wheel') {
          rawResults = await spinWheel(env.DB, pack_id, spinCount, account.id);
        } else {
          rawResults = await spinPack(env.DB, pack_id, spinCount, account.id);
        }

        const processed = await processSpinResults(env.DB, account.id, rawResults, pack.type);

        await env.DB.batch([
          env.DB.prepare('UPDATE accounts SET total_spins = total_spins + ? WHERE id = ?').bind(spinCount, account.id),
          env.DB.prepare('INSERT INTO spin_history (account_id, pack_id, spin_type, count, cost_paid, results) VALUES (?,?,?,?,?,?)').bind(account.id, pack_id, pack.type, spinCount, cost, JSON.stringify(processed)),
        ]);

        return json({ results: processed }, 200, origin);
      }

      // ── PACK DETAILS + REWARDS ───────────────────────────────
      if (p.startsWith('/pack/') && m === 'GET') {
        const packId = p.split('/')[2];
        const pack   = await env.DB.prepare('SELECT * FROM packs WHERE id = ? AND is_live = 1').bind(packId).first();
        if (!pack) return err('Pack not found', 404, origin);

        let rewards;
        if (pack.type === 'wheel') {
          rewards = await env.DB.prepare(`
            SELECT ws.*, c.name as card_name, c.rarity, c.image_url, c.category,
                   r.name as ruc_name, r.rarity as ruc_rarity, r.image_url as ruc_image
            FROM wheel_slots ws
            LEFT JOIN cards c ON ws.card_id = c.id
            LEFT JOIN rank_up_cards r ON ws.ruc_id = r.id
            WHERE ws.pack_id = ? ORDER BY ws.sort_order ASC
          `).bind(packId).all();

          // Check which grand prize user already won
          const won = await env.DB.prepare(
            'SELECT slot_id FROM user_wheel_wins WHERE account_id = ? AND pack_id = ?'
          ).bind(account.id, packId).all();
          const wonIds = new Set(won.results.map(r => r.slot_id));

          rewards = rewards.results.map(s => ({ ...s, is_obtained: wonIds.has(s.id) }));

          // Pity info
          const pity = await env.DB.prepare(
            'SELECT spin_count FROM user_wheel_pity WHERE account_id = ? AND pack_id = ?'
          ).bind(account.id, packId).first();

          return json({ pack, slots: rewards, pity_count: pity?.spin_count || 0 }, 200, origin);
        } else {
          rewards = await env.DB.prepare(`
            SELECT pc.*, c.name as card_name, c.rarity, c.image_url, c.category,
                   c.position, c.club, c.nation, c.series, c.anime_role, c.potential,
                   r.name as ruc_name, r.rarity as ruc_rarity
            FROM pack_cards pc
            LEFT JOIN cards c ON pc.card_id = c.id
            LEFT JOIN rank_up_cards r ON pc.ruc_id = r.id
            WHERE pc.pack_id = ? ORDER BY c.rarity DESC
          `).bind(packId).all();
          return json({ pack, rewards: rewards.results }, 200, origin);
        }
      }

      // ── MARKET ───────────────────────────────────────────────
      if (p === '/market/sell' && m === 'POST') {
        const { user_card_id } = await req.json();
        if (!user_card_id) return err('Missing user_card_id', 400, origin);

        const uc = await env.DB.prepare(
          'SELECT uc.*, c.name, c.market_price, c.id as card_id FROM user_cards uc JOIN cards c ON uc.card_id = c.id WHERE uc.id = ? AND uc.account_id = ?'
        ).bind(user_card_id, account.id).first();
        if (!uc) return err('Card not found in inventory', 404, origin);

        // Check duplicate rule — only 1 can be in starting/sub, can sell from reserve
        const inTeam = await env.DB.prepare(
          'SELECT id FROM user_team_slots WHERE user_card_id = ?'
        ).bind(user_card_id).first();
        if (inTeam) return err('Remove card from team before selling', 400, origin);

        // Check if already listed
        const alreadyListed = await env.DB.prepare(
          'SELECT id FROM market_listings WHERE user_card_id = ? AND status = ?'
        ).bind(user_card_id, 'active').first();
        if (alreadyListed) return err('Card already listed', 409, origin);

        await env.DB.batch([
          env.DB.prepare(
            'INSERT INTO market_listings (seller_id, user_card_id, card_id, price, current_overall) VALUES (?,?,?,?,?)'
          ).bind(account.id, user_card_id, uc.card_id, uc.market_price, uc.current_overall),
          env.DB.prepare('UPDATE cards SET listing_count = listing_count + 1, market_price = market_price * 0.997, updated_at = unixepoch() WHERE id = ?').bind(uc.card_id),
          env.DB.prepare('INSERT INTO price_history (card_id, price, change_pct, trigger) VALUES (?,?,?,?)').bind(uc.card_id, Math.round(uc.market_price * 0.997), -0.3, 'listing'),
        ]);

        return json({ ok: true, price: uc.market_price }, 200, origin);
      }

      if (p === '/market/buy' && m === 'POST') {
        const { listing_id } = await req.json();
        if (!listing_id) return err('Missing listing_id', 400, origin);

        const listing = await env.DB.prepare(`
          SELECT ml.*, c.name as card_name, c.rarity
          FROM market_listings ml JOIN cards c ON ml.card_id = c.id
          WHERE ml.id = ? AND ml.status = 'active'
        `).bind(listing_id).first();
        if (!listing) return err('Listing not found', 404, origin);
        if (listing.seller_id === account.id) return err('Cannot buy your own listing', 400, origin);

        const bank = await env.DB.prepare('SELECT market_tax_pct FROM bank WHERE id = 1').first();
        const tax  = Math.round(listing.price * (bank.market_tax_pct / 100));
        const sellerReceives = listing.price - tax;

        await deductCoins(env.DB, account.id, listing.price, 'market_buy', `Bought: ${listing.card_name}`);
        await addCoins(env.DB, listing.seller_id, sellerReceives, 'market_sale', `Sold: ${listing.card_name}`);
        await taxToBank(env.DB, tax);

        // Transfer card
        const existingCard = await env.DB.prepare(
          'SELECT id, quantity FROM user_cards WHERE account_id = ? AND card_id = ?'
        ).bind(account.id, listing.card_id).first();

        if (existingCard) {
          await env.DB.prepare('UPDATE user_cards SET quantity = quantity + 1 WHERE id = ?').bind(existingCard.id).run();
        } else {
          await env.DB.prepare(
            'INSERT INTO user_cards (account_id, card_id, current_overall, obtained_via) VALUES (?,?,?,?)'
          ).bind(account.id, listing.card_id, listing.current_overall, 'trade').run();
          await env.DB.prepare('UPDATE cards SET holder_count = holder_count + 1 WHERE id = ?').bind(listing.card_id).run();
        }

        // Update listing
        await env.DB.prepare(
          'UPDATE market_listings SET status = ?, buyer_id = ?, sold_at = unixepoch() WHERE id = ?'
        ).bind('sold', account.id, listing_id).run();

        // Seller might lose holder status if quantity = 0
        const sellerCard = await env.DB.prepare(
          'SELECT id, quantity FROM user_cards WHERE account_id = ? AND card_id = ?'
        ).bind(listing.seller_id, listing.card_id).first();
        if (sellerCard) {
          if (sellerCard.quantity <= 1) {
            await env.DB.prepare('DELETE FROM user_cards WHERE id = ?').bind(sellerCard.id).run();
            await env.DB.prepare('UPDATE cards SET holder_count = holder_count - 1, listing_count = listing_count - 1 WHERE id = ?').bind(listing.card_id).run();
          } else {
            await env.DB.prepare('UPDATE user_cards SET quantity = quantity - 1 WHERE id = ?').bind(sellerCard.id).run();
            await env.DB.prepare('UPDATE cards SET listing_count = listing_count - 1 WHERE id = ?').bind(listing.card_id).run();
          }
        }

        // Price drop on sale
        const card = await env.DB.prepare('SELECT * FROM cards WHERE id = ?').bind(listing.card_id).first();
        const sellPressure = 1 / Math.max(card.holder_count, 1);
        let priceDrop = 0;
        if (sellPressure > 0.10)      priceDrop = 0.08;
        else if (sellPressure > 0.03) priceDrop = 0.03;
        else if (sellPressure > 0.01) priceDrop = 0.01;

        if (priceDrop > 0) {
          const floor    = Math.round(card.base_price * 0.3);
          const newPrice = Math.max(floor, Math.round(card.market_price * (1 - priceDrop)));
          await env.DB.batch([
            env.DB.prepare('UPDATE cards SET market_price = ?, updated_at = unixepoch() WHERE id = ?').bind(newPrice, listing.card_id),
            env.DB.prepare('INSERT INTO price_history (card_id, price, change_pct, trigger) VALUES (?,?,?,?)').bind(listing.card_id, newPrice, -(priceDrop * 100), 'sale'),
          ]);
        }

        await notify(env.DB, listing.seller_id, 'market', 'Card Sold!', `${listing.card_name} sold for ${sellerReceives} coins`, 'listing', String(listing_id));

        return json({ ok: true, paid: listing.price, tax }, 200, origin);
      }

      if (p === '/market/cancel' && m === 'POST') {
        const { listing_id } = await req.json();
        const listing = await env.DB.prepare(
          'SELECT * FROM market_listings WHERE id = ? AND seller_id = ? AND status = ?'
        ).bind(listing_id, account.id, 'active').first();
        if (!listing) return err('Listing not found', 404, origin);
        await env.DB.batch([
          env.DB.prepare('UPDATE market_listings SET status = ? WHERE id = ?').bind('cancelled', listing_id),
          env.DB.prepare('UPDATE cards SET listing_count = listing_count - 1 WHERE id = ?').bind(listing.card_id),
        ]);
        return json({ ok: true }, 200, origin);
      }

      // ── TRAINING ─────────────────────────────────────────────
      if (p === '/train/drill' && m === 'POST') {
        const { user_card_id, rank_up_card_id } = await req.json();
        if (!user_card_id || !rank_up_card_id) return err('Missing fields', 400, origin);

        const uc  = await env.DB.prepare('SELECT uc.*, c.potential, c.rarity FROM user_cards uc JOIN cards c ON uc.card_id = c.id WHERE uc.id = ? AND uc.account_id = ?').bind(user_card_id, account.id).first();
        const ruc = await env.DB.prepare('SELECT * FROM user_rank_up_cards WHERE account_id = ? AND rank_up_card_id = ?').bind(account.id, rank_up_card_id).first();
        const drill = await env.DB.prepare('SELECT * FROM rank_up_cards WHERE id = ?').bind(rank_up_card_id).first();

        if (!uc)    return err('Card not in inventory', 404, origin);
        if (!ruc || ruc.quantity < 1) return err('No rank up card available', 404, origin);

        // Rarity ceiling
        const ceilings = { common: 0.85, rare: 0.90, epic: 0.95, legendary: 0.99, mythic: 1.0 };
        const ceiling  = Math.floor(uc.potential * (ceilings[uc.rarity] || 0.85));
        if (uc.current_overall >= ceiling) return err('Card has reached its training ceiling', 400, origin);

        const boost    = Math.min(drill.boost_amount, ceiling - uc.current_overall);
        const newOverall = uc.current_overall + boost;

        await env.DB.batch([
          env.DB.prepare('UPDATE user_cards SET current_overall = ? WHERE id = ?').bind(newOverall, user_card_id),
          env.DB.prepare('UPDATE user_rank_up_cards SET quantity = quantity - 1 WHERE id = ?').bind(ruc.id),
          env.DB.prepare('INSERT INTO card_training_log (account_id, user_card_id, rank_up_card_id, method, boost_applied, overall_before, overall_after) VALUES (?,?,?,?,?,?,?)').bind(account.id, user_card_id, rank_up_card_id, 'drill', boost, uc.current_overall, newOverall),
        ]);

        // Recalculate team strength if card is in a team
        const teamSlot = await env.DB.prepare('SELECT team_id FROM user_team_slots WHERE user_card_id = ?').bind(user_card_id).first();
        if (teamSlot) {
          const strength = await calcTeamStrength(env.DB, teamSlot.team_id);
          await env.DB.prepare('UPDATE user_teams SET strength = ? WHERE id = ?').bind(strength, teamSlot.team_id).run();
        }

        return json({ ok: true, overall_before: uc.current_overall, overall_after: newOverall, boost }, 200, origin);
      }

      if (p === '/train/sacrifice' && m === 'POST') {
        const { base_user_card_id, sacrifice_user_card_id } = await req.json();
        if (!base_user_card_id || !sacrifice_user_card_id) return err('Missing fields', 400, origin);
        if (base_user_card_id === sacrifice_user_card_id) return err('Cannot sacrifice same card', 400, origin);

        const base = await env.DB.prepare('SELECT uc.*, c.potential, c.rarity FROM user_cards uc JOIN cards c ON uc.card_id = c.id WHERE uc.id = ? AND uc.account_id = ?').bind(base_user_card_id, account.id).first();
        const sac  = await env.DB.prepare('SELECT * FROM user_cards WHERE id = ? AND account_id = ?').bind(sacrifice_user_card_id, account.id).first();

        if (!base || !sac) return err('Card not found', 404, origin);
        if (base.card_id !== sac.card_id) return err('Can only sacrifice same player', 400, origin);
        if (base.current_overall >= base.potential) return err('Card already at full potential', 400, origin);

        const boost      = 5; // sacrifice always gives +5 ignoring ceiling
        const newOverall = Math.min(base.potential, base.current_overall + boost);

        await env.DB.batch([
          env.DB.prepare('UPDATE user_cards SET current_overall = ? WHERE id = ?').bind(newOverall, base_user_card_id),
          env.DB.prepare('DELETE FROM user_cards WHERE id = ?').bind(sacrifice_user_card_id),
          env.DB.prepare('UPDATE cards SET current_supply = current_supply - 1, holder_count = holder_count - 1 WHERE id = ?').bind(sac.card_id),
          env.DB.prepare('INSERT INTO card_training_log (account_id, user_card_id, method, boost_applied, overall_before, overall_after) VALUES (?,?,?,?,?,?)').bind(account.id, base_user_card_id, 'sacrifice', boost, base.current_overall, newOverall),
        ]);

        return json({ ok: true, overall_before: base.current_overall, overall_after: newOverall }, 200, origin);
      }

      // ── STORE (rank up cards) ────────────────────────────────
      if (p === '/store' && m === 'GET') {
        const items = await env.DB.prepare('SELECT * FROM rank_up_cards WHERE is_active = 1 ORDER BY boost_amount ASC').all();
        const bank  = await env.DB.prepare('SELECT coin_to_dollar_rate FROM bank WHERE id = 1').first();
        const userRucs = await env.DB.prepare('SELECT rank_up_card_id, quantity FROM user_rank_up_cards WHERE account_id = ?').bind(account.id).all();
        const ownedMap = Object.fromEntries(userRucs.results.map(r => [r.rank_up_card_id, r.quantity]));
        const enriched = items.results.map(item => ({ ...item, owned: ownedMap[item.id] || 0, dollar_price: (item.store_price / bank.coin_to_dollar_rate).toFixed(2) }));
        return json(enriched, 200, origin);
      }

      if (p === '/store/buy' && m === 'POST') {
        const { rank_up_card_id, quantity = 1 } = await req.json();
        const item = await env.DB.prepare('SELECT * FROM rank_up_cards WHERE id = ? AND is_active = 1').bind(rank_up_card_id).first();
        if (!item) return err('Item not found', 404, origin);

        const totalCost = item.store_price * quantity;
        await deductCoins(env.DB, account.id, totalCost, 'store', `Bought ${quantity}x ${item.name}`);

        const existing = await env.DB.prepare('SELECT id FROM user_rank_up_cards WHERE account_id = ? AND rank_up_card_id = ?').bind(account.id, rank_up_card_id).first();
        if (existing) {
          await env.DB.prepare('UPDATE user_rank_up_cards SET quantity = quantity + ? WHERE id = ?').bind(quantity, existing.id).run();
        } else {
          await env.DB.prepare('INSERT INTO user_rank_up_cards (account_id, rank_up_card_id, quantity) VALUES (?,?,?)').bind(account.id, rank_up_card_id, quantity).run();
        }

        return json({ ok: true, spent: totalCost }, 200, origin);
      }

      // ── TEAM BUILDER ─────────────────────────────────────────
      if (p === '/team/list' && m === 'GET') {
        const teams = await env.DB.prepare(
          'SELECT * FROM user_teams WHERE account_id = ? ORDER BY is_active DESC, created_at DESC'
        ).bind(account.id).all();
        return json(teams.results, 200, origin);
      }

      if (p === '/team/create' && m === 'POST') {
        const { category, name, formation } = await req.json();
        if (!category) return err('Missing category', 400, origin);

        const result = await env.DB.prepare(
          'INSERT INTO user_teams (account_id, category, name, formation) VALUES (?,?,?,?)'
        ).bind(account.id, category, name || 'My Team', formation || null).run();

        return json({ ok: true, team_id: result.meta.last_row_id }, 200, origin);
      }

      if (p === '/team/activate' && m === 'POST') {
        const { team_id } = await req.json();
        const team = await env.DB.prepare('SELECT * FROM user_teams WHERE id = ? AND account_id = ?').bind(team_id, account.id).first();
        if (!team) return err('Team not found', 404, origin);

        await env.DB.batch([
          env.DB.prepare('UPDATE user_teams SET is_active = 0 WHERE account_id = ? AND category = ?').bind(account.id, team.category),
          env.DB.prepare('UPDATE user_teams SET is_active = 1 WHERE id = ?').bind(team_id),
        ]);
        return json({ ok: true }, 200, origin);
      }

      if (p === '/team/formation' && m === 'POST') {
        const { team_id, formation } = await req.json();
        const team = await env.DB.prepare('SELECT * FROM user_teams WHERE id = ? AND account_id = ?').bind(team_id, account.id).first();
        if (!team) return err('Team not found', 404, origin);
        await env.DB.prepare('UPDATE user_teams SET formation = ?, updated_at = unixepoch() WHERE id = ?').bind(formation, team_id).run();
        return json({ ok: true }, 200, origin);
      }

      if (p === '/team/slot' && m === 'POST') {
        const { team_id, slot_type, slot_index, position, user_card_id } = await req.json();
        if (!team_id || !slot_type || slot_index === undefined) return err('Missing fields', 400, origin);

        const team = await env.DB.prepare('SELECT * FROM user_teams WHERE id = ? AND account_id = ?').bind(team_id, account.id).first();
        if (!team) return err('Team not found', 404, origin);

        if (user_card_id) {
          const uc = await env.DB.prepare('SELECT * FROM user_cards WHERE id = ? AND account_id = ?').bind(user_card_id, account.id).first();
          if (!uc) return err('Card not in inventory', 404, origin);

          // Duplicate rule: check if same card is already in starting or sub slots
          if (slot_type !== 'reserve') {
            const existingInActiveSlot = await env.DB.prepare(`
              SELECT ts.id FROM user_team_slots ts
              JOIN user_cards uc2 ON ts.user_card_id = uc2.id
              WHERE ts.team_id = ? AND ts.slot_type != 'reserve'
              AND uc2.card_id = ? AND ts.id != (
                SELECT id FROM user_team_slots WHERE team_id = ? AND slot_type = ? AND slot_index = ? LIMIT 1
              )
            `).bind(team_id, uc.card_id, team_id, slot_type, slot_index).first();
            if (existingInActiveSlot) return err('Duplicate card — place in reserve', 400, origin);
          }
        }

        await env.DB.prepare(`
          INSERT INTO user_team_slots (team_id, account_id, slot_type, position, slot_index, user_card_id)
          VALUES (?,?,?,?,?,?)
          ON CONFLICT(team_id, slot_type, slot_index) DO UPDATE SET
            position = excluded.position,
            user_card_id = excluded.user_card_id
        `).bind(team_id, account.id, slot_type, position || null, slot_index, user_card_id || null).run();

        // Recalculate strength
        const strength = await calcTeamStrength(env.DB, team_id);
        await env.DB.prepare('UPDATE user_teams SET strength = ?, updated_at = unixepoch() WHERE id = ?').bind(strength, team_id).run();

        return json({ ok: true, strength }, 200, origin);
      }

      if (p.startsWith('/team/') && m === 'GET') {
        const teamId = p.split('/')[2];
        const team   = await env.DB.prepare('SELECT * FROM user_teams WHERE id = ?').bind(teamId).first();
        if (!team) return err('Team not found', 404, origin);

        const slots = await env.DB.prepare(`
          SELECT ts.*, uc.current_overall, uc.quantity,
                 c.name, c.category, c.rarity, c.image_url, c.position as card_position,
                 c.club, c.nation, c.series, c.anime_role, c.potential,
                 c.market_price, c.price_change_pct
          FROM user_team_slots ts
          LEFT JOIN user_cards uc ON ts.user_card_id = uc.id
          LEFT JOIN cards c ON uc.card_id = c.id
          WHERE ts.team_id = ?
          ORDER BY ts.slot_type, ts.slot_index
        `).bind(teamId).all();

        const bank = await env.DB.prepare('SELECT coin_to_dollar_rate FROM bank WHERE id = 1').first();
        const squadValue = slots.results.reduce((s, sl) => s + (sl.market_price || 0), 0);

        return json({
          team,
          slots: slots.results,
          squad_value_coins: squadValue,
          squad_value_dollars: (squadValue / bank.coin_to_dollar_rate).toFixed(2),
        }, 200, origin);
      }

      // ── NOTIFICATIONS ────────────────────────────────────────
      if (p === '/notifications' && m === 'GET') {
        const notifs = await env.DB.prepare(
          'SELECT * FROM notifications WHERE account_id = ? ORDER BY created_at DESC LIMIT 30'
        ).bind(account.id).all();
        const unread = notifs.results.filter(n => !n.is_read).length;
        return json({ notifications: notifs.results, unread }, 200, origin);
      }

      if (p === '/notifications/read' && m === 'POST') {
        const { id } = await req.json();
        if (id) {
          await env.DB.prepare('UPDATE notifications SET is_read = 1 WHERE id = ? AND account_id = ?').bind(id, account.id).run();
        } else {
          await env.DB.prepare('UPDATE notifications SET is_read = 1 WHERE account_id = ?').bind(account.id).run();
        }
        return json({ ok: true }, 200, origin);
      }

      // ── DAILY LOGIN REWARD ────────────────────────────────────
      if (p === '/daily/claim' && m === 'POST') {
        const today     = new Date();
        const dayOfWeek = today.getDay(); // 0=Sun, 1=Mon...
        const monday    = new Date(today);
        monday.setDate(today.getDate() - ((dayOfWeek + 6) % 7));
        const weekStart = monday.toISOString().split('T')[0];

        // Figure out which day of the streak we're on
        const lastClaim = await env.DB.prepare(
          'SELECT day_number, MAX(claimed_at) as claimed_at FROM login_claims WHERE account_id = ? AND week_start = ? GROUP BY day_number ORDER BY day_number DESC LIMIT 1'
        ).bind(account.id, weekStart).first();

        const dayNumber = lastClaim ? lastClaim.day_number + 1 : 1;
        if (dayNumber > 7) return err('All days claimed this week', 400, origin);

        // Check they haven't already claimed today
        const todayISO = today.toISOString().split('T')[0];
        const alreadyToday = await env.DB.prepare(
          'SELECT id FROM login_claims WHERE account_id = ? AND week_start = ? AND day_number = ?'
        ).bind(account.id, weekStart, dayNumber).first();
        if (alreadyToday) return err('Already claimed today', 409, origin);

        const reward = await env.DB.prepare('SELECT * FROM daily_rewards WHERE day_number = ?').bind(dayNumber).first();
        if (!reward) return err('Reward not configured', 500, origin);

        await env.DB.prepare(
          'INSERT INTO login_claims (account_id, day_number, week_start) VALUES (?,?,?)'
        ).bind(account.id, dayNumber, weekStart).run();

        let granted = null;
        if (reward.reward_type === 'coins') {
          await addCoins(env.DB, account.id, reward.reward_coins, 'login', `Day ${dayNumber} login reward`);
          granted = { type: 'coins', amount: reward.reward_coins };
        } else if (reward.reward_type === 'card' && reward.reward_ref_id) {
          const card = await grantCard(env.DB, account.id, reward.reward_ref_id, 'login');
          granted = { type: 'card', card_id: reward.reward_ref_id, name: card.name };
        } else if (reward.reward_type === 'rank_up_card' && reward.reward_ref_id) {
          const existing = await env.DB.prepare('SELECT id FROM user_rank_up_cards WHERE account_id = ? AND rank_up_card_id = ?').bind(account.id, reward.reward_ref_id).first();
          if (existing) {
            await env.DB.prepare('UPDATE user_rank_up_cards SET quantity = quantity + 1 WHERE id = ?').bind(existing.id).run();
          } else {
            await env.DB.prepare('INSERT INTO user_rank_up_cards (account_id, rank_up_card_id, quantity) VALUES (?,?,1)').bind(account.id, reward.reward_ref_id).run();
          }
          const ruc = await env.DB.prepare('SELECT name FROM rank_up_cards WHERE id = ?').bind(reward.reward_ref_id).first();
          granted = { type: 'rank_up_card', name: ruc?.name };
        }

        await env.DB.prepare('UPDATE accounts SET login_streak = ?, last_login_date = date(), updated_at = unixepoch() WHERE id = ?').bind(dayNumber, account.id).run();
        return json({ ok: true, day: dayNumber, reward: granted }, 200, origin);
      }

      if (p === '/daily/status' && m === 'GET') {
        const today     = new Date();
        const dayOfWeek = today.getDay();
        const monday    = new Date(today);
        monday.setDate(today.getDate() - ((dayOfWeek + 6) % 7));
        const weekStart = monday.toISOString().split('T')[0];

        const claims  = await env.DB.prepare('SELECT day_number FROM login_claims WHERE account_id = ? AND week_start = ?').bind(account.id, weekStart).all();
        const rewards = await env.DB.prepare('SELECT * FROM daily_rewards ORDER BY day_number ASC').all();
        const claimedDays = new Set(claims.results.map(c => c.day_number));

        return json({
          week_start: weekStart,
          claimed_days: [...claimedDays],
          rewards: rewards.results,
          current_streak: account.login_streak,
        }, 200, origin);
      }

      // ── PRICE ALERTS ─────────────────────────────────────────
      if (p === '/alerts' && m === 'GET') {
        const alerts = await env.DB.prepare(`
          SELECT pa.*, c.name as card_name, c.market_price
          FROM price_alerts pa JOIN cards c ON pa.card_id = c.id
          WHERE pa.account_id = ?
        `).bind(account.id).all();
        return json(alerts.results, 200, origin);
      }

      if (p === '/alerts' && m === 'POST') {
        const { card_id, direction, target_price } = await req.json();
        if (!card_id || !direction || !target_price) return err('Missing fields', 400, origin);
        await env.DB.prepare(
          'INSERT OR REPLACE INTO alerts (account_id, card_id, direction, target_price, triggered) VALUES (?,?,?,?,0)'
        ).bind(account.id, card_id, direction, target_price).run();
        return json({ ok: true }, 200, origin);
      }

      // ── TRANSACTIONS ─────────────────────────────────────────
      if (p === '/transactions' && m === 'GET') {
        const txs = await env.DB.prepare(
          'SELECT * FROM transactions WHERE account_id = ? ORDER BY created_at DESC LIMIT 50'
        ).bind(account.id).all();
        return json(txs.results, 200, origin);
      }

      // ══════════════════════════════════════════════════════════
      // ADMIN ROUTES
      // ══════════════════════════════════════════════════════════
      if (p.startsWith('/admin/')) {
        const admin = await requireAdmin(req, env);
        if (!admin) return err('Admin unauthorized', 401, origin);

        // ── ADMIN STATS ──────────────────────────────────────
        if (p === '/admin/stats' && m === 'GET') {
          const [bank, users, cards, packs, listings, spins] = await Promise.all([
            env.DB.prepare('SELECT * FROM bank WHERE id = 1').first(),
            env.DB.prepare('SELECT COUNT(*) as c FROM accounts').first(),
            env.DB.prepare('SELECT COUNT(*) as c FROM cards WHERE is_active = 1').first(),
            env.DB.prepare('SELECT COUNT(*) as c FROM packs WHERE is_live = 1').first(),
            env.DB.prepare('SELECT COUNT(*) as c FROM market_listings WHERE status = ?').bind('active').first(),
            env.DB.prepare('SELECT COUNT(*) as c, SUM(count) as total FROM spin_history').first(),
          ]);
          return json({ bank, users: users.c, cards: cards.c, live_packs: packs.c, active_listings: listings.c, spin_sessions: spins.c, total_spins: spins.total }, 200, origin);
        }

        // ── BANK ─────────────────────────────────────────────
        if (p === '/admin/bank' && m === 'GET') {
          const bank = await env.DB.prepare('SELECT * FROM bank WHERE id = 1').first();
          return json(bank, 200, origin);
        }

        if (p === '/admin/bank/inject' && m === 'POST') {
          const { amount } = await req.json();
          if (!amount || amount <= 0) return err('Invalid amount', 400, origin);
          await env.DB.prepare('UPDATE bank SET coin_supply = coin_supply + ?, total_injected = total_injected + ?, updated_at = unixepoch() WHERE id = 1').bind(amount, amount).run();
          return json({ ok: true }, 200, origin);
        }

        if (p === '/admin/bank/settings' && m === 'POST') {
          const { coin_to_dollar_rate, market_tax_pct, welcome_coins } = await req.json();
          const updates = [];
          if (coin_to_dollar_rate) updates.push(`coin_to_dollar_rate = ${coin_to_dollar_rate}`);
          if (market_tax_pct !== undefined) updates.push(`market_tax_pct = ${market_tax_pct}`);
          if (welcome_coins !== undefined) updates.push(`welcome_coins = ${welcome_coins}`);
          if (!updates.length) return err('Nothing to update', 400, origin);
          await env.DB.prepare(`UPDATE bank SET ${updates.join(',')}, updated_at = unixepoch() WHERE id = 1`).run();
          return json({ ok: true }, 200, origin);
        }

        if (p === '/admin/bank/coins' && m === 'POST') {
          // Give or remove coins from a user
          const { account_id, amount, direction, note } = await req.json();
          if (!account_id || !amount || !direction) return err('Missing fields', 400, origin);
          if (direction === 'credit') {
            await addCoins(env.DB, account_id, amount, 'admin', note || 'Admin grant');
          } else {
            await deductCoins(env.DB, account_id, amount, 'admin', note || 'Admin deduct');
          }
          return json({ ok: true }, 200, origin);
        }

        // ── ADMIN STOCK ───────────────────────────────────────
        if (p === '/admin/stock' && m === 'GET') {
          const status = url.searchParams.get('status') || 'pending';
          const stock  = await env.DB.prepare('SELECT * FROM admin_stock WHERE status = ? ORDER BY imported_at DESC').bind(status).all();
          return json(stock.results, 200, origin);
        }

        if (p === '/admin/stock/import/sportsdb' && m === 'POST') {
          const { team } = await req.json();
          if (!team) return err('Missing team name', 400, origin);

          const res  = await fetch(`https://www.thesportsdb.com/api/v1/json/3/searchplayers.php?t=${encodeURIComponent(team)}`);
          const data = await res.json();
          if (!data.player) return err('No players found', 404, origin);

          const players = data.player.slice(0, 20);
          const inserts = players.map(p => env.DB.prepare(
            'INSERT OR IGNORE INTO admin_stock (source, external_id, name, category, image_url, club, nation, position) VALUES (?,?,?,?,?,?,?,?)'
          ).bind('sportsdb', p.idPlayer, p.strPlayer, 'football', p.strCutout || p.strThumb || '', p.strTeam, p.strNationality, p.strPosition));

          await env.DB.batch(inserts);
          return json({ ok: true, imported: players.length }, 200, origin);
        }

        if (p === '/admin/stock/import/jikan' && m === 'POST') {
          const { query } = await req.json();
          if (!query) return err('Missing query', 400, origin);

          const res  = await fetch(`https://api.jikan.moe/v4/characters?q=${encodeURIComponent(query)}&limit=10`);
          const data = await res.json();
          if (!data.data) return err('No results found', 404, origin);

          const inserts = data.data.map(c => env.DB.prepare(
            'INSERT OR IGNORE INTO admin_stock (source, external_id, name, category, image_url, series) VALUES (?,?,?,?,?,?)'
          ).bind('jikan', String(c.mal_id), c.name, 'anime', c.images?.jpg?.image_url || '', c.anime?.[0]?.anime?.title || ''));

          await env.DB.batch(inserts);
          return json({ ok: true, imported: data.data.length }, 200, origin);
        }

        if (p === '/admin/stock/update' && m === 'POST') {
          const { id, rarity, potential, base_overall, base_price, max_supply, name, club, nation, position, series, anime_role, image_url } = await req.json();
          if (!id) return err('Missing id', 400, origin);
          await env.DB.prepare(`
            UPDATE admin_stock SET
              rarity = COALESCE(?, rarity),
              potential = COALESCE(?, potential),
              base_overall = COALESCE(?, base_overall),
              base_price = COALESCE(?, base_price),
              max_supply = COALESCE(?, max_supply),
              name = COALESCE(?, name),
              club = COALESCE(?, club),
              nation = COALESCE(?, nation),
              position = COALESCE(?, position),
              series = COALESCE(?, series),
              anime_role = COALESCE(?, anime_role),
              image_url = COALESCE(?, image_url)
            WHERE id = ?
          `).bind(rarity, potential, base_overall, base_price, max_supply, name, club, nation, position, series, anime_role, image_url, id).run();
          return json({ ok: true }, 200, origin);
        }

        if (p === '/admin/stock/approve' && m === 'POST') {
          const { id } = await req.json();
          const item = await env.DB.prepare('SELECT * FROM admin_stock WHERE id = ?').bind(id).first();
          if (!item) return err('Stock item not found', 404, origin);
          if (!item.rarity || !item.potential || !item.base_overall || !item.base_price || !item.max_supply) {
            return err('Fill in all card details before approving', 400, origin);
          }

          const result = await env.DB.prepare(`
            INSERT INTO cards (name, category, rarity, image_url, club, nation, position, series, anime_role, potential, base_overall, base_price, market_price, max_supply, source, external_id)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
          `).bind(item.name, item.category, item.rarity, item.image_url, item.club, item.nation, item.position, item.series, item.anime_role, item.potential, item.base_overall, item.base_price, item.base_price, item.max_supply, item.source, item.external_id).run();

          await env.DB.prepare('UPDATE admin_stock SET status = ?, card_id = ?, approved_at = unixepoch() WHERE id = ?').bind('approved', result.meta.last_row_id, id).run();

          // Seed initial price history
          await env.DB.prepare('INSERT INTO price_history (card_id, price, change_pct, trigger) VALUES (?,?,?,?)').bind(result.meta.last_row_id, item.base_price, 0, 'admin').run();

          return json({ ok: true, card_id: result.meta.last_row_id }, 200, origin);
        }

        if (p === '/admin/stock/reject' && m === 'POST') {
          const { id } = await req.json();
          await env.DB.prepare('UPDATE admin_stock SET status = ? WHERE id = ?').bind('rejected', id).run();
          return json({ ok: true }, 200, origin);
        }

        // ── ADMIN CARDS ───────────────────────────────────────
        if (p === '/admin/cards' && m === 'GET') {
          const page   = parseInt(url.searchParams.get('page') || '1');
          const limit  = Math.min(parseInt(url.searchParams.get('limit') || '20'), 50);
          const offset = (page - 1) * limit;
          const cards  = await env.DB.prepare('SELECT * FROM cards ORDER BY created_at DESC LIMIT ? OFFSET ?').bind(limit, offset).all();
          return json({ cards: cards.results, page, limit }, 200, origin);
        }

        if (p === '/admin/cards' && m === 'POST') {
          const { name, category, rarity, image_url, club, nation, position, series, anime_role, potential, base_overall, base_price, max_supply } = await req.json();
          if (!name || !category || !rarity || !potential || !base_overall || !base_price || !max_supply) return err('Missing required fields', 400, origin);

          const result = await env.DB.prepare(`
            INSERT INTO cards (name, category, rarity, image_url, club, nation, position, series, anime_role, potential, base_overall, base_price, market_price, max_supply, source)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,'manual')
          `).bind(name, category, rarity, image_url || '', club, nation, position, series, anime_role, potential, base_overall, base_price, base_price, max_supply).run();

          await env.DB.prepare('INSERT INTO price_history (card_id, price, change_pct, trigger) VALUES (?,?,?,?)').bind(result.meta.last_row_id, base_price, 0, 'admin').run();

          return json({ ok: true, card_id: result.meta.last_row_id }, 201, origin);
        }

        if (p.startsWith('/admin/cards/') && m === 'PATCH') {
          const cardId = p.split('/')[3];
          const body   = await req.json();
          const fields = ['name','rarity','image_url','club','nation','position','series','anime_role','potential','base_overall','base_price','max_supply','is_active'];
          const updates = [];
          const vals = [];
          for (const f of fields) {
            if (body[f] !== undefined) { updates.push(`${f} = ?`); vals.push(body[f]); }
          }
          if (!updates.length) return err('Nothing to update', 400, origin);
          vals.push(cardId);
          await env.DB.prepare(`UPDATE cards SET ${updates.join(',')}, updated_at = unixepoch() WHERE id = ?`).bind(...vals).run();
          return json({ ok: true }, 200, origin);
        }

        // ── ADMIN PACKS ───────────────────────────────────────
        if (p === '/admin/packs' && m === 'GET') {
          const packs = await env.DB.prepare('SELECT * FROM packs ORDER BY created_at DESC').all();
          return json(packs.results, 200, origin);
        }

        if (p === '/admin/packs' && m === 'POST') {
          const { name, category, type, image_url, hero_image_url, description, cost_single, cost_ten, pity_threshold, starts_at, expires_at } = await req.json();
          if (!name || !category || !cost_single || !cost_ten) return err('Missing fields', 400, origin);
          const result = await env.DB.prepare(
            'INSERT INTO packs (name, category, type, image_url, hero_image_url, description, cost_single, cost_ten, pity_threshold, starts_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)'
          ).bind(name, category, type || 'pack', image_url || '', hero_image_url || '', description || '', cost_single, cost_ten, pity_threshold || null, starts_at || null, expires_at || null).run();
          return json({ ok: true, pack_id: result.meta.last_row_id }, 201, origin);
        }

        if (p.startsWith('/admin/packs/') && m === 'PATCH') {
          const packId = p.split('/')[3];
          const body   = await req.json();
          const fields = ['name','image_url','hero_image_url','description','cost_single','cost_ten','pity_threshold','is_live','starts_at','expires_at','sort_order'];
          const updates = [];
          const vals = [];
          for (const f of fields) {
            if (body[f] !== undefined) { updates.push(`${f} = ?`); vals.push(body[f]); }
          }
          if (!updates.length) return err('Nothing to update', 400, origin);
          vals.push(packId);
          await env.DB.prepare(`UPDATE packs SET ${updates.join(',')}, updated_at = unixepoch() WHERE id = ?`).bind(...vals).run();
          return json({ ok: true }, 200, origin);
        }

        if (p.startsWith('/admin/packs/') && p.endsWith('/cards') && m === 'POST') {
          const packId = p.split('/')[3];
          const { reward_type, card_id, ruc_id, coins_amount, weight, is_featured } = await req.json();
          await env.DB.prepare(
            'INSERT INTO pack_cards (pack_id, reward_type, card_id, ruc_id, coins_amount, weight, is_featured) VALUES (?,?,?,?,?,?,?)'
          ).bind(packId, reward_type || 'card', card_id || null, ruc_id || null, coins_amount || null, weight || 100, is_featured || 0).run();
          return json({ ok: true }, 201, origin);
        }

        if (p.startsWith('/admin/packs/') && p.endsWith('/slots') && m === 'POST') {
          const packId = p.split('/')[3];
          const { reward_type, card_id, ruc_id, coins_amount, quantity, weight, is_grand_prize, max_wins, sort_order } = await req.json();
          await env.DB.prepare(
            'INSERT INTO wheel_slots (pack_id, reward_type, card_id, ruc_id, coins_amount, quantity, weight, is_grand_prize, max_wins, sort_order) VALUES (?,?,?,?,?,?,?,?,?,?)'
          ).bind(packId, reward_type || 'card', card_id || null, ruc_id || null, coins_amount || null, quantity || 1, weight || 100, is_grand_prize || 0, max_wins || null, sort_order || 0).run();
          return json({ ok: true }, 201, origin);
        }

        // ── ADMIN TRIVIA ──────────────────────────────────────
        if (p === '/admin/trivia' && m === 'GET') {
          const q = await env.DB.prepare('SELECT * FROM trivia_questions ORDER BY created_at DESC').all();
          return json(q.results, 200, origin);
        }

        if (p === '/admin/trivia' && m === 'POST') {
          const { category, question, option_a, option_b, option_c, option_d, correct_option, difficulty, timer_seconds, reward_type, reward_coins, reward_card_id, reward_ruc_id } = await req.json();
          if (!question || !option_a || !option_b || !option_c || !option_d || !correct_option) return err('Missing fields', 400, origin);
          await env.DB.prepare(
            'INSERT INTO trivia_questions (category, question, option_a, option_b, option_c, option_d, correct_option, difficulty, timer_seconds, reward_type, reward_coins, reward_card_id, reward_ruc_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)'
          ).bind(category || 'general', question, option_a, option_b, option_c, option_d, correct_option, difficulty || 'medium', timer_seconds || 10, reward_type || 'coins', reward_coins || 50, reward_card_id || null, reward_ruc_id || null).run();
          return json({ ok: true }, 201, origin);
        }

        if (p.startsWith('/admin/trivia/') && m === 'PATCH') {
          const qId  = p.split('/')[3];
          const body = await req.json();
          const fields = ['question','option_a','option_b','option_c','option_d','correct_option','difficulty','timer_seconds','reward_type','reward_coins','reward_card_id','reward_ruc_id','is_active'];
          const updates = [];
          const vals = [];
          for (const f of fields) {
            if (body[f] !== undefined) { updates.push(`${f} = ?`); vals.push(body[f]); }
          }
          if (!updates.length) return err('Nothing to update', 400, origin);
          vals.push(qId);
          await env.DB.prepare(`UPDATE trivia_questions SET ${updates.join(',')} WHERE id = ?`).bind(...vals).run();
          return json({ ok: true }, 200, origin);
        }

        if (p.startsWith('/admin/trivia/') && m === 'DELETE') {
          const qId = p.split('/')[3];
          await env.DB.prepare('UPDATE trivia_questions SET is_active = 0 WHERE id = ?').bind(qId).run();
          return json({ ok: true }, 200, origin);
        }

        // ── ADMIN DAILY REWARDS ───────────────────────────────
        if (p === '/admin/daily-rewards' && m === 'GET') {
          const rewards = await env.DB.prepare('SELECT * FROM daily_rewards ORDER BY day_number ASC').all();
          return json(rewards.results, 200, origin);
        }

        if (p === '/admin/daily-rewards' && m === 'POST') {
          const { day_number, reward_type, reward_coins, reward_ref_id, label } = await req.json();
          if (!day_number) return err('Missing day_number', 400, origin);
          await env.DB.prepare(`
            INSERT INTO daily_rewards (day_number, reward_type, reward_coins, reward_ref_id, label)
            VALUES (?,?,?,?,?)
            ON CONFLICT(day_number) DO UPDATE SET
              reward_type = excluded.reward_type,
              reward_coins = excluded.reward_coins,
              reward_ref_id = excluded.reward_ref_id,
              label = excluded.label,
              updated_at = unixepoch()
          `).bind(day_number, reward_type || 'coins', reward_coins || 0, reward_ref_id || null, label || `Day ${day_number}`).run();
          return json({ ok: true }, 200, origin);
        }

        // ── ADMIN RANK UP CARDS ───────────────────────────────
        if (p === '/admin/rank-up-cards' && m === 'GET') {
          const rucs = await env.DB.prepare('SELECT * FROM rank_up_cards ORDER BY boost_amount ASC').all();
          return json(rucs.results, 200, origin);
        }

        if (p === '/admin/rank-up-cards' && m === 'POST') {
          const { name, rarity, boost_amount, image_url, store_price } = await req.json();
          if (!name || !rarity || !boost_amount || !store_price) return err('Missing fields', 400, origin);
          await env.DB.prepare('INSERT INTO rank_up_cards (name, rarity, boost_amount, image_url, store_price) VALUES (?,?,?,?,?)').bind(name, rarity, boost_amount, image_url || '', store_price).run();
          return json({ ok: true }, 201, origin);
        }

        if (p.startsWith('/admin/rank-up-cards/') && m === 'PATCH') {
          const rucId = p.split('/')[3];
          const { name, rarity, boost_amount, store_price, is_active } = await req.json();
          await env.DB.prepare(`
            UPDATE rank_up_cards SET
              name = COALESCE(?, name),
              rarity = COALESCE(?, rarity),
              boost_amount = COALESCE(?, boost_amount),
              store_price = COALESCE(?, store_price),
              is_active = COALESCE(?, is_active)
            WHERE id = ?
          `).bind(name, rarity, boost_amount, store_price, is_active, rucId).run();
          return json({ ok: true }, 200, origin);
        }

        // ── ADMIN ACHIEVEMENTS ────────────────────────────────
        if (p === '/admin/achievements' && m === 'GET') {
          const ach = await env.DB.prepare('SELECT * FROM achievements ORDER BY created_at DESC').all();
          return json(ach.results, 200, origin);
        }

        if (p === '/admin/achievements' && m === 'POST') {
          const { name, description, icon, trigger_type, trigger_value, reward_coins, reward_card_id, reward_ruc_id } = await req.json();
          if (!name || !trigger_type || !trigger_value) return err('Missing fields', 400, origin);
          await env.DB.prepare(
            'INSERT INTO achievements (name, description, icon, trigger_type, trigger_value, reward_coins, reward_card_id, reward_ruc_id) VALUES (?,?,?,?,?,?,?,?)'
          ).bind(name, description || '', icon || '', trigger_type, trigger_value, reward_coins || 0, reward_card_id || null, reward_ruc_id || null).run();
          return json({ ok: true }, 201, origin);
        }

        // ── ADMIN USERS ───────────────────────────────────────
        if (p === '/admin/users' && m === 'GET') {
          const page   = parseInt(url.searchParams.get('page') || '1');
          const limit  = Math.min(parseInt(url.searchParams.get('limit') || '20'), 50);
          const offset = (page - 1) * limit;
          const users  = await env.DB.prepare('SELECT id, email, username, display_name, coins, xp, total_spins, login_streak, is_banned, created_at FROM accounts ORDER BY created_at DESC LIMIT ? OFFSET ?').bind(limit, offset).all();
          return json({ users: users.results, page, limit }, 200, origin);
        }

        if (p.startsWith('/admin/users/') && p.endsWith('/ban') && m === 'POST') {
          const userId = p.split('/')[3];
          const { reason, expires_at } = await req.json();
          await env.DB.prepare('UPDATE accounts SET is_banned = 1, ban_reason = ?, ban_expires_at = ? WHERE id = ?').bind(reason || 'Violation', expires_at || null, userId).run();
          return json({ ok: true }, 200, origin);
        }

        if (p.startsWith('/admin/users/') && p.endsWith('/unban') && m === 'POST') {
          const userId = p.split('/')[3];
          await env.DB.prepare('UPDATE accounts SET is_banned = 0, ban_reason = NULL, ban_expires_at = NULL WHERE id = ?').bind(userId).run();
          return json({ ok: true }, 200, origin);
        }

        // ── ADMIN IMAGE UPLOAD ────────────────────────────────
        if (p === '/admin/upload' && m === 'POST') {
          const formData  = await req.formData();
          const file      = formData.get('file');
          if (!file) return err('No file provided', 400, origin);
          const cloudName = env.CLOUDINARY_CLOUD_NAME;
          const apiKey    = env.CLOUDINARY_API_KEY;
          const apiSecret = env.CLOUDINARY_API_SECRET;
          const ts        = Math.floor(Date.now() / 1000);
          const str       = `folder=virtualpitch&timestamp=${ts}${apiSecret}`;
          const hashBuf   = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(str));
          const sig       = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2,'0')).join('');
          const fd        = new FormData();
          fd.append('file', file);
          fd.append('api_key', apiKey);
          fd.append('timestamp', ts);
          fd.append('signature', sig);
          fd.append('folder', 'virtualpitch');
          const res  = await fetch(`https://api.cloudinary.com/v1_1/${cloudName}/image/upload`, { method: 'POST', body: fd });
          const data = await res.json();
          return json({ url: data.secure_url }, 200, origin);
        }

        return err('Admin route not found', 404, origin);
      }

      return err('Not found', 404, origin);
    } catch (e) {
      console.error('Worker error:', e);
      return err(e.message || 'Internal server error', 500, origin);
    }
  },

  // ═══════════════════════════════════════════════════════════
  // CRON HANDLERS
  // ═══════════════════════════════════════════════════════════
  async scheduled(event, env) {
    const hour = new Date().getHours();

    // Every hour
    await runPriceFluctuation(env.DB);
    await rebuildLeaderboard(env.DB, 'football');
    await rebuildLeaderboard(env.DB, 'anime');

    // Daily at midnight UTC
    if (hour === 0) {
      await runDailyReset(env.DB);
    }
  },
};
