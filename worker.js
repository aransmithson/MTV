// ============================================
// VoucherVault Cloudflare Worker (D1 + R2)
// ============================================

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
  });
}

function errorResponse(message, status = 400) {
  return jsonResponse({ error: message }, status);
}

// Token includes is_admin flag
function generateToken(user) {
  const payload = btoa(JSON.stringify({
    id: user.id,
    username: user.username,
    is_admin: user.is_admin ? 1 : 0,
    exp: Date.now() + 86400000 // 24h
  }));
  const signature = btoa(payload + 'YOUR_SECRET_KEY'); // ← Change this!
  return `${payload}.${signature}`;
}

function verifyToken(token) {
  if (!token) return null;
  try {
    const [payload] = token.split('.');
    const data = JSON.parse(atob(payload));
    if (data.exp < Date.now()) return null;
    return data;
  } catch {
    return null;
  }
}

async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password + 'YOUR_SALT'); // ← Change this!
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Accepts token from Authorization header OR ?token= query param
// The query param method allows <img src="/api/image/...?token=xxx"> to work
function getTokenFromRequest(request) {
  const authHeader = request.headers.get('Authorization');
  if (authHeader) return authHeader.replace('Bearer ', '');
  const url = new URL(request.url);
  return url.searchParams.get('token');
}

// ============================================
// MAIN HANDLER
// ============================================
export default {
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    try {
      // ── Public routes (no auth) ──────────────────────────────────────────

      // Check if first-time setup is needed
      if (path === '/api/auth/setup' && method === 'GET') {
        return await handleSetupCheck(env);
      }

      // One-time admin bootstrap — only succeeds when zero users exist
      if (path === '/api/auth/setup' && method === 'POST') {
        return await handleSetup(request, env);
      }

      // Login
      if (path === '/api/auth/login' && method === 'POST') {
        return await handleLogin(request, env);
      }

      // ── All remaining routes require a valid token ────────────────────────

      const token = getTokenFromRequest(request);
      const userData = verifyToken(token);

      if (!userData) {
        return errorResponse('Unauthorized', 401);
      }

      // Serve R2 image through worker (authenticated)
      // Key format: vouchers/timestamp-random.ext
      if (path.startsWith('/api/image/') && method === 'GET') {
        const key = path.slice('/api/image/'.length);
        return await handleServeImage(key, env);
      }

      // Image upload (auth required — was public in original)
      if (path === '/api/upload' && method === 'POST') {
        return await handleImageUpload(request, env);
      }

      // ── Voucher routes ────────────────────────────────────────────────────

      if (path === '/api/vouchers' && method === 'GET') {
        return await handleGetVouchers(url, env, userData);
      }
      if (path === '/api/vouchers' && method === 'POST') {
        return await handleCreateVoucher(request, env, userData);
      }
      if (path.match(/^\/api\/vouchers\/[^/]+$/) && method === 'GET') {
        return await handleGetVoucher(path.split('/')[3], env, userData);
      }
      if (path.match(/^\/api\/vouchers\/[^/]+$/) && method === 'DELETE') {
        return await handleDeleteVoucher(path.split('/')[3], env, userData);
      }
      if (path.match(/^\/api\/vouchers\/[^/]+\/toggle$/) && method === 'POST') {
        return await handleToggleVoucher(path.split('/')[3], env, userData);
      }

      // ── Admin-only routes ─────────────────────────────────────────────────

      if (!userData.is_admin) {
        return errorResponse('Not found', 404); // Don't leak route existence
      }

      if (path === '/api/admin/users' && method === 'GET') {
        return await handleListUsers(env);
      }
      if (path === '/api/admin/users' && method === 'POST') {
        return await handleCreateUser(request, env);
      }
      if (path.match(/^\/api\/admin\/users\/[^/]+$/) && method === 'DELETE') {
        return await handleDeleteUser(path.split('/')[4], env, userData);
      }

      return errorResponse('Not found', 404);
    } catch (err) {
      console.error('Worker error:', err);
      return errorResponse('Internal server error', 500);
    }
  }
};

// ============================================
// SETUP / AUTH HANDLERS
// ============================================

// Returns whether first-time setup is still needed
async function handleSetupCheck(env) {
  const row = await env.DB.prepare('SELECT COUNT(*) as count FROM users').first();
  return jsonResponse({ needsSetup: row.count === 0 });
}

// Creates the first admin account — rejected if any users already exist
async function handleSetup(request, env) {
  const row = await env.DB.prepare('SELECT COUNT(*) as count FROM users').first();
  if (row.count > 0) {
    return errorResponse('Setup already complete. An admin must create new users.', 403);
  }

  const { username, password } = await request.json();

  if (!username || !password || username.length < 3 || password.length < 6) {
    return errorResponse('Username min 3 chars, password min 6 chars');
  }

  const passwordHash = await hashPassword(password);

  const result = await env.DB.prepare(
    'INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1) RETURNING id, username, is_admin'
  ).bind(username.toLowerCase(), passwordHash).first();

  const token = generateToken(result);
  return jsonResponse({ token, user: { id: result.id, username: result.username, is_admin: 1 } });
}

async function handleLogin(request, env) {
  const { username, password } = await request.json();

  const user = await env.DB.prepare(
    'SELECT id, username, password_hash, is_admin FROM users WHERE username = ?'
  ).bind(username.toLowerCase()).first();

  if (!user) return errorResponse('Invalid credentials', 401);

  const passwordHash = await hashPassword(password);
  if (passwordHash !== user.password_hash) return errorResponse('Invalid credentials', 401);

  const token = generateToken(user);
  return jsonResponse({
    token,
    user: { id: user.id, username: user.username, is_admin: user.is_admin }
  });
}

// ============================================
// IMAGE HANDLERS
// ============================================

// Serves R2 objects through the worker — requires valid auth token
async function handleServeImage(key, env) {
  if (!key) return new Response('Bad request', { status: 400 });

  const object = await env.VOUCHER_IMAGES.get(key);
  if (!object) return new Response('Not found', { status: 404 });

  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set('Cache-Control', 'private, max-age=3600');
  headers.set('ETag', object.httpEtag);

  return new Response(object.body, { headers });
}

async function handleImageUpload(request, env) {
  const formData = await request.formData();
  const file = formData.get('image');

  if (!file || !(file instanceof File)) {
    return errorResponse('No image provided');
  }

  const allowedTypes = ['image/jpeg', 'image/png', 'image/webp'];
  if (!allowedTypes.includes(file.type)) {
    return errorResponse('Invalid file type. Only JPG, PNG, WebP allowed');
  }

  if (file.size > 5 * 1024 * 1024) {
    return errorResponse('File too large. Max 5MB');
  }

  const ext = file.name.split('.').pop().toLowerCase();
  // Store key only — no public URL, served via /api/image/:key
  const key = `vouchers/${Date.now()}-${Math.random().toString(36).substring(2, 15)}.${ext}`;

  await env.VOUCHER_IMAGES.put(key, file.stream(), {
    httpMetadata: {
      contentType: file.type,
      cacheControl: 'private, max-age=3600'
    }
  });

  return jsonResponse({ key });
}

// ============================================
// VOUCHER HANDLERS
// ============================================

async function handleGetVouchers(url, env, userData) {
  const status = url.searchParams.get('status') || 'unspent';

  const results = await env.DB.prepare(`
    SELECT v.*, u.username as spent_by_name
    FROM vouchers v
    LEFT JOIN users u ON v.spent_by = u.id
    WHERE v.user_id = ? AND v.status = ?
    ORDER BY
      CASE WHEN v.status = 'unspent' THEN v.created_at END DESC,
      CASE WHEN v.status = 'spent' THEN v.spent_at END DESC
  `).bind(userData.id, status).all();

  const vouchers = results.results.map(v => ({
    ...v,
    spent_by: v.spent_by_name || v.spent_by,
    value: parseFloat(v.value)
  }));

  return jsonResponse(vouchers);
}

async function handleGetVoucher(id, env, userData) {
  const voucher = await env.DB.prepare(`
    SELECT v.*, u.username as spent_by_name
    FROM vouchers v
    LEFT JOIN users u ON v.spent_by = u.id
    WHERE v.id = ? AND v.user_id = ?
  `).bind(id, userData.id).first();

  if (!voucher) return errorResponse('Voucher not found', 404);

  return jsonResponse({
    ...voucher,
    spent_by: voucher.spent_by_name || voucher.spent_by,
    value: parseFloat(voucher.value)
  });
}

async function handleCreateVoucher(request, env, userData) {
  const body = await request.json();
  const { retailer, value, code, expiry, notes, image_url } = body;

  if (!retailer || !value) {
    return errorResponse('Retailer and value are required');
  }

  const result = await env.DB.prepare(`
    INSERT INTO vouchers (user_id, retailer, value, code, expiry, notes, image_url, status, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'unspent', datetime('now'))
    RETURNING *
  `).bind(userData.id, retailer, value, code || null, expiry || null, notes || null, image_url || null).first();

  return jsonResponse(result, 201);
}

async function handleToggleVoucher(id, env, userData) {
  const voucher = await env.DB.prepare(
    'SELECT * FROM vouchers WHERE id = ? AND user_id = ?'
  ).bind(id, userData.id).first();

  if (!voucher) return errorResponse('Voucher not found', 404);

  const newStatus = voucher.status === 'unspent' ? 'spent' : 'unspent';
  const spentAt = newStatus === 'spent' ? new Date().toISOString() : null;
  const spentBy = newStatus === 'spent' ? userData.id : null;

  await env.DB.prepare(
    'UPDATE vouchers SET status = ?, spent_at = ?, spent_by = ? WHERE id = ?'
  ).bind(newStatus, spentAt, spentBy, id).run();

  const updated = await env.DB.prepare(`
    SELECT v.*, u.username as spent_by_name
    FROM vouchers v
    LEFT JOIN users u ON v.spent_by = u.id
    WHERE v.id = ?
  `).bind(id).first();

  return jsonResponse({
    ...updated,
    spent_by: updated.spent_by_name || updated.spent_by,
    value: parseFloat(updated.value)
  });
}

async function handleDeleteVoucher(id, env, userData) {
  const voucher = await env.DB.prepare(
    'SELECT image_url FROM vouchers WHERE id = ? AND user_id = ?'
  ).bind(id, userData.id).first();

  if (!voucher) return errorResponse('Voucher not found', 404);

  // Delete R2 object using the stored key directly
  if (voucher.image_url && env.VOUCHER_IMAGES) {
    try {
      await env.VOUCHER_IMAGES.delete(voucher.image_url);
    } catch (err) {
      console.error('Failed to delete R2 object:', err);
    }
  }

  await env.DB.prepare('DELETE FROM vouchers WHERE id = ?').bind(id).run();
  return jsonResponse({ success: true });
}

// ============================================
// ADMIN: USER MANAGEMENT
// ============================================

async function handleListUsers(env) {
  const results = await env.DB.prepare(
    'SELECT id, username, is_admin, created_at FROM users ORDER BY created_at ASC'
  ).all();
  return jsonResponse(results.results);
}

async function handleCreateUser(request, env) {
  const { username, password, is_admin } = await request.json();

  if (!username || !password || username.length < 3 || password.length < 6) {
    return errorResponse('Username min 3 chars, password min 6 chars');
  }

  const existing = await env.DB.prepare(
    'SELECT id FROM users WHERE username = ?'
  ).bind(username.toLowerCase()).first();

  if (existing) return errorResponse('Username already taken');

  const passwordHash = await hashPassword(password);

  const result = await env.DB.prepare(
    'INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?) RETURNING id, username, is_admin, created_at'
  ).bind(username.toLowerCase(), passwordHash, is_admin ? 1 : 0).first();

  return jsonResponse(result, 201);
}

async function handleDeleteUser(id, env, currentUser) {
  if (parseInt(id) === currentUser.id) {
    return errorResponse('You cannot delete your own account');
  }

  const user = await env.DB.prepare('SELECT id FROM users WHERE id = ?').bind(id).first();
  if (!user) return errorResponse('User not found', 404);

  await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(id).run();
  return jsonResponse({ success: true });
}
