// ============================================
// VoucherVault Cloudflare Worker (D1 + R2)
// ============================================
// Deploy this as your Cloudflare Worker with D1 and R2 bindings

// CORS headers for Pages frontend
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

// JWT-like simple token (in production, use proper JWT)
function generateToken(user) {
  const payload = btoa(JSON.stringify({ id: user.id, username: user.username, exp: Date.now() + 86400000 }));
  const signature = btoa(payload + 'YOUR_SECRET_KEY'); // Change this secret!
  return `${payload}.${signature}`;
}

function verifyToken(token) {
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
  const data = encoder.encode(password + 'YOUR_SALT'); // Change this salt!
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// ============================================
// MAIN HANDLER
// ============================================
export default {
  async fetch(request, env, ctx) {
    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    try {
      // Auth routes (no auth required)
      if (path === '/api/auth/register' && method === 'POST') {
        return await handleRegister(request, env);
      }
      if (path === '/api/auth/login' && method === 'POST') {
        return await handleLogin(request, env);
      }

      // Image upload (auth required)
      if (path === '/api/upload' && method === 'POST') {
        return await handleImageUpload(request, env);
      }

      // Protected routes - verify auth
      const authHeader = request.headers.get('Authorization');
      const token = authHeader?.replace('Bearer ', '');
      const userData = verifyToken(token);

      if (!userData) {
        return errorResponse('Unauthorized', 401);
      }

      // Voucher routes
      if (path === '/api/vouchers' && method === 'GET') {
        return await handleGetVouchers(url, env, userData);
      }
      if (path === '/api/vouchers' && method === 'POST') {
        return await handleCreateVoucher(request, env, userData);
      }
      if (path.match(/^\/api\/vouchers\/[^/]+$/) && method === 'GET') {
        const id = path.split('/')[3];
        return await handleGetVoucher(id, env, userData);
      }
      if (path.match(/^\/api\/vouchers\/[^/]+$/) && method === 'DELETE') {
        const id = path.split('/')[3];
        return await handleDeleteVoucher(id, env, userData);
      }
      if (path.match(/^\/api\/vouchers\/[^/]+\/toggle$/) && method === 'POST') {
        const id = path.split('/')[3];
        return await handleToggleVoucher(id, env, userData);
      }

      return errorResponse('Not found', 404);
    } catch (err) {
      console.error('Worker error:', err);
      return errorResponse('Internal server error', 500);
    }
  }
};

// ============================================
// AUTH HANDLERS
// ============================================
async function handleRegister(request, env) {
  const { username, password } = await request.json();

  if (!username || !password || username.length < 3 || password.length < 6) {
    return errorResponse('Invalid username or password (min 3 and 6 chars)');
  }

  // Check if user exists
  const existing = await env.DB.prepare(
    'SELECT id FROM users WHERE username = ?'
  ).bind(username.toLowerCase()).first();

  if (existing) {
    return errorResponse('Username already exists');
  }

  const passwordHash = await hashPassword(password);

  const result = await env.DB.prepare(
    'INSERT INTO users (username, password_hash) VALUES (?, ?) RETURNING id, username'
  ).bind(username.toLowerCase(), passwordHash).first();

  const token = generateToken(result);

  return jsonResponse({ token, user: { id: result.id, username: result.username } });
}

async function handleLogin(request, env) {
  const { username, password } = await request.json();

  const user = await env.DB.prepare(
    'SELECT id, username, password_hash FROM users WHERE username = ?'
  ).bind(username.toLowerCase()).first();

  if (!user) {
    return errorResponse('Invalid credentials', 401);
  }

  const passwordHash = await hashPassword(password);

  if (passwordHash !== user.password_hash) {
    return errorResponse('Invalid credentials', 401);
  }

  const token = generateToken(user);

  return jsonResponse({ 
    token, 
    user: { id: user.id, username: user.username } 
  });
}

// ============================================
// IMAGE UPLOAD HANDLER (R2)
// ============================================
async function handleImageUpload(request, env) {
  const formData = await request.formData();
  const file = formData.get('image');

  if (!file || !(file instanceof File)) {
    return errorResponse('No image provided');
  }

  // Validate file type
  const allowedTypes = ['image/jpeg', 'image/png', 'image/webp'];
  if (!allowedTypes.includes(file.type)) {
    return errorResponse('Invalid file type. Only JPG, PNG, WebP allowed');
  }

  // Validate file size (5MB)
  if (file.size > 5 * 1024 * 1024) {
    return errorResponse('File too large. Max 5MB');
  }

  // Generate unique filename
  const ext = file.name.split('.').pop();
  const filename = `vouchers/${Date.now()}-${Math.random().toString(36).substring(2, 15)}.${ext}`;

  // Upload to R2
  await env.VOUCHER_IMAGES.put(filename, file.stream(), {
    httpMetadata: {
      contentType: file.type,
      cacheControl: 'public, max-age=31536000'
    }
  });

  // Return the public URL
  // If using custom domain: `https://images.yourdomain.com/${filename}`
  // If using R2.dev: `https://${env.ACCOUNT_ID}.r2.dev/${filename}`
  const publicUrl = env.R2_PUBLIC_URL 
    ? `${env.R2_PUBLIC_URL}/${filename}`
    : `https://${env.R2_BUCKET_NAME}.${env.ACCOUNT_ID}.r2.dev/${filename}`;

  return jsonResponse({ url: publicUrl, key: filename });
}

// ============================================
// VOUCHER HANDLERS
// ============================================
async function handleGetVouchers(url, env, userData) {
  const status = url.searchParams.get('status') || 'unspent';

  let query = `
    SELECT v.*, u.username as spent_by_name
    FROM vouchers v
    LEFT JOIN users u ON v.spent_by = u.id
    WHERE v.user_id = ? AND v.status = ?
    ORDER BY 
      CASE WHEN v.status = 'unspent' THEN v.created_at END DESC,
      CASE WHEN v.status = 'spent' THEN v.spent_at END DESC
  `;

  const results = await env.DB.prepare(query)
    .bind(userData.id, status)
    .all();

  // Map spent_by_name to spent_by for frontend compatibility
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

  if (!voucher) {
    return errorResponse('Voucher not found', 404);
  }

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
  // Get current voucher
  const voucher = await env.DB.prepare(
    'SELECT * FROM vouchers WHERE id = ? AND user_id = ?'
  ).bind(id, userData.id).first();

  if (!voucher) {
    return errorResponse('Voucher not found', 404);
  }

  const newStatus = voucher.status === 'unspent' ? 'spent' : 'unspent';
  const spentAt = newStatus === 'spent' ? new Date().toISOString() : null;
  const spentBy = newStatus === 'spent' ? userData.id : null;

  await env.DB.prepare(`
    UPDATE vouchers 
    SET status = ?, spent_at = ?, spent_by = ?
    WHERE id = ?
  `).bind(newStatus, spentAt, spentBy, id).run();

  // Fetch updated voucher with username
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

  if (!voucher) {
    return errorResponse('Voucher not found', 404);
  }

  // Delete image from R2 if exists
  if (voucher.image_url && env.VOUCHER_IMAGES) {
    try {
      const key = voucher.image_url.split('/').pop();
      await env.VOUCHER_IMAGES.delete(`vouchers/${key}`);
    } catch (err) {
      console.error('Failed to delete image:', err);
    }
  }

  await env.DB.prepare('DELETE FROM vouchers WHERE id = ?').bind(id).run();

  return jsonResponse({ success: true });
}
