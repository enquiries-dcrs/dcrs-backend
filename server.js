require('dotenv').config();
const { randomUUID } = require('crypto');
const express = require('express');
const multer = require('multer');
const cors = require('cors');
const { Pool } = require('pg');
const { createClient } = require('@supabase/supabase-js');
const rateLimit = require('express-rate-limit');

const app = express();
const port = process.env.PORT || 4000;

if (!process.env.DATABASE_URL) {
  console.error('FATAL: DATABASE_URL is not set. Add it to backend/.env or your environment.');
  process.exit(1);
}

// ============================================================================
// SECURITY FIREWALL 0: RATE LIMITING & ABUSE PROTECTION
// ============================================================================

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 300, // Limit each IP to 300 requests per window
  message: {
    error:
      'Too many requests from this IP. To protect system stability, please try again after 15 minutes.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const aiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 25, // Max 25 AI generations per IP per 15 mins
  message: {
    error: 'AI generation rate limit reached. To protect system resources, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const inviteLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // Max 10 invites per IP per hour
  message: { error: 'Too many staff invites sent. Please wait before inviting more users.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Initialize Supabase Client for validating incoming tokens
const supabaseUrl = process.env.SUPABASE_URL || '';
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY || '';
const supabase =
  supabaseUrl && supabaseAnonKey ? createClient(supabaseUrl, supabaseAnonKey) : null;

// Initialize Supabase Admin Client for user management (requires Service Role Key)
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
const supabaseAdmin =
  supabaseUrl && supabaseServiceKey
    ? createClient(supabaseUrl, supabaseServiceKey, {
        auth: {
          autoRefreshToken: false,
          persistSession: false,
        },
      })
    : null;

/**
 * Find a Supabase Auth user by email (case-insensitive), scanning listUsers pages.
 * Returns null if deleted from Auth or not found (e.g. beyond scan limit).
 */
async function findSupabaseAuthUserByEmail(targetEmail) {
  if (!supabaseAdmin || !targetEmail) return null;
  const want = String(targetEmail).trim().toLowerCase();
  let page = 1;
  const perPage = 500;
  for (let guard = 0; guard < 50; guard += 1) {
    const { data, error } = await supabaseAdmin.auth.admin.listUsers({ page, perPage });
    if (error) throw error;
    const batch = data.users || [];
    const found = batch.find((u) => (u.email || '').toLowerCase() === want);
    if (found) return found;
    if (!data.nextPage || batch.length === 0) return null;
    page = data.nextPage;
  }
  return null;
}

// Hosting behind reverse proxies (Render, etc.) so rate-limit uses correct IP.
app.set('trust proxy', 1);

/** Vercel + local dev. Set FRONTEND_URL (production site) and optional CORS_ORIGINS (comma-separated). */
function buildAllowedCorsOrigins() {
  const set = new Set([
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'https://dcrs-frontend-pearl.vercel.app',
  ]);
  const add = (s) => {
    if (typeof s !== 'string') return;
    const v = s.trim().replace(/\/$/, '');
    if (v) set.add(v);
  };
  add(process.env.FRONTEND_URL);
  (process.env.CORS_ORIGINS || '').split(',').forEach(add);
  return [...set];
}

const allowedCorsOrigins = buildAllowedCorsOrigins();

app.use(
  cors({
    origin(origin, callback) {
      if (!origin) {
        return callback(null, true);
      }
      if (allowedCorsOrigins.includes(origin)) {
        return callback(null, true);
      }
      if (
        process.env.CORS_ALLOW_VERCEL_PREVIEWS === 'true' &&
        /^https:\/\/[^\s/]+\.vercel\.app$/i.test(origin)
      ) {
        return callback(null, true);
      }
      return callback(null, false);
    },
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
    credentials: true,
  })
);

app.use(express.json({ limit: '2mb' }));

const profilePhotoUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter(_req, file, cb) {
    const allowed = new Set(['image/jpeg', 'image/png', 'image/webp']);
    if (allowed.has(file.mimetype)) return cb(null, true);
    cb(new Error('Only JPEG, PNG, or WebP images are allowed.'));
  },
});

function extFromProfileMime(mime) {
  if (mime === 'image/png') return 'png';
  if (mime === 'image/webp') return 'webp';
  return 'jpg';
}

// Correlation ID: structured logs + client support (no stack traces in JSON).
app.use((req, res, next) => {
  const incoming = req.get('x-request-id');
  const safeIncoming =
    typeof incoming === 'string' &&
    incoming.length >= 8 &&
    incoming.length <= 64 &&
    /^[a-zA-Z0-9._-]+$/.test(incoming)
      ? incoming.slice(0, 64)
      : null;
  req.correlationId = safeIncoming || randomUUID();
  res.setHeader('X-Request-ID', req.correlationId);
  next();
});

// Apply rate limits
app.use('/api/', globalLimiter);
app.use('/api/v1/ai/', aiLimiter);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

pool.on('error', (err) => {
  console.error('Unexpected PostgreSQL pool idle client error:', err);
});

function logRequestError(req, err, tag) {
  const payload = {
    level: 'error',
    tag: tag || 'handler',
    correlationId: req.correlationId || null,
    message: err && err.message,
    stack: err && err.stack,
    path: req.originalUrl || req.url,
    method: req.method,
  };
  console.error(JSON.stringify(payload));
}

function clientError(req, res, status, publicMessage) {
  const body = { error: publicMessage };
  if (req.correlationId) body.requestId = req.correlationId;
  return res.status(status).json(body);
}

/**
 * Append-only audit row (see sql/001_audit_logs.sql). Uses req.dbUser.id + req.user.email after auth.
 * Do not store raw clinical text in metadata — lengths/flags only.
 */
async function writeAuditLog(req, { action, resourceType = null, resourceId = null, outcome = 'SUCCESS', metadata = null }) {
  try {
    const actorUserId = req.dbUser?.id ?? null;
    const actorEmail = req.user?.email ?? null;
    const actorRole = req.dbUser?.system_role ?? null;
    const ip = req.ip || null;
    let userAgent = null;
    try {
      userAgent = typeof req.get === 'function' ? req.get('user-agent') : null;
    } catch (_) {
      userAgent = null;
    }
    const path = req.originalUrl || req.url || null;
    const method = req.method || null;

    await pool.query(
      `INSERT INTO public.audit_logs (
        actor_user_id, actor_email, actor_role, action, resource_type, resource_id,
        http_method, request_path, ip_address, user_agent, outcome, metadata
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb)`,
      [
        actorUserId,
        actorEmail,
        actorRole,
        action,
        resourceType,
        resourceId != null ? String(resourceId) : null,
        method,
        path,
        ip,
        userAgent,
        outcome,
        metadata == null ? null : JSON.stringify(metadata),
      ]
    );
  } catch (e) {
    logRequestError(req, e, 'audit-append');
  }
}

function userHomeScope(req) {
  return req.dbUser?.home_scope_id ?? null;
}

function normalizeTaskRow(t) {
  if (!t || typeof t !== 'object') return t;
  const due =
    t.dueDate ??
    t.due_date ??
    t.due_at ??
    t.dueAt ??
    null;
  const dueDate = due ? new Date(due).toLocaleDateString('en-GB') : (t.dueDate || t.due_date || null);
  return {
    id: t.id,
    title: t.title ?? t.task_title ?? t.name ?? '',
    status: t.status ?? t.task_status ?? 'Open',
    priority: t.priority ?? t.task_priority ?? 'Normal',
    dueDate,
    // keep originals for debugging/compat without leaking unexpected columns
    created_at: t.created_at ?? null,
  };
}

app.get('/', (req, res) => {
  res.json({ status: 'online', message: 'DCRS Secured API is running!' });
});

// ---------------------------------------------------------------------------
// SECURITY FIREWALL 1: AUTHENTICATION (Who are you?)
// ---------------------------------------------------------------------------
const authenticateToken = async (req, res, next) => {
  if (req.method === 'OPTIONS') {
    return next();
  }

  if (!supabase) {
    return clientError(req, res, 500, 'Server misconfiguration. Contact support.');
  }

  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return clientError(req, res, 401, 'Unauthorized: No security token provided');
  }

  const {
    data: { user },
    error,
  } = await supabase.auth.getUser(token);

  if (error || !user) {
    console.warn(`[SECURITY] Blocked invalid token attempt from IP: ${req.ip}`);
    return clientError(req, res, 403, 'Forbidden: Invalid or expired token');
  }

  // CRITICAL: Ignore user_metadata from the JWT as the source of truth for authorization.
  // Use PostgreSQL (users table) for system_role + home_scope_id.
  // Deny unknown Supabase identities: no silent "Staff" default (prevents group-wide scope by accident).
  try {
    const email = user.email || null;
    if (!email) {
      console.warn('[SECURITY] Supabase user missing email; blocking API access');
      return clientError(req, res, 403, 'Forbidden: Account is missing a verified email address.');
    }

    const dbResult = await pool.query(
      'SELECT id, email, system_role, home_scope_id, first_name, last_name, is_active FROM users WHERE lower(trim(email)) = lower(trim($1))',
      [email]
    );

    if (dbResult.rows.length === 0) {
      console.warn(`[SECURITY] Unprovisioned Supabase user attempted access: ${email}`);
      return clientError(
        req,
        res,
        403,
        'Forbidden: Your account is not provisioned in DCRS. Contact an administrator.'
      );
    }

    req.dbUser = dbResult.rows[0];
    if (req.dbUser.is_active === false) {
      console.warn(`[SECURITY] Suspended user attempted access: ${email}`);
      return clientError(req, res, 403, 'Forbidden: User account is deactivated.');
    }
  } catch (dbErr) {
    logRequestError(req, dbErr, 'auth-db');
    return clientError(req, res, 500, 'Authentication could not be verified. Please try again later.');
  }

  req.user = user;
  next();
};

// ---------------------------------------------------------------------------
// SECURITY FIREWALL 2: AUTHORIZATION (What are you allowed to do?)
// ---------------------------------------------------------------------------
const requireRole = (allowedRoles) => {
  return (req, res, next) => {
    const userRole = req.dbUser?.system_role;
    if (!userRole) {
      console.warn(`[SECURITY] Missing db role for user ${req.user?.email}`);
      return clientError(req, res, 403, 'Forbidden: Role could not be determined for this account.');
    }

    if (!allowedRoles.includes(userRole)) {
      console.warn(
        `[SECURITY] Access denied for user ${req.user?.email}. Role '${userRole}' attempted unauthorized action.`
      );
      return clientError(
        req,
        res,
        403,
        `Forbidden: Your current role (${userRole}) does not have permission to perform this action.`
      );
    }

    next();
  };
};

// Role matrix — tighten/extend to match your organisation (must match `users.system_role` values).
const ROLES_RESIDENT_AND_FACILITY_READ = [
  'Carer',
  'Senior Carer',
  'Nurse',
  'Deputy Manager',
  'Home Manager',
  'Regional Manager',
  'Admin',
  'Staff',
];
const ROLES_OFFLINE_SYNC_WRITE = ROLES_RESIDENT_AND_FACILITY_READ;
// NHS mock: same role set as routine clinical reads (no drift between lists).
const ROLES_NHS_INTEGRATION_READ = ROLES_RESIDENT_AND_FACILITY_READ;
const ROLES_TASKS_WRITE = ROLES_RESIDENT_AND_FACILITY_READ;
const ROLES_FOOD_DRINK_WRITE = ROLES_RESIDENT_AND_FACILITY_READ;
const ROLES_ACTIVITIES_WRITE = ROLES_RESIDENT_AND_FACILITY_READ;
const ROLES_DAILY_CARE_WRITE = ROLES_RESIDENT_AND_FACILITY_READ;
const ROLES_PEEP_WRITE = ['Deputy Manager', 'Home Manager', 'Regional Manager', 'Admin'];
const ROLES_CARE_PLAN_EDIT = ['Senior Carer', 'Deputy Manager', 'Home Manager', 'Regional Manager', 'Admin'];
const ROLES_CARE_PLAN_ARCHIVE = ['Deputy Manager', 'Home Manager', 'Regional Manager', 'Admin'];
const ROLES_ASSESSMENT_TEMPLATES_EDIT = ['Deputy Manager', 'Home Manager', 'Regional Manager', 'Admin'];
const ROLES_ASSESSMENTS_CREATE = ['Senior Carer', 'Deputy Manager', 'Home Manager', 'Regional Manager', 'Admin'];
const ROLES_RESIDENT_DOCUMENTS_UPLOAD = ['Senior Carer', 'Deputy Manager', 'Home Manager', 'Regional Manager', 'Admin'];
const ROLES_RESIDENT_DOCUMENTS_DELETE = ['Deputy Manager', 'Home Manager', 'Regional Manager', 'Admin'];

const residentDocUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024 }, // 20MB
  fileFilter(_req, file, cb) {
    // Allow common clinical document formats
    const allowed = new Set([
      'application/pdf',
      'image/jpeg',
      'image/png',
      'image/webp',
      'text/plain',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/msword',
    ]);
    if (allowed.has(file.mimetype)) return cb(null, true);
    cb(new Error('Unsupported file type. Allowed: PDF, images, TXT, DOC, DOCX.'));
  },
});

function sanitizeFilename(name) {
  const raw = typeof name === 'string' ? name.trim() : '';
  const base = raw.replace(/[/\\?%*:|"<>]/g, '-').replace(/\s+/g, ' ').trim();
  return base.slice(0, 120) || 'document';
}

app.use('/api/v1', authenticateToken);

// Who is logged in (Postgres is source of truth for role — not Supabase user_metadata).
app.get('/api/v1/auth/me', async (req, res) => {
  try {
    const u = req.dbUser;
    if (!u) {
      return clientError(req, res, 403, 'Account not provisioned.');
    }
    res.json({
      id: u.id,
      email: u.email,
      first_name: u.first_name,
      last_name: u.last_name,
      system_role: u.system_role,
      home_scope_id: u.home_scope_id,
      is_active: u.is_active,
    });
  } catch (err) {
    logRequestError(req, err, 'auth-me');
    clientError(req, res, 500, 'Unable to load profile.');
  }
});

// ---------------------------------------------------------------------------
// AI SAFETY: Disabled in production by default
// ---------------------------------------------------------------------------
const aiEnabled =
  process.env.AI_MODE === 'enabled' || process.env.NODE_ENV !== 'production';

app.use('/api/v1/ai', (req, res, next) => {
  if (req.method === 'OPTIONS') return next();
  if (!aiEnabled) {
    return clientError(req, res, 503, 'AI temporarily disabled for clinical safety / IG approval.');
  }
  next();
});

// ---------------------------------------------------------------------------
// ADMIN SETTINGS & USER MANAGEMENT (RESTRICTED TO ADMINS)
// ---------------------------------------------------------------------------

app.get('/api/v1/admin/users', requireRole(['Regional Manager', 'Admin']), async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, email, first_name, last_name, system_role, home_scope_id, is_active FROM users ORDER BY first_name ASC'
    );
    await writeAuditLog(req, {
      action: 'ADMIN_LIST_USERS',
      resourceType: 'user_directory',
      metadata: { resultCount: rows.length },
    });
    res.json(rows);
  } catch (err) {
    logRequestError(req, err, 'admin-list-users');
    clientError(req, res, 500, 'Unable to load users. Please try again later.');
  }
});

app.post(
  '/api/v1/admin/users/invite',
  inviteLimiter,
  requireRole(['Regional Manager', 'Admin']),
  async (req, res) => {
    const { email, firstName, lastName, role, homeScopeId } = req.body || {};

    try {
      if (!supabaseAdmin) {
        return clientError(req, res, 500, 'Server misconfiguration. Contact support.');
      }

      if (!email || String(email).trim() === '') {
        return res.status(400).json({ error: 'Missing email' });
      }

      const normalizedEmail = String(email).trim().toLowerCase();
      const scopeId = homeScopeId === 'ALL' ? null : homeScopeId || null;

      const appOrigin = (process.env.FRONTEND_URL || 'http://localhost:3000').replace(/\/$/, '');
      const inviteRedirectTo = `${appOrigin}/auth/callback`;

      const { data, error } = await supabaseAdmin.auth.admin.inviteUserByEmail(normalizedEmail, {
        redirectTo: inviteRedirectTo,
        data: {
          full_name: `${firstName || ''} ${lastName || ''}`.trim(),
          role: role || 'Carer',
          home_scope_id: scopeId,
        },
      });

      if (error) throw error;

      await pool.query(
        `INSERT INTO users (email, password_hash, first_name, last_name, system_role, home_scope_id, is_active)
         VALUES ($1, 'invite_pending', $2, $3, $4, $5, true)
         ON CONFLICT (email) DO UPDATE
         SET system_role = EXCLUDED.system_role,
             home_scope_id = EXCLUDED.home_scope_id,
             first_name = EXCLUDED.first_name,
             last_name = EXCLUDED.last_name,
             is_active = true`,
        [normalizedEmail, firstName || '', lastName || '', role || 'Carer', scopeId]
      );

      await writeAuditLog(req, {
        action: 'ADMIN_INVITE_USER',
        resourceType: 'user_email',
        resourceId: normalizedEmail,
        metadata: { role: role || 'Carer', homeScopeAll: homeScopeId === 'ALL' },
      });
      res.json({ success: true, user: data.user });
    } catch (err) {
      logRequestError(req, err, 'admin-invite-user');
      clientError(req, res, 500, 'Unable to invite user. Please try again later.');
    }
  }
);

// Update Role/Scope Approvals
app.put('/api/v1/admin/users/:id', requireRole(['Regional Manager', 'Admin']), async (req, res) => {
  const { id } = req.params;
  const { role, homeScopeId } = req.body || {};
  try {
    if (!supabaseAdmin) return clientError(req, res, 500, 'Server misconfiguration. Contact support.');

    const scopeId = homeScopeId === 'ALL' ? null : homeScopeId || null;

    // 1. Update Postgres
    const result = await pool.query(
      `UPDATE users SET system_role = $1, home_scope_id = $2 WHERE id = $3 RETURNING email`,
      [role, scopeId, id]
    );

    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found in database' });

    // 2. Update Supabase identity metadata (optional but keeps identity aligned)
    const userEmail = result.rows[0].email;
    const sbUser = await findSupabaseAuthUserByEmail(userEmail);
    if (sbUser) {
      await supabaseAdmin.auth.admin.updateUserById(sbUser.id, {
        user_metadata: { role, home_scope_id: scopeId },
      });
    }

    await writeAuditLog(req, {
      action: 'ADMIN_UPDATE_USER',
      resourceType: 'user',
      resourceId: id,
      metadata: { role, homeScopeAll: homeScopeId === 'ALL' },
    });
    res.json({ success: true, message: 'User role and scope updated successfully.' });
  } catch (err) {
    logRequestError(req, err, 'admin-update-user');
    clientError(req, res, 500, 'Unable to update user. Please try again later.');
  }
});

// Process Leavers (Deactivate User)
app.post('/api/v1/admin/users/:id/deactivate', requireRole(['Regional Manager', 'Admin']), async (req, res) => {
  const { id } = req.params;
  try {
    if (!supabaseAdmin) return clientError(req, res, 500, 'Server misconfiguration. Contact support.');

    // 1. Mark inactive in Postgres (blocks API instantly via middleware)
    const result = await pool.query('UPDATE users SET is_active = false WHERE id = $1 RETURNING email', [id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });

    // 2. Suspend at identity level if they still exist in Supabase (already deleted → skip)
    const userEmail = result.rows[0].email;
    const sbUser = await findSupabaseAuthUserByEmail(userEmail);
    if (sbUser) {
      await supabaseAdmin.auth.admin.updateUserById(sbUser.id, { ban_duration: '876000h' });
    }

    await writeAuditLog(req, {
      action: 'ADMIN_DEACTIVATE_USER',
      resourceType: 'user',
      resourceId: id,
      metadata: { targetEmail: userEmail, supabaseUserFound: Boolean(sbUser) },
    });
    res.json({
      success: true,
      message: sbUser
        ? 'User securely deactivated in DCRS and Supabase.'
        : 'User deactivated in DCRS. They were already removed from Supabase Auth.',
    });
  } catch (err) {
    logRequestError(req, err, 'admin-deactivate-user');
    clientError(req, res, 500, 'Unable to deactivate user. Please try again later.');
  }
});

// Password Resets
app.post(
  '/api/v1/admin/users/:id/reset-password',
  requireRole(['Regional Manager', 'Admin']),
  async (req, res) => {
  const { id } = req.params;
  try {
    if (!supabaseAdmin) return clientError(req, res, 500, 'Server misconfiguration. Contact support.');

    const userRes = await pool.query('SELECT email FROM users WHERE id = $1 AND is_active = true', [id]);
    if (userRes.rows.length === 0) return res.status(404).json({ error: 'Active user not found' });

    const { error } = await supabaseAdmin.auth.admin.resetPasswordForEmail(userRes.rows[0].email);
    if (error) throw error;

    await writeAuditLog(req, {
      action: 'ADMIN_RESET_PASSWORD',
      resourceType: 'user',
      resourceId: id,
      metadata: { targetEmail: userRes.rows[0].email },
    });
    res.json({ success: true, message: 'Password reset link sent to user email.' });
  } catch (err) {
    logRequestError(req, err, 'admin-reset-password');
    clientError(req, res, 500, 'Unable to send password reset. Please try again later.');
  }
});

// ---------------------------------------------------------------------------
// Audit trail (governance) — Regional Manager / Admin only, paginated
// ---------------------------------------------------------------------------
app.get('/api/v1/admin/audit-logs', requireRole(['Regional Manager', 'Admin']), async (req, res) => {
  try {
    const limit = Math.min(100, Math.max(1, parseInt(String(req.query.limit ?? '50'), 10) || 50));
    const offset = Math.max(0, parseInt(String(req.query.offset ?? '0'), 10) || 0);

    const actionFilter =
      typeof req.query.action === 'string' && req.query.action.trim() !== ''
        ? req.query.action.trim().slice(0, 128)
        : null;

    let fromTs = null;
    let toTs = null;
    if (typeof req.query.from === 'string' && req.query.from.trim() !== '') {
      const d = new Date(req.query.from);
      if (!Number.isNaN(d.getTime())) fromTs = d.toISOString();
    }
    if (typeof req.query.to === 'string' && req.query.to.trim() !== '') {
      const d = new Date(req.query.to);
      if (!Number.isNaN(d.getTime())) toTs = d.toISOString();
    }

    let actorUserId = null;
    if (typeof req.query.actorUserId === 'string' && req.query.actorUserId.trim() !== '') {
      const raw = req.query.actorUserId.trim();
      if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(raw)) {
        actorUserId = raw;
      }
    }

    const whereParts = [];
    const params = [];
    let p = 1;
    if (actionFilter) {
      whereParts.push(`action = $${p++}`);
      params.push(actionFilter);
    }
    if (fromTs) {
      whereParts.push(`occurred_at >= $${p++}::timestamptz`);
      params.push(fromTs);
    }
    if (toTs) {
      whereParts.push(`occurred_at < $${p++}::timestamptz`);
      params.push(toTs);
    }
    if (actorUserId) {
      whereParts.push(`actor_user_id = $${p++}::uuid`);
      params.push(actorUserId);
    }
    const whereSql = whereParts.length ? whereParts.join(' AND ') : 'TRUE';

    const countResult = await pool.query(
      `SELECT COUNT(*)::int AS total FROM public.audit_logs WHERE ${whereSql}`,
      params
    );
    const total = countResult.rows[0]?.total ?? 0;

    const listParams = [...params, limit, offset];
    const listResult = await pool.query(
      `SELECT id, occurred_at, actor_user_id, actor_email, actor_role, action, resource_type, resource_id,
              http_method, request_path, ip_address, user_agent, outcome, metadata
       FROM public.audit_logs
       WHERE ${whereSql}
       ORDER BY occurred_at DESC
       LIMIT $${p}::int OFFSET $${p + 1}::int`,
      listParams
    );

    await writeAuditLog(req, {
      action: 'ADMIN_AUDIT_LOG_VIEW',
      resourceType: 'audit_logs',
      metadata: {
        returnedCount: listResult.rows.length,
        limit,
        offset,
        hasActionFilter: Boolean(actionFilter),
        hasDateFilter: Boolean(fromTs || toTs),
        hasActorUserFilter: Boolean(actorUserId),
      },
    });

    res.json({
      total,
      limit,
      offset,
      items: listResult.rows,
    });
  } catch (err) {
    logRequestError(req, err, 'admin-audit-logs');
    clientError(req, res, 500, 'Unable to load audit trail. Please try again later.');
  }
});

function toCsvValue(v) {
  if (v === null || v === undefined) return '';
  const s = typeof v === 'string' ? v : JSON.stringify(v);
  // Escape double-quotes; wrap in quotes if it contains a special char.
  const needsQuotes = /[",\n\r]/.test(s);
  const escaped = s.replace(/"/g, '""');
  return needsQuotes ? `"${escaped}"` : escaped;
}

function parseOptionalIsoTs(v) {
  if (typeof v !== 'string' || v.trim() === '') return null;
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) return null;
  return d.toISOString();
}

function computePeriodRange(period) {
  const now = new Date();
  const toTs = now.toISOString();
  const p = typeof period === 'string' ? period.trim().toLowerCase() : '';

  if (p === '7d' || p === 'last7' || p === 'last_7') {
    const from = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    return { fromTs: from.toISOString(), toTs, label: 'Last 7 days' };
  }
  if (p === '28d' || p === 'last28' || p === 'last_28') {
    const from = new Date(now.getTime() - 28 * 24 * 60 * 60 * 1000);
    return { fromTs: from.toISOString(), toTs, label: 'Last 28 days' };
  }
  if (p === 'qtd' || p === 'quarter' || p === 'quarter_to_date') {
    const start = new Date(Date.UTC(now.getUTCFullYear(), Math.floor(now.getUTCMonth() / 3) * 3, 1, 0, 0, 0));
    return { fromTs: start.toISOString(), toTs, label: 'Quarter to date' };
  }
  const from = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  return { fromTs: from.toISOString(), toTs, label: 'Last 7 days' };
}

// ---------------------------------------------------------------------------
// Audit trail export (governance evidence) — Regional Manager / Admin only
// ---------------------------------------------------------------------------
app.get('/api/v1/admin/audit-logs/export.csv', requireRole(['Regional Manager', 'Admin']), async (req, res) => {
  try {
    const actionFilter =
      typeof req.query.action === 'string' && req.query.action.trim() !== ''
        ? req.query.action.trim().slice(0, 128)
        : null;
    const fromTs = parseOptionalIsoTs(req.query.from);
    const toTs = parseOptionalIsoTs(req.query.to);

    const whereParts = [];
    const params = [];
    let p = 1;
    if (actionFilter) {
      whereParts.push(`action = $${p++}`);
      params.push(actionFilter);
    }
    if (fromTs) {
      whereParts.push(`occurred_at >= $${p++}::timestamptz`);
      params.push(fromTs);
    }
    if (toTs) {
      whereParts.push(`occurred_at < $${p++}::timestamptz`);
      params.push(toTs);
    }
    const whereSql = whereParts.length ? whereParts.join(' AND ') : 'TRUE';

    const { rows } = await pool.query(
      `SELECT occurred_at, actor_email, actor_role, action, resource_type, resource_id, http_method, request_path, outcome, metadata
       FROM public.audit_logs
       WHERE ${whereSql}
       ORDER BY occurred_at DESC
       LIMIT 5000`,
      params
    );

    await writeAuditLog(req, {
      action: 'ADMIN_AUDIT_LOG_EXPORT_CSV',
      resourceType: 'audit_logs',
      metadata: {
        exportedCount: rows.length,
        hasActionFilter: Boolean(actionFilter),
        hasDateFilter: Boolean(fromTs || toTs),
      },
    });

    const header = [
      'occurred_at',
      'actor_email',
      'actor_role',
      'action',
      'resource_type',
      'resource_id',
      'http_method',
      'request_path',
      'outcome',
      'metadata',
    ];
    const lines = [header.join(',')];
    for (const r of rows) {
      const line = [
        r.occurred_at,
        r.actor_email,
        r.actor_role,
        r.action,
        r.resource_type,
        r.resource_id,
        r.http_method,
        r.request_path,
        r.outcome,
        r.metadata,
      ]
        .map(toCsvValue)
        .join(',');
      lines.push(line);
    }

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="audit-logs-${new Date().toISOString().slice(0, 10)}.csv"`);
    res.status(200).send(lines.join('\n'));
  } catch (err) {
    logRequestError(req, err, 'admin-audit-logs-export');
    clientError(req, res, 500, 'Unable to export audit trail. Please try again later.');
  }
});

// ---------------------------------------------------------------------------
// Analytics (governance reporting) — real KPIs sourced from audit_logs + ops tables
// ---------------------------------------------------------------------------
app.get('/api/v1/analytics/summary', requireRole(ROLES_RESIDENT_AND_FACILITY_READ), async (req, res) => {
  try {
    const { fromTs, toTs, label } = computePeriodRange(req.query.period);
    const scope = userHomeScope(req);

    const [notes, residents, audits, topActions] = await Promise.all([
      pool.query(
        `SELECT COUNT(*)::int AS count
         FROM public.daily_notes dn
         INNER JOIN public.service_users su ON su.id = dn.service_user_id
         WHERE dn.created_at >= $1::timestamptz AND dn.created_at < $2::timestamptz
           AND (CAST($3 AS uuid) IS NULL OR su.home_id = CAST($3 AS uuid))`,
        [fromTs, toTs, scope]
      ),
      pool.query(
        `SELECT
           COUNT(*) FILTER (WHERE status = 'ADMITTED')::int AS admitted,
           COUNT(*) FILTER (WHERE status = 'DISCHARGED')::int AS discharged,
           COUNT(*) FILTER (WHERE status = 'PENDING')::int AS pending
         FROM public.service_users
         WHERE (CAST($1 AS uuid) IS NULL OR home_id = CAST($1 AS uuid))`,
        [scope]
      ),
      pool.query(
        `SELECT
           COUNT(*)::int AS total,
           COUNT(*) FILTER (WHERE action LIKE 'AI_%')::int AS ai_actions,
           COUNT(*) FILTER (WHERE outcome <> 'SUCCESS')::int AS non_success
         FROM public.audit_logs
         WHERE occurred_at >= $1::timestamptz AND occurred_at < $2::timestamptz`,
        [fromTs, toTs]
      ),
      pool.query(
        `SELECT action, COUNT(*)::int AS count
         FROM public.audit_logs
         WHERE occurred_at >= $1::timestamptz AND occurred_at < $2::timestamptz
         GROUP BY action
         ORDER BY COUNT(*) DESC
         LIMIT 10`,
        [fromTs, toTs]
      ),
    ]);

    await writeAuditLog(req, {
      action: 'ANALYTICS_SUMMARY_VIEW',
      resourceType: 'analytics',
      metadata: { periodLabel: label },
    });

    res.json({
      period: { label, from: fromTs, to: toTs },
      notesCreated: notes.rows[0]?.count ?? 0,
      residents: residents.rows[0] ?? { admitted: 0, discharged: 0, pending: 0 },
      audit: audits.rows[0] ?? { total: 0, ai_actions: 0, non_success: 0 },
      topActions: topActions.rows ?? [],
    });
  } catch (err) {
    logRequestError(req, err, 'analytics-summary');
    clientError(req, res, 500, 'Unable to load analytics summary. Please try again later.');
  }
});

// ---------------------------------------------------------------------------
// 1. GET ALL RESIDENTS (SCOPED)
// ---------------------------------------------------------------------------
app.get(
  '/api/v1/residents',
  requireRole(ROLES_RESIDENT_AND_FACILITY_READ),
  async (req, res) => {
  try {
    const scope = userHomeScope(req);
    const query = `
      SELECT 
        su.id, su.first_name, su.last_name, su.date_of_birth, su.nhs_number, su.status,
        su.profile_image_url,
        b.room_number, u.name as unit_name, h.name as home_name, h.id as home_id
      FROM service_users su
      LEFT JOIN beds b ON su.current_bed_id = b.id
      LEFT JOIN units u ON b.unit_id = u.id
      LEFT JOIN homes h ON su.home_id = h.id
      WHERE su.status IN ('ADMITTED', 'DISCHARGED', 'PENDING')
      AND (CAST($1 AS uuid) IS NULL OR su.home_id = CAST($1 AS uuid))
    `;
    const result = await pool.query(query, [scope]);
    await writeAuditLog(req, {
      action: 'RESIDENT_DIRECTORY_VIEW',
      resourceType: 'service_user',
      metadata: { resultCount: result.rows.length },
    });
    res.json(result.rows);
  } catch (err) {
    logRequestError(req, err, 'residents-list');
    clientError(req, res, 500, 'Unable to load residents. Please try again later.');
  }
  }
);

const ROLES_RESIDENT_MANAGEMENT = ['Deputy Manager', 'Regional Manager', 'Home Manager', 'Admin'];

app.post(
  '/api/v1/residents',
  requireRole(ROLES_RESIDENT_MANAGEMENT),
  async (req, res) => {
    const scope = userHomeScope(req);
    const body = req.body || {};
    const firstName = typeof body.firstName === 'string' ? body.firstName.trim() : '';
    const lastName = typeof body.lastName === 'string' ? body.lastName.trim() : '';
    const dateOfBirth = body.dateOfBirth != null && String(body.dateOfBirth).trim() !== '' ? String(body.dateOfBirth).trim() : null;
    const nhsNumber =
      body.nhsNumber != null && String(body.nhsNumber).trim() !== '' ? String(body.nhsNumber).trim() : null;
    let homeId = body.homeId != null && String(body.homeId).trim() !== '' ? String(body.homeId).trim() : null;

    if (!firstName || !lastName) {
      return res.status(400).json({ error: 'firstName and lastName are required.' });
    }

    if (scope != null) {
      homeId = String(scope);
    } else if (!homeId) {
      return res.status(400).json({ error: 'homeId is required when your account is not limited to a single home.' });
    }

    try {
      const homeCheck = await pool.query(
        `SELECT id FROM homes WHERE id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR id = CAST($2 AS uuid))`,
        [homeId, scope]
      );
      if (homeCheck.rows.length === 0) {
        return clientError(req, res, 400, 'Invalid home or home is outside your scope.');
      }

      const insert = await pool.query(
        `INSERT INTO service_users (first_name, last_name, date_of_birth, nhs_number, status, legal_hold, home_id, current_bed_id)
         VALUES ($1, $2, $3::date, $4, 'PENDING', false, $5::uuid, NULL)
         RETURNING id`,
        [firstName, lastName, dateOfBirth, nhsNumber, homeId]
      );
      const newId = insert.rows[0].id;

      await writeAuditLog(req, {
        action: 'RESIDENT_CREATE',
        resourceType: 'service_user',
        resourceId: String(newId),
        metadata: { homeId: String(homeId), hasDob: Boolean(dateOfBirth), hasNhs: Boolean(nhsNumber) },
      });

      res.status(201).json({ id: newId });
    } catch (err) {
      if (err && err.code === '23505') {
        return clientError(req, res, 409, 'A service user with this NHS number may already exist.');
      }
      logRequestError(req, err, 'resident-create');
      clientError(req, res, 500, 'Could not create service user. Please try again later.');
    }
  }
);

// ---------------------------------------------------------------------------
// 2. GET SINGLE RESIDENT (SCOPED)
// ---------------------------------------------------------------------------
app.get(
  '/api/v1/residents/:id',
  requireRole(ROLES_RESIDENT_AND_FACILITY_READ),
  async (req, res) => {
  const { id } = req.params;
  const scope = userHomeScope(req);

  try {
    const residentQuery = `
      SELECT 
        su.id, su.first_name, su.last_name, su.date_of_birth, su.nhs_number, su.status, su.legal_hold,
        su.profile_image_url,
        b.room_number, u.name as unit_name, h.name as home_name
      FROM service_users su
      LEFT JOIN beds b ON su.current_bed_id = b.id
      LEFT JOIN units u ON b.unit_id = u.id
      LEFT JOIN homes h ON su.home_id = h.id
      WHERE su.id = $1 AND (CAST($2 AS uuid) IS NULL OR su.home_id = CAST($2 AS uuid))
    `;
    const residentResult = await pool.query(residentQuery, [id, scope]);

    if (residentResult.rows.length === 0) {
      return res.status(404).json({ error: 'Resident not found or access denied' });
    }

    const resident = residentResult.rows[0];

    // Child rows: join service_users so rows are tied to the same resident AND staff home scope (defence in depth).
    const tasksQuery = `
      SELECT t.* FROM tasks t
      INNER JOIN service_users su ON su.id = t.service_user_id
      WHERE t.service_user_id = $1::uuid
        AND (CAST($2 AS uuid) IS NULL OR su.home_id = CAST($2 AS uuid))
      ORDER BY t.due_date ASC`;
    const notesQuery = `
      SELECT dn.* FROM daily_notes dn
      INNER JOIN service_users su ON su.id = dn.service_user_id
      WHERE dn.service_user_id = $1::uuid
        AND (CAST($2 AS uuid) IS NULL OR su.home_id = CAST($2 AS uuid))
      ORDER BY dn.created_at DESC`;
    const medsQuery = `
      SELECT m.* FROM medications m
      INNER JOIN service_users su ON su.id = m.service_user_id
      WHERE m.service_user_id = $1::uuid
        AND (CAST($2 AS uuid) IS NULL OR su.home_id = CAST($2 AS uuid))`;
    const obsQuery = `
      SELECT o.* FROM observations o
      INNER JOIN service_users su ON su.id = o.service_user_id
      WHERE o.service_user_id = $1::uuid
        AND (CAST($2 AS uuid) IS NULL OR su.home_id = CAST($2 AS uuid))
      ORDER BY o.recorded_at DESC`;

    const [tasksRes, notesRes, medsRes, obsRes] = await Promise.all([
      pool.query(tasksQuery, [id, scope]),
      pool.query(notesQuery, [id, scope]),
      pool.query(medsQuery, [id, scope]),
      pool.query(obsQuery, [id, scope]),
    ]);

    resident.tasks = (tasksRes.rows || []).map(normalizeTaskRow);
    resident.dailyNotes = notesRes.rows.map((n) => ({
      id: n.id,
      text: n.note_text,
      time: new Date(n.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      author: n.author_name || 'Staff',
    }));
    resident.medications = medsRes.rows.map((m) => ({
      id: m.id,
      name: m.name,
      dose: m.dose,
      frequency: m.frequency,
      route: m.route,
      stockCount: m.stock_count,
    }));
    resident.observations = obsRes.rows.map((o) => ({
      type: o.observation_type,
      value: o.value,
      unit: o.unit,
      time: new Date(o.recorded_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      date: new Date(o.recorded_at).toLocaleDateString(),
      author: o.recorded_by_name || 'Staff',
    }));
    resident.documents = [];

    await writeAuditLog(req, {
      action: 'RESIDENT_RECORD_VIEW',
      resourceType: 'service_user',
      resourceId: id,
      metadata: {
        noteCount: resident.dailyNotes?.length ?? 0,
        medCount: resident.medications?.length ?? 0,
      },
    });
    res.json(resident);
  } catch (err) {
    logRequestError(req, err, 'resident-detail');
    clientError(req, res, 500, 'Unable to load resident record. Please try again later.');
  }
  }
);

// ---------------------------------------------------------------------------
// CARE PLANS (V1 MINIMAL) — SCOPED TO RESIDENT + HOME
// ---------------------------------------------------------------------------

app.get(
  '/api/v1/residents/:id/care-plans',
  requireRole(ROLES_RESIDENT_AND_FACILITY_READ),
  async (req, res) => {
    const { id } = req.params;
    const scope = userHomeScope(req);
    try {
      const scopeCheck = await pool.query(
        `SELECT id FROM service_users WHERE id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR home_id = CAST($2 AS uuid))`,
        [id, scope]
      );
      if (scopeCheck.rows.length === 0) return clientError(req, res, 403, 'Access denied to this resident');

      const plansRes = await pool.query(
        `SELECT
           cp.id,
           cp.service_user_id,
           cp.title,
           cp.status,
           cp.created_by,
           cp.updated_by,
           cp.created_at,
           cp.updated_at,
           COALESCE(NULLIF(TRIM(CONCAT(uc.first_name, ' ', uc.last_name)), ''), uc.email) AS created_by_name,
           COALESCE(NULLIF(TRIM(CONCAT(uu.first_name, ' ', uu.last_name)), ''), uu.email) AS updated_by_name
         FROM public.care_plans cp
         INNER JOIN public.service_users su ON su.id = cp.service_user_id
         LEFT JOIN public.users uc ON uc.id = cp.created_by
         LEFT JOIN public.users uu ON uu.id = cp.updated_by
         WHERE cp.service_user_id = $1::uuid
           AND (CAST($2 AS uuid) IS NULL OR su.home_id = CAST($2 AS uuid))
         ORDER BY (cp.status = 'ACTIVE') DESC, cp.updated_at DESC`,
        [id, scope]
      );

      const planIds = plansRes.rows.map((p) => p.id);
      let goalsByPlan = {};
      if (planIds.length > 0) {
        const goalsRes = await pool.query(
          `SELECT
             g.id,
             g.care_plan_id,
             g.goal_text,
             g.target_date,
             g.status,
             g.created_by,
             g.updated_by,
             g.created_at,
             g.updated_at,
             COALESCE(NULLIF(TRIM(CONCAT(uc.first_name, ' ', uc.last_name)), ''), uc.email) AS created_by_name,
             COALESCE(NULLIF(TRIM(CONCAT(uu.first_name, ' ', uu.last_name)), ''), uu.email) AS updated_by_name
           FROM public.care_plan_goals g
           LEFT JOIN public.users uc ON uc.id = g.created_by
           LEFT JOIN public.users uu ON uu.id = g.updated_by
           WHERE g.care_plan_id = ANY($1::uuid[])
           ORDER BY (g.status IN ('OPEN','IN_PROGRESS')) DESC, g.updated_at DESC`,
          [planIds]
        );

        const goals = goalsRes.rows || [];
        const goalIds = goals.map((g) => g.id);

        // Linked tasks per goal (optional table; if missing, treat as none)
        let tasksByGoal = {};
        if (goalIds.length > 0) {
          try {
            const linksRes = await pool.query(
              `SELECT
                 l.goal_id,
                 t.*
               FROM public.care_plan_goal_tasks l
               INNER JOIN public.tasks t ON t.id = l.task_id
               INNER JOIN public.service_users su ON su.id = t.service_user_id
               WHERE l.goal_id = ANY($1::uuid[])
                 AND (CAST($2 AS uuid) IS NULL OR su.home_id = CAST($2 AS uuid))
               ORDER BY t.created_at DESC`,
              [goalIds, scope]
            );
            tasksByGoal = (linksRes.rows || []).reduce((acc, row) => {
              const gid = row.goal_id;
              const task = normalizeTaskRow(row);
              (acc[gid] ||= []).push(task);
              return acc;
            }, {});
          } catch (e) {
            // If migration not applied yet, don't fail the whole care plan list.
            const code = e && typeof e === 'object' ? e.code : null;
            const msg = e && typeof e === 'object' ? e.message : '';
            if (code !== '42P01' && !/care_plan_goal_tasks/i.test(String(msg))) {
              throw e;
            }
            tasksByGoal = {};
          }
        }

        goalsByPlan = goalsRes.rows.reduce((acc, row) => {
          (acc[row.care_plan_id] ||= []).push({
            ...row,
            linkedTasks: tasksByGoal[row.id] || [],
          });
          return acc;
        }, {});
      }

      await writeAuditLog(req, {
        action: 'CARE_PLAN_LIST_VIEW',
        resourceType: 'service_user',
        resourceId: id,
        metadata: { planCount: plansRes.rows.length },
      });

      res.json({
        plans: plansRes.rows.map((p) => ({
          ...p,
          goals: goalsByPlan[p.id] || [],
        })),
      });
    } catch (err) {
      if (err && typeof err === 'object' && ('code' in err || 'message' in err)) {
        const code = err.code;
        const msg = err.message || '';
        if (code === '42P01' || /care_plans|care_plan_goals/i.test(String(msg))) {
          return clientError(
            req,
            res,
            503,
            'Care plans are not available yet (database migration not applied). Run the care plans SQL migration in Supabase and retry.'
          );
        }
      }
      logRequestError(req, err, 'care-plan-list');
      clientError(req, res, 500, 'Unable to load care plans.');
    }
  }
);

app.post(
  '/api/v1/residents/:id/care-plans',
  requireRole(ROLES_CARE_PLAN_EDIT),
  async (req, res) => {
    const { id } = req.params;
    const scope = userHomeScope(req);
    const body = req.body || {};
    const title = typeof body.title === 'string' ? body.title.trim() : '';
    const statusRaw = typeof body.status === 'string' ? body.status.trim().toUpperCase() : 'ACTIVE';
    const status = statusRaw === 'DRAFT' || statusRaw === 'ACTIVE' ? statusRaw : 'ACTIVE';
    if (!title) return clientError(req, res, 400, 'title is required.');
    if (title.length > 200) return clientError(req, res, 400, 'title is too long.');

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      const scopeCheck = await client.query(
        `SELECT id FROM service_users WHERE id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR home_id = CAST($2 AS uuid))`,
        [id, scope]
      );
      if (scopeCheck.rows.length === 0) {
        await client.query('ROLLBACK');
        return clientError(req, res, 403, 'Access denied to this resident');
      }

      const ins = await client.query(
        `INSERT INTO public.care_plans (service_user_id, title, status, created_by, updated_by, created_at, updated_at)
         VALUES ($1::uuid, $2, $3, $4::uuid, $4::uuid, now(), now())
         RETURNING id, service_user_id, title, status, created_by, updated_by, created_at, updated_at`,
        [id, title, status, req.dbUser?.id ?? null]
      );
      const newPlanId = ins.rows[0]?.id;

      let archivedCount = 0;
      if (status === 'ACTIVE' && newPlanId) {
        const arch = await client.query(
          `UPDATE public.care_plans
           SET status = 'ARCHIVED', updated_at = now()
           WHERE service_user_id = $1::uuid
             AND id <> $2::uuid
             AND status = 'ACTIVE'`,
          [id, newPlanId]
        );
        archivedCount = arch.rowCount || 0;
      }

      await client.query('COMMIT');

      await writeAuditLog(req, {
        action: 'CARE_PLAN_CREATE',
        resourceType: 'care_plan',
        resourceId: newPlanId ?? null,
        metadata: { serviceUserId: id, status, archivedOtherActivePlans: archivedCount },
      });

      res.status(201).json({ plan: { ...ins.rows[0], goals: [] } });
    } catch (err) {
      try {
        await client.query('ROLLBACK');
      } catch (rollbackErr) {
        logRequestError(req, rollbackErr, 'care-plan-create-rollback');
      }
      // Unique index: only one ACTIVE plan per resident
      if (err && typeof err === 'object' && err.code === '23505') {
        return clientError(req, res, 409, 'This resident already has an active care plan. Archive it first or set another plan active.');
      }
      logRequestError(req, err, 'care-plan-create');
      clientError(req, res, 500, 'Could not create care plan.');
    } finally {
      client.release();
    }
  }
);

app.patch(
  '/api/v1/care-plans/:planId',
  requireRole(ROLES_CARE_PLAN_EDIT),
  async (req, res) => {
    const { planId } = req.params;
    const scope = userHomeScope(req);
    const body = req.body || {};

    const title = typeof body.title === 'string' ? body.title.trim() : null;
    const statusRaw = typeof body.status === 'string' ? body.status.trim().toUpperCase() : null;
    const status =
      statusRaw && ['DRAFT', 'ACTIVE', 'ARCHIVED'].includes(statusRaw) ? statusRaw : null;

    if (title === null && status === null) return clientError(req, res, 400, 'No changes provided.');
    if (title !== null && title.length === 0) return clientError(req, res, 400, 'title cannot be empty.');
    if (title !== null && title.length > 200) return clientError(req, res, 400, 'title is too long.');
    if (status === 'ARCHIVED') {
      // Promotion: only managers can archive
      const userRole = req.dbUser?.system_role;
      if (!userRole || !ROLES_CARE_PLAN_ARCHIVE.includes(userRole)) {
        return clientError(req, res, 403, 'Only management roles can archive care plans.');
      }
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const up = await client.query(
        `UPDATE public.care_plans cp
         SET
           title = COALESCE($1, cp.title),
           status = COALESCE($2, cp.status),
           updated_by = $5::uuid,
           updated_at = now()
         FROM public.service_users su
         WHERE cp.id = $3::uuid
           AND su.id = cp.service_user_id
           AND (CAST($4 AS uuid) IS NULL OR su.home_id = CAST($4 AS uuid))
         RETURNING cp.id, cp.service_user_id, cp.title, cp.status, cp.created_by, cp.updated_by, cp.created_at, cp.updated_at`,
        [title, status, planId, scope, req.dbUser?.id ?? null]
      );
      if (up.rows.length === 0) {
        await client.query('ROLLBACK');
        return clientError(req, res, 403, 'Access denied or care plan not found.');
      }

      let archivedCount = 0;
      if (status === 'ACTIVE') {
        const residentId = up.rows[0].service_user_id;
        const arch = await client.query(
          `UPDATE public.care_plans
           SET status = 'ARCHIVED', updated_at = now()
           WHERE service_user_id = $1::uuid
             AND id <> $2::uuid
             AND status = 'ACTIVE'`,
          [residentId, planId]
        );
        archivedCount = arch.rowCount || 0;
      }

      await client.query('COMMIT');

      await writeAuditLog(req, {
        action: 'CARE_PLAN_UPDATE',
        resourceType: 'care_plan',
        resourceId: planId,
        metadata: {
          changedTitle: title != null,
          changedStatus: status != null,
          status: status ?? undefined,
          archivedOtherActivePlans: archivedCount,
        },
      });

      res.json({ plan: up.rows[0] });
    } catch (err) {
      try {
        await client.query('ROLLBACK');
      } catch (rollbackErr) {
        logRequestError(req, rollbackErr, 'care-plan-update-rollback');
      }
      if (err && typeof err === 'object' && err.code === '23505') {
        return clientError(req, res, 409, 'This resident already has an active care plan. Archive it first or set another plan active.');
      }
      logRequestError(req, err, 'care-plan-update');
      clientError(req, res, 500, 'Could not update care plan.');
    } finally {
      client.release();
    }
  }
);

app.post(
  '/api/v1/care-plans/:planId/goals',
  requireRole(ROLES_CARE_PLAN_EDIT),
  async (req, res) => {
    const { planId } = req.params;
    const scope = userHomeScope(req);
    const body = req.body || {};
    const goalText = typeof body.goalText === 'string' ? body.goalText.trim() : '';
    const statusRaw = typeof body.status === 'string' ? body.status.trim().toUpperCase() : 'OPEN';
    const status = ['OPEN', 'IN_PROGRESS', 'DONE', 'CANCELLED'].includes(statusRaw) ? statusRaw : 'OPEN';
    let targetDate = null;
    if (body.targetDate) {
      const s = String(body.targetDate).trim();
      if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return clientError(req, res, 400, 'targetDate must be YYYY-MM-DD.');
      targetDate = s;
    }
    if (!goalText) return clientError(req, res, 400, 'goalText is required.');
    if (goalText.length > 2000) return clientError(req, res, 400, 'goalText is too long.');

    try {
      const ins = await pool.query(
        `INSERT INTO public.care_plan_goals (care_plan_id, goal_text, target_date, status, created_by, updated_by, created_at, updated_at)
         SELECT cp.id, $1, $2::date, $3, $4::uuid, $4::uuid, now(), now()
         FROM public.care_plans cp
         INNER JOIN public.service_users su ON su.id = cp.service_user_id
         WHERE cp.id = $5::uuid
           AND (CAST($6 AS uuid) IS NULL OR su.home_id = CAST($6 AS uuid))
         RETURNING id, care_plan_id, goal_text, target_date, status, created_by, updated_by, created_at, updated_at`,
        [goalText, targetDate, status, req.dbUser?.id ?? null, planId, scope]
      );
      if (ins.rows.length === 0) return clientError(req, res, 403, 'Access denied or care plan not found.');

      await pool.query(`UPDATE public.care_plans SET updated_at = now() WHERE id = $1::uuid`, [planId]);

      await writeAuditLog(req, {
        action: 'CARE_PLAN_GOAL_CREATE',
        resourceType: 'care_plan_goal',
        resourceId: ins.rows[0]?.id ?? null,
        metadata: { carePlanId: planId, hasTargetDate: Boolean(targetDate), status },
      });

      res.status(201).json({ goal: ins.rows[0] });
    } catch (err) {
      logRequestError(req, err, 'care-goal-create');
      clientError(req, res, 500, 'Could not create goal.');
    }
  }
);

app.patch(
  '/api/v1/care-plans/:planId/goals/:goalId',
  requireRole(ROLES_CARE_PLAN_EDIT),
  async (req, res) => {
    const { planId, goalId } = req.params;
    const scope = userHomeScope(req);
    const body = req.body || {};
    const goalText = typeof body.goalText === 'string' ? body.goalText.trim() : null;
    const statusRaw = typeof body.status === 'string' ? body.status.trim().toUpperCase() : null;
    const status = statusRaw && ['OPEN', 'IN_PROGRESS', 'DONE', 'CANCELLED'].includes(statusRaw) ? statusRaw : null;
    let targetDate = null;
    if (Object.prototype.hasOwnProperty.call(body, 'targetDate')) {
      if (body.targetDate == null || String(body.targetDate).trim() === '') {
        targetDate = '';
      } else {
        const s = String(body.targetDate).trim();
        if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return clientError(req, res, 400, 'targetDate must be YYYY-MM-DD.');
        targetDate = s;
      }
    }

    if (goalText === null && status === null && targetDate === null) {
      return clientError(req, res, 400, 'No changes provided.');
    }
    if (goalText !== null && goalText.length === 0) return clientError(req, res, 400, 'goalText cannot be empty.');
    if (goalText !== null && goalText.length > 2000) return clientError(req, res, 400, 'goalText is too long.');

    try {
      const up = await pool.query(
        `UPDATE public.care_plan_goals g
         SET
           goal_text = COALESCE($1, g.goal_text),
           status = COALESCE($2, g.status),
           target_date = CASE WHEN $3::text IS NULL THEN g.target_date WHEN $3::text = '' THEN NULL ELSE $3::date END,
           updated_by = $7::uuid,
           updated_at = now()
         FROM public.care_plans cp
         INNER JOIN public.service_users su ON su.id = cp.service_user_id
         WHERE g.id = $4::uuid
           AND g.care_plan_id = cp.id
           AND cp.id = $5::uuid
           AND (CAST($6 AS uuid) IS NULL OR su.home_id = CAST($6 AS uuid))
         RETURNING g.id, g.care_plan_id, g.goal_text, g.target_date, g.status, g.created_by, g.updated_by, g.created_at, g.updated_at`,
        [goalText, status, targetDate, goalId, planId, scope, req.dbUser?.id ?? null]
      );
      if (up.rows.length === 0) return clientError(req, res, 403, 'Access denied or goal not found.');

      await pool.query(`UPDATE public.care_plans SET updated_at = now() WHERE id = $1::uuid`, [planId]);

      await writeAuditLog(req, {
        action: 'CARE_PLAN_GOAL_UPDATE',
        resourceType: 'care_plan_goal',
        resourceId: goalId,
        metadata: { carePlanId: planId, changedText: goalText != null, changedStatus: status != null, changedTarget: targetDate != null },
      });

      res.json({ goal: up.rows[0] });
    } catch (err) {
      logRequestError(req, err, 'care-goal-update');
      clientError(req, res, 500, 'Could not update goal.');
    }
  }
);

app.delete(
  '/api/v1/care-plans/:planId/goals/:goalId',
  requireRole(ROLES_CARE_PLAN_EDIT),
  async (req, res) => {
    const { planId, goalId } = req.params;
    const scope = userHomeScope(req);
    try {
      const del = await pool.query(
        `DELETE FROM public.care_plan_goals g
         USING public.care_plans cp, public.service_users su
         WHERE g.id = $1::uuid
           AND g.care_plan_id = cp.id
           AND cp.id = $2::uuid
           AND su.id = cp.service_user_id
           AND (CAST($3 AS uuid) IS NULL OR su.home_id = CAST($3 AS uuid))
         RETURNING g.id`,
        [goalId, planId, scope]
      );
      if (del.rows.length === 0) return clientError(req, res, 403, 'Access denied or goal not found.');

      await pool.query(`UPDATE public.care_plans SET updated_at = now() WHERE id = $1::uuid`, [planId]);

      await writeAuditLog(req, {
        action: 'CARE_PLAN_GOAL_DELETE',
        resourceType: 'care_plan_goal',
        resourceId: goalId,
        metadata: { carePlanId: planId },
      });

      res.json({ success: true });
    } catch (err) {
      logRequestError(req, err, 'care-goal-delete');
      clientError(req, res, 500, 'Could not delete goal.');
    }
  }
);

// Create a task from a care plan goal (and store the link)
app.post(
  '/api/v1/care-plans/:planId/goals/:goalId/tasks',
  requireRole(ROLES_TASKS_WRITE),
  async (req, res) => {
    const { planId, goalId } = req.params;
    const scope = userHomeScope(req);
    const body = req.body || {};

    const priority = typeof body.priority === 'string' ? body.priority.trim() : 'Normal';
    const dueDateRaw = body.dueDate ?? body.due_date ?? null;
    let dueDate = null;
    if (dueDateRaw) {
      const d = new Date(String(dueDateRaw));
      if (Number.isNaN(d.getTime())) return clientError(req, res, 400, 'dueDate must be a valid date.');
      dueDate = d.toISOString().slice(0, 10);
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Scope check through plan→resident→home; also get goal text + resident id.
      const goalRes = await client.query(
        `SELECT g.goal_text, cp.service_user_id
         FROM public.care_plan_goals g
         INNER JOIN public.care_plans cp ON cp.id = g.care_plan_id
         INNER JOIN public.service_users su ON su.id = cp.service_user_id
         WHERE cp.id = $1::uuid
           AND g.id = $2::uuid
           AND (CAST($3 AS uuid) IS NULL OR su.home_id = CAST($3 AS uuid))`,
        [planId, goalId, scope]
      );
      if (goalRes.rows.length === 0) {
        await client.query('ROLLBACK');
        return clientError(req, res, 403, 'Access denied or goal not found.');
      }

      const residentId = goalRes.rows[0].service_user_id;
      const goalText = String(goalRes.rows[0].goal_text || '').trim().replace(/\s+/g, ' ');
      const title = goalText.length > 180 ? `${goalText.slice(0, 177)}…` : goalText;
      if (!title) {
        await client.query('ROLLBACK');
        return clientError(req, res, 400, 'Goal text is empty.');
      }

      const taskIns = await client.query(
        `INSERT INTO tasks (service_user_id, title, status, priority, due_date)
         VALUES ($1::uuid, $2, $3, $4, $5)
         RETURNING *`,
        [residentId, title, 'Open', priority || 'Normal', dueDate]
      );
      const taskRow = taskIns.rows[0];

      await client.query(
        `INSERT INTO public.care_plan_goal_tasks (goal_id, task_id, created_by)
         VALUES ($1::uuid, $2::uuid, $3::uuid)
         ON CONFLICT (goal_id, task_id) DO NOTHING`,
        [goalId, taskRow?.id, req.dbUser?.id ?? null]
      );

      await client.query(`UPDATE public.care_plans SET updated_at = now(), updated_by = $2::uuid WHERE id = $1::uuid`, [
        planId,
        req.dbUser?.id ?? null,
      ]);

      await client.query('COMMIT');

      await writeAuditLog(req, {
        action: 'CARE_PLAN_GOAL_TASK_CREATE',
        resourceType: 'task',
        resourceId: taskRow?.id ?? null,
        metadata: { carePlanId: planId, goalId },
      });

      res.status(201).json({ success: true, task: normalizeTaskRow(taskRow) });
    } catch (err) {
      try {
        await client.query('ROLLBACK');
      } catch (rollbackErr) {
        logRequestError(req, rollbackErr, 'care-goal-task-rollback');
      }
      logRequestError(req, err, 'care-goal-task-create');
      clientError(req, res, 500, 'Could not create task from goal.');
    } finally {
      client.release();
    }
  }
);

// ---------------------------------------------------------------------------
// ASSESSMENTS (TEMPLATES + COMPLETED) — SCOPED
// ---------------------------------------------------------------------------

app.get('/api/v1/assessment-templates', requireRole(ROLES_RESIDENT_AND_FACILITY_READ), async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, name, version, schema_json, scoring_json, is_active, created_by, updated_by, created_at, updated_at
       FROM public.assessment_templates
       ORDER BY is_active DESC, name ASC, version DESC`
    );
    await writeAuditLog(req, {
      action: 'ASSESSMENT_TEMPLATE_LIST_VIEW',
      resourceType: 'assessment_template',
      metadata: { resultCount: rows.length },
    });
    res.json({ templates: rows });
  } catch (err) {
    if (err && typeof err === 'object' && ('code' in err || 'message' in err)) {
      const code = err.code;
      const msg = err.message || '';
      if (code === '42P01' || /assessment_templates/i.test(String(msg))) {
        return clientError(
          req,
          res,
          503,
          'Assessment templates are not available yet (database migration not applied). Run the assessment templates SQL migration in Supabase and retry.'
        );
      }
    }
    logRequestError(req, err, 'assessment-templates-list');
    clientError(req, res, 500, 'Unable to load assessment templates.');
  }
});

app.post('/api/v1/assessment-templates', requireRole(ROLES_ASSESSMENT_TEMPLATES_EDIT), async (req, res) => {
  const body = req.body || {};
  const name = typeof body.name === 'string' ? body.name.trim() : '';
  const schemaJson = body.schema_json ?? body.schemaJson ?? null;
  const scoringJson = body.scoring_json ?? body.scoringJson ?? null;
  if (!name) return clientError(req, res, 400, 'name is required.');
  if (name.length > 200) return clientError(req, res, 400, 'name is too long.');
  if (schemaJson == null || typeof schemaJson !== 'object') return clientError(req, res, 400, 'schema_json must be an object.');

  try {
    const ins = await pool.query(
      `INSERT INTO public.assessment_templates (name, version, schema_json, scoring_json, is_active, created_by, updated_by, created_at, updated_at)
       VALUES ($1, 1, $2::jsonb, $3::jsonb, true, $4::uuid, $4::uuid, now(), now())
       RETURNING *`,
      [name, JSON.stringify(schemaJson), scoringJson == null ? null : JSON.stringify(scoringJson), req.dbUser?.id ?? null]
    );
    await writeAuditLog(req, {
      action: 'ASSESSMENT_TEMPLATE_CREATE',
      resourceType: 'assessment_template',
      resourceId: ins.rows[0]?.id ?? null,
      metadata: { name },
    });
    res.status(201).json({ template: ins.rows[0] });
  } catch (err) {
    logRequestError(req, err, 'assessment-template-create');
    clientError(req, res, 500, 'Could not create assessment template.');
  }
});

app.patch('/api/v1/assessment-templates/:templateId', requireRole(ROLES_ASSESSMENT_TEMPLATES_EDIT), async (req, res) => {
  const { templateId } = req.params;
  const body = req.body || {};
  const name = typeof body.name === 'string' ? body.name.trim() : null;
  const schemaJson =
    Object.prototype.hasOwnProperty.call(body, 'schema_json') || Object.prototype.hasOwnProperty.call(body, 'schemaJson')
      ? (body.schema_json ?? body.schemaJson)
      : null;
  const scoringJson =
    Object.prototype.hasOwnProperty.call(body, 'scoring_json') || Object.prototype.hasOwnProperty.call(body, 'scoringJson')
      ? (body.scoring_json ?? body.scoringJson)
      : undefined;
  const isActive =
    Object.prototype.hasOwnProperty.call(body, 'is_active') || Object.prototype.hasOwnProperty.call(body, 'isActive')
      ? Boolean(body.is_active ?? body.isActive)
      : null;
  const bumpVersion = Boolean(body.bumpVersion);

  if (name !== null && name.length === 0) return clientError(req, res, 400, 'name cannot be empty.');
  if (name !== null && name.length > 200) return clientError(req, res, 400, 'name is too long.');
  if (schemaJson !== null && (schemaJson == null || typeof schemaJson !== 'object')) {
    return clientError(req, res, 400, 'schema_json must be an object.');
  }
  if (scoringJson !== undefined && scoringJson !== null && typeof scoringJson !== 'object') {
    return clientError(req, res, 400, 'scoring_json must be an object or null.');
  }

  try {
    const up = await pool.query(
      `UPDATE public.assessment_templates
       SET
         name = COALESCE($1, name),
         schema_json = COALESCE($2::jsonb, schema_json),
         scoring_json = CASE WHEN $3::text IS NULL THEN scoring_json ELSE $3::jsonb END,
         is_active = COALESCE($4::boolean, is_active),
         version = CASE WHEN $5::boolean THEN version + 1 ELSE version END,
         updated_by = $6::uuid,
         updated_at = now()
       WHERE id = $7::uuid
       RETURNING *`,
      [
        name,
        schemaJson === null ? null : JSON.stringify(schemaJson),
        scoringJson === undefined ? null : scoringJson === null ? 'null' : JSON.stringify(scoringJson),
        isActive,
        bumpVersion,
        req.dbUser?.id ?? null,
        templateId,
      ]
    );
    if (up.rows.length === 0) return clientError(req, res, 404, 'Template not found.');
    await writeAuditLog(req, {
      action: 'ASSESSMENT_TEMPLATE_UPDATE',
      resourceType: 'assessment_template',
      resourceId: templateId,
      metadata: { changedName: name != null, changedSchema: schemaJson != null, changedActive: isActive != null, bumpVersion },
    });
    res.json({ template: up.rows[0] });
  } catch (err) {
    logRequestError(req, err, 'assessment-template-update');
    clientError(req, res, 500, 'Could not update assessment template.');
  }
});

app.get('/api/v1/residents/:id/assessments', requireRole(ROLES_RESIDENT_AND_FACILITY_READ), async (req, res) => {
  const { id } = req.params;
  const scope = userHomeScope(req);
  try {
    const scopeCheck = await pool.query(
      `SELECT id FROM service_users WHERE id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR home_id = CAST($2 AS uuid))`,
      [id, scope]
    );
    if (scopeCheck.rows.length === 0) return clientError(req, res, 403, 'Access denied to this resident');

    const { rows } = await pool.query(
      `SELECT
         a.id,
         a.service_user_id,
         a.template_id,
         a.status,
         a.answers_json,
         a.score,
         a.review_date,
         a.created_by,
         a.created_at,
         at.name AS template_name,
         at.version AS template_version
       FROM public.assessments a
       INNER JOIN public.assessment_templates at ON at.id = a.template_id
       INNER JOIN public.service_users su ON su.id = a.service_user_id
       WHERE a.service_user_id = $1::uuid
         AND (CAST($2 AS uuid) IS NULL OR su.home_id = CAST($2 AS uuid))
       ORDER BY a.created_at DESC
       LIMIT 200`,
      [id, scope]
    );
    await writeAuditLog(req, {
      action: 'ASSESSMENT_LIST_VIEW',
      resourceType: 'service_user',
      resourceId: id,
      metadata: { resultCount: rows.length },
    });
    res.json({ assessments: rows });
  } catch (err) {
    if (err && typeof err === 'object' && ('code' in err || 'message' in err)) {
      const code = err.code;
      const msg = err.message || '';
      if (code === '42P01' || /assessments|assessment_templates/i.test(String(msg))) {
        return clientError(
          req,
          res,
          503,
          'Assessments are not available yet (database migration not applied). Run the assessments SQL migrations in Supabase and retry.'
        );
      }
    }
    logRequestError(req, err, 'assessments-list');
    clientError(req, res, 500, 'Unable to load assessments.');
  }
});

function schemaFieldsFromTemplateSchema(schemaJson) {
  if (!schemaJson || typeof schemaJson !== 'object') return [];
  const fields = schemaJson.fields;
  return Array.isArray(fields) ? fields : [];
}

function allowedSelectValues(field) {
  const opts = field?.options;
  if (!Array.isArray(opts)) return null;
  const values = new Set();
  for (const o of opts) {
    if (o && typeof o === 'object') values.add(String(o.value ?? o.label ?? ''));
    else values.add(String(o));
  }
  values.delete('');
  return values;
}

function validateAnswersAgainstSchema(schemaJson, answersJson) {
  const errors = {};
  const fields = schemaFieldsFromTemplateSchema(schemaJson);
  for (const f of fields) {
    const key = typeof f?.key === 'string' ? f.key.trim() : '';
    if (!key) continue;
    const label = typeof f?.label === 'string' ? f.label.trim() : key;
    const type = typeof f?.type === 'string' ? f.type.trim().toLowerCase() : 'text';
    const required = Boolean(f?.required);

    const value = answersJson ? answersJson[key] : undefined;
    const isEmpty =
      value === null ||
      value === undefined ||
      (typeof value === 'string' && value.trim() === '') ||
      (type === 'checkbox' && value === false);

    if (required && isEmpty) {
      errors[key] = `${label} is required.`;
      continue;
    }

    if (isEmpty) continue;

    if (type === 'number') {
      const n = typeof value === 'number' ? value : Number(value);
      if (!Number.isFinite(n)) {
        errors[key] = `${label} must be a number.`;
        continue;
      }
      if (f.min != null && Number.isFinite(Number(f.min)) && n < Number(f.min)) {
        errors[key] = `${label} must be at least ${Number(f.min)}.`;
        continue;
      }
      if (f.max != null && Number.isFinite(Number(f.max)) && n > Number(f.max)) {
        errors[key] = `${label} must be at most ${Number(f.max)}.`;
        continue;
      }
      continue;
    }

    if (type === 'checkbox') {
      if (typeof value !== 'boolean') {
        errors[key] = `${label} must be true/false.`;
      }
      continue;
    }

    // text-like
    const s = typeof value === 'string' ? value : String(value);
    if (f.minLength != null && Number.isFinite(Number(f.minLength)) && s.length < Number(f.minLength)) {
      errors[key] = `${label} must be at least ${Number(f.minLength)} characters.`;
      continue;
    }
    if (f.maxLength != null && Number.isFinite(Number(f.maxLength)) && s.length > Number(f.maxLength)) {
      errors[key] = `${label} must be at most ${Number(f.maxLength)} characters.`;
      continue;
    }
    if (type === 'select') {
      const allowed = allowedSelectValues(f);
      if (allowed && !allowed.has(String(s))) {
        errors[key] = `${label} must be one of the allowed options.`;
        continue;
      }
    }
    if (typeof f.pattern === 'string' && f.pattern.trim() !== '') {
      try {
        const re = new RegExp(f.pattern);
        if (!re.test(s)) errors[key] = `${label} is not in the expected format.`;
      } catch (_) {
        // ignore invalid patterns
      }
    }
  }
  return errors;
}

function computeScoreFromScoringJson(scoringJson, answersJson) {
  if (!scoringJson || typeof scoringJson !== 'object') return { score: null, band: null };
  const type = typeof scoringJson.type === 'string' ? scoringJson.type.trim().toLowerCase() : '';
  if (type !== 'sum') return { score: null, band: null };

  const fields = scoringJson.fields && typeof scoringJson.fields === 'object' ? scoringJson.fields : {};
  let total = 0;
  for (const [key, rule] of Object.entries(fields)) {
    if (!rule || typeof rule !== 'object') continue;
    const map = rule.map && typeof rule.map === 'object' ? rule.map : null;
    const def = rule.default != null && Number.isFinite(Number(rule.default)) ? Number(rule.default) : 0;
    const v = answersJson ? answersJson[key] : undefined;
    if (v === null || v === undefined || v === '') {
      total += def;
      continue;
    }
    if (map) {
      const mapped = map[String(v)];
      if (mapped != null && Number.isFinite(Number(mapped))) total += Number(mapped);
      else total += def;
    } else if (typeof v === 'number' && Number.isFinite(v)) {
      total += v;
    } else if (Number.isFinite(Number(v))) {
      total += Number(v);
    } else {
      total += def;
    }
  }

  let band = null;
  if (Array.isArray(scoringJson.bands)) {
    for (const b of scoringJson.bands) {
      const min = b?.min != null && Number.isFinite(Number(b.min)) ? Number(b.min) : null;
      const max = b?.max != null && Number.isFinite(Number(b.max)) ? Number(b.max) : null;
      if (min != null && total < min) continue;
      if (max != null && total > max) continue;
      if (typeof b?.label === 'string' && b.label.trim()) {
        band = b.label.trim();
        break;
      }
    }
  }
  return { score: total, band };
}

app.post('/api/v1/residents/:id/assessments', requireRole(ROLES_ASSESSMENTS_CREATE), async (req, res) => {
  const { id } = req.params;
  const scope = userHomeScope(req);
  const body = req.body || {};
  const templateId = typeof body.templateId === 'string' ? body.templateId.trim() : '';
  const answersJson = body.answers_json ?? body.answersJson ?? null;
  const statusRaw = typeof body.status === 'string' ? body.status.trim().toUpperCase() : 'COMPLETED';
  const status = statusRaw === 'DRAFT' || statusRaw === 'COMPLETED' ? statusRaw : 'COMPLETED';
  const clientScore = body.score == null || body.score === '' ? null : Number(body.score);
  const reviewDateRaw = body.reviewDate ?? body.review_date ?? null;
  let reviewDate = null;
  if (reviewDateRaw) {
    const s = String(reviewDateRaw).trim();
    if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return clientError(req, res, 400, 'reviewDate must be YYYY-MM-DD.');
    reviewDate = s;
  }
  if (!templateId) return clientError(req, res, 400, 'templateId is required.');
  if (answersJson == null || typeof answersJson !== 'object') return clientError(req, res, 400, 'answers_json must be an object.');
  if (clientScore !== null && !Number.isFinite(clientScore)) return clientError(req, res, 400, 'score must be a number.');

  try {
    const tmplRes = await pool.query(
      `SELECT id, name, version, schema_json, scoring_json, is_active
       FROM public.assessment_templates
       WHERE id = $1::uuid`,
      [templateId]
    );
    if (tmplRes.rows.length === 0) return clientError(req, res, 404, 'Template not found.');
    const tmpl = tmplRes.rows[0];
    if (tmpl.is_active === false) return clientError(req, res, 400, 'Template is inactive.');

    const validationErrors = validateAnswersAgainstSchema(tmpl.schema_json, answersJson);
    if (Object.keys(validationErrors).length > 0) {
      return res.status(400).json({ error: 'Assessment answers did not pass validation.', details: validationErrors });
    }

    const scoring = computeScoreFromScoringJson(tmpl.scoring_json, answersJson);
    const score = scoring.score != null ? scoring.score : clientScore;

    const ins = await pool.query(
      `INSERT INTO public.assessments (service_user_id, template_id, status, answers_json, score, review_date, created_by, created_at, updated_at)
       SELECT $1::uuid, $2::uuid, $3, $4::jsonb, $5::numeric, $6::date, $7::uuid, now(), now()
       FROM public.service_users su
       WHERE su.id = $1::uuid
         AND (CAST($8 AS uuid) IS NULL OR su.home_id = CAST($8 AS uuid))
       RETURNING id, service_user_id, template_id, status, answers_json, score, review_date, created_by, created_at`,
      [id, templateId, status, JSON.stringify(answersJson), score, reviewDate, req.dbUser?.id ?? null, scope]
    );
    if (ins.rows.length === 0) return clientError(req, res, 403, 'Access denied to this resident');

    await writeAuditLog(req, {
      action: 'ASSESSMENT_CREATE',
      resourceType: 'assessment',
      resourceId: ins.rows[0]?.id ?? null,
      metadata: {
        serviceUserId: id,
        templateId,
        status,
        hasScore: score != null,
        scoreSource: scoring.score != null ? 'computed' : clientScore != null ? 'client' : 'none',
        hasReviewDate: Boolean(reviewDate),
        hasBand: Boolean(scoring.band),
      },
    });

    res.status(201).json({ assessment: ins.rows[0], computed: { band: scoring.band } });
  } catch (err) {
    logRequestError(req, err, 'assessment-create');
    clientError(req, res, 500, 'Could not save assessment.');
  }
});

app.get('/api/v1/assessments/:assessmentId', requireRole(ROLES_RESIDENT_AND_FACILITY_READ), async (req, res) => {
  const { assessmentId } = req.params;
  const scope = userHomeScope(req);
  try {
    const { rows } = await pool.query(
      `SELECT
         a.id,
         a.service_user_id,
         a.template_id,
         a.status,
         a.answers_json,
         a.score,
         a.review_date,
         a.created_by,
         a.created_at,
         at.name AS template_name,
         at.version AS template_version,
         at.schema_json,
         at.scoring_json
       FROM public.assessments a
       INNER JOIN public.assessment_templates at ON at.id = a.template_id
       INNER JOIN public.service_users su ON su.id = a.service_user_id
       WHERE a.id = $1::uuid
         AND (CAST($2 AS uuid) IS NULL OR su.home_id = CAST($2 AS uuid))`,
      [assessmentId, scope]
    );
    if (rows.length === 0) return clientError(req, res, 404, 'Assessment not found.');
    await writeAuditLog(req, {
      action: 'ASSESSMENT_VIEW',
      resourceType: 'assessment',
      resourceId: assessmentId,
      metadata: {},
    });
    res.json({ assessment: rows[0] });
  } catch (err) {
    logRequestError(req, err, 'assessment-view');
    clientError(req, res, 500, 'Unable to load assessment.');
  }
});

// ---------------------------------------------------------------------------
// RESIDENT DOCUMENTS (UPLOAD/LIST/DOWNLOAD/DELETE) — SCOPED
// ---------------------------------------------------------------------------

app.get('/api/v1/residents/:id/documents', requireRole(ROLES_RESIDENT_AND_FACILITY_READ), async (req, res) => {
  const { id } = req.params;
  const scope = userHomeScope(req);
  try {
    const { rows } = await pool.query(
      `SELECT d.id, d.service_user_id, d.file_name, d.mime_type, d.size_bytes, d.doc_type, d.uploaded_by, d.uploaded_at
       FROM public.resident_documents d
       INNER JOIN public.service_users su ON su.id = d.service_user_id
       WHERE d.service_user_id = $1::uuid
         AND d.is_deleted = false
         AND (CAST($2 AS uuid) IS NULL OR su.home_id = CAST($2 AS uuid))
       ORDER BY d.uploaded_at DESC
       LIMIT 500`,
      [id, scope]
    );
    await writeAuditLog(req, {
      action: 'RESIDENT_DOCUMENT_LIST_VIEW',
      resourceType: 'service_user',
      resourceId: id,
      metadata: { resultCount: rows.length },
    });
    res.json({ documents: rows });
  } catch (err) {
    if (err && typeof err === 'object' && ('code' in err || 'message' in err)) {
      const code = err.code;
      const msg = err.message || '';
      if (code === '42P01' || /resident_documents/i.test(String(msg))) {
        return clientError(
          req,
          res,
          503,
          'Resident documents are not available yet (database migration not applied). Run the resident documents SQL migration in Supabase and retry.'
        );
      }
    }
    logRequestError(req, err, 'resident-docs-list');
    clientError(req, res, 500, 'Unable to load resident documents.');
  }
});

app.post(
  '/api/v1/residents/:id/documents',
  requireRole(ROLES_RESIDENT_DOCUMENTS_UPLOAD),
  (req, res, next) => {
    residentDocUpload.single('file')(req, res, (err) => {
      if (err) {
        if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
          return clientError(req, res, 400, 'File must be 20MB or smaller.');
        }
        return clientError(req, res, 400, err.message || 'Invalid upload.');
      }
      next();
    });
  },
  async (req, res) => {
    const { id } = req.params;
    const scope = userHomeScope(req);
    const docType = typeof req.body?.docType === 'string' ? req.body.docType.trim() : null;

    if (!req.file || !req.file.buffer) {
      return clientError(req, res, 400, 'Missing file (field name: file).');
    }
    if (!supabaseAdmin) {
      return clientError(req, res, 500, 'Server misconfiguration. Contact support.');
    }

    const bucket =
      (process.env.SUPABASE_RESIDENT_DOCUMENTS_BUCKET || 'resident-documents').trim() || 'resident-documents';

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Scope check + home id (for storage key)
      const suRes = await client.query(
        `SELECT id, home_id FROM public.service_users
         WHERE id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR home_id = CAST($2 AS uuid))`,
        [id, scope]
      );
      if (suRes.rows.length === 0) {
        await client.query('ROLLBACK');
        return clientError(req, res, 403, 'Access denied to this resident');
      }
      const homeId = suRes.rows[0].home_id || null;

      // Create metadata row first to get id for object path
      const originalName = sanitizeFilename(req.file.originalname || 'document');
      const mime = req.file.mimetype || 'application/octet-stream';
      const size = req.file.size || req.file.buffer.length || 0;

      const metaIns = await client.query(
        `INSERT INTO public.resident_documents
          (service_user_id, home_scope_id, file_path, file_name, mime_type, size_bytes, doc_type, uploaded_by, uploaded_at, is_deleted)
         VALUES ($1::uuid, $2::uuid, '', $3, $4, $5::bigint, $6, $7::uuid, now(), false)
         RETURNING id`,
        [id, homeId, originalName, mime, size, docType, req.dbUser?.id ?? null]
      );
      const docId = metaIns.rows[0].id;

      const objectPath = `home/${homeId || 'ALL'}/resident/${id}/${docId}-${originalName}`;

      const { error: upErr } = await supabaseAdmin.storage.from(bucket).upload(objectPath, req.file.buffer, {
        contentType: mime,
        upsert: false,
      });
      if (upErr) {
        const msg = upErr.message || String(upErr);
        if (/not found|does not exist|Bucket/i.test(msg)) {
          await client.query('ROLLBACK');
          return clientError(
            req,
            res,
            503,
            `Storage bucket "${bucket}" is missing or not configured. Create a private bucket with this name in Supabase (Storage), then retry.`
          );
        }
        throw upErr;
      }

      await client.query(`UPDATE public.resident_documents SET file_path = $1 WHERE id = $2::uuid`, [
        objectPath,
        docId,
      ]);

      await client.query('COMMIT');

      await writeAuditLog(req, {
        action: 'RESIDENT_DOCUMENT_UPLOAD',
        resourceType: 'resident_document',
        resourceId: docId,
        metadata: { serviceUserId: id, bucket, mimeType: mime, sizeBytes: size, docType: docType || undefined },
      });

      res.status(201).json({
        success: true,
        document: {
          id: docId,
          service_user_id: id,
          file_name: originalName,
          mime_type: mime,
          size_bytes: size,
          doc_type: docType,
          uploaded_at: new Date().toISOString(),
        },
      });
    } catch (err) {
      try {
        await client.query('ROLLBACK');
      } catch (rollbackErr) {
        logRequestError(req, rollbackErr, 'resident-doc-upload-rollback');
      }
      logRequestError(req, err, 'resident-doc-upload');
      clientError(req, res, 500, 'Could not upload document.');
    } finally {
      client.release();
    }
  }
);

app.get('/api/v1/documents/:docId/download', requireRole(ROLES_RESIDENT_AND_FACILITY_READ), async (req, res) => {
  const { docId } = req.params;
  const scope = userHomeScope(req);
  if (!supabaseAdmin) return clientError(req, res, 500, 'Server misconfiguration. Contact support.');
  const bucket =
    (process.env.SUPABASE_RESIDENT_DOCUMENTS_BUCKET || 'resident-documents').trim() || 'resident-documents';

  try {
    const docRes = await pool.query(
      `SELECT d.id, d.file_path, d.service_user_id
       FROM public.resident_documents d
       INNER JOIN public.service_users su ON su.id = d.service_user_id
       WHERE d.id = $1::uuid
         AND d.is_deleted = false
         AND (CAST($2 AS uuid) IS NULL OR su.home_id = CAST($2 AS uuid))`,
      [docId, scope]
    );
    if (docRes.rows.length === 0) return clientError(req, res, 404, 'Document not found.');
    const filePath = docRes.rows[0].file_path;
    if (!filePath) return clientError(req, res, 500, 'Document storage path missing.');

    const { data, error } = await supabaseAdmin.storage.from(bucket).createSignedUrl(filePath, 60 * 10);
    if (error) throw error;

    await writeAuditLog(req, {
      action: 'RESIDENT_DOCUMENT_DOWNLOAD',
      resourceType: 'resident_document',
      resourceId: docId,
      metadata: { serviceUserId: docRes.rows[0].service_user_id, bucket },
    });

    res.json({ url: data?.signedUrl });
  } catch (err) {
    logRequestError(req, err, 'resident-doc-download');
    clientError(req, res, 500, 'Could not generate download link.');
  }
});

app.delete('/api/v1/documents/:docId', requireRole(ROLES_RESIDENT_DOCUMENTS_DELETE), async (req, res) => {
  const { docId } = req.params;
  const scope = userHomeScope(req);
  const bucket =
    (process.env.SUPABASE_RESIDENT_DOCUMENTS_BUCKET || 'resident-documents').trim() || 'resident-documents';

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const docRes = await client.query(
      `SELECT d.id, d.file_path, d.service_user_id
       FROM public.resident_documents d
       INNER JOIN public.service_users su ON su.id = d.service_user_id
       WHERE d.id = $1::uuid
         AND d.is_deleted = false
         AND (CAST($2 AS uuid) IS NULL OR su.home_id = CAST($2 AS uuid))`,
      [docId, scope]
    );
    if (docRes.rows.length === 0) {
      await client.query('ROLLBACK');
      return clientError(req, res, 404, 'Document not found.');
    }

    await client.query(`UPDATE public.resident_documents SET is_deleted = true WHERE id = $1::uuid`, [docId]);
    await client.query('COMMIT');

    // Best-effort storage removal (optional)
    if (supabaseAdmin && docRes.rows[0].file_path) {
      try {
        await supabaseAdmin.storage.from(bucket).remove([docRes.rows[0].file_path]);
      } catch (_) {
        // ignore storage delete failures (soft delete already applied)
      }
    }

    await writeAuditLog(req, {
      action: 'RESIDENT_DOCUMENT_DELETE',
      resourceType: 'resident_document',
      resourceId: docId,
      metadata: { serviceUserId: docRes.rows[0].service_user_id, bucket },
    });

    res.json({ success: true });
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch (rollbackErr) {
      logRequestError(req, rollbackErr, 'resident-doc-delete-rollback');
    }
    logRequestError(req, err, 'resident-doc-delete');
    clientError(req, res, 500, 'Could not delete document.');
  } finally {
    client.release();
  }
});

// ---------------------------------------------------------------------------
// TASKS (SCOPED TO RESIDENT + HOME)
// ---------------------------------------------------------------------------
app.post(
  '/api/v1/residents/:id/tasks',
  requireRole(ROLES_TASKS_WRITE),
  async (req, res) => {
    const { id } = req.params;
    const scope = userHomeScope(req);
    const body = req.body || {};

    const title = typeof body.title === 'string' ? body.title.trim() : '';
    const priority = typeof body.priority === 'string' ? body.priority.trim() : 'Normal';
    const dueDateRaw = body.dueDate ?? body.due_date ?? null;

    if (!title) return clientError(req, res, 400, 'Task title is required.');
    if (title.length > 200) return clientError(req, res, 400, 'Task title is too long.');

    let dueDate = null;
    if (dueDateRaw) {
      const d = new Date(String(dueDateRaw));
      if (Number.isNaN(d.getTime())) return clientError(req, res, 400, 'dueDate must be a valid date.');
      // tasks.due_date is a DATE (no time). Store as YYYY-MM-DD.
      dueDate = d.toISOString().slice(0, 10);
    }

    try {
      // Ensure resident exists and is in scope
      const scopeCheck = await pool.query(
        `SELECT id FROM service_users WHERE id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR home_id = CAST($2 AS uuid))`,
        [id, scope]
      );
      if (scopeCheck.rows.length === 0) {
        return clientError(req, res, 403, 'Access denied to this resident');
      }

      // Insert into tasks table. Column names may vary across environments; try common DCRS schema.
      // Expected columns: id uuid, service_user_id uuid, title text, status text, priority text, due_date timestamptz/date, created_at timestamptz
      const ins = await pool.query(
        `INSERT INTO tasks (service_user_id, title, status, priority, due_date)
         VALUES ($1::uuid, $2, $3, $4, $5)
         RETURNING *`,
        [id, title, 'Open', priority || 'Normal', dueDate]
      );

      const row = ins.rows[0];
      await writeAuditLog(req, {
        action: 'TASK_CREATE',
        resourceType: 'task',
        resourceId: row?.id ?? null,
        metadata: { serviceUserId: id, hasDueDate: Boolean(dueDate) },
      });

      res.status(201).json({ success: true, task: normalizeTaskRow(row) });
    } catch (err) {
      logRequestError(req, err, 'task-create');
      clientError(req, res, 500, 'Could not create task. Please try again later.');
    }
  }
);

app.patch(
  '/api/v1/residents/:id/tasks/:taskId',
  requireRole(ROLES_TASKS_WRITE),
  async (req, res) => {
    const { id, taskId } = req.params;
    const scope = userHomeScope(req);
    const body = req.body || {};

    const status = typeof body.status === 'string' ? body.status.trim() : '';
    if (!status) return clientError(req, res, 400, 'status is required.');

    try {
      // Update is scoped through service_users.home_id via join (defence in depth)
      const up = await pool.query(
        `UPDATE tasks t
         SET status = $1
         FROM service_users su
         WHERE t.id = $2::uuid
           AND t.service_user_id = $3::uuid
           AND su.id = t.service_user_id
           AND (CAST($4 AS uuid) IS NULL OR su.home_id = CAST($4 AS uuid))
         RETURNING t.*`,
        [status, taskId, id, scope]
      );

      if (up.rows.length === 0) {
        return clientError(req, res, 403, 'Access denied or task not found.');
      }

      await writeAuditLog(req, {
        action: 'TASK_UPDATE',
        resourceType: 'task',
        resourceId: taskId,
        metadata: { serviceUserId: id, status },
      });

      res.json({ success: true, task: normalizeTaskRow(up.rows[0]) });
    } catch (err) {
      logRequestError(req, err, 'task-update');
      clientError(req, res, 500, 'Could not update task. Please try again later.');
    }
  }
);

// ---------------------------------------------------------------------------
// FOOD & DRINK CHART (DAILY, SCOPED)
// ---------------------------------------------------------------------------
app.get(
  '/api/v1/residents/:id/food-drink',
  requireRole(ROLES_RESIDENT_AND_FACILITY_READ),
  async (req, res) => {
    const { id } = req.params;
    const scope = userHomeScope(req);
    const dateRaw = typeof req.query?.date === 'string' ? req.query.date : null; // YYYY-MM-DD

    let chartDate = null;
    if (dateRaw) {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(dateRaw)) {
        return clientError(req, res, 400, 'date must be YYYY-MM-DD.');
      }
      chartDate = dateRaw;
    }

    try {
      const scopeCheck = await pool.query(
        `SELECT id FROM service_users WHERE id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR home_id = CAST($2 AS uuid))`,
        [id, scope]
      );
      if (scopeCheck.rows.length === 0) {
        return clientError(req, res, 403, 'Access denied to this resident');
      }

      const q = `
        SELECT fde.*
        FROM food_drink_entries fde
        INNER JOIN service_users su ON su.id = fde.service_user_id
        WHERE fde.service_user_id = $1::uuid
          AND (CAST($2 AS uuid) IS NULL OR su.home_id = CAST($2 AS uuid))
          AND ($3::date IS NULL OR fde.chart_date = $3::date)
        ORDER BY fde.created_at DESC
      `;
      const rows = (await pool.query(q, [id, scope, chartDate])).rows || [];

      res.json({ date: chartDate, entries: rows });
    } catch (err) {
      logRequestError(req, err, 'food-drink-list');
      clientError(req, res, 500, 'Unable to load food and drink chart.');
    }
  }
);

app.post(
  '/api/v1/residents/:id/food-drink',
  requireRole(ROLES_FOOD_DRINK_WRITE),
  async (req, res) => {
    const { id } = req.params;
    const scope = userHomeScope(req);
    const body = req.body || {};

    const entryType = typeof body.entryType === 'string' ? body.entryType.trim().toUpperCase() : '';
    const periodRaw = body.period ?? null;
    const description = typeof body.description === 'string' ? body.description.trim() : '';
    const amountMlRaw = body.amountMl ?? body.amount_ml ?? null;
    const dateRaw = body.date ?? body.chartDate ?? body.chart_date ?? null; // YYYY-MM-DD

    if (entryType !== 'FOOD' && entryType !== 'DRINK') {
      return clientError(req, res, 400, 'entryType must be FOOD or DRINK.');
    }
    if (!description) return clientError(req, res, 400, 'description is required.');
    if (description.length > 500) return clientError(req, res, 400, 'description is too long.');

    const allowedPeriods = new Set([
      'Breakfast',
      'Mid-morning',
      'Lunch',
      'Mid-Afternoon',
      'Evening',
      'Bedtime',
    ]);
    const period = typeof periodRaw === 'string' ? periodRaw.trim() : '';
    if (!period || !allowedPeriods.has(period)) {
      return clientError(
        req,
        res,
        400,
        'period is required and must be one of: Breakfast, Mid-morning, Lunch, Mid-Afternoon, Evening, Bedtime.'
      );
    }

    let amountMl = null;
    if (amountMlRaw !== null && amountMlRaw !== undefined && amountMlRaw !== '') {
      const n = Number(amountMlRaw);
      if (!Number.isFinite(n) || n < 0) return clientError(req, res, 400, 'amountMl must be a non-negative number.');
      amountMl = Math.round(n);
    }

    let chartDate = null;
    if (dateRaw) {
      const s = String(dateRaw);
      if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return clientError(req, res, 400, 'date must be YYYY-MM-DD.');
      chartDate = s;
    }

    try {
      const scopeCheck = await pool.query(
        `SELECT id FROM service_users WHERE id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR home_id = CAST($2 AS uuid))`,
        [id, scope]
      );
      if (scopeCheck.rows.length === 0) {
        return clientError(req, res, 403, 'Access denied to this resident');
      }

      const recordedBy =
        (req.dbUser?.first_name || req.dbUser?.last_name)
          ? `${req.dbUser?.first_name || ''} ${req.dbUser?.last_name || ''}`.trim()
          : (req.dbUser?.email ?? req.user?.email ?? null);

      const ins = await pool.query(
        `INSERT INTO food_drink_entries (service_user_id, chart_date, period, entry_type, description, amount_ml, recorded_by)
         VALUES ($1::uuid, COALESCE($2::date, (now() at time zone 'utc')::date), $3, $4, $5, $6, $7)
         RETURNING *`,
        [id, chartDate, period, entryType, description, amountMl, recordedBy]
      );

      const row = ins.rows[0];
      await writeAuditLog(req, {
        action: 'FOOD_DRINK_ENTRY_CREATE',
        resourceType: 'food_drink_entry',
        resourceId: row?.id ?? null,
        metadata: { serviceUserId: id, entryType, period, hasAmount: amountMl != null, date: row?.chart_date ?? null },
      });

      res.status(201).json({ success: true, entry: row });
    } catch (err) {
      logRequestError(req, err, 'food-drink-create');
      clientError(req, res, 500, 'Could not add entry. Please try again later.');
    }
  }
);

// ---------------------------------------------------------------------------
// ACTIVITIES CHART (DAILY, SCOPED)
// ---------------------------------------------------------------------------
app.get(
  '/api/v1/residents/:id/activities',
  requireRole(ROLES_RESIDENT_AND_FACILITY_READ),
  async (req, res) => {
    const { id } = req.params;
    const scope = userHomeScope(req);
    const dateRaw = typeof req.query?.date === 'string' ? req.query.date : null; // YYYY-MM-DD

    let chartDate = null;
    if (dateRaw) {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(dateRaw)) {
        return clientError(req, res, 400, 'date must be YYYY-MM-DD.');
      }
      chartDate = dateRaw;
    }

    try {
      const scopeCheck = await pool.query(
        `SELECT id FROM service_users WHERE id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR home_id = CAST($2 AS uuid))`,
        [id, scope]
      );
      if (scopeCheck.rows.length === 0) {
        return clientError(req, res, 403, 'Access denied to this resident');
      }

      const q = `
        SELECT ae.*
        FROM activity_entries ae
        INNER JOIN service_users su ON su.id = ae.service_user_id
        WHERE ae.service_user_id = $1::uuid
          AND (CAST($2 AS uuid) IS NULL OR su.home_id = CAST($2 AS uuid))
          AND ($3::date IS NULL OR ae.chart_date = $3::date)
        ORDER BY ae.created_at DESC
      `;
      const rows = (await pool.query(q, [id, scope, chartDate])).rows || [];
      res.json({ date: chartDate, entries: rows });
    } catch (err) {
      if (err && typeof err === 'object' && ('code' in err || 'message' in err)) {
        const code = err.code;
        const msg = err.message || '';
        // Missing table migration
        if (code === '42P01' || /activity_entries/i.test(String(msg))) {
          return clientError(
            req,
            res,
            503,
            'Activities chart is not available yet (database migration not applied). Run the activities SQL migration in Supabase and retry.'
          );
        }
      }
      logRequestError(req, err, 'activities-list');
      clientError(req, res, 500, 'Unable to load activities chart.');
    }
  }
);

app.post(
  '/api/v1/residents/:id/activities',
  requireRole(ROLES_ACTIVITIES_WRITE),
  async (req, res) => {
    const { id } = req.params;
    const scope = userHomeScope(req);
    const body = req.body || {};

    const activityType = typeof body.activityType === 'string' ? body.activityType.trim() : '';
    const notes = typeof body.notes === 'string' ? body.notes.trim() : '';
    const dateRaw = body.date ?? body.chartDate ?? body.chart_date ?? null; // YYYY-MM-DD

    const allowed = new Set([
      'Exercise class',
      'Arts and Crafts',
      'Puzzles',
      'Watched television',
      'Movie matinee',
      'Gardening',
      'Sitting in the garden',
      'Pampering session',
      'Bingo',
      'Seasonal crafts',
      'Reading',
      'Social outings',
      'Visitors',
      'Dominoes',
    ]);

    if (!activityType || !allowed.has(activityType)) {
      return clientError(req, res, 400, 'activityType must be one of the approved activity names.');
    }
    if (notes && notes.length > 1000) return clientError(req, res, 400, 'notes is too long.');

    let chartDate = null;
    if (dateRaw) {
      const s = String(dateRaw);
      if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return clientError(req, res, 400, 'date must be YYYY-MM-DD.');
      chartDate = s;
    }

    try {
      const scopeCheck = await pool.query(
        `SELECT id FROM service_users WHERE id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR home_id = CAST($2 AS uuid))`,
        [id, scope]
      );
      if (scopeCheck.rows.length === 0) {
        return clientError(req, res, 403, 'Access denied to this resident');
      }

      const recordedBy =
        (req.dbUser?.first_name || req.dbUser?.last_name)
          ? `${req.dbUser?.first_name || ''} ${req.dbUser?.last_name || ''}`.trim()
          : (req.dbUser?.email ?? req.user?.email ?? null);

      const ins = await pool.query(
        `INSERT INTO activity_entries (service_user_id, chart_date, activity_type, notes, recorded_by)
         VALUES ($1::uuid, COALESCE($2::date, (now() at time zone 'utc')::date), $3, NULLIF($4, ''), $5)
         RETURNING *`,
        [id, chartDate, activityType, notes, recordedBy]
      );

      const row = ins.rows[0];
      await writeAuditLog(req, {
        action: 'ACTIVITY_ENTRY_CREATE',
        resourceType: 'activity_entry',
        resourceId: row?.id ?? null,
        metadata: { serviceUserId: id, activityType, date: row?.chart_date ?? null },
      });

      res.status(201).json({ success: true, entry: row });
    } catch (err) {
      if (err && typeof err === 'object' && ('code' in err || 'message' in err)) {
        const code = err.code;
        const msg = err.message || '';
        // Missing table migration
        if (code === '42P01' || /activity_entries/i.test(String(msg))) {
          return clientError(
            req,
            res,
            503,
            'Activities chart is not available yet (database migration not applied). Run the activities SQL migration in Supabase and retry.'
          );
        }
        // CHECK constraint violation
        if (code === '23514') {
          return clientError(req, res, 400, 'Invalid activityType (not allowed by database constraint).');
        }
      }
      logRequestError(req, err, 'activities-create');
      clientError(req, res, 500, 'Could not add activity entry. Please try again later.');
    }
  }
);

// ---------------------------------------------------------------------------
// DAILY CARE RECORD (DAILY, SCOPED)
// ---------------------------------------------------------------------------
app.get(
  '/api/v1/residents/:id/daily-care',
  requireRole(ROLES_RESIDENT_AND_FACILITY_READ),
  async (req, res) => {
    const { id } = req.params;
    const scope = userHomeScope(req);
    const dateRaw = typeof req.query?.date === 'string' ? req.query.date : null; // YYYY-MM-DD

    let chartDate = null;
    if (dateRaw) {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(dateRaw)) {
        return clientError(req, res, 400, 'date must be YYYY-MM-DD.');
      }
      chartDate = dateRaw;
    }

    try {
      const scopeCheck = await pool.query(
        `SELECT id FROM service_users WHERE id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR home_id = CAST($2 AS uuid))`,
        [id, scope]
      );
      if (scopeCheck.rows.length === 0) {
        return clientError(req, res, 403, 'Access denied to this resident');
      }

      const q = `
        SELECT dce.*
        FROM daily_care_entries dce
        INNER JOIN service_users su ON su.id = dce.service_user_id
        WHERE dce.service_user_id = $1::uuid
          AND (CAST($2 AS uuid) IS NULL OR su.home_id = CAST($2 AS uuid))
          AND ($3::date IS NULL OR dce.chart_date = $3::date)
        ORDER BY dce.created_at DESC
      `;
      const rows = (await pool.query(q, [id, scope, chartDate])).rows || [];
      res.json({ date: chartDate, entries: rows });
    } catch (err) {
      if (err && typeof err === 'object' && ('code' in err || 'message' in err)) {
        const code = err.code;
        const msg = err.message || '';
        if (code === '42P01' || /daily_care_entries/i.test(String(msg))) {
          return clientError(
            req,
            res,
            503,
            'Daily care chart is not available yet (database migration not applied). Run the daily care SQL migration in Supabase and retry.'
          );
        }
      }
      logRequestError(req, err, 'daily-care-list');
      clientError(req, res, 500, 'Unable to load daily care chart.');
    }
  }
);

app.post(
  '/api/v1/residents/:id/daily-care',
  requireRole(ROLES_DAILY_CARE_WRITE),
  async (req, res) => {
    const { id } = req.params;
    const scope = userHomeScope(req);
    const body = req.body || {};

    const careItem = typeof body.careItem === 'string' ? body.careItem.trim() : '';
    const value = typeof body.value === 'string' ? body.value.trim() : '';
    const notes = typeof body.notes === 'string' ? body.notes.trim() : '';
    const dateRaw = body.date ?? body.chartDate ?? body.chart_date ?? null; // YYYY-MM-DD

    const allowed = new Set([
      'Bath',
      'Hair',
      'Nails',
      'Bowels Open',
      'Fluids',
      'Medicate',
      'Visitors',
      'Been out',
      'Stayed in',
      'Other',
    ]);

    if (!careItem || !allowed.has(careItem)) {
      return clientError(req, res, 400, 'careItem must be one of the approved daily care items.');
    }
    if (value.length > 200) return clientError(req, res, 400, 'value is too long.');
    if (notes.length > 2000) return clientError(req, res, 400, 'notes is too long.');

    let chartDate = null;
    if (dateRaw) {
      const s = String(dateRaw);
      if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return clientError(req, res, 400, 'date must be YYYY-MM-DD.');
      chartDate = s;
    }

    try {
      const scopeCheck = await pool.query(
        `SELECT id FROM service_users WHERE id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR home_id = CAST($2 AS uuid))`,
        [id, scope]
      );
      if (scopeCheck.rows.length === 0) {
        return clientError(req, res, 403, 'Access denied to this resident');
      }

      const recordedBy =
        (req.dbUser?.first_name || req.dbUser?.last_name)
          ? `${req.dbUser?.first_name || ''} ${req.dbUser?.last_name || ''}`.trim()
          : (req.dbUser?.email ?? req.user?.email ?? null);

      const ins = await pool.query(
        `INSERT INTO daily_care_entries (service_user_id, chart_date, care_item, value, notes, recorded_by)
         VALUES ($1::uuid, COALESCE($2::date, (now() at time zone 'utc')::date), $3, NULLIF($4, ''), NULLIF($5, ''), $6)
         RETURNING *`,
        [id, chartDate, careItem, value, notes, recordedBy]
      );

      const row = ins.rows[0];
      await writeAuditLog(req, {
        action: 'DAILY_CARE_ENTRY_CREATE',
        resourceType: 'daily_care_entry',
        resourceId: row?.id ?? null,
        metadata: { serviceUserId: id, careItem, date: row?.chart_date ?? null },
      });

      res.status(201).json({ success: true, entry: row });
    } catch (err) {
      if (err && typeof err === 'object' && ('code' in err || 'message' in err)) {
        const code = err.code;
        const msg = err.message || '';
        if (code === '42P01' || /daily_care_entries/i.test(String(msg))) {
          return clientError(
            req,
            res,
            503,
            'Daily care chart is not available yet (database migration not applied). Run the daily care SQL migration in Supabase and retry.'
          );
        }
        if (code === '23514') {
          return clientError(req, res, 400, 'Invalid careItem (not allowed by database constraint).');
        }
      }
      logRequestError(req, err, 'daily-care-create');
      clientError(req, res, 500, 'Could not add daily care entry. Please try again later.');
    }
  }
);

// ---------------------------------------------------------------------------
// PEEP (PERSONAL EMERGENCY EVACUATION PLAN) — SCOPED
// ---------------------------------------------------------------------------
app.get(
  '/api/v1/residents/:id/peep',
  requireRole(ROLES_RESIDENT_AND_FACILITY_READ),
  async (req, res) => {
    const { id } = req.params;
    const scope = userHomeScope(req);
    try {
      const scopeCheck = await pool.query(
        `SELECT id FROM service_users WHERE id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR home_id = CAST($2 AS uuid))`,
        [id, scope]
      );
      if (scopeCheck.rows.length === 0) {
        return clientError(req, res, 403, 'Access denied to this resident');
      }

      const q = `
        SELECT pd.*
        FROM peep_documents pd
        INNER JOIN service_users su ON su.id = pd.service_user_id
        WHERE pd.service_user_id = $1::uuid
          AND (CAST($2 AS uuid) IS NULL OR su.home_id = CAST($2 AS uuid))
      `;
      const r = await pool.query(q, [id, scope]);
      const doc = r.rows[0] || null;
      res.json({ peep: doc });
    } catch (err) {
      if (err && typeof err === 'object' && ('code' in err || 'message' in err)) {
        const code = err.code;
        const msg = err.message || '';
        if (code === '42P01' || /peep_documents/i.test(String(msg))) {
          return clientError(
            req,
            res,
            503,
            'PEEP document is not available yet (database migration not applied). Run the PEEP SQL migration in Supabase and retry.'
          );
        }
      }
      logRequestError(req, err, 'peep-get');
      clientError(req, res, 500, 'Unable to load PEEP.');
    }
  }
);

app.put(
  '/api/v1/residents/:id/peep',
  requireRole(ROLES_PEEP_WRITE),
  async (req, res) => {
    const { id } = req.params;
    const scope = userHomeScope(req);
    const body = req.body || {};

    const textOrNull = (v, max) => {
      if (v === null || v === undefined) return null;
      if (typeof v !== 'string') return null;
      const s = v.trim();
      if (!s) return null;
      return s.length > max ? s.slice(0, max) : s;
    };

    const mobility = textOrNull(body.mobility, 1000);
    const assistanceRequired = textOrNull(body.assistance_required ?? body.assistanceRequired, 1000);
    const evacuationMethod = textOrNull(body.evacuation_method ?? body.evacuationMethod, 1000);
    const alarmAwareness = textOrNull(body.alarm_awareness ?? body.alarmAwareness, 1000);
    const communicationNeeds = textOrNull(body.communication_needs ?? body.communicationNeeds, 1000);
    const nightArrangements = textOrNull(body.night_arrangements ?? body.nightArrangements, 1000);
    const equipmentRequired = textOrNull(body.equipment_required ?? body.equipmentRequired, 1000);
    const keyRisks = textOrNull(body.key_risks ?? body.keyRisks, 1500);
    const routeAndRefuge = textOrNull(body.route_and_refuge ?? body.routeAndRefuge, 1500);
    const otherNotes = textOrNull(body.other_notes ?? body.otherNotes, 1500);

    let reviewDate = null;
    const reviewRaw = body.review_date ?? body.reviewDate ?? null;
    if (reviewRaw) {
      const s = String(reviewRaw);
      if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return clientError(req, res, 400, 'reviewDate must be YYYY-MM-DD.');
      reviewDate = s;
    }

    try {
      const scopeCheck = await pool.query(
        `SELECT id FROM service_users WHERE id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR home_id = CAST($2 AS uuid))`,
        [id, scope]
      );
      if (scopeCheck.rows.length === 0) {
        return clientError(req, res, 403, 'Access denied to this resident');
      }

      const updatedBy =
        (req.dbUser?.first_name || req.dbUser?.last_name)
          ? `${req.dbUser?.first_name || ''} ${req.dbUser?.last_name || ''}`.trim()
          : (req.dbUser?.email ?? req.user?.email ?? null);

      const up = await pool.query(
        `INSERT INTO peep_documents (
          service_user_id,
          mobility,
          assistance_required,
          evacuation_method,
          alarm_awareness,
          communication_needs,
          night_arrangements,
          equipment_required,
          key_risks,
          route_and_refuge,
          other_notes,
          review_date,
          updated_by,
          updated_at
        ) VALUES (
          $1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::date, $13, now()
        )
        ON CONFLICT (service_user_id) DO UPDATE SET
          mobility = EXCLUDED.mobility,
          assistance_required = EXCLUDED.assistance_required,
          evacuation_method = EXCLUDED.evacuation_method,
          alarm_awareness = EXCLUDED.alarm_awareness,
          communication_needs = EXCLUDED.communication_needs,
          night_arrangements = EXCLUDED.night_arrangements,
          equipment_required = EXCLUDED.equipment_required,
          key_risks = EXCLUDED.key_risks,
          route_and_refuge = EXCLUDED.route_and_refuge,
          other_notes = EXCLUDED.other_notes,
          review_date = EXCLUDED.review_date,
          updated_by = EXCLUDED.updated_by,
          updated_at = now()
        RETURNING *`,
        [
          id,
          mobility,
          assistanceRequired,
          evacuationMethod,
          alarmAwareness,
          communicationNeeds,
          nightArrangements,
          equipmentRequired,
          keyRisks,
          routeAndRefuge,
          otherNotes,
          reviewDate,
          updatedBy,
        ]
      );

      const doc = up.rows[0] || null;
      await writeAuditLog(req, {
        action: 'PEEP_UPDATE',
        resourceType: 'peep_document',
        resourceId: id,
        metadata: { serviceUserId: id, hasReviewDate: Boolean(reviewDate) },
      });

      res.json({ success: true, peep: doc });
    } catch (err) {
      if (err && typeof err === 'object' && ('code' in err || 'message' in err)) {
        const code = err.code;
        const msg = err.message || '';
        if (code === '42P01' || /peep_documents/i.test(String(msg))) {
          return clientError(
            req,
            res,
            503,
            'PEEP document is not available yet (database migration not applied). Run the PEEP SQL migration in Supabase and retry.'
          );
        }
      }
      logRequestError(req, err, 'peep-put');
      clientError(req, res, 500, 'Could not save PEEP. Please try again later.');
    }
  }
);

app.patch(
  '/api/v1/residents/:id',
  requireRole(ROLES_RESIDENT_MANAGEMENT),
  async (req, res) => {
    const { id } = req.params;
    const scope = userHomeScope(req);
    const body = req.body || {};

    if (!Object.prototype.hasOwnProperty.call(body, 'profileImageUrl')) {
      return res.status(400).json({ error: 'Request must include profileImageUrl (string or null).' });
    }

    let profileImageUrl = body.profileImageUrl;
    if (profileImageUrl === '' || profileImageUrl === undefined) {
      profileImageUrl = null;
    } else if (typeof profileImageUrl !== 'string') {
      return res.status(400).json({ error: 'profileImageUrl must be a string or null.' });
    } else {
      profileImageUrl = profileImageUrl.trim();
      if (profileImageUrl.length > 2048) {
        return clientError(req, res, 400, 'profileImageUrl is too long.');
      }
      if (!/^https?:\/\//i.test(profileImageUrl)) {
        return clientError(req, res, 400, 'profileImageUrl must start with http:// or https://');
      }
    }

    try {
      const up = await pool.query(
        `UPDATE service_users SET profile_image_url = $1
         WHERE id = $2::uuid AND (CAST($3 AS uuid) IS NULL OR home_id = CAST($3 AS uuid))
         RETURNING id`,
        [profileImageUrl, id, scope]
      );
      if (up.rows.length === 0) {
        return clientError(req, res, 403, 'Access denied to this resident');
      }
      await writeAuditLog(req, {
        action: 'RESIDENT_PROFILE_IMAGE_UPDATE',
        resourceType: 'service_user',
        resourceId: id,
        metadata: {
          cleared: profileImageUrl === null,
          length: profileImageUrl ? profileImageUrl.length : 0,
        },
      });
      res.json({ success: true, profileImageUrl });
    } catch (err) {
      logRequestError(req, err, 'resident-profile-image');
      clientError(req, res, 500, 'Could not update profile photo. Please try again later.');
    }
  }
);

// Upload profile photo (camera / gallery) → Supabase Storage public URL stored on service_users.
// Create a PUBLIC bucket named by SUPABASE_PROFILE_PHOTOS_BUCKET (default: service-user-profile-photos).
app.post(
  '/api/v1/residents/:id/profile-photo',
  requireRole(ROLES_RESIDENT_MANAGEMENT),
  (req, res, next) => {
    profilePhotoUpload.single('photo')(req, res, (err) => {
      if (err) {
        if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
          return clientError(req, res, 400, 'Image must be 5MB or smaller.');
        }
        return clientError(req, res, 400, err.message || 'Invalid upload.');
      }
      next();
    });
  },
  async (req, res) => {
    const { id } = req.params;
    const scope = userHomeScope(req);

    if (!req.file || !req.file.buffer) {
      return res.status(400).json({ error: 'Missing image file (field name: photo).' });
    }
    if (!supabaseAdmin) {
      return clientError(req, res, 500, 'Server misconfiguration. Contact support.');
    }

    const bucket =
      (process.env.SUPABASE_PROFILE_PHOTOS_BUCKET || 'service-user-profile-photos').trim() ||
      'service-user-profile-photos';

    try {
      const scopeCheck = await pool.query(
        `SELECT id FROM service_users WHERE id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR home_id = CAST($2 AS uuid))`,
        [id, scope]
      );
      if (scopeCheck.rows.length === 0) {
        return clientError(req, res, 403, 'Access denied to this resident');
      }

      const ext = extFromProfileMime(req.file.mimetype);
      const objectPath = `${id}/${randomUUID()}.${ext}`;

      const { error: upErr } = await supabaseAdmin.storage.from(bucket).upload(objectPath, req.file.buffer, {
        contentType: req.file.mimetype,
        upsert: true,
      });

      if (upErr) {
        const msg = upErr.message || String(upErr);
        if (/not found|does not exist|Bucket/i.test(msg)) {
          return clientError(
            req,
            res,
            503,
            `Storage bucket "${bucket}" is missing or not configured. Create a public bucket with this name in Supabase (Storage), then retry.`
          );
        }
        logRequestError(req, upErr, 'resident-profile-photo-storage');
        return clientError(req, res, 500, 'Could not upload photo to storage.');
      }

      const { data: pub } = supabaseAdmin.storage.from(bucket).getPublicUrl(objectPath);
      const publicUrl = pub?.publicUrl;
      if (!publicUrl) {
        return clientError(req, res, 500, 'Could not resolve public URL for uploaded photo.');
      }

      const up = await pool.query(
        `UPDATE service_users SET profile_image_url = $1
         WHERE id = $2::uuid AND (CAST($3 AS uuid) IS NULL OR home_id = CAST($3 AS uuid))
         RETURNING id`,
        [publicUrl, id, scope]
      );
      if (up.rows.length === 0) {
        return clientError(req, res, 403, 'Access denied to this resident');
      }

      await writeAuditLog(req, {
        action: 'RESIDENT_PROFILE_PHOTO_UPLOAD',
        resourceType: 'service_user',
        resourceId: id,
        metadata: { bucket, objectPath },
      });

      res.json({ success: true, profileImageUrl: publicUrl });
    } catch (err) {
      logRequestError(req, err, 'resident-profile-photo');
      clientError(req, res, 500, 'Could not save profile photo. Please try again later.');
    }
  }
);

// ---------------------------------------------------------------------------
// 3. GET FACILITY LAYOUT (SCOPED)
// ---------------------------------------------------------------------------
app.get(
  '/api/v1/facility-layout',
  requireRole(ROLES_RESIDENT_AND_FACILITY_READ),
  async (req, res) => {
  try {
    const scope = userHomeScope(req);
    const unitsResult = await pool.query(
      `SELECT * FROM units WHERE CAST($1 AS uuid) IS NULL OR home_id = CAST($1 AS uuid)`,
      [scope]
    );
    const bedsResult = await pool.query(
      `SELECT * FROM beds WHERE CAST($1 AS uuid) IS NULL OR home_id = CAST($1 AS uuid)`,
      [scope]
    );
    const homesResult = await pool.query(
      `SELECT id, name FROM homes WHERE CAST($1 AS uuid) IS NULL OR id = CAST($1 AS uuid) ORDER BY name ASC`,
      [scope]
    );
    await writeAuditLog(req, {
      action: 'FACILITY_LAYOUT_VIEW',
      resourceType: 'facility',
      metadata: {
        unitCount: unitsResult.rows.length,
        bedCount: bedsResult.rows.length,
        homeCount: homesResult.rows.length,
      },
    });
    res.json({ units: unitsResult.rows, beds: bedsResult.rows, homes: homesResult.rows });
  } catch (err) {
    logRequestError(req, err, 'facility-layout');
    clientError(req, res, 500, 'Unable to load facility layout. Please try again later.');
  }
  }
);

// ---------------------------------------------------------------------------
// 4. TRANSFER & DISCHARGE (MANAGEMENT + SCOPED)
// ---------------------------------------------------------------------------
app.post(
  '/api/v1/residents/:id/transfer',
  requireRole(['Deputy Manager', 'Regional Manager', 'Home Manager', 'Admin']),
  async (req, res) => {
    const { id } = req.params;
    const { newBedId } = req.body;
    const scope = userHomeScope(req);

    if (newBedId === undefined || newBedId === null || newBedId === '') {
      return res.status(400).json({ error: 'Request body must include newBedId' });
    }

    try {
      const check = await pool.query(
        `SELECT id FROM service_users WHERE id = $1 AND (CAST($2 AS uuid) IS NULL OR home_id = CAST($2 AS uuid))`,
        [id, scope]
      );
      if (check.rows.length === 0) {
        return clientError(req, res, 403, 'Access denied to this resident');
      }

      const bedCheck = await pool.query(
        `SELECT id FROM beds WHERE id = $1 AND (CAST($2 AS uuid) IS NULL OR home_id = CAST($2 AS uuid))`,
        [newBedId, scope]
      );
      if (bedCheck.rows.length === 0) {
        return clientError(req, res, 403, 'Access denied to target bed');
      }

      await pool.query(
        `UPDATE beds SET status = 'AVAILABLE' WHERE id = (SELECT current_bed_id FROM service_users WHERE id = $1)`,
        [id]
      );
      await pool.query(`UPDATE beds SET status = 'OCCUPIED' WHERE id = $1`, [newBedId]);
      await pool.query(
        `UPDATE service_users SET current_bed_id = $1, home_id = COALESCE((SELECT home_id FROM beds WHERE id = $1), home_id) WHERE id = $2`,
        [newBedId, id]
      );
      await writeAuditLog(req, {
        action: 'RESIDENT_TRANSFER',
        resourceType: 'service_user',
        resourceId: id,
        metadata: { newBedId: String(newBedId) },
      });
      res.json({ success: true });
    } catch (err) {
      logRequestError(req, err, 'resident-transfer');
      clientError(req, res, 500, 'Transfer could not be completed. Please try again later.');
    }
  }
);

app.post(
  '/api/v1/residents/:id/discharge',
  requireRole(['Deputy Manager', 'Regional Manager', 'Home Manager', 'Admin']),
  async (req, res) => {
    const { id } = req.params;
    const scope = userHomeScope(req);

    try {
      const check = await pool.query(
        `SELECT id FROM service_users WHERE id = $1 AND (CAST($2 AS uuid) IS NULL OR home_id = CAST($2 AS uuid))`,
        [id, scope]
      );
      if (check.rows.length === 0) {
        return clientError(req, res, 403, 'Access denied to this resident');
      }

      await pool.query(
        `UPDATE beds SET status = 'AVAILABLE' WHERE id = (SELECT current_bed_id FROM service_users WHERE id = $1)`,
        [id]
      );
      await pool.query(`UPDATE service_users SET status = 'DISCHARGED', current_bed_id = NULL WHERE id = $1`, [id]);
      await writeAuditLog(req, {
        action: 'RESIDENT_DISCHARGE',
        resourceType: 'service_user',
        resourceId: id,
        metadata: {},
      });
      res.json({ success: true });
    } catch (err) {
      logRequestError(req, err, 'resident-discharge');
      clientError(req, res, 500, 'Discharge could not be completed. Please try again later.');
    }
  }
);

app.post(
  '/api/v1/residents/:id/admit',
  requireRole(['Deputy Manager', 'Regional Manager', 'Home Manager', 'Admin']),
  async (req, res) => {
    const { id } = req.params;
    const { newBedId } = req.body || {};
    const scope = userHomeScope(req);

    if (newBedId === undefined || newBedId === null || String(newBedId).trim() === '') {
      return res.status(400).json({ error: 'Request body must include newBedId' });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      const suRes = await client.query(
        `SELECT id, status, current_bed_id FROM service_users WHERE id = $1 AND (CAST($2 AS uuid) IS NULL OR home_id = CAST($2 AS uuid))`,
        [id, scope]
      );
      if (suRes.rows.length === 0) {
        await client.query('ROLLBACK');
        return clientError(req, res, 403, 'Access denied to this resident');
      }

      const row = suRes.rows[0];
      const status = String(row.status || '').toUpperCase();
      if (status === 'ADMITTED' && row.current_bed_id != null) {
        await client.query('ROLLBACK');
        return clientError(req, res, 409, 'Service user already has a bed assigned. Use transfer to move them.');
      }
      if (status !== 'DISCHARGED' && status !== 'PENDING') {
        await client.query('ROLLBACK');
        return clientError(
          req,
          res,
          409,
          'Use transfer to assign a bed to an admitted service user who does not have one yet.'
        );
      }

      const bedRes = await client.query(
        `SELECT id, home_id FROM beds WHERE id = $1 AND status = 'AVAILABLE' AND (CAST($2 AS uuid) IS NULL OR home_id = CAST($2 AS uuid))`,
        [newBedId, scope]
      );
      if (bedRes.rows.length === 0) {
        await client.query('ROLLBACK');
        return clientError(req, res, 400, 'Bed is not available or not in your scope.');
      }
      const bedHomeId = bedRes.rows[0].home_id;

      await client.query(
        `UPDATE beds SET status = 'AVAILABLE' WHERE id = (SELECT current_bed_id FROM service_users WHERE id = $1)`,
        [id]
      );
      const occ = await client.query(`UPDATE beds SET status = 'OCCUPIED' WHERE id = $1 AND status = 'AVAILABLE'`, [
        newBedId,
      ]);
      if (occ.rowCount === 0) {
        await client.query('ROLLBACK');
        return clientError(req, res, 400, 'Bed is no longer available.');
      }
      await client.query(
        `UPDATE service_users SET status = 'ADMITTED', current_bed_id = $1, home_id = COALESCE($2::uuid, home_id) WHERE id = $3`,
        [newBedId, bedHomeId, id]
      );

      await client.query('COMMIT');

      await writeAuditLog(req, {
        action: 'RESIDENT_ADMIT_OR_READMIT',
        resourceType: 'service_user',
        resourceId: id,
        metadata: { previousStatus: status, newBedId: String(newBedId) },
      });

      res.json({ success: true });
    } catch (err) {
      try {
        await client.query('ROLLBACK');
      } catch (rollbackErr) {
        logRequestError(req, rollbackErr, 'resident-admit-rollback');
      }
      logRequestError(req, err, 'resident-admit');
      clientError(req, res, 500, 'Admission could not be completed. Please try again later.');
    } finally {
      client.release();
    }
  }
);

// ---------------------------------------------------------------------------
// 5. OFFLINE SYNC ENGINE (SCOPED)
// ---------------------------------------------------------------------------
app.post(
  '/api/v1/sync',
  requireRole(ROLES_OFFLINE_SYNC_WRITE),
  async (req, res) => {
  const { operations } = req.body;
  if (!Array.isArray(operations)) {
    return res.status(400).json({ error: 'Request body must include an operations array' });
  }

  const scope = userHomeScope(req);
  const dbAuthorName = req.dbUser ? `${req.dbUser.first_name} ${req.dbUser.last_name}` : 'System User';
  const client = await pool.connect();

  try {
    await client.query('BEGIN');
    for (const op of operations) {
      if (op.type === 'ADD_NOTE') {
        const ins = await client.query(
          `INSERT INTO daily_notes (service_user_id, note_text, author_name)
           SELECT $1::uuid, $2, $3
           FROM service_users su
           WHERE su.id = $1::uuid
             AND (CAST($4 AS uuid) IS NULL OR su.home_id = CAST($4 AS uuid))`,
          [op.payload.residentId, op.payload.text, dbAuthorName, scope]
        );
        if (ins.rowCount === 0) {
          throw new Error('Access denied or resident not in scope for note insert');
        }
      }
    }
    await client.query('COMMIT');
    const opTypes = [...new Set(operations.map((o) => o.type).filter(Boolean))];
    await writeAuditLog(req, {
      action: 'SYNC_BATCH_COMMIT',
      resourceType: 'sync',
      metadata: { operationCount: operations.length, operationTypes: opTypes },
    });
    res.status(200).json({ success: true });
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch (rollbackErr) {
      logRequestError(req, rollbackErr, 'sync-rollback');
    }
    logRequestError(req, err, 'sync-batch');
    clientError(req, res, 500, 'Sync could not be completed. Please try again later.');
  } finally {
    client.release();
  }
});

// ---------------------------------------------------------------------------
// 6. AI ORCHESTRATOR
// ---------------------------------------------------------------------------
app.post(
  '/api/v1/ai/handover',
  requireRole(ROLES_RESIDENT_AND_FACILITY_READ),
  async (req, res) => {
  const { notes } = req.body;
  try {
    if (!process.env.GEMINI_API_KEY) throw new Error('Missing Gemini API Key in .env');
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-09-2025:generateContent?key=${process.env.GEMINI_API_KEY}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [
            {
              parts: [
                {
                  text: `Summarize these clinical shift notes for a handover. Keep it brief and professional:\n\n${notes}`,
                },
              ],
            },
          ],
        }),
      }
    );
    const data = await response.json();
    await writeAuditLog(req, {
      action: 'AI_HANDOVER',
      resourceType: 'ai',
      metadata: { notesChars: typeof notes === 'string' ? notes.length : 0 },
    });
    res.json({
      summary: data.candidates?.[0]?.content?.parts?.[0]?.text || 'AI generated summary here.',
    });
  } catch (err) {
    logRequestError(req, err, 'ai-handover');
    clientError(req, res, 500, 'AI request could not be completed. Please try again later.');
  }
});

app.post(
  '/api/v1/ai/draft-incident',
  requireRole(ROLES_RESIDENT_AND_FACILITY_READ),
  async (req, res) => {
  const { notes } = req.body;
  try {
    if (!process.env.GEMINI_API_KEY) throw new Error('Missing Gemini API Key');
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-09-2025:generateContent?key=${process.env.GEMINI_API_KEY}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [
            {
              parts: [
                {
                  text: `Based strictly on these recent care notes, draft a formal, objective, and factual clinical Incident Report summary. Keep it concise.\n\nNotes:\n${notes}`,
                },
              ],
            },
          ],
        }),
      }
    );
    const data = await response.json();
    await writeAuditLog(req, {
      action: 'AI_DRAFT_INCIDENT',
      resourceType: 'ai',
      metadata: { notesChars: typeof notes === 'string' ? notes.length : 0 },
    });
    res.json({
      report: data.candidates?.[0]?.content?.parts?.[0]?.text || 'AI generated incident report here.',
    });
  } catch (err) {
    logRequestError(req, err, 'ai-draft-incident');
    clientError(req, res, 500, 'AI request could not be completed. Please try again later.');
  }
  }
);

app.post(
  '/api/v1/ai/med-safety',
  requireRole(ROLES_RESIDENT_AND_FACILITY_READ),
  async (req, res) => {
  const { medications } = req.body;
  try {
    if (!process.env.GEMINI_API_KEY) throw new Error('Missing Gemini API Key');
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-09-2025:generateContent?key=${process.env.GEMINI_API_KEY}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [
            {
              parts: [
                {
                  text: `Review this medication list for a care home resident: ${medications}. Briefly list obvious common side effects staff should watch for, and note potential interactions. Keep it concise, helpful, and under 150 words. Add a disclaimer.`,
                },
              ],
            },
          ],
        }),
      }
    );
    const data = await response.json();
    await writeAuditLog(req, {
      action: 'AI_MED_SAFETY',
      resourceType: 'ai',
      metadata: {
        medicationsPayloadType: medications == null ? 'null' : typeof medications,
      },
    });
    res.json({
      report: data.candidates?.[0]?.content?.parts?.[0]?.text || 'AI generated med safety report here.',
    });
  } catch (err) {
    logRequestError(req, err, 'ai-med-safety');
    clientError(req, res, 500, 'AI request could not be completed. Please try again later.');
  }
  }
);

app.post(
  '/api/v1/ai/dictation',
  requireRole(ROLES_RESIDENT_AND_FACILITY_READ),
  async (req, res) => {
  const { transcript } = req.body;
  try {
    if (!process.env.GEMINI_API_KEY) throw new Error('Missing Gemini API Key');
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-09-2025:generateContent?key=${process.env.GEMINI_API_KEY}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [
            {
              parts: [
                {
                  text: `Turn this raw dictated care note into a professional, objective clinical sentence without adding fabricated details: "${transcript}"`,
                },
              ],
            },
          ],
        }),
      }
    );
    const data = await response.json();
    await writeAuditLog(req, {
      action: 'AI_DICTATION',
      resourceType: 'ai',
      metadata: { transcriptChars: typeof transcript === 'string' ? transcript.length : 0 },
    });
    res.json({
      formattedText: data.candidates?.[0]?.content?.parts?.[0]?.text || transcript,
    });
  } catch (err) {
    logRequestError(req, err, 'ai-dictation');
    clientError(req, res, 500, 'AI request could not be completed. Please try again later.');
  }
  }
);

// ---------------------------------------------------------------------------
// 7. EXTERNAL INTEGRATIONS (NHS SPINE MOCK)
// ---------------------------------------------------------------------------
app.get(
  '/api/v1/integrations/nhs/meds/:nhsNumber',
  requireRole(ROLES_NHS_INTEGRATION_READ),
  async (req, res) => {
  const { nhsNumber } = req.params;
  try {
    const mockGPData = `[GP Connect Data for NHS ${nhsNumber}]\n- Amlodipine 5mg OD\n- Paracetamol 1000mg QDS\n- Simvastatin 20mg ON (NEW POST-DISCHARGE)\n- Stopped: Warfarin`;

    const timer = setTimeout(() => {
      void (async () => {
        if (!res.headersSent) {
          await writeAuditLog(req, {
            action: 'NHS_MEDS_MOCK_FETCH',
            resourceType: 'nhs_number',
            resourceId: String(nhsNumber),
            metadata: { integration: 'mock_spine' },
          });
          res.json({ data: mockGPData });
        }
      })();
    }, 1500);

    req.on('close', () => {
      clearTimeout(timer);
    });
  } catch (err) {
    if (!res.headersSent) {
      logRequestError(req, err, 'nhs-meds-mock');
      clientError(req, res, 500, 'Integration request could not be completed. Please try again later.');
    }
  }
});

app.listen(port, () => {
  console.log(`DCRS SECURE Backend server running on port ${port}`);
});
