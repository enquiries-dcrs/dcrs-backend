require('dotenv').config();
const { randomUUID } = require('crypto');
const express = require('express');
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
      'SELECT id, email, system_role, home_scope_id, first_name, last_name, is_active FROM users WHERE email = $1',
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
  'Home Manager',
  'Regional Manager',
  'Admin',
  'Staff',
];
const ROLES_OFFLINE_SYNC_WRITE = ROLES_RESIDENT_AND_FACILITY_READ;
// NHS mock: same role set as routine clinical reads (no drift between lists).
const ROLES_NHS_INTEGRATION_READ = ROLES_RESIDENT_AND_FACILITY_READ;

app.use('/api/v1', authenticateToken);

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

      const scopeId = homeScopeId === 'ALL' ? null : homeScopeId || null;

      const { data, error } = await supabaseAdmin.auth.admin.inviteUserByEmail(email, {
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
         SET system_role = EXCLUDED.system_role, home_scope_id = EXCLUDED.home_scope_id`,
        [email, firstName || '', lastName || '', role || 'Carer', scopeId]
      );

      await writeAuditLog(req, {
        action: 'ADMIN_INVITE_USER',
        resourceType: 'user_email',
        resourceId: String(email).trim(),
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
    const { data: { users }, error } = await supabaseAdmin.auth.admin.listUsers();
    if (error) throw error;
    const sbUser = users.find((u) => u.email === userEmail);
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

    // 2. Suspend at identity level (prevents fresh token generation)
    const userEmail = result.rows[0].email;
    const { data: { users }, error } = await supabaseAdmin.auth.admin.listUsers();
    if (error) throw error;
    const sbUser = users.find((u) => u.email === userEmail);
    if (sbUser) {
      await supabaseAdmin.auth.admin.updateUserById(sbUser.id, { ban_duration: '876000h' });
    }

    await writeAuditLog(req, {
      action: 'ADMIN_DEACTIVATE_USER',
      resourceType: 'user',
      resourceId: id,
      metadata: { targetEmail: userEmail },
    });
    res.json({ success: true, message: 'User securely deactivated.' });
  } catch (err) {
    logRequestError(req, err, 'admin-deactivate-user');
    clientError(req, res, 500, 'Unable to deactivate user. Please try again later.');
  }
});

// Password Resets
app.post('/api/v1/admin/users/:id/reset-password', requireRole(['Regional Manager', 'Admin']), async (req, res) => {
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

const ROLES_RESIDENT_MANAGEMENT = ['Regional Manager', 'Home Manager', 'Admin'];

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

    resident.tasks = tasksRes.rows;
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
  requireRole(['Regional Manager', 'Home Manager', 'Admin']),
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
  requireRole(['Regional Manager', 'Home Manager', 'Admin']),
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
  requireRole(['Regional Manager', 'Home Manager', 'Admin']),
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
