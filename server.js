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

function normalizeTaskPriorityForDb(raw) {
  if (raw == null || raw === '') return 'Normal';
  const s = String(raw).trim().toUpperCase().replace(/\s+/g, '_');
  if (s === 'LOW') return 'Low';
  if (s === 'HIGH') return 'High';
  if (s === 'CRITICAL') return 'Critical';
  if (s === 'NORMAL') return 'Normal';
  // legacy / title case
  const t = String(raw).trim();
  if (/^high$/i.test(t)) return 'High';
  if (/^low$/i.test(t)) return 'Low';
  if (/^critical$/i.test(t)) return 'Critical';
  if (/^normal$/i.test(t)) return 'Normal';
  return 'Normal';
}

function taskPriorityIsHigh(p) {
  const s = String(p || '').trim().toLowerCase();
  return s === 'high' || s === 'critical';
}

/** 8-4-4-4-12 hex — matches Postgres uuid text (incl. non-RFC fixture IDs). */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function filterValidUuidList(ids) {
  const out = [];
  const seen = new Set();
  for (const raw of ids) {
    if (raw == null) continue;
    const s = String(raw).trim();
    if (!UUID_RE.test(s) || seen.has(s)) continue;
    seen.add(s);
    out.push(s);
  }
  return out;
}

function normalizeTaskRow(t) {
  if (!t || typeof t !== 'object') return t;
  const due =
    t.dueDate ??
    t.due_date ??
    t.due_at ??
    t.dueAt ??
    null;
  let dueDateIso = null;
  if (due) {
    const d = new Date(due);
    if (!Number.isNaN(d.getTime())) dueDateIso = d.toISOString().slice(0, 10);
  }
  const dueDate = dueDateIso
    ? new Date(`${dueDateIso}T12:00:00Z`).toLocaleDateString('en-GB')
    : t.dueDate || t.due_date || null;
  const pr = t.priority ?? t.task_priority ?? 'Normal';
  const af = t.assigned_first_name ?? t.assignee_first_name ?? null;
  const al = t.assigned_last_name ?? t.assignee_last_name ?? null;
  const assignedToName =
    t.assigned_to && (af || al)
      ? `${String(af || '').trim()} ${String(al || '').trim()}`.trim() || null
      : t.assigned_to
        ? 'Staff'
        : null;
  return {
    id: t.id,
    title: t.title ?? t.task_title ?? t.name ?? '',
    status: t.status ?? t.task_status ?? 'Open',
    priority: pr,
    dueDate,
    dueDateIso,
    assignedToId: t.assigned_to ?? null,
    assignedToName,
    // keep originals for debugging/compat without leaking unexpected columns
    created_at: t.created_at ?? null,
  };
}

function normalizeObservationTypeCode(raw) {
  const t = typeof raw === 'string' ? raw.trim() : '';
  if (!t) return '';
  const key = t.toLowerCase().replace(/\s+/g, ' ');
  const map = new Map([
    ['blood pressure', 'BP'],
    ['bp', 'BP'],
    ['heart rate', 'PULSE'],
    ['pulse', 'PULSE'],
    ['temperature', 'TEMP'],
    ['temp', 'TEMP'],
    ['weight', 'WEIGHT'],
    ['spo2', 'SPO2'],
    ['sp02', 'SPO2'],
    ['oxygen saturation', 'SPO2'],
    ['respiratory rate', 'RESP_RATE'],
    ['resp rate', 'RESP_RATE'],
    ['pain', 'PAIN'],
  ]);
  if (map.has(key)) return map.get(key);
  const up = t.toUpperCase();
  if (/^[A-Z][A-Z0-9_]*$/.test(up) && up.length <= 40) return up;
  if (['BP', 'PULSE', 'TEMP', 'WEIGHT', 'SPO2', 'RESP_RATE', 'PAIN', 'OTHER'].includes(up)) return up;
  return 'OTHER';
}

function defaultUnitForObservationCode(code) {
  switch (code) {
    case 'BP':
      return 'mmHg';
    case 'PULSE':
      return 'bpm';
    case 'TEMP':
      return '°C';
    case 'WEIGHT':
      return 'kg';
    case 'SPO2':
      return '%';
    case 'RESP_RATE':
      return '/min';
    case 'PAIN':
      return '/10';
    default:
      return '';
  }
}

function observationLabel(code) {
  switch (code) {
    case 'BP':
      return 'Blood pressure';
    case 'PULSE':
      return 'Heart rate';
    case 'TEMP':
      return 'Temperature';
    case 'WEIGHT':
      return 'Weight';
    case 'SPO2':
      return 'SpO₂';
    case 'RESP_RATE':
      return 'Respiratory rate';
    case 'PAIN':
      return 'Pain';
    default:
      return code || 'Observation';
  }
}

function mapObservationRow(o) {
  const code = o.observation_type ?? o.type ?? '';
  return {
    id: o.id,
    type: code,
    typeLabel: observationLabel(code),
    value: o.value != null ? String(o.value) : '',
    unit: o.unit || '',
    notes: o.notes ?? null,
    recordedAt: o.recorded_at,
    time: o.recorded_at ? new Date(o.recorded_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '',
    date: o.recorded_at ? new Date(o.recorded_at).toLocaleDateString() : '',
    author: o.recorded_by_name || 'Staff',
  };
}

function csvEscape(value) {
  if (value === null || value === undefined) return '';
  const s = String(value);
  if (/[",\r\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

function csvLine(fields) {
  return `${fields.map(csvEscape).join(',')}\r\n`;
}

function oneLine(s) {
  return String(s ?? '')
    .replace(/\r\n|\n|\r/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function parseLeadingNumberFromObservationValue(valueRaw) {
  const m = String(valueRaw ?? '').match(/-?\d+(?:\.\d+)?/);
  if (!m) return null;
  const n = parseFloat(m[0]);
  return Number.isFinite(n) ? n : null;
}

const CLINICAL_RISK_SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

function sortClinicalRiskItems(items) {
  return [...items].sort(
    (a, b) =>
      (CLINICAL_RISK_SEVERITY_ORDER[a.severity] ?? 9) - (CLINICAL_RISK_SEVERITY_ORDER[b.severity] ?? 9)
  );
}

function clampClinicalRiskAckHours(n) {
  const x = Number(n);
  if (!Number.isFinite(x)) return null;
  return Math.min(168, Math.max(1, Math.round(x)));
}

/**
 * Per-home override: homes.metadata.clinicalRiskReview.ackCooldownHours (1–168),
 * or legacy homes.metadata.clinicalRiskAckCooldownHours.
 */
function ackCooldownHoursFromHomeMetadata(metadata, fallbackHours) {
  const fb = clampClinicalRiskAckHours(fallbackHours) ?? 48;
  if (!metadata || typeof metadata !== 'object') return fb;
  const nested = metadata.clinicalRiskReview;
  if (nested && typeof nested === 'object' && nested.ackCooldownHours != null) {
    const c = clampClinicalRiskAckHours(nested.ackCooldownHours);
    if (c != null) return c;
  }
  if (metadata.clinicalRiskAckCooldownHours != null) {
    const c = clampClinicalRiskAckHours(metadata.clinicalRiskAckCooldownHours);
    if (c != null) return c;
  }
  return fb;
}

/**
 * Rule-based clinical risk & review inbox (not predictive ML).
 * Each item carries a stable `fingerprint` for POST acknowledgement + cooldown suppression.
 * Cooldown hours default from options; each home can override via homes.metadata (see sql/024).
 */
async function assembleClinicalRiskReviewItems(scope, options = {}) {
  const defaultAckHours = clampClinicalRiskAckHours(options.defaultAckCooldownHours) ?? 48;
  const items = [];
  const warnings = [];
  const homeAckCooldownByHomeId = {};
  const homeCooldownMap = new Map();
  let ackRows = [];

  try {
    const { rows: homeRows } = await pool.query(
      `SELECT id, name, COALESCE(metadata, '{}'::jsonb) AS metadata
       FROM public.homes
       WHERE (CAST($1 AS uuid) IS NULL OR id = CAST($1 AS uuid))
       ORDER BY name ASC NULLS LAST`,
      [scope]
    );
    for (const h of homeRows) {
      const hid = String(h.id);
      const hrs = ackCooldownHoursFromHomeMetadata(h.metadata, defaultAckHours);
      homeCooldownMap.set(hid, hrs);
      homeAckCooldownByHomeId[hid] = { homeName: h.name || null, ackCooldownHours: hrs };
    }
  } catch (err) {
    if (String(err.code || '') === '42703' || /metadata/i.test(String(err.message))) {
      warnings.push(
        'homes.metadata column missing — run backend/sql/024_homes_metadata_risk_ack_home.sql. Using default acknowledgement cooldown only.'
      );
      homeCooldownMap.clear();
    } else {
      console.error('[clinical-risk-homes-meta]', err);
      warnings.push('Could not load home metadata for acknowledgement cooldowns.');
    }
  }

  function resolveAckHoursForHome(homeId) {
    if (homeId && homeCooldownMap.has(String(homeId))) return homeCooldownMap.get(String(homeId));
    return defaultAckHours;
  }

  try {
    const { rows } = await pool.query(
      `SELECT fingerprint, created_at
       FROM public.risk_review_acknowledgements
       WHERE created_at >= now() - interval '168 hours'`
    );
    ackRows = rows;
  } catch (err) {
    if (String(err.code || '') === '42P01' || /risk_review_acknowledgements/i.test(String(err.message))) {
      warnings.push(
        'Acknowledgements table is not installed yet. Run backend/sql/023_risk_review_acknowledgements.sql — review items still show, but “Acknowledge” will fail until then.'
      );
      ackRows = [];
    } else {
      throw err;
    }
  }

  function latestAckMs(fingerprint) {
    let latest = 0;
    for (const a of ackRows) {
      if (String(a.fingerprint) !== String(fingerprint)) continue;
      const t = new Date(a.created_at).getTime();
      if (!Number.isNaN(t) && t > latest) latest = t;
    }
    return latest;
  }

  function isSuppressedByAck(fingerprint, homeId) {
    const latest = latestAckMs(fingerprint);
    if (!latest) return false;
    const cd = resolveAckHoursForHome(homeId);
    return Date.now() - latest < cd * 3600000;
  }

  function pushItem(item) {
    if (!item?.fingerprint) return;
    if (isSuppressedByAck(item.fingerprint, item.homeId)) return;
    const hrs = resolveAckHoursForHome(item.homeId);
    items.push({ ...item, ackCooldownHours: hrs });
  }

  const residentLabel = (fn, ln) =>
    `${String(fn || '').trim()} ${String(ln || '').trim()}`.trim() || 'Service user';

  // --- Overdue high / critical tasks (per task) ---
  try {
    const { rows: taskRows } = await pool.query(
      `SELECT t.id, t.title, t.priority, t.due_date, t.service_user_id,
              su.first_name AS rf, su.last_name AS rl, su.home_id, h.name AS home_name
       FROM tasks t
       INNER JOIN service_users su ON su.id = t.service_user_id
       LEFT JOIN homes h ON h.id = su.home_id
       WHERE (CAST($1 AS uuid) IS NULL OR su.home_id = CAST($1 AS uuid))
         AND su.status = 'ADMITTED'
         AND t.due_date IS NOT NULL
         AND t.due_date::date < (timezone('UTC', now()))::date
         AND lower(trim(coalesce(t.status, ''))) NOT IN ('completed', 'done')
         AND lower(trim(coalesce(t.priority, ''))) IN ('high', 'critical')
       ORDER BY t.due_date ASC NULLS LAST
       LIMIT 100`,
      [scope]
    );
    for (const t of taskRows) {
      const pr = String(t.priority || '').trim().toLowerCase();
      const sev = pr === 'critical' ? 'critical' : 'high';
      const dueStr = t.due_date
        ? new Date(t.due_date).toLocaleDateString('en-GB', { timeZone: 'UTC' })
        : 'unknown';
      pushItem({
        fingerprint: `OVERDUE_HIGH_TASK:${t.id}`,
        severity: sev,
        category: 'TASK_ESCALATION',
        type: 'OVERDUE_HIGH_PRIORITY_TASK',
        title: `Overdue ${pr === 'critical' ? 'critical' : 'high'}-priority task`,
        detail: `${oneLine(t.title) || 'Task'} — due ${dueStr}.`,
        serviceUserId: String(t.service_user_id),
        residentName: residentLabel(t.rf, t.rl),
        homeId: t.home_id ? String(t.home_id) : null,
        homeName: t.home_name || null,
        ref: { type: 'task', id: String(t.id) },
        suggestedActions: [
          'Resolve or re-date the task on the resident chart (Tasks tab).',
          'If care was delayed for a clinical reason, record it in daily notes.',
        ],
      });
    }
  } catch (err) {
    console.error('[clinical-risk-tasks-high]', err);
    warnings.push('Could not evaluate overdue high-priority tasks.');
  }

  // --- Many overdue open tasks per resident (coordination risk) ---
  try {
    const { rows: backRows } = await pool.query(
      `SELECT t.service_user_id, COUNT(*)::int AS cnt,
              su.first_name AS rf, su.last_name AS rl, su.home_id, h.name AS home_name
       FROM tasks t
       INNER JOIN service_users su ON su.id = t.service_user_id
       LEFT JOIN homes h ON h.id = su.home_id
       WHERE (CAST($1 AS uuid) IS NULL OR su.home_id = CAST($1 AS uuid))
         AND su.status = 'ADMITTED'
         AND t.due_date IS NOT NULL
         AND t.due_date::date < (timezone('UTC', now()))::date
         AND lower(trim(coalesce(t.status, ''))) NOT IN ('completed', 'done')
       GROUP BY t.service_user_id, su.first_name, su.last_name, su.home_id, h.name
       HAVING COUNT(*) >= 5
       ORDER BY cnt DESC
       LIMIT 40`,
      [scope]
    );
    for (const b of backRows) {
      pushItem({
        fingerprint: `TASK_BACKLOG:${b.service_user_id}`,
        severity: 'medium',
        category: 'TASK_COORDINATION',
        type: 'OVERDUE_TASK_BACKLOG',
        title: 'Large backlog of overdue open tasks',
        detail: `${residentLabel(b.rf, b.rl)} has ${b.cnt} overdue tasks that are still open — review workload and priorities.`,
        serviceUserId: String(b.service_user_id),
        residentName: residentLabel(b.rf, b.rl),
        homeId: b.home_id ? String(b.home_id) : null,
        homeName: b.home_name || null,
        ref: { type: 'service_user', id: String(b.service_user_id) },
        suggestedActions: [
          'Open the Tasks tab and triage: complete, delegate, or set realistic new dates.',
          'Consider a multidisciplinary huddle if this pattern persists.',
        ],
      });
    }
  } catch (err) {
    console.error('[clinical-risk-task-backlog]', err);
    warnings.push('Could not evaluate overdue task backlog.');
  }

  // --- Recent temperature (48h) ---
  try {
    const { rows: tempRows } = await pool.query(
      `SELECT DISTINCT ON (o.service_user_id)
         o.service_user_id, o.value, o.recorded_at, o.id AS observation_id,
         su.first_name AS rf, su.last_name AS rl, su.home_id, h.name AS home_name
       FROM observations o
       INNER JOIN service_users su ON su.id = o.service_user_id
       LEFT JOIN homes h ON h.id = su.home_id
       WHERE (CAST($1 AS uuid) IS NULL OR su.home_id = CAST($1 AS uuid))
         AND su.status = 'ADMITTED'
         AND lower(trim(coalesce(o.observation_type::text, ''))) IN ('temp', 'temperature')
         AND o.recorded_at >= now() - interval '48 hours'
       ORDER BY o.service_user_id, o.recorded_at DESC`,
      [scope]
    );
    for (const row of tempRows) {
      const v = parseLeadingNumberFromObservationValue(row.value);
      if (v == null) continue;
      let severity = null;
      if (v >= 39.0) severity = 'critical';
      else if (v >= 38.0) severity = 'high';
      else if (v >= 37.5) severity = 'medium';
      if (!severity) continue;
      pushItem({
        fingerprint: `TEMP_ELEVATED_48H:${row.service_user_id}`,
        severity,
        category: 'VITALS',
        type: 'TEMPERATURE_ELEVATED_RECENT',
        title: 'Elevated temperature (recent charting)',
        detail: `${residentLabel(row.rf, row.rl)} — latest temperature ${v}°C recorded ${row.recorded_at ? new Date(row.recorded_at).toLocaleString('en-GB') : 'recently'}.`,
        serviceUserId: String(row.service_user_id),
        residentName: residentLabel(row.rf, row.rl),
        homeId: row.home_id ? String(row.home_id) : null,
        homeName: row.home_name || null,
        ref: { type: 'observation', id: String(row.observation_id) },
        suggestedActions: [
          'Follow local infection prevention and escalation policy.',
          'Repeat observations and review associated notes and MAR.',
        ],
      });
    }
  } catch (err) {
    if (String(err.code || '') === '42P01' || /observations/i.test(String(err.message))) {
      warnings.push('Observations table unavailable — temperature rules skipped.');
    } else {
      console.error('[clinical-risk-temp]', err);
      warnings.push('Could not evaluate recent temperature observations.');
    }
  }

  // --- Recent SpO₂ (48h) ---
  try {
    const { rows: spoRows } = await pool.query(
      `SELECT DISTINCT ON (o.service_user_id)
         o.service_user_id, o.value, o.recorded_at, o.id AS observation_id,
         su.first_name AS rf, su.last_name AS rl, su.home_id, h.name AS home_name
       FROM observations o
       INNER JOIN service_users su ON su.id = o.service_user_id
       LEFT JOIN homes h ON h.id = su.home_id
       WHERE (CAST($1 AS uuid) IS NULL OR su.home_id = CAST($1 AS uuid))
         AND su.status = 'ADMITTED'
         AND lower(trim(coalesce(o.observation_type::text, ''))) IN ('spo2', 'sp02')
         AND o.recorded_at >= now() - interval '48 hours'
       ORDER BY o.service_user_id, o.recorded_at DESC`,
      [scope]
    );
    for (const row of spoRows) {
      const v = parseLeadingNumberFromObservationValue(row.value);
      if (v == null) continue;
      let severity = null;
      if (v < 88) severity = 'critical';
      else if (v < 92) severity = 'high';
      else if (v < 94) severity = 'medium';
      if (!severity) continue;
      pushItem({
        fingerprint: `SPO2_LOW_48H:${row.service_user_id}`,
        severity,
        category: 'VITALS',
        type: 'SPO2_LOW_RECENT',
        title: 'Low oxygen saturation (recent charting)',
        detail: `${residentLabel(row.rf, row.rl)} — latest SpO₂ ${v}% recorded ${row.recorded_at ? new Date(row.recorded_at).toLocaleString('en-GB') : 'recently'}.`,
        serviceUserId: String(row.service_user_id),
        residentName: residentLabel(row.rf, row.rl),
        homeId: row.home_id ? String(row.home_id) : null,
        homeName: row.home_name || null,
        ref: { type: 'observation', id: String(row.observation_id) },
        suggestedActions: [
          'Confirm device and resident state; escalate per local respiratory distress protocol.',
          'Review observations trend and clinician/GP involvement where indicated.',
        ],
      });
    }
  } catch (err) {
    if (String(err.code || '') === '42P01' || /observations/i.test(String(err.message))) {
      /* already warned */
    } else {
      console.error('[clinical-risk-spo2]', err);
      warnings.push('Could not evaluate recent SpO₂ observations.');
    }
  }

  // --- PEEP review dates ---
  try {
    const { rows: peepRows } = await pool.query(
      `SELECT pd.service_user_id, pd.review_date, pd.updated_at,
              su.first_name AS rf, su.last_name AS rl, su.home_id, h.name AS home_name
       FROM peep_documents pd
       INNER JOIN service_users su ON su.id = pd.service_user_id
       LEFT JOIN homes h ON h.id = su.home_id
       WHERE (CAST($1 AS uuid) IS NULL OR su.home_id = CAST($1 AS uuid))
         AND su.status = 'ADMITTED'
         AND pd.review_date IS NOT NULL
         AND pd.review_date <= (CURRENT_DATE + interval '14 days')
       ORDER BY pd.review_date ASC
       LIMIT 80`,
      [scope]
    );
    for (const row of peepRows) {
      const rd = row.review_date;
      if (!rd) continue;
      const rdDate = new Date(`${String(rd).slice(0, 10)}T12:00:00Z`);
      const todayUtc = new Date();
      const todayMid = new Date(
        `${todayUtc.getUTCFullYear()}-${String(todayUtc.getUTCMonth() + 1).padStart(2, '0')}-${String(todayUtc.getUTCDate()).padStart(2, '0')}T12:00:00Z`
      );
      const overdue = rdDate.getTime() < todayMid.getTime();
      const sev = overdue ? 'high' : 'medium';
      const fp = overdue ? `PEEP_REVIEW_OVERDUE:${row.service_user_id}` : `PEEP_REVIEW_DUE_SOON:${row.service_user_id}`;
      pushItem({
        fingerprint: fp,
        severity: sev,
        category: 'SAFETY_PLANNING',
        type: overdue ? 'PEEP_REVIEW_OVERDUE' : 'PEEP_REVIEW_DUE_SOON',
        title: overdue ? 'PEEP review date has passed' : 'PEEP review due within 14 days',
        detail: `${residentLabel(row.rf, row.rl)} — review date ${new Date(rd).toLocaleDateString('en-GB', { timeZone: 'UTC' })}.`,
        serviceUserId: String(row.service_user_id),
        residentName: residentLabel(row.rf, row.rl),
        homeId: row.home_id ? String(row.home_id) : null,
        homeName: row.home_name || null,
        ref: { type: 'peep', id: String(row.service_user_id) },
        suggestedActions: [
          'Open the PEEP tab, confirm evacuation arrangements, and set the next review date.',
          'Upload a refreshed PEEP document if your governance model requires it.',
        ],
      });
    }
  } catch (err) {
    if (String(err.code || '') === '42P01' || /peep_documents/i.test(String(err.message))) {
      warnings.push('PEEP table unavailable — PEEP review rules skipped.');
    } else {
      console.error('[clinical-risk-peep]', err);
      warnings.push('Could not evaluate PEEP review dates.');
    }
  }

  return {
    items: sortClinicalRiskItems(items),
    methodology: [
      'This inbox applies transparent, deterministic rules to existing operational data (tasks, observations, PEEP).',
      'It is not a predictive AI model and must not replace clinical judgement or local policy.',
      'Thresholds (examples): overdue high/critical tasks; ≥5 overdue open tasks per resident; temperature ≥37.5°C within 48h (severity rises ≥38°C / ≥39°C); SpO₂ <94% / <92% / <88% within 48h; PEEP review within 14 days or overdue.',
      `Acknowledgement cooldown is per home via homes.metadata JSON: set clinicalRiskReview.ackCooldownHours (integer 1–168). If unset, the API default (${defaultAckHours}h) applies. Optional query ?defaultAckCooldownHours= overrides that fallback when a home has no metadata.`,
      'GET /api/v1/clinical-risk-review returns homeAckCooldownByHomeId with resolved hours per home in your scope.',
    ],
    defaultAckCooldownHours: defaultAckHours,
    homeAckCooldownByHomeId,
    warnings,
    generatedAt: new Date().toISOString(),
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
/** Assign / clear task assignee (Senior Carer+). */
const ROLES_TASK_ASSIGN = ['Senior Carer', 'Deputy Manager', 'Home Manager', 'Regional Manager', 'Admin'];
const ROLES_FOOD_DRINK_WRITE = ROLES_RESIDENT_AND_FACILITY_READ;
const ROLES_ACTIVITIES_WRITE = ROLES_RESIDENT_AND_FACILITY_READ;
const ROLES_DAILY_CARE_WRITE = ROLES_RESIDENT_AND_FACILITY_READ;
const ROLES_OBSERVATIONS_WRITE = ROLES_RESIDENT_AND_FACILITY_READ;
const ROLES_PEEP_WRITE = ['Deputy Manager', 'Home Manager', 'Regional Manager', 'Admin'];
const ROLES_CARE_PLAN_EDIT = ['Senior Carer', 'Deputy Manager', 'Home Manager', 'Regional Manager', 'Admin'];
const ROLES_CARE_PLAN_ARCHIVE = ['Deputy Manager', 'Home Manager', 'Regional Manager', 'Admin'];
const ROLES_ASSESSMENT_TEMPLATES_EDIT = ['Deputy Manager', 'Home Manager', 'Regional Manager', 'Admin'];
const ROLES_ASSESSMENTS_CREATE = ['Senior Carer', 'Deputy Manager', 'Home Manager', 'Regional Manager', 'Admin'];
const ROLES_RESIDENT_DOCUMENTS_UPLOAD = ['Senior Carer', 'Deputy Manager', 'Home Manager', 'Regional Manager', 'Admin'];
const ROLES_RESIDENT_DOCUMENTS_DELETE = ['Deputy Manager', 'Home Manager', 'Regional Manager', 'Admin'];
/** Clinical record CSV export + assurance pack + emergency transfer pack (governance). */
const ROLES_RESIDENT_RECORD_EXPORT = ['Deputy Manager', 'Home Manager', 'Regional Manager', 'Admin'];
/** Who may edit emergency transfer profile fields on the service user. */
const ROLES_EMERGENCY_TRANSFER_PROFILE_WRITE = [
  'Senior Carer',
  'Deputy Manager',
  'Home Manager',
  'Regional Manager',
  'Admin',
];

/** Family portal: read-only updates for linked relatives (provisioned `users` row, role Family). */
const ROLES_ADMIN_FAMILY_LINK = ['Regional Manager', 'Admin', 'Home Manager'];
/** Who may send Supabase invites for family contacts tied to a resident. */
const ROLES_FAMILY_INVITE_SENDERS = ['Deputy Manager', 'Home Manager', 'Regional Manager', 'Admin'];

function requireFamilyPortalActor(req, res, next) {
  const r = req.dbUser?.system_role;
  if (!r) {
    return clientError(req, res, 403, 'Forbidden: Role could not be determined for this account.');
  }
  if (r === 'Family' || ROLES_RESIDENT_AND_FACILITY_READ.includes(r)) {
    return next();
  }
  return clientError(req, res, 403, 'Forbidden: Family portal requires a Family or clinical staff account.');
}

async function userCanViewResidentInFamilyPortal(req, serviceUserId) {
  const role = req.dbUser?.system_role;
  if (!role) return false;
  if (role === 'Family') {
    const r = await pool.query(
      `SELECT 1 FROM family_portal_access f
       WHERE f.user_id = $1::uuid AND f.service_user_id = $2::uuid
       LIMIT 1`,
      [req.dbUser.id, serviceUserId]
    );
    return r.rows.length > 0;
  }
  if (ROLES_RESIDENT_AND_FACILITY_READ.includes(role)) {
    const scope = userHomeScope(req);
    const r = await pool.query(
      `SELECT 1 FROM service_users su
       WHERE su.id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR su.home_id = CAST($2 AS uuid))
       LIMIT 1`,
      [serviceUserId, scope]
    );
    return r.rows.length > 0;
  }
  return false;
}

async function assertAdminCanLinkFamilyToResident(req, serviceUserId) {
  const role = req.dbUser?.system_role;
  const scope = userHomeScope(req);
  const h = await pool.query(`SELECT home_id FROM service_users WHERE id = $1::uuid`, [serviceUserId]);
  if (!h.rows.length) return { ok: false, status: 404, message: 'Resident not found.' };
  const homeId = h.rows[0].home_id;
  if (role === 'Admin' || role === 'Regional Manager') return { ok: true };
  if (role === 'Home Manager') {
    if (scope && String(homeId) === String(scope)) return { ok: true };
    return { ok: false, status: 403, message: 'That resident is outside your home scope.' };
  }
  return { ok: false, status: 403, message: 'Forbidden.' };
}

async function buildFamilyPortalFeed(req, serviceUserId) {
  const items = [];
  try {
    const nq = await pool.query(
      `SELECT id, note_text, author_name, created_at
       FROM daily_notes
       WHERE service_user_id = $1::uuid AND share_with_family = true
       ORDER BY created_at DESC
       LIMIT 40`,
      [serviceUserId]
    );
    for (const n of nq.rows || []) {
      items.push({
        id: `note-${n.id}`,
        kind: 'shared_note',
        title: `Message from ${n.author_name || 'the care team'}`,
        body: oneLine(n.note_text).slice(0, 4000),
        occurredAt: n.created_at ? new Date(n.created_at).toISOString() : null,
      });
    }
  } catch (err) {
    if (err && err.code === '42703') {
      // share_with_family column missing until migration 020 is applied
    } else {
      logRequestError(req, err, 'family-feed-notes');
    }
  }

  try {
    const aq = await pool.query(
      `SELECT ae.id, ae.activity_type, ae.notes, ae.chart_date, ae.created_at, ae.recorded_by
       FROM activity_entries ae
       WHERE ae.service_user_id = $1::uuid
       ORDER BY ae.created_at DESC
       LIMIT 25`,
      [serviceUserId]
    );
    for (const a of aq.rows || []) {
      const at = a.created_at || a.chart_date;
      const detail = a.notes
        ? oneLine(a.notes).slice(0, 2000)
        : `Recorded${a.recorded_by ? ` by ${a.recorded_by}` : ''}.`;
      items.push({
        id: `activity-${a.id}`,
        kind: 'activity',
        title: a.activity_type || 'Activity',
        body: detail,
        occurredAt: at ? new Date(at).toISOString() : null,
      });
    }
  } catch (err) {
    const code = err && err.code;
    const msg = err && err.message ? String(err.message) : '';
    if (code !== '42P01' && !/activity_entries/i.test(msg)) {
      logRequestError(req, err, 'family-feed-activities');
    }
  }

  try {
    const dq = await pool.query(
      `SELECT id, care_item, value, notes, chart_date, created_at, recorded_by
       FROM daily_care_entries
       WHERE service_user_id = $1::uuid
         AND care_item IN ('Visitors','Been out','Stayed in')
       ORDER BY created_at DESC
       LIMIT 20`,
      [serviceUserId]
    );
    for (const d of dq.rows || []) {
      const at = d.created_at || d.chart_date;
      const bits = [d.care_item, d.value, d.notes].filter(Boolean).join(' — ');
      items.push({
        id: `care-${d.id}`,
        kind: 'daily_life',
        title: d.care_item || 'Daily update',
        body: oneLine(bits).slice(0, 2000),
        occurredAt: at ? new Date(at).toISOString() : null,
      });
    }
  } catch (err) {
    const code = err && err.code;
    const msg = err && err.message ? String(err.message) : '';
    if (code !== '42P01' && !/daily_care_entries/i.test(msg)) {
      logRequestError(req, err, 'family-feed-daily-care');
    }
  }

  items.sort((a, b) => {
    const ta = a.occurredAt ? new Date(a.occurredAt).getTime() : 0;
    const tb = b.occurredAt ? new Date(b.occurredAt).getTime() : 0;
    return tb - ta;
  });
  return items.filter((x) => x.occurredAt).slice(0, 60);
}

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
// FAMILY PORTAL (linked Family accounts + clinical preview)
// ---------------------------------------------------------------------------
app.get('/api/v1/family/context', requireFamilyPortalActor, async (req, res) => {
  try {
    const role = req.dbUser.system_role;
    if (role === 'Family') {
      try {
        const { rows } = await pool.query(
          `SELECT su.id AS service_user_id, su.first_name, su.last_name, h.name AS home_name, f.relationship
           FROM family_portal_access f
           INNER JOIN service_users su ON su.id = f.service_user_id
           LEFT JOIN homes h ON h.id = su.home_id
           WHERE f.user_id = $1::uuid
           ORDER BY su.last_name ASC NULLS LAST, su.first_name ASC NULLS LAST`,
          [req.dbUser.id]
        );
        return res.json({ role: 'Family', residents: rows });
      } catch (err) {
        if (err && err.code === '42P01') {
          return clientError(
            req,
            res,
            503,
            'Family portal is not available until database migration 020_family_portal.sql is applied.'
          );
        }
        throw err;
      }
    }

    const scope = userHomeScope(req);
    const { rows } = await pool.query(
      `SELECT su.id AS service_user_id, su.first_name, su.last_name, h.name AS home_name, NULL::text AS relationship
       FROM service_users su
       LEFT JOIN beds b ON su.current_bed_id = b.id
       LEFT JOIN units u ON b.unit_id = u.id
       LEFT JOIN homes h ON su.home_id = h.id
       WHERE su.status IN ('ADMITTED', 'DISCHARGED', 'PENDING')
         AND (CAST($1 AS uuid) IS NULL OR su.home_id = CAST($1 AS uuid))
       ORDER BY su.last_name ASC NULLS LAST, su.first_name ASC NULLS LAST`,
      [scope]
    );
    return res.json({ role: 'staff', residents: rows });
  } catch (err) {
    logRequestError(req, err, 'family-context');
    clientError(req, res, 500, 'Unable to load family portal context.');
  }
});

app.get('/api/v1/family/residents/:id/feed', requireFamilyPortalActor, async (req, res) => {
  const { id } = req.params;
  try {
    if (!(await userCanViewResidentInFamilyPortal(req, id))) {
      return clientError(req, res, 403, 'You do not have access to this resident on the family portal.');
    }
    const rq = await pool.query(
      `SELECT su.id, su.first_name, su.last_name, h.name AS home_name
       FROM service_users su
       LEFT JOIN homes h ON h.id = su.home_id
       WHERE su.id = $1::uuid`,
      [id]
    );
    if (rq.rows.length === 0) {
      return res.status(404).json({ error: 'Resident not found.' });
    }
    const resident = rq.rows[0];
    const feed = await buildFamilyPortalFeed(req, id);
    await writeAuditLog(req, {
      action: 'FAMILY_PORTAL_FEED_VIEW',
      resourceType: 'service_user',
      resourceId: id,
      metadata: { itemCount: feed.length },
    });
    res.json({ resident, feed });
  } catch (err) {
    logRequestError(req, err, 'family-feed');
    clientError(req, res, 500, 'Unable to load family portal updates.');
  }
});

/** YYYY-MM-DD calendar date in UTC; returns null if invalid. */
function parsePreferredVisitDateUtc(isoDay) {
  const s = typeof isoDay === 'string' ? isoDay.trim() : '';
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s);
  if (!m) return null;
  const y = Number(m[1]);
  const mo = Number(m[2]);
  const da = Number(m[3]);
  const t = Date.UTC(y, mo - 1, da);
  if (Number.isNaN(t)) return null;
  const d = new Date(t);
  if (d.getUTCFullYear() !== y || d.getUTCMonth() !== mo - 1 || d.getUTCDate() !== da) return null;
  return { isoDay: s, utcMidnight: t };
}

app.post('/api/v1/family/residents/:id/visit-request', requireFamilyPortalActor, async (req, res) => {
  const { id: residentId } = req.params;
  try {
    if (req.dbUser?.system_role !== 'Family') {
      return clientError(req, res, 403, 'Only family accounts can submit visit requests.');
    }
    if (!(await userCanViewResidentInFamilyPortal(req, residentId))) {
      return clientError(req, res, 403, 'You do not have access to this resident on the family portal.');
    }

    const body = req.body || {};
    const preferredRaw = body.preferredDate ?? body.preferred_date;
    const preferredParsed = parsePreferredVisitDateUtc(
      typeof preferredRaw === 'string' ? preferredRaw : preferredRaw != null ? String(preferredRaw) : ''
    );
    if (!preferredParsed) {
      return clientError(req, res, 400, 'preferredDate is required and must be YYYY-MM-DD.');
    }

    const now = new Date();
    const todayUtc = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
    if (preferredParsed.utcMidnight < todayUtc) {
      return clientError(req, res, 400, 'preferredDate must be today or a future date.');
    }
    if (preferredParsed.utcMidnight > todayUtc + 370 * 86400000) {
      return clientError(req, res, 400, 'preferredDate is too far in the future.');
    }

    const timeNoteRaw = body.preferredTimeNote ?? body.preferred_time_note;
    const timeNote =
      typeof timeNoteRaw === 'string' ? timeNoteRaw.trim().slice(0, 120) : '';
    const messageRaw = body.message;
    const message = typeof messageRaw === 'string' ? messageRaw.trim().slice(0, 2000) : '';

    const fn = String(req.dbUser.first_name || '').trim();
    const ln = String(req.dbUser.last_name || '').trim();
    const who = [fn, ln].filter(Boolean).join(' ') || 'Family contact';
    const dateLabel = new Date(preferredParsed.utcMidnight).toLocaleDateString('en-GB', {
      day: 'numeric',
      month: 'short',
      year: 'numeric',
      timeZone: 'UTC',
    });
    let taskTitle = `Family visit request: ${who} — ${dateLabel}`;
    if (timeNote) taskTitle += ` (${timeNote})`;
    if (message) taskTitle += ` — ${message.replace(/\s+/g, ' ').trim()}`;
    taskTitle = taskTitle.slice(0, 200);

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      let vrRow;
      try {
        const vr = await client.query(
          `INSERT INTO family_visit_requests (service_user_id, requested_by_user_id, preferred_date, preferred_time_note, message)
           VALUES ($1::uuid, $2::uuid, $3::date, $4, $5)
           RETURNING id, created_at`,
          [
            residentId,
            req.dbUser.id,
            preferredParsed.isoDay,
            timeNote || null,
            message || null,
          ]
        );
        vrRow = vr.rows[0];
      } catch (err) {
        if (err && err.code === '42P01') {
          await client.query('ROLLBACK');
          return clientError(
            req,
            res,
            503,
            'Visit requests require database migration 021_family_visit_requests.sql to be applied.'
          );
        }
        throw err;
      }

      let taskRow;
      try {
        const ins = await client.query(
          `INSERT INTO tasks (service_user_id, title, status, priority, due_date, assigned_to)
           VALUES ($1::uuid, $2, 'Open', $3, $4::date, NULL)
           RETURNING id`,
          [residentId, taskTitle, normalizeTaskPriorityForDb('High'), preferredParsed.isoDay]
        );
        taskRow = ins.rows[0];
      } catch (eIns) {
        const code = eIns && typeof eIns === 'object' ? eIns.code : null;
        const msg = eIns && typeof eIns === 'object' ? String(eIns.message || '') : '';
        const missingAssignCol = code === '42703' || /assigned_to/i.test(msg);
        if (!missingAssignCol) throw eIns;
        const ins2 = await client.query(
          `INSERT INTO tasks (service_user_id, title, status, priority, due_date)
           VALUES ($1::uuid, $2, 'Open', $3, $4::date)
           RETURNING id`,
          [residentId, taskTitle, normalizeTaskPriorityForDb('High'), preferredParsed.isoDay]
        );
        taskRow = ins2.rows[0];
      }

      await client.query('COMMIT');

      await writeAuditLog(req, {
        action: 'FAMILY_VISIT_REQUEST_CREATE',
        resourceType: 'family_visit_request',
        resourceId: vrRow.id,
        metadata: {
          serviceUserId: residentId,
          preferredDate: preferredParsed.isoDay,
          taskId: taskRow.id,
        },
      });

      return res.status(201).json({
        success: true,
        visitRequestId: vrRow.id,
        taskId: taskRow.id,
        createdAt: vrRow.created_at,
      });
    } catch (e) {
      try {
        await client.query('ROLLBACK');
      } catch (_rb) {
        /* ignore */
      }
      throw e;
    } finally {
      client.release();
    }
  } catch (err) {
    logRequestError(req, err, 'family-visit-request');
    clientError(req, res, 500, 'Could not submit visit request. Please try again later.');
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
  requireRole(['Regional Manager', 'Admin', 'Home Manager', 'Deputy Manager']),
  async (req, res) => {
    const { email, firstName, lastName, role, homeScopeId } = req.body || {};
    const actorRole = req.dbUser?.system_role;

    try {
      if (!supabaseAdmin) {
        return clientError(req, res, 500, 'Server misconfiguration. Contact support.');
      }

      if (!email || String(email).trim() === '') {
        return res.status(400).json({ error: 'Missing email' });
      }

      const roleToInvite = String(role || 'Carer').trim();
      if (['Home Manager', 'Deputy Manager'].includes(actorRole)) {
        if (roleToInvite !== 'Family') {
          return clientError(
            req,
            res,
            403,
            'Only Regional Manager or Admin can invite staff accounts. Home and deputy managers may invite Family portal users only.'
          );
        }
      }

      const normalizedEmail = String(email).trim().toLowerCase();
      let scopeId = homeScopeId === 'ALL' ? null : homeScopeId || null;
      if (actorRole === 'Home Manager' && userHomeScope(req) != null) {
        scopeId = userHomeScope(req);
      }

      const appOrigin = (process.env.FRONTEND_URL || 'http://localhost:3000').replace(/\/$/, '');
      const inviteRedirectTo = `${appOrigin}/auth/callback`;

      const { data, error } = await supabaseAdmin.auth.admin.inviteUserByEmail(normalizedEmail, {
        redirectTo: inviteRedirectTo,
        data: {
          full_name: `${firstName || ''} ${lastName || ''}`.trim(),
          role: roleToInvite,
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
        [normalizedEmail, firstName || '', lastName || '', roleToInvite, scopeId]
      );

      await writeAuditLog(req, {
        action: 'ADMIN_INVITE_USER',
        resourceType: 'user_email',
        resourceId: normalizedEmail,
        metadata: { role: roleToInvite, homeScopeAll: homeScopeId === 'ALL' },
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

app.post('/api/v1/admin/family-portal-access', requireRole(ROLES_ADMIN_FAMILY_LINK), async (req, res) => {
  const { email, serviceUserId, relationship } = req.body || {};
  const emailNorm = typeof email === 'string' ? email.trim().toLowerCase() : '';
  const suId = typeof serviceUserId === 'string' ? serviceUserId.trim() : '';
  const rel = typeof relationship === 'string' ? relationship.trim().slice(0, 120) : null;

  if (!emailNorm || !suId) {
    return res.status(400).json({ error: 'email and serviceUserId are required.' });
  }

  try {
    const gate = await assertAdminCanLinkFamilyToResident(req, suId);
    if (!gate.ok) {
      return res.status(gate.status).json({ error: gate.message });
    }

    const uq = await pool.query(`SELECT id FROM users WHERE lower(trim(email)) = lower(trim($1))`, [emailNorm]);
    if (uq.rows.length === 0) {
      return res.status(404).json({ error: 'No provisioned DCRS user exists for that email. Invite them first.' });
    }
    const targetUserId = uq.rows[0].id;

    await pool.query(
      `INSERT INTO family_portal_access (user_id, service_user_id, relationship)
       VALUES ($1::uuid, $2::uuid, $3)
       ON CONFLICT (user_id, service_user_id) DO UPDATE SET relationship = EXCLUDED.relationship`,
      [targetUserId, suId, rel || null]
    );

    await writeAuditLog(req, {
      action: 'ADMIN_FAMILY_PORTAL_LINK_UPSERT',
      resourceType: 'family_portal_access',
      resourceId: String(suId),
      metadata: { targetEmail: emailNorm },
    });
    res.json({ success: true });
  } catch (err) {
    if (err && err.code === '42P01') {
      return clientError(
        req,
        res,
        503,
        'Family portal is not available until database migration 020_family_portal.sql is applied.'
      );
    }
    logRequestError(req, err, 'admin-family-portal-access');
    clientError(req, res, 500, 'Unable to save family portal link.');
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

/** Home scope for analytics CSV / assurance pack (matches roster export rules). */
async function resolveAnalyticsHomeFilter(req) {
  const scope = userHomeScope(req);
  const homeIdRaw = typeof req.query?.homeId === 'string' ? req.query.homeId.trim() : '';
  if (scope != null) {
    const filterHomeId = scope;
    if (homeIdRaw && homeIdRaw.toUpperCase() !== 'ALL') {
      if (String(homeIdRaw).replace(/-/g, '').toLowerCase() !== String(scope).replace(/-/g, '').toLowerCase()) {
        return { ok: false, status: 403, message: 'You can only export residents for your assigned home.' };
      }
    }
    return { ok: true, filterHomeId };
  }
  if (!homeIdRaw || homeIdRaw.toUpperCase() === 'ALL') {
    return { ok: true, filterHomeId: null };
  }
  if (!/^[0-9a-f-]{36}$/i.test(homeIdRaw)) {
    return { ok: false, status: 400, message: 'homeId must be a UUID, or omit / use ALL for all homes.' };
  }
  const hk = await pool.query(`SELECT id FROM homes WHERE id = $1::uuid`, [homeIdRaw]);
  if (hk.rows.length === 0) return { ok: false, status: 404, message: 'Home not found.' };
  return { ok: true, filterHomeId: homeIdRaw };
}

/** Manager-grade assurance metrics grouped for CQC *quality statement* themes (evidence prompts, not ratings). */
async function buildAssurancePackPayload(req, filterHomeId, { fromTs, toTs, label }) {
  const h = filterHomeId;
  const q3 = [fromTs, toTs, h];

  const intOrNull = (v) => (v == null ? null : Number(v));

  const runCount = async (sql, params, tag) => {
    try {
      const r = await pool.query(sql, params);
      return intOrNull(r.rows[0]?.count);
    } catch (err) {
      logRequestError(req, err, tag);
      return null;
    }
  };

  const [
    notesCreated,
    observationsRecorded,
    activitiesRecorded,
    assessmentsCreated,
    documentsUploaded,
    carePlansActive,
    tasksOpen,
    tasksOpenOverdue,
    tasksCompletedInPeriod,
    auditRows,
    auditNonSuccess,
    auditFamilyEvents,
    auditResidentExports,
    staffUsersActive,
    familyPortalLinks,
    familyVisitRequests,
  ] = await Promise.all([
    runCount(
      `SELECT COUNT(*)::int AS count FROM public.daily_notes dn
       INNER JOIN public.service_users su ON su.id = dn.service_user_id
       WHERE dn.created_at >= $1::timestamptz AND dn.created_at < $2::timestamptz
         AND (CAST($3 AS uuid) IS NULL OR su.home_id = CAST($3 AS uuid))`,
      q3,
      'assurance-notes'
    ),
    runCount(
      `SELECT COUNT(*)::int AS count FROM public.observations o
       INNER JOIN public.service_users su ON su.id = o.service_user_id
       WHERE o.recorded_at >= $1::timestamptz AND o.recorded_at < $2::timestamptz
         AND (CAST($3 AS uuid) IS NULL OR su.home_id = CAST($3 AS uuid))`,
      q3,
      'assurance-obs'
    ),
    runCount(
      `SELECT COUNT(*)::int AS count FROM public.activity_entries ae
       INNER JOIN public.service_users su ON su.id = ae.service_user_id
       WHERE COALESCE(ae.created_at, ae.chart_date::timestamptz) >= $1::timestamptz
         AND COALESCE(ae.created_at, ae.chart_date::timestamptz) < $2::timestamptz
         AND (CAST($3 AS uuid) IS NULL OR su.home_id = CAST($3 AS uuid))`,
      q3,
      'assurance-act'
    ),
    runCount(
      `SELECT COUNT(*)::int AS count FROM public.assessments a
       INNER JOIN public.service_users su ON su.id = a.service_user_id
       WHERE a.created_at >= $1::timestamptz AND a.created_at < $2::timestamptz
         AND (CAST($3 AS uuid) IS NULL OR su.home_id = CAST($3 AS uuid))`,
      q3,
      'assurance-asmt'
    ),
    runCount(
      `SELECT COUNT(*)::int AS count FROM public.resident_documents d
       INNER JOIN public.service_users su ON su.id = d.service_user_id
       WHERE d.is_deleted = false AND d.uploaded_at >= $1::timestamptz AND d.uploaded_at < $2::timestamptz
         AND (CAST($3 AS uuid) IS NULL OR su.home_id = CAST($3 AS uuid))`,
      q3,
      'assurance-docs'
    ),
    runCount(
      `SELECT COUNT(*)::int AS count FROM public.care_plans cp
       INNER JOIN public.service_users su ON su.id = cp.service_user_id
       WHERE cp.status = 'ACTIVE' AND su.status = 'ADMITTED'
         AND (CAST($1 AS uuid) IS NULL OR su.home_id = CAST($1 AS uuid))`,
      [h],
      'assurance-plans'
    ),
    runCount(
      `SELECT COUNT(*)::int AS count FROM public.tasks t
       INNER JOIN public.service_users su ON su.id = t.service_user_id
       WHERE LOWER(TRIM(COALESCE(t.status, ''))) NOT IN ('completed', 'done', 'cancelled', 'closed')
         AND (CAST($1 AS uuid) IS NULL OR su.home_id = CAST($1 AS uuid))`,
      [h],
      'assurance-tasks-open'
    ),
    runCount(
      `SELECT COUNT(*)::int AS count FROM public.tasks t
       INNER JOIN public.service_users su ON su.id = t.service_user_id
       WHERE LOWER(TRIM(COALESCE(t.status, ''))) NOT IN ('completed', 'done', 'cancelled', 'closed')
         AND t.due_date IS NOT NULL AND t.due_date::date < (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')::date
         AND (CAST($1 AS uuid) IS NULL OR su.home_id = CAST($1 AS uuid))`,
      [h],
      'assurance-tasks-od'
    ),
    runCount(
      `SELECT COUNT(*)::int AS count FROM public.tasks t
       INNER JOIN public.service_users su ON su.id = t.service_user_id
       WHERE LOWER(TRIM(COALESCE(t.status, ''))) IN ('completed', 'done')
         AND COALESCE(t.updated_at, t.created_at) >= $1::timestamptz AND COALESCE(t.updated_at, t.created_at) < $2::timestamptz
         AND (CAST($3 AS uuid) IS NULL OR su.home_id = CAST($3 AS uuid))`,
      q3,
      'assurance-tasks-done'
    ),
    runCount(
      `SELECT COUNT(*)::int AS count FROM public.audit_logs
       WHERE occurred_at >= $1::timestamptz AND occurred_at < $2::timestamptz`,
      [fromTs, toTs],
      'assurance-audit-all'
    ),
    runCount(
      `SELECT COUNT(*)::int AS count FROM public.audit_logs
       WHERE occurred_at >= $1::timestamptz AND occurred_at < $2::timestamptz AND outcome <> 'SUCCESS'`,
      [fromTs, toTs],
      'assurance-audit-fail'
    ),
    runCount(
      `SELECT COUNT(*)::int AS count FROM public.audit_logs
       WHERE occurred_at >= $1::timestamptz AND occurred_at < $2::timestamptz AND action LIKE 'FAMILY_%'`,
      [fromTs, toTs],
      'assurance-audit-family'
    ),
    runCount(
      `SELECT COUNT(*)::int AS count FROM public.audit_logs
       WHERE occurred_at >= $1::timestamptz AND occurred_at < $2::timestamptz
         AND (action LIKE 'RESIDENT_%EXPORT%' OR action IN ('ANALYTICS_RESIDENT_ROSTER_EXPORT_CSV', 'ANALYTICS_ASSURANCE_PACK_EXPORT_CSV'))`,
      [fromTs, toTs],
      'assurance-audit-export'
    ),
    runCount(
      `SELECT COUNT(*)::int AS count FROM public.users
       WHERE is_active = true AND COALESCE(system_role, '') <> 'Family'
         AND (CAST($1 AS uuid) IS NULL OR home_scope_id IS NULL OR home_scope_id = CAST($1 AS uuid))`,
      [h],
      'assurance-staff'
    ),
    runCount(
      `SELECT COUNT(*)::int AS count FROM public.family_portal_access f
       INNER JOIN public.service_users su ON su.id = f.service_user_id
       WHERE (CAST($1 AS uuid) IS NULL OR su.home_id = CAST($1 AS uuid))`,
      [h],
      'assurance-fpa'
    ),
    (async () => {
      try {
        return await runCount(
          `SELECT COUNT(*)::int AS count FROM public.family_visit_requests v
           INNER JOIN public.service_users su ON su.id = v.service_user_id
           WHERE v.created_at >= $1::timestamptz AND v.created_at < $2::timestamptz
             AND (CAST($3 AS uuid) IS NULL OR su.home_id = CAST($3 AS uuid))`,
          q3,
          'assurance-fvr'
        );
      } catch (err) {
        if (err && err.code === '42P01') return null;
        logRequestError(req, err, 'assurance-fvr');
        return null;
      }
    })(),
  ]);

  let homeLabel = 'All homes (estate)';
  if (h) {
    try {
      const hn = await pool.query(`SELECT name FROM public.homes WHERE id = $1::uuid`, [h]);
      homeLabel = hn.rows[0]?.name ? String(hn.rows[0].name) : `Home ${h}`;
    } catch (e) {
      logRequestError(req, e, 'assurance-home-name');
      homeLabel = `Home ${h}`;
    }
  }

  const mk = (key, label, value, unit = 'count', hint = '') => ({ key, label, value, unit, hint });

  const domains = [
    {
      id: 'safe',
      title: 'Safe',
      cqcPrompt:
        'Evidence prompts: harm prevention, medicines governance, infection control, accidents, safeguarding culture (map local incidents to your SAB process).',
      indicators: [
        mk('observations_recorded', 'Structured observations recorded', observationsRecorded, 'count', 'Vitals and clinical observations in period.'),
        mk('tasks_open', 'Open tasks (current snapshot)', tasksOpen, 'count', 'Outstanding work items for residents in scope.'),
        mk('tasks_open_overdue', 'Open tasks past due date', tasksOpenOverdue, 'count', 'Review allocation and escalation.'),
        mk('documents_uploaded', 'Resident documents uploaded', documentsUploaded, 'count', 'Letters, MAR charts on file, etc.'),
      ],
    },
    {
      id: 'effective',
      title: 'Effective',
      cqcPrompt:
        'Evidence prompts: care outcomes, assessments, nutrition/hydration, clinical tasks completed, care planning currency.',
      indicators: [
        mk('assessments_created', 'Assessments recorded (period)', assessmentsCreated, 'count', 'Template-based assessments created.'),
        mk('care_plans_active', 'Active care plans (admitted residents)', carePlansActive, 'count', 'Snapshot — plans with status ACTIVE.'),
        mk('tasks_completed_period', 'Tasks completed (period)', tasksCompletedInPeriod, 'count', 'Requires tasks.updated_at or created_at.'),
      ],
    },
    {
      id: 'caring',
      title: 'Caring',
      cqcPrompt:
        'Evidence prompts: dignity, compassion, daily life engagement, involvement of people who use the service.',
      indicators: [
        mk('daily_notes_created', 'Daily notes created (period)', notesCreated, 'count', 'Includes all notes; triangulate with quality audits.'),
        mk('activities_recorded', 'Activity entries recorded (period)', activitiesRecorded, 'count', 'Social and meaningful activity.'),
      ],
    },
    {
      id: 'responsive',
      title: 'Responsive',
      cqcPrompt:
        'Evidence prompts: personalised care, complaints, end-of-life wishes, family partnership.',
      indicators: [
        mk('family_portal_links', 'Family portal access links (snapshot)', familyPortalLinks, 'count', 'Linked family user ↔ resident rows.'),
        mk(
          'family_visit_requests',
          'Family visit requests (period)',
          familyVisitRequests,
          'count',
          familyVisitRequests == null ? 'Requires migration 021_family_visit_requests.sql.' : ''
        ),
        mk('family_related_audit_events', 'Family-related audit events (period)', auditFamilyEvents, 'count', 'Feed views, invites, etc. (audit action prefix FAMILY_).'),
      ],
    },
    {
      id: 'well_led',
      title: 'Well-led',
      cqcPrompt:
        'Evidence prompts: governance, assurance, learning culture, oversight of access and exports.',
      indicators: [
        mk('audit_events_total', 'Audit log rows (period, system-wide)', auditRows, 'count', 'Includes all homes; filter exports by home in your SIEM if required.'),
        mk('audit_non_success', 'Audit rows with non-SUCCESS outcome', auditNonSuccess, 'count', 'Investigate failures and access denials.'),
        mk('resident_record_exports', 'Record / roster / assurance CSV export events (period)', auditResidentExports, 'count', 'Resident CSV exports, roster CSV, and CQC assurance pack CSV downloads.'),
        mk('staff_users_active', 'Active non-family user accounts (snapshot)', staffUsersActive, 'count', 'Scoped by home_scope_id when a home is selected.'),
      ],
    },
  ];

  return {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    period: { label, from: fromTs, to: toTs },
    home: { filterHomeId: h, label: homeLabel },
    disclaimer:
      'This assurance pack groups operational metrics under CQC quality statement themes (Safe, Effective, Caring, Responsive, Well-led) as evidence prompts for registered managers and governance leads. It does not predict inspection ratings, replace statutory notifications (CQC, safeguarding, etc.), or satisfy every Key Line of Enquiry. Use with professional judgement, local policies, and your Data Protection Impact Assessment.',
    domains,
  };
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

app.get('/api/v1/analytics/assurance-pack', requireRole(ROLES_RESIDENT_RECORD_EXPORT), async (req, res) => {
  try {
    const resolved = await resolveAnalyticsHomeFilter(req);
    if (!resolved.ok) return clientError(req, res, resolved.status, resolved.message);
    const period = computePeriodRange(req.query.period);
    const payload = await buildAssurancePackPayload(req, resolved.filterHomeId, period);
    await writeAuditLog(req, {
      action: 'ANALYTICS_ASSURANCE_PACK_VIEW',
      resourceType: 'analytics',
      resourceId: resolved.filterHomeId,
      metadata: { periodLabel: period.label, domainCount: payload.domains?.length ?? 0 },
    });
    res.json(payload);
  } catch (err) {
    logRequestError(req, err, 'analytics-assurance-pack');
    clientError(req, res, 500, 'Unable to build assurance pack.');
  }
});

app.get('/api/v1/analytics/assurance-pack.csv', requireRole(ROLES_RESIDENT_RECORD_EXPORT), async (req, res) => {
  try {
    const resolved = await resolveAnalyticsHomeFilter(req);
    if (!resolved.ok) return clientError(req, res, resolved.status, resolved.message);
    const period = computePeriodRange(req.query.period);
    const payload = await buildAssurancePackPayload(req, resolved.filterHomeId, period);

    const lines = ['\ufeff'];
    lines.push(csvLine(['section', 'field', 'value']));
    lines.push(csvLine(['meta', 'schemaVersion', String(payload.schemaVersion)]));
    lines.push(csvLine(['meta', 'generatedAt', payload.generatedAt]));
    lines.push(csvLine(['meta', 'periodLabel', payload.period.label]));
    lines.push(csvLine(['meta', 'periodFrom', payload.period.from]));
    lines.push(csvLine(['meta', 'periodTo', payload.period.to]));
    lines.push(csvLine(['meta', 'homeLabel', payload.home.label]));
    lines.push(csvLine(['meta', 'filterHomeId', payload.home.filterHomeId || '']));
    lines.push(csvLine(['meta', 'disclaimer', payload.disclaimer]));
    lines.push('');
    lines.push(csvLine(['domain_id', 'domain_title', 'indicator_key', 'indicator_label', 'value', 'unit', 'hint']));
    for (const d of payload.domains || []) {
      for (const ind of d.indicators || []) {
        const val = ind.value == null ? '' : String(ind.value);
        lines.push(
          csvLine([
            d.id,
            d.title,
            ind.key,
            ind.label,
            val,
            ind.unit || 'count',
            ind.hint || '',
          ])
        );
      }
    }

    const slug = resolved.filterHomeId ? String(resolved.filterHomeId).slice(0, 8) : 'estate';
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="cqc-assurance-pack-${slug}-${new Date().toISOString().slice(0, 10)}.csv"`
    );
    await writeAuditLog(req, {
      action: 'ANALYTICS_ASSURANCE_PACK_EXPORT_CSV',
      resourceType: 'analytics',
      resourceId: resolved.filterHomeId,
      metadata: { periodLabel: period.label, rowCount: lines.length },
    });
    res.status(200).send(lines.join('\n'));
  } catch (err) {
    logRequestError(req, err, 'analytics-assurance-pack-csv');
    clientError(req, res, 500, 'Unable to export assurance pack CSV.');
  }
});

// ---------------------------------------------------------------------------
// Analytics — per-home (or estate) resident roster CSV
// ---------------------------------------------------------------------------
app.get('/api/v1/analytics/residents-export.csv', requireRole(ROLES_RESIDENT_RECORD_EXPORT), async (req, res) => {
  try {
    const resolved = await resolveAnalyticsHomeFilter(req);
    if (!resolved.ok) return clientError(req, res, resolved.status, resolved.message);
    const filterHomeId = resolved.filterHomeId;

    const { rows } = await pool.query(
      `SELECT su.id, su.first_name, su.last_name, su.date_of_birth, su.nhs_number, su.status, su.legal_hold,
              su.profile_image_url,
              h.id AS home_id, h.name AS home_name, u.name AS unit_name, b.room_number
       FROM service_users su
       LEFT JOIN beds b ON su.current_bed_id = b.id
       LEFT JOIN units u ON b.unit_id = u.id
       LEFT JOIN homes h ON su.home_id = h.id
       WHERE su.status IN ('ADMITTED', 'DISCHARGED', 'PENDING')
         AND (CAST($1 AS uuid) IS NULL OR su.home_id = CAST($1 AS uuid))
       ORDER BY h.name NULLS LAST, su.last_name ASC NULLS LAST, su.first_name ASC NULLS LAST`,
      [filterHomeId]
    );

    const lines = ['\ufeff'];
    lines.push(
      csvLine([
        'service_user_id',
        'first_name',
        'last_name',
        'date_of_birth',
        'nhs_number',
        'status',
        'legal_hold',
        'home_id',
        'home_name',
        'unit_name',
        'room_number',
        'has_profile_photo',
      ])
    );
    for (const r of rows) {
      const hasPhoto = Boolean(r.profile_image_url && String(r.profile_image_url).trim());
      lines.push(
        csvLine([
          r.id,
          r.first_name,
          r.last_name,
          r.date_of_birth ? new Date(r.date_of_birth).toISOString().slice(0, 10) : '',
          r.nhs_number,
          r.status,
          r.legal_hold ? 'true' : 'false',
          r.home_id,
          r.home_name,
          r.unit_name,
          r.room_number,
          hasPhoto ? 'true' : 'false',
        ])
      );
    }
    const body = lines.join('');
    const slug = filterHomeId ? String(filterHomeId) : 'all-homes';
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="residents-roster-${slug}.csv"`);
    await writeAuditLog(req, {
      action: 'ANALYTICS_RESIDENT_ROSTER_EXPORT_CSV',
      resourceType: 'analytics',
      resourceId: filterHomeId,
      metadata: {
        rowCount: rows.length,
        homeScopeAll: filterHomeId == null,
      },
    });
    return res.status(200).send(body);
  } catch (err) {
    logRequestError(req, err, 'analytics-residents-export');
    clientError(req, res, 500, 'Unable to generate roster export.');
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
// RESIDENT CSV EXPORT (Chunk F)
// ---------------------------------------------------------------------------
app.get('/api/v1/residents/:id/export.csv', requireRole(ROLES_RESIDENT_RECORD_EXPORT), async (req, res) => {
  const { id } = req.params;
  const scope = userHomeScope(req);
  const typeRaw = typeof req.query?.type === 'string' ? req.query.type.trim().toLowerCase() : 'timeline';
  const exportType = typeRaw === 'documents' ? 'documents' : 'timeline';

  try {
    const scopeCheck = await pool.query(
      `SELECT id, first_name, last_name FROM service_users WHERE id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR home_id = CAST($2 AS uuid))`,
      [id, scope]
    );
    if (scopeCheck.rows.length === 0) {
      return clientError(req, res, 403, 'Access denied to this resident');
    }
    const rn = `${String(scopeCheck.rows[0].first_name || '').trim()} ${String(scopeCheck.rows[0].last_name || '').trim()}`.trim();

    if (exportType === 'documents') {
      let rows = [];
      try {
        const r = await pool.query(
          `SELECT d.id, d.file_name, d.mime_type, d.size_bytes, d.doc_type, d.uploaded_at, d.is_deleted
           FROM public.resident_documents d
           INNER JOIN service_users su ON su.id = d.service_user_id
           WHERE d.service_user_id = $1::uuid
             AND (CAST($2 AS uuid) IS NULL OR su.home_id = CAST($2 AS uuid))
           ORDER BY d.uploaded_at DESC`,
          [id, scope]
        );
        rows = r.rows || [];
      } catch (e) {
        if (e && typeof e === 'object' && ('code' in e || 'message' in e)) {
          const code = e.code;
          const msg = e.message || '';
          if (code === '42P01' || /resident_documents/i.test(String(msg))) {
            return clientError(
              req,
              res,
              503,
              'Resident documents export is not available yet (database migration not applied).'
            );
          }
        }
        throw e;
      }

      const lines = ['\ufeff'];
      lines.push(csvLine(['uploaded_at_utc', 'document_id', 'file_name', 'mime_type', 'size_bytes', 'doc_type', 'is_deleted']));
      for (const d of rows) {
        lines.push(
          csvLine([
            d.uploaded_at ? new Date(d.uploaded_at).toISOString() : '',
            d.id,
            d.file_name,
            d.mime_type,
            d.size_bytes,
            d.doc_type,
            d.is_deleted ? 'true' : 'false',
          ])
        );
      }
      const body = lines.join('');
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="resident-${id}-documents.csv"`);
      await writeAuditLog(req, {
        action: 'RESIDENT_EXPORT_CSV',
        resourceType: 'service_user',
        resourceId: id,
        metadata: { exportType: 'documents', rowCount: rows.length, residentNameChars: rn.length },
      });
      return res.status(200).send(body);
    }

    /** @type {Array<{ at: Date; category: string; ref: string; summary: string; details: string }>} */
    const events = [];

    const pushEvent = (atRaw, category, ref, summary, details) => {
      if (!atRaw) return;
      const at = atRaw instanceof Date ? atRaw : new Date(atRaw);
      if (Number.isNaN(at.getTime())) return;
      events.push({
        at,
        category,
        ref: ref != null ? String(ref) : '',
        summary: oneLine(summary).slice(0, 500),
        details: oneLine(details).slice(0, 1500),
      });
    };

    try {
      const tq = await pool.query(
        `SELECT t.id, t.title, t.status, t.priority, t.due_date, t.created_at
         FROM tasks t
         INNER JOIN service_users su ON su.id = t.service_user_id
         WHERE t.service_user_id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR su.home_id = CAST($2 AS uuid))`,
        [id, scope]
      );
      for (const t of tq.rows || []) {
        const at = t.created_at || (t.due_date ? `${String(t.due_date).slice(0, 10)}T12:00:00Z` : null);
        pushEvent(
          at,
          'task',
          t.id,
          `${t.title || 'Task'} (${t.status || ''})`,
          `priority=${t.priority || ''}; due_date=${t.due_date || ''}`
        );
      }
    } catch (e) {
      logRequestError(req, e, 'export-csv-tasks');
    }

    try {
      const nq = await pool.query(
        `SELECT dn.id, dn.created_at, dn.author_name, dn.note_text
         FROM daily_notes dn
         INNER JOIN service_users su ON su.id = dn.service_user_id
         WHERE dn.service_user_id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR su.home_id = CAST($2 AS uuid))`,
        [id, scope]
      );
      for (const n of nq.rows || []) {
        pushEvent(n.created_at, 'daily_note', n.id, `Note by ${n.author_name || 'Staff'}`, oneLine(n.note_text).slice(0, 800));
      }
    } catch (e) {
      logRequestError(req, e, 'export-csv-notes');
    }

    try {
      const oq = await pool.query(
        `SELECT o.id, o.recorded_at, o.observation_type, o.value, o.unit, o.notes
         FROM observations o
         INNER JOIN service_users su ON su.id = o.service_user_id
         WHERE o.service_user_id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR su.home_id = CAST($2 AS uuid))`,
        [id, scope]
      );
      for (const o of oq.rows || []) {
        pushEvent(
          o.recorded_at,
          'observation',
          o.id,
          `${o.observation_type || ''}: ${o.value || ''} ${o.unit || ''}`.trim(),
          oneLine(o.notes || '')
        );
      }
    } catch (e) {
      logRequestError(req, e, 'export-csv-obs');
    }

    try {
      const aq = await pool.query(
        `SELECT a.id, a.created_at, a.status, a.score, a.review_date, t.name AS template_name, t.version AS template_version
         FROM public.assessments a
         INNER JOIN service_users su ON su.id = a.service_user_id
         LEFT JOIN public.assessment_templates t ON t.id = a.template_id
         WHERE a.service_user_id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR su.home_id = CAST($2 AS uuid))`,
        [id, scope]
      );
      for (const a of aq.rows || []) {
        pushEvent(
          a.created_at,
          'assessment',
          a.id,
          `${a.template_name || 'Assessment'} v${a.template_version ?? ''} (${a.status || ''})`.trim(),
          `score=${a.score ?? ''}; review_date=${a.review_date || ''}`
        );
      }
    } catch (e) {
      logRequestError(req, e, 'export-csv-assessments');
    }

    try {
      const dq = await pool.query(
        `SELECT d.id, d.uploaded_at, d.file_name, d.mime_type, d.size_bytes, d.doc_type
         FROM public.resident_documents d
         INNER JOIN service_users su ON su.id = d.service_user_id
         WHERE d.service_user_id = $1::uuid
           AND d.is_deleted = false
           AND (CAST($2 AS uuid) IS NULL OR su.home_id = CAST($2 AS uuid))`,
        [id, scope]
      );
      for (const d of dq.rows || []) {
        pushEvent(
          d.uploaded_at,
          'document',
          d.id,
          `Document: ${d.file_name || ''}`,
          `mime=${d.mime_type || ''}; size_bytes=${d.size_bytes ?? ''}; doc_type=${d.doc_type || ''}`
        );
      }
    } catch (e) {
      logRequestError(req, e, 'export-csv-documents');
    }

    try {
      const fq = await pool.query(
        `SELECT fde.id, fde.created_at, fde.chart_date, fde.entry_type, fde.description, fde.amount_ml, fde.recorded_by
         FROM food_drink_entries fde
         INNER JOIN service_users su ON su.id = fde.service_user_id
         WHERE fde.service_user_id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR su.home_id = CAST($2 AS uuid))`,
        [id, scope]
      );
      for (const f of fq.rows || []) {
        pushEvent(
          f.created_at || f.chart_date,
          'food_drink',
          f.id,
          `${f.entry_type || ''}`,
          `chart_date=${f.chart_date || ''}; amount_ml=${f.amount_ml ?? ''}; desc=${oneLine(f.description).slice(0, 300)}; by=${f.recorded_by || ''}`
        );
      }
    } catch (e) {
      logRequestError(req, e, 'export-csv-food');
    }

    try {
      const actq = await pool.query(
        `SELECT ae.id, ae.created_at, ae.chart_date, ae.activity_type, ae.notes, ae.recorded_by
         FROM activity_entries ae
         INNER JOIN service_users su ON su.id = ae.service_user_id
         WHERE ae.service_user_id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR su.home_id = CAST($2 AS uuid))`,
        [id, scope]
      );
      for (const a of actq.rows || []) {
        pushEvent(
          a.created_at || a.chart_date,
          'activity',
          a.id,
          `${a.activity_type || 'Activity'}`,
          `chart_date=${a.chart_date || ''}; notes=${oneLine(a.notes).slice(0, 400)}; by=${a.recorded_by || ''}`
        );
      }
    } catch (e) {
      logRequestError(req, e, 'export-csv-activities');
    }

    try {
      const cq = await pool.query(
        `SELECT dce.id, dce.created_at, dce.chart_date, dce.care_item, dce.value, dce.notes, dce.recorded_by
         FROM daily_care_entries dce
         INNER JOIN service_users su ON su.id = dce.service_user_id
         WHERE dce.service_user_id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR su.home_id = CAST($2 AS uuid))`,
        [id, scope]
      );
      for (const c of cq.rows || []) {
        pushEvent(
          c.created_at || c.chart_date,
          'daily_care',
          c.id,
          `${c.care_item || 'Care'}: ${c.value || ''}`,
          `chart_date=${c.chart_date || ''}; notes=${oneLine(c.notes).slice(0, 400)}; by=${c.recorded_by || ''}`
        );
      }
    } catch (e) {
      logRequestError(req, e, 'export-csv-daily-care');
    }

    events.sort((a, b) => b.at.getTime() - a.at.getTime());

    const lines = ['\ufeff'];
    lines.push(
      csvLine([
        'occurred_at_utc',
        'category',
        'reference_id',
        'summary',
        'details',
        'service_user_id',
        'resident_name_hint',
      ])
    );
    for (const ev of events) {
      lines.push(
        csvLine([
          ev.at.toISOString(),
          ev.category,
          ev.ref,
          ev.summary,
          ev.details,
          id,
          rn,
        ])
      );
    }
    const body = lines.join('');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="resident-${id}-timeline.csv"`);
    await writeAuditLog(req, {
      action: 'RESIDENT_EXPORT_CSV',
      resourceType: 'service_user',
      resourceId: id,
      metadata: { exportType: 'timeline', rowCount: events.length, residentNameChars: rn.length },
    });
    return res.status(200).send(body);
  } catch (err) {
    logRequestError(req, err, 'resident-export-csv');
    clientError(req, res, 500, 'Unable to generate export.');
  }
});

/**
 * DCRS emergency / hospital transfer pack (standard v1).
 * Aligns with UK practice: identity, allergies, meds, recent vitals, PEEP, GP/NOK, advance care pointers.
 * Not a national NHS message schema — structured JSON/CSV for ambulance and acute handover.
 */
async function assembleEmergencyTransferPack(req, serviceUserId, scope) {
  const suq = await pool.query(
    `SELECT su.id, su.first_name, su.last_name, su.date_of_birth, su.nhs_number, su.status, su.legal_hold,
            su.known_allergies, su.gp_practice_name, su.gp_practice_phone,
            su.next_of_kin_name, su.next_of_kin_phone, su.next_of_kin_relationship,
            su.advance_care_notes,
            h.name AS home_name, h.id AS home_id, b.room_number, u.name AS unit_name
     FROM service_users su
     LEFT JOIN beds b ON su.current_bed_id = b.id
     LEFT JOIN units u ON b.unit_id = u.id
     LEFT JOIN homes h ON su.home_id = h.id
     WHERE su.id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR su.home_id = CAST($2 AS uuid))`,
    [serviceUserId, scope]
  );
  if (suq.rows.length === 0) {
    const err = new Error('NOT_FOUND');
    err.code = 'ENOTFOUND';
    throw err;
  }
  const su = suq.rows[0];

  const [medsRes, obsRes, plansRes, noteCountRes] = await Promise.all([
    pool.query(
      `SELECT m.id, m.name, m.dose, m.route, m.frequency, m.stock_count
       FROM medications m
       INNER JOIN service_users su2 ON su2.id = m.service_user_id
       WHERE m.service_user_id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR su2.home_id = CAST($2 AS uuid))
       ORDER BY m.name ASC NULLS LAST`,
      [serviceUserId, scope]
    ),
    pool.query(
      `SELECT o.id, o.observation_type, o.value, o.unit, o.recorded_at, o.recorded_by_name, o.notes
       FROM observations o
       INNER JOIN service_users su2 ON su2.id = o.service_user_id
       WHERE o.service_user_id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR su2.home_id = CAST($2 AS uuid))
       ORDER BY o.recorded_at DESC NULLS LAST
       LIMIT 25`,
      [serviceUserId, scope]
    ),
    pool.query(
      `SELECT cp.title, cp.status, cp.updated_at
       FROM care_plans cp
       INNER JOIN service_users su2 ON su2.id = cp.service_user_id
       WHERE cp.service_user_id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR su2.home_id = CAST($2 AS uuid))
         AND cp.status = 'ACTIVE'
       ORDER BY cp.updated_at DESC NULLS LAST
       LIMIT 8`,
      [serviceUserId, scope]
    ),
    pool.query(
      `SELECT COUNT(*)::int AS c FROM daily_notes dn
       INNER JOIN service_users su2 ON su2.id = dn.service_user_id
       WHERE dn.service_user_id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR su2.home_id = CAST($2 AS uuid))
         AND dn.created_at >= NOW() - INTERVAL '72 hours'`,
      [serviceUserId, scope]
    ),
  ]);

  let peep = null;
  try {
    const peepRes = await pool.query(
      `SELECT mobility, assistance_required, evacuation_method, communication_needs, equipment_required, key_risks, route_and_refuge, other_notes, review_date, updated_at
       FROM peep_documents WHERE service_user_id = $1::uuid`,
      [serviceUserId]
    );
    if (peepRes.rows && peepRes.rows.length > 0) {
      const p = peepRes.rows[0];
      peep = {
        mobility: p.mobility,
        assistanceRequired: p.assistance_required,
        evacuationMethod: p.evacuation_method,
        communicationNeeds: p.communication_needs,
        equipmentRequired: p.equipment_required,
        keyRisks: p.key_risks,
        routeAndRefuge: p.route_and_refuge,
        otherNotes: p.other_notes,
        reviewDate: p.review_date,
        updatedAt: p.updated_at,
      };
    }
  } catch (e) {
    const code = e && typeof e === 'object' ? e.code : null;
    const msg = e && typeof e === 'object' ? String(e.message || '') : '';
    if (code !== '42P01' && !/peep_documents/i.test(msg)) {
      logRequestError(req, e, 'emergency-transfer-pack-peep');
    }
  }

  const medications = (medsRes.rows || []).map((m) => ({
    id: m.id,
    name: m.name,
    dose: m.dose,
    route: m.route,
    frequency: m.frequency,
    stockCount: m.stock_count,
  }));

  const recentObservations = (obsRes.rows || []).map((o) => ({
    id: o.id,
    type: o.observation_type,
    value: o.value,
    unit: o.unit,
    recordedAt: o.recorded_at ? new Date(o.recorded_at).toISOString() : null,
    recordedBy: o.recorded_by_name || null,
    notes: o.notes ? oneLine(o.notes).slice(0, 500) : null,
  }));

  const activeCarePlans = (plansRes.rows || []).map((r) => ({
    title: r.title,
    status: r.status,
    updatedAt: r.updated_at ? new Date(r.updated_at).toISOString() : null,
  }));

  return {
    standardId: 'dcrs.emergencyTransferPack',
    standardVersion: 1,
    generatedAt: new Date().toISOString(),
    disclaimer:
      'DCRS emergency transfer pack v1: operational handover aid for UK social care. Not a substitute for NHS e-Referral, ambulance ePRF, or trust-specific acute documentation. Verify medications and allergies against the original MAR and clinical records before transfer. Advance care information is indicative only — follow local policy and statutory forms (e.g. RESPECT, DNACPR) held on file.',
    identity: {
      serviceUserId: su.id,
      givenName: su.first_name,
      familyName: su.last_name,
      dateOfBirth: su.date_of_birth ? new Date(su.date_of_birth).toISOString().slice(0, 10) : null,
      nhsNumber: su.nhs_number || null,
      legalHold: Boolean(su.legal_hold),
      residentStatus: su.status,
      careHomeName: su.home_name || null,
      homeId: su.home_id || null,
      roomNumber: su.room_number || null,
      unitName: su.unit_name || null,
    },
    allergiesAndAlerts: {
      knownAllergies: su.known_allergies ? String(su.known_allergies).trim() : null,
    },
    medications,
    recentObservations,
    carePlanning: {
      activeCarePlans,
    },
    mobilityAndEvacuation: {
      peep,
    },
    contacts: {
      gpPracticeName: su.gp_practice_name ? String(su.gp_practice_name).trim() : null,
      gpPracticePhone: su.gp_practice_phone ? String(su.gp_practice_phone).trim() : null,
      nextOfKinName: su.next_of_kin_name ? String(su.next_of_kin_name).trim() : null,
      nextOfKinPhone: su.next_of_kin_phone ? String(su.next_of_kin_phone).trim() : null,
      nextOfKinRelationship: su.next_of_kin_relationship ? String(su.next_of_kin_relationship).trim() : null,
    },
    advanceCare: {
      notes: su.advance_care_notes ? String(su.advance_care_notes).trim() : null,
    },
    communicationAndHandover: {
      dailyNotesRecordedLast72h: noteCountRes.rows[0]?.c ?? 0,
    },
  };
}

function flattenEmergencyTransferPackToCsvRows(pack) {
  const rows = [];
  const meta = (field, value) => rows.push(['meta', field, value == null ? '' : String(value)]);
  meta('standardId', pack.standardId);
  meta('standardVersion', pack.standardVersion);
  meta('generatedAt', pack.generatedAt);
  meta('disclaimer', pack.disclaimer);
  const walk = (prefix, obj) => {
    if (obj == null) return;
    if (Array.isArray(obj)) {
      obj.forEach((item, i) => {
        if (item && typeof item === 'object') walk(`${prefix}[${i}]`, item);
        else rows.push(['data', `${prefix}[${i}]`, item == null ? '' : String(item)]);
      });
      return;
    }
    if (typeof obj === 'object') {
      for (const [k, v] of Object.entries(obj)) {
        const p = prefix ? `${prefix}.${k}` : k;
        if (v == null) rows.push(['data', p, '']);
        else if (typeof v === 'object') walk(p, v);
        else rows.push(['data', p, String(v)]);
      }
    }
  };
  walk('identity', pack.identity);
  walk('allergiesAndAlerts', pack.allergiesAndAlerts);
  walk('medications', pack.medications);
  walk('recentObservations', pack.recentObservations);
  walk('carePlanning', pack.carePlanning);
  walk('mobilityAndEvacuation', pack.mobilityAndEvacuation);
  walk('contacts', pack.contacts);
  walk('advanceCare', pack.advanceCare);
  walk('communicationAndHandover', pack.communicationAndHandover);
  return rows;
}

app.get(
  '/api/v1/residents/:id/emergency-transfer-pack',
  requireRole(ROLES_RESIDENT_AND_FACILITY_READ),
  async (req, res) => {
    const { id } = req.params;
    const scope = userHomeScope(req);
    try {
      const pack = await assembleEmergencyTransferPack(req, id, scope);
      await writeAuditLog(req, {
        action: 'EMERGENCY_TRANSFER_PACK_VIEW',
        resourceType: 'service_user',
        resourceId: id,
        metadata: {
          medCount: pack.medications?.length ?? 0,
          obsCount: pack.recentObservations?.length ?? 0,
          hasPeep: Boolean(pack.mobilityAndEvacuation?.peep),
        },
      });
      res.json(pack);
    } catch (err) {
      if (err && err.code === '42703') {
        return clientError(
          req,
          res,
          503,
          'Emergency transfer profile requires database migration 022_emergency_transfer_profile.sql to be applied.'
        );
      }
      if (err && err.code === 'ENOTFOUND') {
        return clientError(req, res, 404, 'Resident not found or access denied.');
      }
      logRequestError(req, err, 'emergency-transfer-pack');
      clientError(req, res, 500, 'Unable to build emergency transfer pack.');
    }
  }
);

app.get(
  '/api/v1/residents/:id/emergency-transfer-pack.csv',
  requireRole(ROLES_RESIDENT_AND_FACILITY_READ),
  async (req, res) => {
    const { id } = req.params;
    const scope = userHomeScope(req);
    try {
      const pack = await assembleEmergencyTransferPack(req, id, scope);
      const lines = ['\ufeff'];
      lines.push(csvLine(['row_type', 'field_path', 'value']));
      for (const r of flattenEmergencyTransferPackToCsvRows(pack)) {
        lines.push(csvLine(r));
      }
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="emergency-transfer-pack-${id}-${new Date().toISOString().slice(0, 10)}.csv"`
      );
      await writeAuditLog(req, {
        action: 'EMERGENCY_TRANSFER_PACK_EXPORT_CSV',
        resourceType: 'service_user',
        resourceId: id,
        metadata: { csvLineCount: lines.length },
      });
      res.status(200).send(lines.join('\n'));
    } catch (err) {
      if (err && err.code === '42703') {
        return clientError(
          req,
          res,
          503,
          'Emergency transfer profile requires database migration 022_emergency_transfer_profile.sql to be applied.'
        );
      }
      if (err && err.code === 'ENOTFOUND') {
        return clientError(req, res, 404, 'Resident not found or access denied.');
      }
      logRequestError(req, err, 'emergency-transfer-pack-csv');
      clientError(req, res, 500, 'Unable to export emergency transfer pack CSV.');
    }
  }
);

app.patch(
  '/api/v1/residents/:id/emergency-transfer-profile',
  requireRole(ROLES_EMERGENCY_TRANSFER_PROFILE_WRITE),
  async (req, res) => {
    const { id } = req.params;
    const scope = userHomeScope(req);
    const body = req.body || {};
    const trimStr = (v, max) => {
      if (v === undefined) return undefined;
      if (v === null) return null;
      if (typeof v !== 'string') return undefined;
      return v.trim().slice(0, max);
    };

    const map = {
      knownAllergies: { col: 'known_allergies', max: 4000 },
      gpPracticeName: { col: 'gp_practice_name', max: 500 },
      gpPracticePhone: { col: 'gp_practice_phone', max: 80 },
      nextOfKinName: { col: 'next_of_kin_name', max: 200 },
      nextOfKinPhone: { col: 'next_of_kin_phone', max: 80 },
      nextOfKinRelationship: { col: 'next_of_kin_relationship', max: 120 },
      advanceCareNotes: { col: 'advance_care_notes', max: 4000 },
    };

    const sets = [];
    const vals = [];
    let i = 1;
    for (const [key, { col, max }] of Object.entries(map)) {
      if (!Object.prototype.hasOwnProperty.call(body, key)) continue;
      const t = trimStr(body[key], max);
      if (t === undefined) continue;
      sets.push(`${col} = $${i++}`);
      vals.push(t);
    }
    if (sets.length === 0) {
      return clientError(
        req,
        res,
        400,
        'Provide at least one of: knownAllergies, gpPracticeName, gpPracticePhone, nextOfKinName, nextOfKinPhone, nextOfKinRelationship, advanceCareNotes (strings or null).'
      );
    }

    vals.push(id, scope);
    try {
      const up = await pool.query(
        `UPDATE service_users su SET ${sets.join(', ')}
         WHERE su.id = $${i}::uuid AND (CAST($${i + 1} AS uuid) IS NULL OR su.home_id = CAST($${i + 1} AS uuid))
         RETURNING su.id, su.known_allergies, su.gp_practice_name, su.gp_practice_phone,
                   su.next_of_kin_name, su.next_of_kin_phone, su.next_of_kin_relationship, su.advance_care_notes`,
        vals
      );
      if (up.rows.length === 0) {
        return clientError(req, res, 403, 'Resident not found or access denied.');
      }
      const r = up.rows[0];
      await writeAuditLog(req, {
        action: 'EMERGENCY_TRANSFER_PROFILE_UPDATE',
        resourceType: 'service_user',
        resourceId: id,
        metadata: { fieldsUpdated: sets.length },
      });
      res.json({
        success: true,
        emergencyTransferProfile: {
          knownAllergies: r.known_allergies,
          gpPracticeName: r.gp_practice_name,
          gpPracticePhone: r.gp_practice_phone,
          nextOfKinName: r.next_of_kin_name,
          nextOfKinPhone: r.next_of_kin_phone,
          nextOfKinRelationship: r.next_of_kin_relationship,
          advanceCareNotes: r.advance_care_notes,
        },
      });
    } catch (err) {
      if (err && err.code === '42703') {
        return clientError(
          req,
          res,
          503,
          'Emergency transfer profile requires database migration 022_emergency_transfer_profile.sql to be applied.'
        );
      }
      logRequestError(req, err, 'emergency-transfer-profile-patch');
      clientError(req, res, 500, 'Could not update emergency transfer profile.');
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
    const residentQueryBase = `
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
    const residentQueryWithEmergency = `
      SELECT 
        su.id, su.first_name, su.last_name, su.date_of_birth, su.nhs_number, su.status, su.legal_hold,
        su.profile_image_url,
        su.known_allergies, su.gp_practice_name, su.gp_practice_phone,
        su.next_of_kin_name, su.next_of_kin_phone, su.next_of_kin_relationship,
        su.advance_care_notes,
        b.room_number, u.name as unit_name, h.name as home_name
      FROM service_users su
      LEFT JOIN beds b ON su.current_bed_id = b.id
      LEFT JOIN units u ON b.unit_id = u.id
      LEFT JOIN homes h ON su.home_id = h.id
      WHERE su.id = $1 AND (CAST($2 AS uuid) IS NULL OR su.home_id = CAST($2 AS uuid))
    `;

    let residentResult;
    try {
      residentResult = await pool.query(residentQueryWithEmergency, [id, scope]);
    } catch (firstErr) {
      if (firstErr && firstErr.code === '42703') {
        residentResult = await pool.query(residentQueryBase, [id, scope]);
        if (residentResult.rows[0]) {
          Object.assign(residentResult.rows[0], {
            known_allergies: null,
            gp_practice_name: null,
            gp_practice_phone: null,
            next_of_kin_name: null,
            next_of_kin_phone: null,
            next_of_kin_relationship: null,
            advance_care_notes: null,
          });
        }
      } else {
        throw firstErr;
      }
    }

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
      ORDER BY
        CASE WHEN lower(trim(coalesce(t.status, ''))) IN ('completed', 'done') THEN 1 ELSE 0 END,
        t.due_date ASC NULLS LAST`;
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

    // Load child tables independently so a missing migration on one chart (e.g. observations)
    // does not 500 the entire clinical record.
    const childTags = ['tasks', 'notes', 'medications', 'observations'];
    const settled = await Promise.allSettled([
      pool.query(tasksQuery, [id, scope]),
      pool.query(notesQuery, [id, scope]),
      pool.query(medsQuery, [id, scope]),
      pool.query(obsQuery, [id, scope]),
    ]);
    const rowsAt = (i) => {
      const r = settled[i];
      if (r.status === 'fulfilled') return r.value.rows || [];
      logRequestError(req, r.reason, `resident-detail-${childTags[i]}`);
      return [];
    };

    const taskRows = rowsAt(0);
    const assignIds = filterValidUuidList(taskRows.map((r) => r.assigned_to));
    let assignNameById = {};
    if (assignIds.length) {
      try {
        const an = await pool.query(
          `SELECT id, first_name, last_name FROM users WHERE id = ANY($1::uuid[])`,
          [assignIds]
        );
        assignNameById = Object.fromEntries(
          an.rows.map((u) => [String(u.id), { first_name: u.first_name, last_name: u.last_name }])
        );
      } catch (e) {
        logRequestError(req, e, 'resident-task-assignees');
      }
    }
    resident.tasks = taskRows.map((r) => {
      const aid = r.assigned_to ? String(r.assigned_to) : null;
      const nm = aid ? assignNameById[aid] : null;
      return normalizeTaskRow(
        nm ? { ...r, assigned_first_name: nm.first_name, assigned_last_name: nm.last_name } : r
      );
    });
    resident.dailyNotes = rowsAt(1).map((n) => ({
      id: n.id,
      text: n.note_text != null ? String(n.note_text) : '',
      time: n.created_at
        ? new Date(n.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        : '',
      author: n.author_name || 'Staff',
      shareWithFamily: Boolean(n.share_with_family),
    }));
    resident.medications = rowsAt(2).map((m) => ({
      id: m.id,
      name: m.name != null ? String(m.name) : '',
      dose: m.dose != null ? String(m.dose) : '',
      frequency: m.frequency != null ? String(m.frequency) : '',
      route: m.route != null ? String(m.route) : '',
      stockCount: Number(m.stock_count != null ? m.stock_count : 0) || 0,
    }));
    resident.observations = rowsAt(3).map((o) => mapObservationRow(o));
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

app.post('/api/v1/residents/:id/daily-notes', requireRole(ROLES_RESIDENT_AND_FACILITY_READ), async (req, res) => {
  const { id } = req.params;
  const scope = userHomeScope(req);
  const body = req.body || {};
  const text = typeof body.text === 'string' ? body.text.trim() : '';
  const shareWithFamily = Boolean(body.shareWithFamily);

  if (!text) {
    return clientError(req, res, 400, 'text is required.');
  }
  if (text.length > 20000) {
    return clientError(req, res, 400, 'text is too long.');
  }

  try {
    const scopeCheck = await pool.query(
      `SELECT id FROM service_users WHERE id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR home_id = CAST($2 AS uuid))`,
      [id, scope]
    );
    if (scopeCheck.rows.length === 0) {
      return clientError(req, res, 403, 'Access denied to this resident');
    }

    const dbAuthorName = req.dbUser
      ? `${req.dbUser.first_name || ''} ${req.dbUser.last_name || ''}`.trim() || req.dbUser.email
      : 'Staff';

    const ins = await pool.query(
      `INSERT INTO daily_notes (service_user_id, note_text, author_name, share_with_family)
       VALUES ($1::uuid, $2, $3, $4)
       RETURNING id, note_text, author_name, created_at, share_with_family`,
      [id, text, dbAuthorName, shareWithFamily]
    );
    const row = ins.rows[0];
    await writeAuditLog(req, {
      action: 'DAILY_NOTE_CREATE',
      resourceType: 'daily_note',
      resourceId: row?.id ?? null,
      metadata: { serviceUserId: id, shareWithFamily },
    });
    res.status(201).json({
      note: {
        id: row.id,
        text: row.note_text,
        time: new Date(row.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        author: row.author_name || 'Staff',
        shareWithFamily: Boolean(row.share_with_family),
      },
    });
  } catch (err) {
    if (err && err.code === '42703') {
      return clientError(
        req,
        res,
        503,
        'Daily notes sharing requires migration 020_family_portal.sql (share_with_family column).'
      );
    }
    logRequestError(req, err, 'daily-note-create');
    clientError(req, res, 500, 'Could not save note.');
  }
});

app.patch('/api/v1/residents/:id/daily-notes/:noteId', requireRole(ROLES_RESIDENT_AND_FACILITY_READ), async (req, res) => {
  const { id, noteId } = req.params;
  const scope = userHomeScope(req);
  const shareWithFamily = req.body?.shareWithFamily;
  if (typeof shareWithFamily !== 'boolean') {
    return clientError(req, res, 400, 'shareWithFamily boolean is required.');
  }

  try {
    const up = await pool.query(
      `UPDATE daily_notes dn
       SET share_with_family = $4
       FROM service_users su
       WHERE dn.id = $2::uuid
         AND dn.service_user_id = $1::uuid
         AND su.id = dn.service_user_id
         AND (CAST($3 AS uuid) IS NULL OR su.home_id = CAST($3 AS uuid))
       RETURNING dn.id, dn.note_text, dn.author_name, dn.created_at, dn.share_with_family`,
      [id, noteId, scope, shareWithFamily]
    );
    if (up.rows.length === 0) {
      return clientError(req, res, 404, 'Note not found or access denied.');
    }
    const row = up.rows[0];
    await writeAuditLog(req, {
      action: 'DAILY_NOTE_FAMILY_SHARE_UPDATE',
      resourceType: 'daily_note',
      resourceId: noteId,
      metadata: { serviceUserId: id, shareWithFamily },
    });
    res.json({
      note: {
        id: row.id,
        text: row.note_text,
        time: new Date(row.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        author: row.author_name || 'Staff',
        shareWithFamily: Boolean(row.share_with_family),
      },
    });
  } catch (err) {
    if (err && err.code === '42703') {
      return clientError(
        req,
        res,
        503,
        'Daily notes sharing requires migration 020_family_portal.sql (share_with_family column).'
      );
    }
    logRequestError(req, err, 'daily-note-patch');
    clientError(req, res, 500, 'Could not update note.');
  }
});

app.post(
  '/api/v1/residents/:id/family-invite',
  inviteLimiter,
  requireRole(ROLES_FAMILY_INVITE_SENDERS),
  async (req, res) => {
    const { id } = req.params;
    const scope = userHomeScope(req);
    const body = req.body || {};
    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
    const firstName = typeof body.firstName === 'string' ? body.firstName.trim() : '';
    const lastName = typeof body.lastName === 'string' ? body.lastName.trim() : '';
    const relationship =
      typeof body.relationship === 'string' ? body.relationship.trim().slice(0, 120) : '';

    if (!email) {
      return clientError(req, res, 400, 'email is required.');
    }

    try {
      const su = await pool.query(
        `SELECT id, home_id FROM service_users WHERE id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR home_id = CAST($2 AS uuid))`,
        [id, scope]
      );
      if (su.rows.length === 0) {
        return clientError(req, res, 403, 'Resident not found or outside your scope.');
      }
      const residentHomeId = su.rows[0].home_id;

      const existing = await pool.query(
        `SELECT id, system_role FROM users WHERE lower(trim(email)) = lower(trim($1))`,
        [email]
      );

      if (existing.rows.length > 0) {
        const u = existing.rows[0];
        if (u.system_role !== 'Family') {
          return clientError(
            req,
            res,
            409,
            'That email is already used for a staff-type login. Family contacts need a separate personal email.'
          );
        }
        await pool.query(
          `INSERT INTO family_portal_access (user_id, service_user_id, relationship)
           VALUES ($1::uuid, $2::uuid, NULLIF($3, ''))
           ON CONFLICT (user_id, service_user_id) DO UPDATE SET relationship = EXCLUDED.relationship`,
          [u.id, id, relationship]
        );
        await writeAuditLog(req, {
          action: 'FAMILY_PORTAL_LINK_EXISTING_USER',
          resourceType: 'service_user',
          resourceId: id,
          metadata: { targetEmail: email },
        });
        return res.json({
          success: true,
          linkedExisting: true,
          message: 'That person already has a family account. They can now see this resident on the family portal.',
        });
      }

      if (!supabaseAdmin) {
        return clientError(req, res, 500, 'Server misconfiguration. Contact support.');
      }

      const appOrigin = (process.env.FRONTEND_URL || 'http://localhost:3000').replace(/\/$/, '');
      const inviteRedirectTo = `${appOrigin}/auth/callback`;

      const { data, error } = await supabaseAdmin.auth.admin.inviteUserByEmail(email, {
        redirectTo: inviteRedirectTo,
        data: {
          full_name: `${firstName} ${lastName}`.trim(),
          role: 'Family',
          home_scope_id: residentHomeId,
        },
      });

      if (error) throw error;

      const ins = await pool.query(
        `INSERT INTO users (email, password_hash, first_name, last_name, system_role, home_scope_id, is_active)
         VALUES ($1, 'invite_pending', $2, $3, 'Family', $4::uuid, true)
         RETURNING id`,
        [email, firstName, lastName, residentHomeId]
      );
      const newUserId = ins.rows[0]?.id;
      if (!newUserId) {
        throw new Error('Failed to provision family user row');
      }

      await pool.query(
        `INSERT INTO family_portal_access (user_id, service_user_id, relationship)
         VALUES ($1::uuid, $2::uuid, NULLIF($3, ''))
         ON CONFLICT (user_id, service_user_id) DO UPDATE SET relationship = EXCLUDED.relationship`,
        [newUserId, id, relationship]
      );

      await writeAuditLog(req, {
        action: 'FAMILY_CONTACT_INVITE_SENT',
        resourceType: 'service_user',
        resourceId: id,
        metadata: { targetEmail: email },
      });

      res.status(201).json({
        success: true,
        linkedExisting: false,
        user: data?.user ?? null,
        message: 'Invitation email sent. They should use the link to set a password, then sign in at the family portal.',
      });
    } catch (err) {
      if (err && err.code === '42P01') {
        return clientError(
          req,
          res,
          503,
          'Family portal is not available until database migration 020_family_portal.sql is applied.'
        );
      }
      logRequestError(req, err, 'resident-family-invite');
      clientError(req, res, 500, 'Unable to send family invitation. Try again or contact support.');
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
        [residentId, title, 'Open', normalizeTaskPriorityForDb(priority), dueDate]
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
// OBSERVATIONS (SCOPED) — Chunk E
// ---------------------------------------------------------------------------

app.get('/api/v1/residents/:id/observations', requireRole(ROLES_RESIDENT_AND_FACILITY_READ), async (req, res) => {
  const { id } = req.params;
  const scope = userHomeScope(req);
  const sinceRaw = typeof req.query?.since === 'string' ? req.query.since.trim() : '';
  let since = null;
  if (sinceRaw) {
    const d = new Date(sinceRaw);
    if (Number.isNaN(d.getTime())) return clientError(req, res, 400, 'since must be a valid ISO date/time.');
    since = d.toISOString();
  }

  try {
    const { rows } = await pool.query(
      `SELECT o.*
       FROM observations o
       INNER JOIN service_users su ON su.id = o.service_user_id
       WHERE o.service_user_id = $1::uuid
         AND (CAST($2 AS uuid) IS NULL OR su.home_id = CAST($2 AS uuid))
         AND ($3::timestamptz IS NULL OR o.recorded_at >= $3::timestamptz)
       ORDER BY o.recorded_at DESC
       LIMIT 2000`,
      [id, scope, since]
    );
    await writeAuditLog(req, {
      action: 'OBSERVATIONS_LIST_VIEW',
      resourceType: 'service_user',
      resourceId: id,
      metadata: { resultCount: rows.length, hasSince: Boolean(since) },
    });
    res.json({ observations: rows.map((r) => mapObservationRow(r)) });
  } catch (err) {
    if (err && typeof err === 'object' && ('code' in err || 'message' in err)) {
      const code = err.code;
      const msg = err.message || '';
      if (code === '42P01' || /observations/i.test(String(msg))) {
        return clientError(
          req,
          res,
          503,
          'Observations are not available yet (database table missing). Create the observations table in Supabase and retry.'
        );
      }
    }
    logRequestError(req, err, 'observations-list');
    clientError(req, res, 500, 'Unable to load observations.');
  }
});

app.get(
  '/api/v1/residents/:id/observations/summary',
  requireRole(ROLES_RESIDENT_AND_FACILITY_READ),
  async (req, res) => {
    const { id } = req.params;
    const scope = userHomeScope(req);
    try {
      const { rows } = await pool.query(
        `SELECT DISTINCT ON (o.observation_type) o.*
         FROM observations o
         INNER JOIN service_users su ON su.id = o.service_user_id
         WHERE o.service_user_id = $1::uuid
           AND (CAST($2 AS uuid) IS NULL OR su.home_id = CAST($2 AS uuid))
         ORDER BY o.observation_type, o.recorded_at DESC`,
        [id, scope]
      );
      res.json({ latestByType: rows.map((r) => mapObservationRow(r)) });
    } catch (err) {
      logRequestError(req, err, 'observations-summary');
      clientError(req, res, 500, 'Unable to load observation summary.');
    }
  }
);

app.post('/api/v1/residents/:id/observations', requireRole(ROLES_OBSERVATIONS_WRITE), async (req, res) => {
  const { id } = req.params;
  const scope = userHomeScope(req);
  const body = req.body || {};
  const typeRaw = body.observationType ?? body.observation_type ?? body.type ?? '';
  const typeCode = normalizeObservationTypeCode(String(typeRaw));
  const valueRaw = body.value ?? body.value_text ?? '';
  const value = typeof valueRaw === 'string' ? valueRaw.trim() : String(valueRaw ?? '').trim();
  const unitRaw = body.unit != null && body.unit !== '' ? String(body.unit).trim() : defaultUnitForObservationCode(typeCode);
  const notesRaw = body.notes != null ? String(body.notes).trim() : '';
  const notes = notesRaw.length > 2000 ? notesRaw.slice(0, 2000) : notesRaw;
  const recordedAtRaw = body.recordedAt ?? body.recorded_at ?? null;
  let recordedAt = null;
  if (recordedAtRaw) {
    const d = new Date(String(recordedAtRaw));
    if (Number.isNaN(d.getTime())) return clientError(req, res, 400, 'recordedAt must be a valid ISO date/time.');
    recordedAt = d.toISOString();
  }

  if (!typeCode) {
    return clientError(req, res, 400, 'type is required (e.g. Blood Pressure, BP, Temperature).');
  }
  if (!value) return clientError(req, res, 400, 'value is required.');

  const recordedByName =
    (req.dbUser?.first_name || req.dbUser?.last_name)
      ? `${req.dbUser?.first_name || ''} ${req.dbUser?.last_name || ''}`.trim()
      : (req.dbUser?.email ?? req.user?.email ?? 'Staff');

  async function tryInsertObservation(includeNotes) {
    if (includeNotes) {
      return pool.query(
        `INSERT INTO observations (service_user_id, observation_type, value, unit, recorded_at, recorded_by_name, notes)
         SELECT $1::uuid, $2, $3, $4, COALESCE($5::timestamptz, now()), $6, $7
         FROM service_users su
         WHERE su.id = $1::uuid AND (CAST($8 AS uuid) IS NULL OR su.home_id = CAST($8 AS uuid))
         RETURNING *`,
        [id, typeCode, value, unitRaw || null, recordedAt, recordedByName, notes || null, scope]
      );
    }
    return pool.query(
      `INSERT INTO observations (service_user_id, observation_type, value, unit, recorded_at, recorded_by_name)
       SELECT $1::uuid, $2, $3, $4, COALESCE($5::timestamptz, now()), $6
       FROM service_users su
       WHERE su.id = $1::uuid AND (CAST($7 AS uuid) IS NULL OR su.home_id = CAST($7 AS uuid))
       RETURNING *`,
      [id, typeCode, value, unitRaw || null, recordedAt, recordedByName, scope]
    );
  }

  try {
    let ins;
    if (notes) {
      try {
        ins = await tryInsertObservation(true);
      } catch (e1) {
        const code = e1 && typeof e1 === 'object' ? e1.code : null;
        const msg = e1 && typeof e1 === 'object' ? String(e1.message || '') : '';
        if (code === '42703' || /notes/i.test(msg)) ins = await tryInsertObservation(false);
        else throw e1;
      }
    } else {
      ins = await tryInsertObservation(false);
    }

    if (ins.rows.length === 0) {
      return clientError(req, res, 403, 'Access denied to this resident');
    }

    const row = ins.rows[0];
    await writeAuditLog(req, {
      action: 'OBSERVATION_CREATE',
      resourceType: 'observation',
      resourceId: row?.id ?? null,
      metadata: { serviceUserId: id, observationType: typeCode, valueChars: value.length, hasNotes: Boolean(notes) },
    });

    res.status(201).json({ success: true, observation: mapObservationRow(row) });
  } catch (err) {
    logRequestError(req, err, 'observation-create');
    clientError(req, res, 500, 'Could not save observation.');
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
    const hasAssignOnCreate =
      Object.prototype.hasOwnProperty.call(body, 'assigned_to') ||
      Object.prototype.hasOwnProperty.call(body, 'assignedTo');
    let assignedTo = null;
    if (hasAssignOnCreate) {
      if (!ROLES_TASK_ASSIGN.includes(req.dbUser?.system_role)) {
        return clientError(req, res, 403, 'You do not have permission to assign tasks.');
      }
      const rawAssign = body.assigned_to ?? body.assignedTo;
      if (rawAssign !== null && rawAssign !== undefined && String(rawAssign).trim() !== '') {
        const sid = String(rawAssign).trim();
        if (!/^[0-9a-f-]{36}$/i.test(sid)) return clientError(req, res, 400, 'assigned_to must be a UUID.');
        assignedTo = sid;
      }
    }

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
        `SELECT id, home_id FROM service_users WHERE id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR home_id = CAST($2 AS uuid))`,
        [id, scope]
      );
      if (scopeCheck.rows.length === 0) {
        return clientError(req, res, 403, 'Access denied to this resident');
      }
      const residentHomeId = scopeCheck.rows[0].home_id ?? null;

      if (assignedTo) {
        const ures = await pool.query(`SELECT id, home_scope_id FROM users WHERE id = $1::uuid`, [assignedTo]);
        if (ures.rows.length === 0) return clientError(req, res, 400, 'Assignee not found.');
        const ah = ures.rows[0].home_scope_id;
        if (ah != null && residentHomeId != null && String(ah) !== String(residentHomeId)) {
          return clientError(req, res, 403, 'Assignee is not in the same home as this service user.');
        }
      }

      // Insert into tasks table. Column names may vary across environments; try common DCRS schema.
      // Expected columns: id uuid, service_user_id uuid, title text, status text, priority text, due_date timestamptz/date, created_at timestamptz
      let ins;
      try {
        ins = await pool.query(
          `INSERT INTO tasks (service_user_id, title, status, priority, due_date, assigned_to)
           VALUES ($1::uuid, $2, $3, $4, $5, $6)
           RETURNING *`,
          [id, title, 'Open', normalizeTaskPriorityForDb(priority), dueDate, assignedTo]
        );
      } catch (eIns) {
        const code = eIns && typeof eIns === 'object' ? eIns.code : null;
        const msg = eIns && typeof eIns === 'object' ? String(eIns.message || '') : '';
        const missingAssignCol = code === '42703' || /assigned_to/i.test(msg);
        if (missingAssignCol && assignedTo) {
          return clientError(
            req,
            res,
            503,
            'Task assignee column is not available yet (database migration not applied). Run backend/sql/018_tasks_assigned_priority_index.sql in Supabase and retry.'
          );
        }
        if (!missingAssignCol) throw eIns;
        ins = await pool.query(
          `INSERT INTO tasks (service_user_id, title, status, priority, due_date)
           VALUES ($1::uuid, $2, $3, $4, $5)
           RETURNING *`,
          [id, title, 'Open', normalizeTaskPriorityForDb(priority), dueDate]
        );
      }

      const row = ins.rows[0];
      await writeAuditLog(req, {
        action: 'TASK_CREATE',
        resourceType: 'task',
        resourceId: row?.id ?? null,
        metadata: {
          serviceUserId: id,
          hasDueDate: Boolean(dueDate),
          priority: normalizeTaskPriorityForDb(priority),
          hasAssignee: Boolean(assignedTo),
        },
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

    const hasStatus = body.status !== undefined && String(body.status).trim() !== '';
    const hasPriority = body.priority !== undefined;
    const hasDue = body.dueDate !== undefined || body.due_date !== undefined;
    const hasAssign =
      Object.prototype.hasOwnProperty.call(body, 'assigned_to') ||
      Object.prototype.hasOwnProperty.call(body, 'assignedTo');

    if (!hasStatus && !hasPriority && !hasDue && !hasAssign) {
      return clientError(req, res, 400, 'Provide at least one of: status, priority, dueDate, assigned_to.');
    }

    if (hasAssign && !ROLES_TASK_ASSIGN.includes(req.dbUser?.system_role)) {
      return clientError(req, res, 403, 'You do not have permission to assign tasks.');
    }

    const sets = [];
    const vals = [];
    let i = 1;
    if (hasStatus) {
      sets.push(`status = $${i++}`);
      vals.push(String(body.status).trim());
    }
    if (hasPriority) {
      sets.push(`priority = $${i++}`);
      vals.push(normalizeTaskPriorityForDb(body.priority));
    }
    if (hasDue) {
      const rawDue = body.dueDate ?? body.due_date;
      if (rawDue === null || rawDue === '') {
        sets.push(`due_date = $${i++}`);
        vals.push(null);
      } else {
        const d = new Date(String(rawDue));
        if (Number.isNaN(d.getTime())) return clientError(req, res, 400, 'dueDate must be a valid date or empty.');
        sets.push(`due_date = $${i++}`);
        vals.push(d.toISOString().slice(0, 10));
      }
    }
    if (hasAssign) {
      const rawAssign = body.assigned_to ?? body.assignedTo;
      let assignUuid = null;
      if (rawAssign !== null && rawAssign !== undefined && String(rawAssign).trim() !== '') {
        const sid = String(rawAssign).trim();
        if (!/^[0-9a-f-]{36}$/i.test(sid)) return clientError(req, res, 400, 'assigned_to must be a UUID or null.');
        assignUuid = sid;
      }
      if (assignUuid) {
        const homeRes = await pool.query(
          `SELECT home_id FROM service_users WHERE id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR home_id = CAST($2 AS uuid))`,
          [id, scope]
        );
        if (homeRes.rows.length === 0) return clientError(req, res, 403, 'Access denied to this resident');
        const residentHomeId = homeRes.rows[0].home_id ?? null;
        const ures = await pool.query(`SELECT id, home_scope_id FROM users WHERE id = $1::uuid`, [assignUuid]);
        if (ures.rows.length === 0) return clientError(req, res, 400, 'Assignee not found.');
        const ah = ures.rows[0].home_scope_id;
        if (ah != null && residentHomeId != null && String(ah) !== String(residentHomeId)) {
          return clientError(req, res, 403, 'Assignee is not in the same home as this service user.');
        }
      }
      sets.push(`assigned_to = $${i++}`);
      vals.push(assignUuid);
    }

    vals.push(taskId, id, scope);

    try {
      // Update is scoped through service_users.home_id via join (defence in depth)
      const up = await pool.query(
        `UPDATE tasks t
         SET ${sets.join(', ')}
         FROM service_users su
         WHERE t.id = $${i}::uuid
           AND t.service_user_id = $${i + 1}::uuid
           AND su.id = t.service_user_id
           AND (CAST($${i + 2} AS uuid) IS NULL OR su.home_id = CAST($${i + 2} AS uuid))
         RETURNING t.*`,
        vals
      );

      if (up.rows.length === 0) {
        return clientError(req, res, 403, 'Access denied or task not found.');
      }

      let rowOut = up.rows[0];
      if (rowOut?.assigned_to) {
        try {
          const an = await pool.query(
            `SELECT first_name, last_name FROM users WHERE id = $1::uuid`,
            [rowOut.assigned_to]
          );
          if (an.rows[0]) {
            rowOut = {
              ...rowOut,
              assigned_first_name: an.rows[0].first_name,
              assigned_last_name: an.rows[0].last_name,
            };
          }
        } catch (e) {
          logRequestError(req, e, 'task-update-assignee-name');
        }
      }

      await writeAuditLog(req, {
        action: 'TASK_UPDATE',
        resourceType: 'task',
        resourceId: taskId,
        metadata: {
          serviceUserId: id,
          fields: {
            status: hasStatus,
            priority: hasPriority,
            dueDate: hasDue,
            assigned_to: hasAssign,
          },
        },
      });

      res.json({ success: true, task: normalizeTaskRow(rowOut) });
    } catch (err) {
      if (err && typeof err === 'object' && ('code' in err || 'message' in err)) {
        const code = err.code;
        const msg = err.message || '';
        if (code === '42703' || /assigned_to/i.test(String(msg))) {
          return clientError(
            req,
            res,
            503,
            'Task assignee column is not available yet (database migration not applied). Run backend/sql/018_tasks_assigned_priority_index.sql in Supabase and retry.'
          );
        }
      }
      logRequestError(req, err, 'task-update');
      clientError(req, res, 500, 'Could not update task. Please try again later.');
    }
  }
);

app.get('/api/v1/tasks', requireRole(ROLES_RESIDENT_AND_FACILITY_READ), async (req, res) => {
  const scope = userHomeScope(req);
  const overdue = req.query.overdue === 'true';
  const dueToday = req.query.dueToday === 'true' || req.query.due_today === 'true';
  const highPriority = req.query.highPriority === 'true' || req.query.high_priority === 'true';

  try {
    const filters = [];
    if (overdue) {
      filters.push(`t.due_date IS NOT NULL
        AND t.due_date::date < (timezone('UTC', now()))::date
        AND lower(trim(coalesce(t.status,''))) NOT IN ('completed','done')`);
    }
    if (dueToday) {
      filters.push(`t.due_date IS NOT NULL AND t.due_date::date = (timezone('UTC', now()))::date`);
    }
    if (highPriority) {
      filters.push(`lower(trim(coalesce(t.priority,''))) IN ('high','critical')`);
    }

    const whereExtra = filters.length ? `AND (${filters.join(' AND ')})` : '';

    const q = `
      SELECT t.*,
             su.first_name AS resident_first_name,
             su.last_name AS resident_last_name
      FROM tasks t
      INNER JOIN service_users su ON su.id = t.service_user_id
      WHERE (CAST($1 AS uuid) IS NULL OR su.home_id = CAST($1 AS uuid))
      ${whereExtra}
      ORDER BY
        CASE WHEN lower(trim(coalesce(t.status, ''))) IN ('completed', 'done') THEN 1 ELSE 0 END,
        t.due_date ASC NULLS LAST,
        su.last_name ASC,
        su.first_name ASC
      LIMIT 300
    `;
    const { rows } = await pool.query(q, [scope]);
    const inboxAssignIds = filterValidUuidList(rows.map((r) => r.assigned_to));
    let inboxAssignNameById = {};
    if (inboxAssignIds.length) {
      try {
        const an = await pool.query(
          `SELECT id, first_name, last_name FROM users WHERE id = ANY($1::uuid[])`,
          [inboxAssignIds]
        );
        inboxAssignNameById = Object.fromEntries(
          an.rows.map((u) => [String(u.id), { first_name: u.first_name, last_name: u.last_name }])
        );
      } catch (e) {
        logRequestError(req, e, 'tasks-inbox-assignees');
      }
    }
    await writeAuditLog(req, {
      action: 'TASK_INBOX_VIEW',
      resourceType: 'task',
      resourceId: null,
      metadata: { resultCount: rows.length, overdue, dueToday, highPriority },
    });
    res.json({
      tasks: rows.map((r) => {
        const aid = r.assigned_to ? String(r.assigned_to) : null;
        const nm = aid ? inboxAssignNameById[aid] : null;
        const enriched = nm
          ? { ...r, assigned_first_name: nm.first_name, assigned_last_name: nm.last_name }
          : r;
        return {
          ...normalizeTaskRow(enriched),
          serviceUserId: r.service_user_id,
          residentName: `${String(r.resident_first_name || '').trim()} ${String(r.resident_last_name || '').trim()}`.trim(),
        };
      }),
    });
  } catch (err) {
    logRequestError(req, err, 'tasks-inbox');
    clientError(req, res, 500, 'Unable to load tasks.');
  }
});

// ---------------------------------------------------------------------------
// Clinical risk & review inbox (deterministic rules — not predictive AI)
// ---------------------------------------------------------------------------
async function validateRiskReviewAcknowledgement(fingerprint, serviceUserId, scope) {
  const fp = String(fingerprint || '').trim();
  const su = String(serviceUserId || '').trim();
  if (!UUID_RE.test(su)) return { ok: false, message: 'serviceUserId must be a UUID.' };
  const p = fp.indexOf(':');
  if (p < 1) return { ok: false, message: 'Invalid fingerprint.' };
  const kind = fp.slice(0, p);
  const suffix = fp.slice(p + 1).trim();
  if (!UUID_RE.test(suffix)) return { ok: false, message: 'Invalid fingerprint suffix.' };

  const suRow = await pool.query(
    `SELECT id FROM service_users WHERE id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR home_id = CAST($2 AS uuid))`,
    [su, scope]
  );
  if (suRow.rows.length === 0) return { ok: false, message: 'Service user not in scope.' };

  if (kind === 'OVERDUE_HIGH_TASK') {
    const tq = await pool.query(
      `SELECT t.service_user_id
       FROM tasks t
       INNER JOIN service_users su ON su.id = t.service_user_id
       WHERE t.id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR su.home_id = CAST($2 AS uuid))
       LIMIT 1`,
      [suffix, scope]
    );
    if (tq.rows.length === 0) return { ok: false, message: 'Task not found in scope.' };
    if (String(tq.rows[0].service_user_id).toLowerCase() !== su.toLowerCase()) {
      return { ok: false, message: 'Fingerprint does not match service user.' };
    }
    return { ok: true };
  }

  if (String(suffix).toLowerCase() !== su.toLowerCase()) {
    return { ok: false, message: 'Fingerprint does not match service user.' };
  }

  const allowed = new Set([
    'TASK_BACKLOG',
    'TEMP_ELEVATED_48H',
    'SPO2_LOW_48H',
    'PEEP_REVIEW_OVERDUE',
    'PEEP_REVIEW_DUE_SOON',
  ]);
  if (!allowed.has(kind)) return { ok: false, message: 'Unknown fingerprint kind.' };
  return { ok: true };
}

app.get('/api/v1/clinical-risk-review', requireRole(ROLES_RESIDENT_AND_FACILITY_READ), async (req, res) => {
  const scope = userHomeScope(req);
  try {
    const defRaw =
      req.query?.defaultAckCooldownHours ?? req.query?.ackCooldownHours ?? req.query?.ack_hours;
    const defaultAckCooldownHours = Math.min(168, Math.max(1, parseInt(String(defRaw ?? '48'), 10) || 48));
    const payload = await assembleClinicalRiskReviewItems(scope, { defaultAckCooldownHours });
    await writeAuditLog(req, {
      action: 'CLINICAL_RISK_REVIEW_VIEW',
      resourceType: 'clinical_risk_review',
      metadata: {
        itemCount: payload.items.length,
        defaultAckCooldownHours: payload.defaultAckCooldownHours,
        homesWithPolicy: Object.keys(payload.homeAckCooldownByHomeId || {}).length,
      },
    });
    res.json(payload);
  } catch (err) {
    logRequestError(req, err, 'clinical-risk-review-get');
    clientError(req, res, 500, 'Unable to load clinical risk review inbox.');
  }
});

app.post('/api/v1/clinical-risk-review/acknowledge', requireRole(ROLES_RESIDENT_AND_FACILITY_READ), async (req, res) => {
  const scope = userHomeScope(req);
  const body = req.body || {};
  const fingerprint = typeof body.fingerprint === 'string' ? body.fingerprint.trim() : '';
  const serviceUserId = typeof body.serviceUserId === 'string' ? body.serviceUserId.trim() : '';
  let note = typeof body.note === 'string' ? body.note.trim() : '';
  if (note.length > 2000) note = note.slice(0, 2000);

  if (!fingerprint || !serviceUserId) {
    return clientError(req, res, 400, 'fingerprint and serviceUserId are required.');
  }

  const v = await validateRiskReviewAcknowledgement(fingerprint, serviceUserId, scope);
  if (!v.ok) return clientError(req, res, 400, v.message);

  let homeIdAck = null;
  try {
    const homeRow = await pool.query(
      `SELECT home_id FROM service_users WHERE id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR home_id = CAST($2 AS uuid)) LIMIT 1`,
      [serviceUserId, scope]
    );
    homeIdAck = homeRow.rows[0]?.home_id ?? null;
  } catch (e) {
    /* non-fatal */
  }

  try {
    let ins;
    try {
      ins = await pool.query(
        `INSERT INTO public.risk_review_acknowledgements
           (actor_user_id, actor_email, fingerprint, service_user_id, home_id, note)
         VALUES ($1::uuid, $2, $3, $4::uuid, $5::uuid, NULLIF($6, ''))
         RETURNING id, created_at`,
        [
          req.dbUser?.id ?? null,
          req.dbUser?.email ?? req.user?.email ?? null,
          fingerprint,
          serviceUserId,
          homeIdAck,
          note,
        ]
      );
    } catch (e0) {
      if (String(e0.code || '') === '42703' && /home_id/i.test(String(e0.message))) {
        ins = await pool.query(
          `INSERT INTO public.risk_review_acknowledgements
             (actor_user_id, actor_email, fingerprint, service_user_id, note)
           VALUES ($1::uuid, $2, $3, $4::uuid, NULLIF($5, ''))
           RETURNING id, created_at`,
          [
            req.dbUser?.id ?? null,
            req.dbUser?.email ?? req.user?.email ?? null,
            fingerprint,
            serviceUserId,
            note,
          ]
        );
      } else {
        throw e0;
      }
    }
    await writeAuditLog(req, {
      action: 'CLINICAL_RISK_REVIEW_ACK',
      resourceType: 'service_user',
      resourceId: serviceUserId,
      metadata: { fingerprint, note: note || null, homeId: homeIdAck },
    });
    res.status(201).json({ success: true, acknowledgement: ins.rows[0] });
  } catch (err) {
    if (String(err.code || '') === '42P01' || /risk_review_acknowledgements/i.test(String(err.message))) {
      return clientError(
        req,
        res,
        503,
        'Acknowledgements table is not installed. Run backend/sql/023_risk_review_acknowledgements.sql in the database.'
      );
    }
    logRequestError(req, err, 'clinical-risk-review-ack');
    clientError(req, res, 500, 'Could not record acknowledgement.');
  }
});

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
// TOPICAL MEDICINES — application record sheet (body map, scoped)
// ---------------------------------------------------------------------------
const TOPICAL_BODY_REGION_IDS = new Set([
  'head',
  'neck',
  'chest',
  'abdomen',
  'left_upper_arm',
  'right_upper_arm',
  'left_forearm',
  'right_forearm',
  'left_hand',
  'right_hand',
  'left_thigh',
  'right_thigh',
  'left_shin',
  'right_shin',
  'left_foot',
  'right_foot',
  'groin',
  'upper_back',
  'mid_back',
  'lower_back',
  'left_buttock',
  'right_buttock',
  'left_calf_back',
  'right_calf_back',
]);

function normalizeTopicalBodyRegions(raw) {
  if (!Array.isArray(raw)) return [];
  const out = [];
  for (const x of raw) {
    const s = String(x || '').trim();
    if (!s || !TOPICAL_BODY_REGION_IDS.has(s)) continue;
    if (!out.includes(s)) out.push(s);
    if (out.length >= 24) break;
  }
  return out;
}

app.get(
  '/api/v1/residents/:id/topical-applications',
  requireRole(ROLES_RESIDENT_AND_FACILITY_READ),
  async (req, res) => {
    const { id } = req.params;
    const scope = userHomeScope(req);
    const dateRaw = typeof req.query?.date === 'string' ? req.query.date.trim() : null;

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
        SELECT tar.*
        FROM topical_application_records tar
        INNER JOIN service_users su ON su.id = tar.service_user_id
        WHERE tar.service_user_id = $1::uuid
          AND (CAST($2 AS uuid) IS NULL OR su.home_id = CAST($2 AS uuid))
          AND ($3::date IS NULL OR tar.chart_date = $3::date)
        ORDER BY tar.applied_at DESC, tar.created_at DESC
        LIMIT 200
      `;
      const rows = (await pool.query(q, [id, scope, chartDate])).rows || [];
      res.json({
        date: chartDate,
        allowedBodyRegions: [...TOPICAL_BODY_REGION_IDS].sort(),
        entries: rows.map((r) => ({
          id: r.id,
          chartDate: r.chart_date,
          appliedAt: r.applied_at,
          medicationName: r.medication_name,
          medicationId: r.medication_id,
          bodyRegions: Array.isArray(r.body_regions) ? r.body_regions : [],
          siteNotes: r.site_notes,
          batchLot: r.batch_lot,
          recordedBy: r.recorded_by,
          createdAt: r.created_at,
        })),
      });
    } catch (err) {
      if (err && typeof err === 'object' && ('code' in err || 'message' in err)) {
        const code = err.code;
        const msg = err.message || '';
        if (code === '42P01' || /topical_application_records/i.test(String(msg))) {
          return clientError(
            req,
            res,
            503,
            'Topical application records are not available yet. Run backend/sql/025_topical_application_records.sql in Supabase and retry.'
          );
        }
      }
      logRequestError(req, err, 'topical-applications-list');
      clientError(req, res, 500, 'Unable to load topical application records.');
    }
  }
);

app.post(
  '/api/v1/residents/:id/topical-applications',
  requireRole(ROLES_DAILY_CARE_WRITE),
  async (req, res) => {
    const { id } = req.params;
    const scope = userHomeScope(req);
    const body = req.body || {};

    const medicationName =
      typeof body.medicationName === 'string'
        ? body.medicationName.trim()
        : typeof body.medication_name === 'string'
          ? body.medication_name.trim()
          : '';
    const medicationIdRaw = body.medicationId ?? body.medication_id ?? null;
    const siteNotes =
      typeof body.siteNotes === 'string'
        ? body.siteNotes.trim()
        : typeof body.site_notes === 'string'
          ? body.site_notes.trim()
          : '';
    const batchLot =
      typeof body.batchLot === 'string'
        ? body.batchLot.trim()
        : typeof body.batch_lot === 'string'
          ? body.batch_lot.trim()
          : '';
    const dateRaw = body.date ?? body.chartDate ?? body.chart_date ?? null;
    const appliedAtRaw = body.appliedAt ?? body.applied_at ?? null;

    const regions = normalizeTopicalBodyRegions(body.bodyRegions ?? body.body_regions);
    if (!medicationName || medicationName.length > 300) {
      return clientError(req, res, 400, 'medicationName is required (max 300 characters).');
    }
    if (regions.length === 0) {
      return clientError(req, res, 400, 'Select at least one body region on the map.');
    }
    if (siteNotes.length > 2000) return clientError(req, res, 400, 'siteNotes is too long.');
    if (batchLot.length > 120) return clientError(req, res, 400, 'batchLot is too long.');

    let chartDate = null;
    if (dateRaw) {
      const s = String(dateRaw);
      if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return clientError(req, res, 400, 'date must be YYYY-MM-DD.');
      chartDate = s;
    }

    let appliedAt = null;
    if (appliedAtRaw) {
      const d = new Date(String(appliedAtRaw));
      if (Number.isNaN(d.getTime())) return clientError(req, res, 400, 'appliedAt must be a valid ISO date/time.');
      appliedAt = d.toISOString();
    }

    let medicationId = null;
    if (medicationIdRaw != null && String(medicationIdRaw).trim() !== '') {
      const mid = String(medicationIdRaw).trim();
      if (!UUID_RE.test(mid)) return clientError(req, res, 400, 'medicationId must be a UUID when provided.');
      medicationId = mid;
    }

    try {
      const scopeCheck = await pool.query(
        `SELECT id FROM service_users WHERE id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR home_id = CAST($2 AS uuid))`,
        [id, scope]
      );
      if (scopeCheck.rows.length === 0) {
        return clientError(req, res, 403, 'Access denied to this resident');
      }

      if (medicationId) {
        const mv = await pool.query(
          `SELECT id FROM medications WHERE id = $1::uuid AND service_user_id = $2::uuid LIMIT 1`,
          [medicationId, id]
        );
        if (mv.rows.length === 0) {
          return clientError(req, res, 400, 'medicationId does not match a medication for this service user.');
        }
      }

      const recordedBy =
        (req.dbUser?.first_name || req.dbUser?.last_name)
          ? `${req.dbUser?.first_name || ''} ${req.dbUser?.last_name || ''}`.trim()
          : (req.dbUser?.email ?? req.user?.email ?? null);

      const ins = await pool.query(
        `INSERT INTO topical_application_records
          (service_user_id, chart_date, applied_at, medication_name, medication_id, body_regions, site_notes, batch_lot, recorded_by)
         VALUES ($1::uuid, COALESCE($2::date, (now() AT TIME ZONE 'utc')::date), COALESCE($3::timestamptz, now()),
                 $4, $5::uuid, $6::text[], NULLIF($7, ''), NULLIF($8, ''), $9)
         RETURNING *`,
        [id, chartDate, appliedAt, medicationName, medicationId, regions, siteNotes, batchLot, recordedBy]
      );

      const row = ins.rows[0];
      await writeAuditLog(req, {
        action: 'TOPICAL_APPLICATION_CREATE',
        resourceType: 'topical_application_record',
        resourceId: row?.id ?? null,
        metadata: {
          serviceUserId: id,
          regionCount: regions.length,
          chartDate: row?.chart_date ?? null,
        },
      });

      res.status(201).json({
        success: true,
        entry: {
          id: row.id,
          chartDate: row.chart_date,
          appliedAt: row.applied_at,
          medicationName: row.medication_name,
          medicationId: row.medication_id,
          bodyRegions: row.body_regions || [],
          siteNotes: row.site_notes,
          batchLot: row.batch_lot,
          recordedBy: row.recorded_by,
          createdAt: row.created_at,
        },
      });
    } catch (err) {
      if (err && typeof err === 'object' && ('code' in err || 'message' in err)) {
        const code = err.code;
        const msg = err.message || '';
        if (code === '42P01' || /topical_application_records/i.test(String(msg))) {
          return clientError(
            req,
            res,
            503,
            'Topical application records are not available yet. Run backend/sql/025_topical_application_records.sql in Supabase and retry.'
          );
        }
        if (code === '23503') {
          return clientError(req, res, 400, 'Invalid medication reference.');
        }
      }
      logRequestError(req, err, 'topical-applications-create');
      clientError(req, res, 500, 'Could not save topical application record.');
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
// COMMUNAL BATHROOM — weekly deep clean checklist (per home)
// ---------------------------------------------------------------------------
const COMMUNAL_BATHROOM_CHECKLIST_DEF = [
  { key: 'tile_walls_shower', label: 'Wall tiles & shower enclosure', hint: 'Scrub; remove soap residue and limescale.' },
  { key: 'grout_seals', label: 'Grout & silicone seals', hint: 'Inspect for mould/damage; clean or flag maintenance.' },
  { key: 'bath_shower_tray', label: 'Bath / shower tray', hint: 'Descale, disinfect, rinse thoroughly.' },
  { key: 'toilet_full', label: 'Toilet (full deep clean)', hint: 'Bowl, rim, seat, hinges, exterior, behind pan where reachable.' },
  { key: 'sinks_taps', label: 'Sinks & taps', hint: 'Descale outlets; polish metalware; clear overflow channels.' },
  { key: 'mirrors_glass', label: 'Mirrors & glass', hint: 'Streak-free clean; check for cracks.' },
  { key: 'floor_mop_disinfect', label: 'Floors — mop & disinfect', hint: 'Behind doors, corners, under furniture edges.' },
  { key: 'drains_traps', label: 'Drains & traps', hint: 'Clear hair/debris; check flow; note odours.' },
  { key: 'extractor_fan', label: 'Extractor / ventilation', hint: 'Clean cover/grille; confirm operation.' },
  { key: 'bins_sanitised', label: 'Bins & clinical waste points', hint: 'Sanitise; fresh liners; lids functioning.' },
  { key: 'consumables_restock', label: 'Consumables restocked', hint: 'Soap, paper, hand towels, toilet rolls per home policy.' },
  { key: 'high_touch_surfaces', label: 'High-touch surfaces', hint: 'Door handles, rails, flush plates, light switches.' },
  { key: 'equipment_storage', label: 'Equipment & storage', hint: 'Hoists / shower chairs / commodes stored clean and dry.' },
  { key: 'final_inspection', label: 'Final visual inspection', hint: 'Odour, slip hazards, lighting; sign-off ready.' },
];

const COMMUNAL_BATHROOM_CHECK_KEYS = new Set(COMMUNAL_BATHROOM_CHECKLIST_DEF.map((d) => d.key));

function mondayOfWeekLocalFromDate(d) {
  const t = new Date(d.getFullYear(), d.getMonth(), d.getDate());
  const day = t.getDay();
  const diff = day === 0 ? -6 : 1 - day;
  t.setDate(t.getDate() + diff);
  const yyyy = t.getFullYear();
  const mm = String(t.getMonth() + 1).padStart(2, '0');
  const dd = String(t.getDate()).padStart(2, '0');
  return `${yyyy}-${mm}-${dd}`;
}

function parseWeekStartMondayParam(raw) {
  if (raw == null || raw === '') return mondayOfWeekLocalFromDate(new Date());
  const s = String(raw).trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return null;
  const d = new Date(`${s}T12:00:00`);
  if (Number.isNaN(d.getTime())) return null;
  return mondayOfWeekLocalFromDate(d);
}

function actorDisplayName(req) {
  const fn = req.dbUser?.first_name || '';
  const ln = req.dbUser?.last_name || '';
  const n = `${fn} ${ln}`.trim();
  return n || req.dbUser?.email || req.user?.email || 'Staff';
}

function sanitizeCommunalChecklistIncoming(raw) {
  if (!raw || typeof raw !== 'object') return {};
  const out = {};
  for (const key of COMMUNAL_BATHROOM_CHECK_KEYS) {
    const v = raw[key];
    if (!v || typeof v !== 'object') continue;
    out[key] = { done: Boolean(v.done) };
  }
  return out;
}

function mergeCommunalChecklistPersistence(existingJson, incomingSanitized, req) {
  const existing = existingJson && typeof existingJson === 'object' ? existingJson : {};
  const actor = actorDisplayName(req);
  const out = {};
  for (const key of COMMUNAL_BATHROOM_CHECK_KEYS) {
    const want = incomingSanitized[key];
    const nowDone = want && want.done;
    if (!nowDone) {
      out[key] = { done: false };
      continue;
    }
    const prev = existing[key];
    if (prev && prev.done === true && prev.at) {
      out[key] = { done: true, at: String(prev.at), by: String(prev.by || actor).slice(0, 200) };
    } else {
      out[key] = { done: true, at: new Date().toISOString(), by: actor.slice(0, 200) };
    }
  }
  return out;
}

async function resolveCommunalCleanHomeId(req, queryHomeId) {
  const scope = userHomeScope(req);
  if (scope != null) {
    return { ok: true, homeId: String(scope) };
  }
  const hid = queryHomeId != null ? String(queryHomeId).trim() : '';
  if (!hid) {
    return {
      ok: false,
      message: 'homeId query parameter is required when your account is not scoped to a single home.',
    };
  }
  if (!UUID_RE.test(hid)) {
    return { ok: false, message: 'homeId must be a valid UUID (check location scope or home picker).' };
  }
  return { ok: true, homeId: hid };
}

app.get(
  '/api/v1/facility/communal-bathroom-weekly-clean',
  requireRole(ROLES_RESIDENT_AND_FACILITY_READ),
  async (req, res) => {
    const scope = userHomeScope(req);
    const weekRaw = req.query?.weekStart ?? req.query?.week_start;
    const weekStart = parseWeekStartMondayParam(weekRaw);
    if (!weekStart) {
      return clientError(req, res, 400, 'weekStart must be YYYY-MM-DD (Monday of the week you are recording).');
    }

    const homeRes = await resolveCommunalCleanHomeId(req, req.query?.homeId ?? req.query?.home_id);
    if (!homeRes.ok) {
      return clientError(req, res, 400, homeRes.message);
    }
    const { homeId } = homeRes;

    try {
      const hk = await pool.query(
        `SELECT id, name FROM homes WHERE id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR id = CAST($2 AS uuid)) LIMIT 1`,
        [homeId, scope]
      );
      if (hk.rows.length === 0) {
        return clientError(req, res, 403, 'Home not found or not in your scope.');
      }

      let row = null;
      try {
        const r = await pool.query(
          `SELECT * FROM communal_bathroom_weekly_checks WHERE home_id = $1::uuid AND week_start_monday = $2::date LIMIT 1`,
          [homeId, weekStart]
        );
        row = r.rows[0] || null;
      } catch (e) {
        if (String(e.code || '') === '42P01' || /communal_bathroom_weekly_checks/i.test(String(e.message))) {
          return clientError(
            req,
            res,
            503,
            'Communal bathroom weekly checklist is not available yet. Run backend/sql/026_communal_bathroom_weekly_clean.sql in Supabase and retry.'
          );
        }
        throw e;
      }

      const state = row?.checklist_state && typeof row.checklist_state === 'object' ? row.checklist_state : {};
      const items = COMMUNAL_BATHROOM_CHECKLIST_DEF.map((def) => {
        const s = state[def.key] && typeof state[def.key] === 'object' ? state[def.key] : {};
        return {
          ...def,
          done: Boolean(s.done),
          completedAt: s.at || null,
          completedBy: s.by || null,
        };
      });

      await writeAuditLog(req, {
        action: 'COMMUNAL_BATHROOM_WEEKLY_CLEAN_VIEW',
        resourceType: 'facility',
        resourceId: homeId,
        metadata: { weekStart, hasSavedRow: Boolean(row) },
      });

      res.json({
        home: hk.rows[0],
        weekStartMonday: weekStart,
        templateVersion: 1,
        items,
        supervisorNotes: row?.supervisor_notes ?? null,
        updatedAt: row?.updated_at ?? null,
        updatedBy: row?.updated_by ?? null,
      });
    } catch (err) {
      logRequestError(req, err, 'communal-bathroom-weekly-clean-get');
      clientError(req, res, 500, 'Unable to load communal bathroom weekly checklist.');
    }
  }
);

app.put(
  '/api/v1/facility/communal-bathroom-weekly-clean',
  requireRole(ROLES_DAILY_CARE_WRITE),
  async (req, res) => {
    const scope = userHomeScope(req);
    const body = req.body || {};
    const weekRaw = body.weekStartMonday ?? body.week_start_monday ?? body.weekStart;
    const weekStart = parseWeekStartMondayParam(weekRaw);
    if (!weekStart) {
      return clientError(req, res, 400, 'weekStartMonday must be YYYY-MM-DD (Monday of the week).');
    }

    const homeRes = await resolveCommunalCleanHomeId(req, body.homeId ?? body.home_id ?? req.query?.homeId);
    if (!homeRes.ok) {
      return clientError(req, res, 400, homeRes.message);
    }
    const { homeId } = homeRes;

    const supervisorNotes =
      typeof body.supervisorNotes === 'string'
        ? body.supervisorNotes.trim()
        : typeof body.supervisor_notes === 'string'
          ? body.supervisor_notes.trim()
          : '';
    if (supervisorNotes.length > 2000) {
      return clientError(req, res, 400, 'supervisorNotes is too long.');
    }

    const incoming = sanitizeCommunalChecklistIncoming(body.checklistState ?? body.checklist_state);

    try {
      const hk = await pool.query(
        `SELECT id FROM homes WHERE id = $1::uuid AND (CAST($2 AS uuid) IS NULL OR id = CAST($2 AS uuid)) LIMIT 1`,
        [homeId, scope]
      );
      if (hk.rows.length === 0) {
        return clientError(req, res, 403, 'Home not found or not in your scope.');
      }

      let existingState = {};
      try {
        const ex = await pool.query(
          `SELECT checklist_state FROM communal_bathroom_weekly_checks WHERE home_id = $1::uuid AND week_start_monday = $2::date LIMIT 1`,
          [homeId, weekStart]
        );
        if (ex.rows[0]?.checklist_state && typeof ex.rows[0].checklist_state === 'object') {
          existingState = ex.rows[0].checklist_state;
        }
      } catch (e) {
        if (String(e.code || '') === '42P01' || /communal_bathroom_weekly_checks/i.test(String(e.message))) {
          return clientError(
            req,
            res,
            503,
            'Communal bathroom weekly checklist is not available yet. Run backend/sql/026_communal_bathroom_weekly_clean.sql in Supabase and retry.'
          );
        }
        throw e;
      }

      const merged = mergeCommunalChecklistPersistence(existingState, incoming, req);
      const updater = actorDisplayName(req);

      const up = await pool.query(
        `INSERT INTO communal_bathroom_weekly_checks (home_id, week_start_monday, checklist_state, supervisor_notes, updated_by)
         VALUES ($1::uuid, $2::date, $3::jsonb, NULLIF($4, ''), $5)
         ON CONFLICT (home_id, week_start_monday)
         DO UPDATE SET
           checklist_state = EXCLUDED.checklist_state,
           supervisor_notes = EXCLUDED.supervisor_notes,
           updated_by = EXCLUDED.updated_by,
           updated_at = now()
         RETURNING *`,
        [homeId, weekStart, JSON.stringify(merged), supervisorNotes, updater]
      );

      const row = up.rows[0];
      await writeAuditLog(req, {
        action: 'COMMUNAL_BATHROOM_WEEKLY_CLEAN_SAVE',
        resourceType: 'facility',
        resourceId: homeId,
        metadata: { weekStart, doneCount: Object.values(merged).filter((x) => x && x.done).length },
      });

      const state = row.checklist_state && typeof row.checklist_state === 'object' ? row.checklist_state : {};
      const items = COMMUNAL_BATHROOM_CHECKLIST_DEF.map((def) => {
        const s = state[def.key] && typeof state[def.key] === 'object' ? state[def.key] : {};
        return {
          ...def,
          done: Boolean(s.done),
          completedAt: s.at || null,
          completedBy: s.by || null,
        };
      });

      res.json({
        success: true,
        homeId,
        weekStartMonday: weekStart,
        items,
        supervisorNotes: row.supervisor_notes ?? null,
        updatedAt: row.updated_at,
        updatedBy: row.updated_by,
      });
    } catch (err) {
      logRequestError(req, err, 'communal-bathroom-weekly-clean-put');
      clientError(req, res, 500, 'Could not save communal bathroom weekly checklist.');
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
        const share = Boolean(op.payload && op.payload.shareWithFamily);
        const ins = await client.query(
          `INSERT INTO daily_notes (service_user_id, note_text, author_name, share_with_family)
           SELECT $1::uuid, $2, $3, $5
           FROM service_users su
           WHERE su.id = $1::uuid
             AND (CAST($4 AS uuid) IS NULL OR su.home_id = CAST($4 AS uuid))`,
          [op.payload.residentId, op.payload.text, dbAuthorName, scope, share]
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
