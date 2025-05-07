// --------------------------------------------------------------
//  auth-server/server.js   (ESM, PostgreSQL)
// --------------------------------------------------------------
import dotenv from 'dotenv';
dotenv.config();
/* ---------- config --------------------------------------------------- */
const PORT       = process.env.PORT       || 4000;
const JWT_SECRET = process.env.JWT_SECRET || '';
const ISSUER     = process.env.ISSUER     || 'AI-SSO';
if (!JWT_SECRET) {
  console.error('❌  Missing JWT_SECRET in .env');
  process.exit(1);
}

function issueJwt(userId, role) {
  return jwt.sign(
    { sub: userId, role },
    JWT_SECRET,
    {
      issuer: ISSUER,
      expiresIn: '30m'
    }
  );
}


/* ────────────────────────────────────────────────────────────── */
/*  Database (pg)                                                */
/* ────────────────────────────────────────────────────────────── */
import { pool } from './db.js';
const db = pool;                  // ← alias so existing code keeps using “db”

// Optional: test connection
db.connect()
  .then(c => { c.release(); console.log('✅  Connected to PostgreSQL'); })
  .catch(err => { console.error('❌  PostgreSQL connection error:', err.stack); });

/* ────────────────────────────────────────────────────────────── */
/*  Imports                                                      */
/* ────────────────────────────────────────────────────────────── */
import express   from 'express';
import cors      from 'cors';
import helmet    from 'helmet';
import morgan    from 'morgan';
import bcrypt    from 'bcryptjs';
import jwt       from 'jsonwebtoken';
import speakeasy from 'speakeasy';
import qrcode    from 'qrcode';
import { v4 as uuid } from 'uuid';
import fetch     from 'node-fetch';
import { logEntry } from '../shared/logger.js';
import session from 'express-session';
import passport from './passport.js'; 

/* ------------------------------------------------------------------ */
/* --- Prepared SQL (now async / PostgreSQL) ------------------------ */
/* ------------------------------------------------------------------ */
/**
 *  NOTE – the pg client (`db`) comes from the Pool you created above.
 *  Every helper returns a Promise, so callers must `await` them.
 *  Place-holders are PostgreSQL style: $1, $2, … (not ?)
 */

// Find user by username OR email (case-insensitive)
async function findUser(identifier) {
  const { rows } = await db.query(
    `SELECT *
       FROM users
      WHERE username ILIKE $1
         OR email    ILIKE $1
      LIMIT 1`,
    [identifier]                          // ← $1
  );
  return rows[0] ?? null;
}

// Insert a new user
async function insertUserExtended({
  id, username, hash, email,
  department, role, idNumber
}) {
  await db.query(
    `INSERT INTO users
         (id, username, hash, email, department, role, idNumber)
     VALUES ($1,$2,$3,$4,$5,$6,$7)`,
    [id, username, hash, email, department, role, idNumber]
  );
}

// Update MFA secret
async function setMfa(uid, secret) {
  await db.query(
    `UPDATE users SET "mfaSecret" = $1 WHERE id = $2`,
    [secret, uid]
  );
}

// Log any event
async function logEvent(uid, ts, ip, ua) {
  await db.query(
    `INSERT INTO events (uid, ts, ip, ua) VALUES ($1,$2,$3,$4)`,
    [uid, ts, ip, ua]
  );
}

/* ------------------------------------------------------------------ */
/* --- Lock-out parameters (unchanged) ----------------------------- */
/* ------------------------------------------------------------------ */
const WINDOW_MS = 15 * 60_000;   // look at last 15 min
const LOCK_MS   = 15 * 60_000;   // lock for   15 min
const MAX_FAILS = 5;             // after 5 bad tries

/* ------------------------------------------------------------------ */
/* --- Helper: Map origin → app name -------------------------------- */
/* ------------------------------------------------------------------ */
function getAppName(origin) {
  switch (origin) {
    case 'http://localhost:3000': return 'App1';
    case 'http://localhost:3001': return 'App2';
    default:                      return origin;
  }
}

/* ------------------------------------------------------------------ */
/* --- Middleware: brute-force / lock-out guard --------------------- */
/* ------------------------------------------------------------------ */
async function accountGuard(req, res, next) {
  try {
    const identifier = (req.body.identifier || req.body.username || '')
                       .trim().toLowerCase();
    if (!identifier) return next();          // nothing to check

    /* normalise client IP */
    let clientIp = (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim();
    if (clientIp === '::1' || clientIp.startsWith('::ffff:')) clientIp = '127.0.0.1';

    /* 1️⃣  Is the account currently locked? */
    const lockRow = await db.query(
      `SELECT locked_until
         FROM users
        WHERE username ILIKE $1
           OR email    ILIKE $1`,
      [identifier]
    );

    const lockedUntil = lockRow.rows[0] ? Number(lockRow.rows[0].locked_until) : 0;
    if (lockedUntil > Date.now()) {
      const unlockAt = lockedUntil;
      const lockAt   = unlockAt - LOCK_MS;

      logEntry('LOCKOUT_HIT', {
        identifier, ip: clientIp,
        app: getAppName(req.headers.origin),
        browser: req.headers['user-agent'],
        lockAt:   new Date(lockAt).toISOString(),
        unlockAt: new Date(unlockAt).toISOString()
      });
      return res.status(423).json({ msg: 'account-locked', unlock: unlockAt });
    }

    /* 2️⃣  Count recent failures */
    const since = Date.now() - WINDOW_MS;
    const { rows } = await db.query(
      `SELECT COUNT(*) AS cnt
         FROM login_failures
        WHERE identifier = $1
          AND ts > $2`,
      [identifier, since]
    );
    const fails = Number(rows[0].cnt);

    /* 3️⃣  Exceeded max?  → lock account */
    if (fails >= MAX_FAILS && lockRow.rows.length) {
      const lockAt   = Date.now();
      const unlockAt = lockAt + LOCK_MS;

      await db.query(
        `UPDATE users
            SET locked_until = $1
          WHERE username ILIKE $2
             OR email    ILIKE $2`,
        [unlockAt, identifier]
      );

      logEntry('LOCKOUT_SET', {
        identifier, ip: clientIp,
        app: getAppName(req.headers.origin),
        browser: req.headers['user-agent'],
        lockAt:   new Date(lockAt).toISOString(),
        unlockAt: new Date(unlockAt).toISOString()
      });

      return res.status(429).json({ msg: 'too-many-attempts' });
    }

    next();                                   // ✅  all clear
  } catch (err) {
    console.error('accountGuard error:', err);
    res.status(500).json({ msg: 'internal-error' });
  }
}

/* ------------------------------------------------------------------ */
/* --- Middleware: admin-only guard (unchanged) --------------------- */
/* ------------------------------------------------------------------ */
function adminGuard(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ msg: 'no token provided' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'admin')
      return res.status(403).json({ msg: 'admins only' });
    next();
  } catch (err) {
    console.error('❌ Failed to verify token in adminGuard:', err.message);
    return res.status(401).json({ msg: 'invalid token' });
  }
}

/* ------------------------------------------------------------------ */
/* --- Sign JWT token + log login event (PostgreSQL) ---------------- */
/* ------------------------------------------------------------------ */
async function signAndLog(uid, req) {
  // 1️⃣ fetch username & role
  const { rows: userRows } =
    await db.query(
      'SELECT username, role FROM users WHERE id = $1',
      [uid]
    );
  const user = userRows[0];

  // 2️⃣ issue JWT
  const token = jwt.sign(
    { sub: uid, role: user.role },      // payload
    JWT_SECRET,
    { issuer: ISSUER, expiresIn: '30m' }
  );

  // 3️⃣ how many log-ins so far?
  const { rows: cntRows } =
    await db.query(
      'SELECT COUNT(*)::int AS cnt FROM events WHERE uid = $1',
      [uid]
    );
  const loginCount = cntRows[0].cnt;

  // 4️⃣ structured file log
  const origin = req.headers.origin;
  logEntry('SIGN', {
    uid,
    username:   user.username,
    role:       user.role,
    origin,
    app:        getAppName(origin),
    browser:    req.headers['user-agent'],
    loginCount,
    token
  });

  // 5️⃣ persist the login event
  await logEvent(
    uid,
    Date.now(),
    (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim(),
    req.headers['user-agent']
  );

  // ⇨ now return both
  return { token, role: user.role };
}


/* ------------------------------------------------------------------ */
/* ---------- Express setup (unchanged) ----------------------------- */
/* ------------------------------------------------------------------ */
const app = express();
app.use(cors({
  origin: [
    'http://localhost:3000',
    'http://localhost:3001',
    'http://localhost:4001'
  ],
  credentials: true,
  methods: 'GET,POST,PUT,DELETE,OPTIONS',
  allowedHeaders: 'Content-Type,Authorization'
}));
app.use(express.json());
app.use(helmet());
app.use(morgan('dev'));

/* ------Add session and Passport middleware------------------------------ */

// Session middleware (required by Passport)
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // true only if using HTTPS
}));

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());



/* ------------------------------------------------------------------ */
/* ---------- ROUTES ------------------------------------------------ */
/* ------------------------------------------------------------------ */

// --------------------------------------------------------------
//  1)  POST /register
//      Collects: username, email, password, department, role, idNumber
// --------------------------------------------------------------
app.post('/register', async (req, res) => {
  const origin    = req.headers.origin;
  const appName   = getAppName(origin);
  const browser   = req.headers['user-agent'];
  const { username, email, password, department, role, idNumber } = req.body;

  /* 1️⃣  Username already taken? */
  {
    const { rows } = await pool.query(
      `SELECT 1 FROM users WHERE username ILIKE $1 LIMIT 1`,
      [username.trim()]
    );
    if (rows.length) {
      logEntry('REGISTER_FAIL_USERNAME', { username, origin, app: appName, browser });
      return res.status(409).json({ msg: 'username-taken' });
    }
  }

  /* 2️⃣  ID-number already used? */
  {
    const { rows } = await pool.query(
      `SELECT 1 FROM users WHERE idnumber = $1 LIMIT 1`,
      [idNumber]
    );
    if (rows.length) {
      logEntry('REGISTER_FAIL_IDNUMBER', { idNumber, origin, app: appName, browser });
      return res.status(409).json({ msg: 'idnumber-taken' });
    }
  }

  /* 3️⃣  Kickbox e-mail verification (if configured) */
  let kb = { result: 'skipped', free: true };
  if (process.env.KICKBOX_API_KEY) {
    try {
      const kickboxUrl = `https://api.kickbox.com/v2/verify?email=${encodeURIComponent(email)}&apikey=${process.env.KICKBOX_API_KEY}`;
      const verifyRes  = await fetch(kickboxUrl);
      kb = await verifyRes.json();
      console.log('📝 Kickbox response for', email, ':', kb);

      logEntry('EMAIL_VERIFY', {
        email,
        result:     kb.result,
        reason:     kb.reason,
        disposable: kb.disposable,
        role:       kb.role,
        free:       kb.free,
        app:        appName,
        browser
      });

      // reject only if truly undeliverable (and NOT a free provider), or disposable, or role-based
      if (
        (kb.result === 'undeliverable' && !kb.free) ||
        kb.disposable ||
        kb.role
      ) {
        logEntry('REGISTER_FAIL_SUSPICIOUS_EMAIL', {
          username, email,
          reason:     kb.reason,
          result:     kb.result,
          disposable: kb.disposable,
          role:       kb.role,
          app:        appName,
          browser
        });
        return res.status(400).json({ msg: 'invalid-email', reason: kb.reason });
      }
    } catch (err) {
      console.warn('⚠️  Kickbox check failed, skipping it:', err.message);
    }
  } else {
    console.log('🟡  No KICKBOX_API_KEY set – skipping email verification');
  }

  /* 4️⃣  Insert user into `users(...)` */
  const uid = uuid();
  await pool.query(
    `INSERT INTO users
       (id, username, hash, email, department, role, idnumber)
     VALUES ($1,$2,$3,$4,$5,$6,$7)`,
    [
      uid,
      username.trim(),
      await bcrypt.hash(password, 10),
      email.trim().toLowerCase(),
      department,
      role,
      idNumber
    ]
  );

  logEntry('REGISTER_SUCCESS', {
    uid, username,
    email:      email.trim().toLowerCase(),
    department, role, idNumber,
    origin, app: appName, browser
  });

  /* 5️⃣  DEBUG: fetch & display the newly-created user in the terminal */
  {
    const { rows } = await pool.query(
      `SELECT id, username, email, department, role, idnumber AS "idNumber"
         FROM users
        WHERE id = $1`,
      [uid]
    );
    console.log('🆕  New user registered:', rows[0]);
  }

  /* 6️⃣  Respond to client */
  res.json({ msg: 'registered' });
});
/* ------------------------------------------------------------------ */
/* setup-profile                                                      */
/* ------------------------------------------------------------------ */
// auth-server/server.js

app.post('/setup-profile', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ msg: 'No token provided' });

  try {
    const { sub: uid } = jwt.verify(token, JWT_SECRET);
    const { idNumber, department, role } = req.body;

    // ── 1) Update the user record
    await pool.query(`
      UPDATE users
         SET idnumber   = $1,
             department = $2,
             role       = $3
       WHERE id = $4
    `, [idNumber, department, role, uid]);

    // ── 2) Log the profile‐setup completion
    logEntry('PROFILE_SETUP_COMPLETE', {
      uid,
      idNumber,
      department,
      role,
      app:     req.session.app || 'app1',
      ip:      req.ip,
      browser: req.headers['user-agent']
    });

    // ── 3) Also persist in your events table if you want it there:
    await pool.query(
      `INSERT INTO events (uid, ts, ip, ua)
         VALUES ($1, $2, $3, $4)`,
      [uid, Date.now(), req.ip, req.headers['user-agent']]
    );

    return res.json({ msg: 'profile-updated' });
  } catch (err) {
    console.error('❌ /setup-profile error:', err);
    return res.status(400).json({ msg: 'invalid or expired token' });
  }
});


/* ------------------------------------------------------------------ */
/* 2a)  Login STEP-1 ─ identifier + password                          */
/* ------------------------------------------------------------------ */
app.post('/login', accountGuard, async (req, res) => {
  const origin    = req.headers.origin;
  const appName   = getAppName(origin);
  const browser   = req.headers['user-agent'];
  const { identifier, password } = req.body || {};

  // 0️⃣ missing fields
  if (!identifier || !password) {
    logEntry('LOGIN_FAIL_MISSING_FIELDS', { identifier, origin, app: appName, browser });
    console.log('[LOGIN ERROR] Missing identifier or password');
    return res.status(400).json({ msg: 'missing fields' });
  }

  const idClean = identifier.trim().toLowerCase();
  console.log(`[LOGIN] Attempt for identifier="${idClean}"`);

  // 1️⃣ fetch user
  const { rows } = await pool.query(
    `SELECT * FROM users
      WHERE LOWER(username) = $1
         OR LOWER(email)    = $1`,
    [idClean]
  );
  const u = rows[0];

  // 2️⃣ user not found
  if (!u) {
    logEntry('LOGIN_FAIL_USER_NOT_FOUND', { identifier, origin, app: appName, browser });
    console.log(`[LOGIN ERROR] No user for identifier="${idClean}"`);
    await pool.query(
      `INSERT INTO login_failures (identifier, ip, ts)
       VALUES ($1,$2,$3)`,
      [idClean, req.ip, Date.now()]
    );
    return res.status(401).json({ msg: '❌ User not found' });
  }

  // 3️⃣ wrong password
  const ok = await bcrypt.compare(password, u.hash);
  if (!ok) {
    logEntry('LOGIN_FAIL_WRONG_PASSWORD', { uid: u.id, identifier, origin, app: appName, browser });
    console.log(`[LOGIN ERROR] Wrong password for user id=${u.id}`);
    await pool.query(
      `INSERT INTO login_failures (identifier, ip, ts)
       VALUES ($1,$2,$3)`,
      [idClean, req.ip, Date.now()]
    );
    return res.status(401).json({ msg: '❌ Wrong password' });
  }

  // 4️⃣ success → clear failures & unlock
  console.log(`[LOGIN] Credentials valid for user id=${u.id}`);
  await pool.query('DELETE FROM login_failures WHERE identifier = $1', [idClean]);
  await pool.query('UPDATE users SET locked_until = 0 WHERE id = $1', [u.id]);

  // 5️⃣ MFA bootstrap
  if (!u.mfasecret) {
    const secret = speakeasy.generateSecret({ issuer: ISSUER, name: u.username });
    await pool.query('UPDATE users SET mfasecret = $1 WHERE id = $2',
                     [secret.base32, u.id]);
    logEntry('MFA_SETUP_INIT', {
      uid: u.id, username: u.username, origin, app: appName, browser
    });
    const qrData = await qrcode.toDataURL(secret.otpauth_url);
    console.log(`[LOGIN] MFA setup for user id=${u.id}; secret (base32)=${secret.base32}`);
    return res.json({ mfaRequired: true, qrData });
  }

  // 6️⃣ otherwise just ask for the TOTP code
  console.log(`[LOGIN] MFA code requested for user id=${u.id}`);
  res.json({ mfaRequired: true });
});


/* ------------------------------------------------------------------ */
/* 2b)  Login STEP-2 ─ verify TOTP                                    */
/* ------------------------------------------------------------------ */
app.post('/verify-mfa', async (req, res) => {
  const origin  = req.headers.origin;
  const appName = getAppName(origin);
  const browser = req.headers['user-agent'];
  const { identifier, token } = req.body || {};

  // 0️⃣  Missing fields
  if (!identifier || !token) {
    logEntry('TOTP_FAIL_MISSING_FIELDS', { identifier, origin, app: appName, browser });
    console.log('[TOTP] Missing identifier or token');
    return res.status(400).json({ msg: 'missing fields' });
  }

  const idClean    = identifier.trim().toLowerCase();
  const tokenClean = token.trim();
  console.log(`[TOTP] Verifying for identifier="${idClean}", provided token="${tokenClean}"`);

  // 1️⃣  Fetch user, secret & role
  const { rows } = await pool.query(
    `SELECT id, username, mfasecret, role
       FROM users
      WHERE LOWER(username) = $1
         OR LOWER(email)    = $1`,
    [idClean]
  );
  const u = rows[0];
  if (!u) {
    logEntry('TOTP_FAIL_USER_NOT_FOUND', { identifier, origin, app: appName, browser });
    console.log('[TOTP] No user found for identifier');
    return res.status(401).json({ msg: 'user not found' });
  }

  console.log(`[TOTP] Using secret="${u.mfasecret}" for user id=${u.id}`);

  // 2️⃣  Dump the codes for prev/now/next windows
  const codePrev = speakeasy.totp({ secret: u.mfasecret, encoding: 'base32', time: Date.now() - 30000 });
  const codeNow  = speakeasy.totp({ secret: u.mfasecret, encoding: 'base32' });
  const codeNext = speakeasy.totp({ secret: u.mfasecret, encoding: 'base32', time: Date.now() + 30000 });
  console.log(`[TOTP] Codes → prev=${codePrev}, now=${codeNow}, next=${codeNext}`);

  // 3️⃣  Verify with ±1 window
  const verified = speakeasy.totp.verify({
    secret:   u.mfasecret,
    encoding: 'base32',
    token:    tokenClean,
    window:   1
  });
  console.log(`[TOTP] Verified? ${verified}`);

  if (!verified) {
    logEntry('TOTP_FAIL_BAD_TOKEN', { uid: u.id, username: u.username, origin, app: appName, browser });
    console.log('[TOTP] Bad token');
    return res.status(401).json({ msg: 'bad TOTP' });
  }

  // 4️⃣  Success → record event & sign JWT
  await pool.query(
    'INSERT INTO events (uid, ts, ip, ua) VALUES ($1,$2,$3,$4)',
    [u.id, Date.now(), req.ip, browser]
  );

  // ⇨ now sign + log returns both token & role
  const { token: jwtToken, role } = await signAndLog(u.id, req);

  // console.log(`[TOTP] Success for user id=${u.id}; issuing JWT`);
  // console.log('[verify-mfa] responding with →', { token: jwtToken, role });

  // ⇨ send both back
  res.json({ token: jwtToken, role });
});


/* ------------------------------------------------------------------ */
/* 3)  POST /refresh  – renew token                                   */
/* ------------------------------------------------------------------ */
app.post('/refresh', async (req, res) => {
  const origin  = req.headers.origin;
  const appName = getAppName(origin);
  const browser = req.headers['user-agent'];

  try {
    /* 0️⃣  Missing token in body? */
    const oldToken = req.body?.token;
    if (!oldToken) {
      logEntry('REFRESH_FAIL_MISSING_TOKEN', { origin, app: appName, browser });
      console.warn('⚠️  /refresh called without a token');
      return res.status(400).json({ msg: 'missing token' });
    }

    /* 1️⃣  Decode the old token (ignore expiration just to get the claims) */
    const { sub, role } = jwt.verify(oldToken, JWT_SECRET, { ignoreExpiration: true });

    /* 2️⃣  Issue a fresh JWT */
    const newToken = jwt.sign(
      { sub, role }, 
      JWT_SECRET, 
      { issuer: ISSUER, expiresIn: '30m' }
    );

    /* 3️⃣  Gather some logging context */
    const { rows: cntRows } = await db.query(
      'SELECT COUNT(*)::int AS cnt FROM events WHERE uid = $1',
      [sub]
    );
    const loginCount = cntRows[0].cnt;

    const { rows: uRows } = await db.query(
      'SELECT username FROM users WHERE id = $1',
      [sub]
    );
    const username = uRows[0]?.username || 'unknown';

    /* 4️⃣  Log success */
    logEntry('REFRESH_SUCCESS', {
      uid:        sub,
      username,
      role,
      origin,
      app:        appName,
      browser,
      loginCount,
      newToken
    });

    /* 5️⃣  Respond with both token + role */
    res.json({ token: newToken, role });

  } catch (err) {
    console.error('❌  Refresh token error:', err.message);
    logEntry('REFRESH_FAIL', { error: err.message, origin, app: appName, browser });
    res.status(400).json({ msg: 'invalid or expired token' });
  }
});

// -------------------------------------------------------------------
// 4)  Protected  (profile endpoints)          POSTGRESQL VERSION
// -------------------------------------------------------------------

// helper – run a single-row SELECT and give back obj|undefined
const one = async (text, params) => (await pool.query(text, params)).rows[0];

/* 4a) GET /profile & GET /me */
async function getProfile(req, res) {
  const origin  = req.headers.origin;
  const appName = getAppName(origin);
  const browser = req.headers['user-agent'];

  try {
    /* 0️⃣  Missing token? */
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      logEntry('PROFILE_FAIL_MISSING_TOKEN', { origin, app: appName, browser });
      console.warn('⚠️  GET /profile called without token');
      return res.status(401).json({ msg: 'missing token' });
    }

    /* 1️⃣  Verify & extract user id */
    const { sub } = jwt.verify(token, JWT_SECRET);

    /* 2️⃣  Fetch user fields we expose to the front-end */
    const user = await one(
      `SELECT
         username,
         email,
         department,
         role,
         idnumber AS "idNumber"
       FROM users
       WHERE id = $1`,
      [sub]
    );

    if (!user) {
      console.warn(`⚠️  /profile: no user row for id=${sub}`);
      return res.status(404).json({ msg: 'user not found' });
    }

    /* 3️⃣  Log and return */
    if (req.path === '/profile') {
      logEntry('PROFILE_FETCH', {
        uid: sub,
        app: appName,
        browser,
        origin
      });
    }
    
    console.log(`[PROFILE] Fetched profile for uid=${sub}:`, user);
    res.json(user);

  } catch (err) {
    console.error('❌  /profile error:', err.message);
    res.status(401).json({ msg: 'invalid or expired token' });
  }
}

app.get('/profile', getProfile);
app.get('/me',      getProfile);


/* 4b/4c) PUT /profile & PUT /me */
async function updateProfile(req, res) {
  const origin  = req.headers.origin;
  const appName = getAppName(origin);
  const browser = req.headers['user-agent'];

  try {
    /* 1️⃣  Verify & extract user id */
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      logEntry('PROFILE_FAIL_MISSING_TOKEN', { origin, app: appName, browser });
      console.warn('⚠️  PUT /profile called without token');
      return res.status(401).json({ msg: 'missing token' });
    }
    const { sub: userId } = jwt.verify(token, JWT_SECRET);

    /* 2️⃣  Pull new values from body */
    let {
      username   = '',
      email      = '',
      department = '',
      role       = '',
      idNumber   = ''
    } = req.body ?? {};

    username = username.trim();
    email    = email.trim().toLowerCase();

    /* 3️⃣  Uniqueness checks */
    const nameConflict = await one(
      `SELECT 1
         FROM users
        WHERE LOWER(username) = LOWER($1)
          AND id <> $2`,
      [username, userId]
    );
    if (nameConflict) {
      console.warn(`⚠️  Profile update blocked: username "${username}" already in use`);
      return res.status(409).json({ msg: 'username-taken' });
    }

    if (idNumber) {
      const idConflict = await one(
        `SELECT 1
           FROM users
          WHERE idnumber = $1
            AND id <> $2`,
        [idNumber, userId]
      );
      if (idConflict) {
        console.warn(`⚠️  Profile update blocked: idNumber "${idNumber}" already in use`);
        return res.status(409).json({ msg: 'idnumber-taken' });
      }
    }

    /* 4️⃣  Perform update */
    await pool.query(
      `UPDATE users
          SET username   = $1,
              email      = $2,
              department = $3,
              role       = $4,
              idnumber   = $5
        WHERE id = $6`,
      [username, email, department, role, idNumber, userId]
    );

    logEntry('PROFILE_UPDATE', {
      uid:           userId,
      updatedFields: { username, email, department, role, idNumber },
      app:           appName,
      browser
    });
    console.log(`[PROFILE_UPDATE] uid=${userId}`, { username, email, department, role, idNumber });

    /* 5️⃣  Fetch new record & return it */
    const updated = await one(
      `SELECT
         username,
         email,
         department,
         role,
         idnumber AS "idNumber"
       FROM users
       WHERE id = $1`,
      [userId]
    );

    res.json(updated);

  } catch (err) {
    console.error('❌  profile update failed:', err.message);
    res.status(500).json({ msg: 'profile-update-failed' });
  }
}

app.put('/profile', updateProfile);
app.put('/me',      updateProfile);


// -------------------------------------------------------------------
// 5)  Logout   – records an EVENT row + writes to structured logger
// -------------------------------------------------------------------
app.post('/logout', async (req, res) => {
  const origin  = req.headers.origin;
  const appName = getAppName(origin);
  const browser = req.headers['user-agent'];
  const token   = req.headers.authorization?.split(' ')[1];

  /* 0️⃣  Missing token? */
  if (!token) {
    logEntry('LOGOUT_FAIL_MISSING_TOKEN', { origin, app: appName, browser });
    console.warn('⚠️  /logout called without token');
    // still respond 200 so front-end can clear its state
    return res.json({ msg: 'logged out (no token)' });
  }

  try {
    /* 1️⃣  Verify JWT */
    const { sub } = jwt.verify(token, JWT_SECRET);

    /* 2️⃣  Fetch username/role for logging context */
    const user = await one(
      `SELECT username, role
         FROM users
        WHERE id = $1`,
      [sub]
    );

    /* 3️⃣  Decide logout context (admin vs regular) */
    const isAdmin       = user?.role === 'admin';
    const isAdminOrigin = origin?.startsWith('http://localhost:4001');
    const ctx           = isAdmin && isAdminOrigin
                          ? 'ADMIN_LOGOUT'
                          : 'LOGOUT';

    /* 4️⃣  Structured log entry */
    logEntry(ctx, {
      uid:       sub,
      username:  user?.username ?? 'unknown',
      role:      user?.role     ?? 'unknown',
      origin,
      app:       appName,
      browser
    });

    /* 5️⃣  Persist logout event */
    await pool.query(
      `INSERT INTO events (uid, ts, ip, ua)
       VALUES ($1,$2,$3,$4)`,
      [ sub, Date.now(),
        (req.headers['x-forwarded-for'] || req.ip)
          .split(',')[0].trim(),
        browser
      ]
    );

    console.log(`🔒  User ${user?.username || sub} logged out (${ctx})`);

  } catch (err) {
    /* 6️⃣  Token invalid/expired */
    logEntry('LOGOUT_FAIL_INVALID_TOKEN', { origin, app: appName, browser, error: err.message });
    console.error('❌  /logout JWT verify failed:', err.message);
    return res.status(401).json({ msg: 'invalid or expired token' });
  }

  /* 7️⃣  Always respond OK so client can un‐set its local auth state */
  res.json({ msg: 'logged out' });
});
// ──────────────────────────────────────────────────────────────
// OAuth2: Google
// ──────────────────────────────────────────────────────────────

// 1) Capture which app initiated the login
app.get(
  '/auth/google',
  (req, res, next) => {
    req.session.app = req.query.app || 'app1';
    next();
  },
  passport.authenticate('google', { scope: ['email', 'profile'] })
);

// 2) Handle the callback
app.get(
  '/auth/google/callback',
  passport.authenticate('google', {
    session: false,
    failureRedirect: 'http://localhost:3000/login'
  }),
  (req, res) => {
    const token = issueJwt(req.user.id, req.user.role || 'user');
    const app   = req.session.app || 'app1';
    const base  = app === 'app2' ? 'http://localhost:3001' : 'http://localhost:3000';
    const path  = req.user.needsSetup ? '/setup-profile' : '/sso-callback';

    res.redirect(`${base}${path}?token=${token}`);
  }
);

// ──────────────────────────────────────────────────────────────
// OAuth2: GitHub
// ──────────────────────────────────────────────────────────────

// 1) Capture which app initiated the login
app.get(
  '/auth/github',
  (req, res, next) => {
    req.session.app = req.query.app || 'app1';
    next();
  },
  passport.authenticate('github', { scope: ['user:email'] })
);

// 2) Handle the callback (note the correct path!)
app.get(
  '/auth/github/callback',
  passport.authenticate('github', {
    session: false,
    failureRedirect: 'http://localhost:3000/login'
  }),
  (req, res) => {
    const token = issueJwt(req.user.id, req.user.role || 'user');
    const app   = req.session.app || 'app1';
    const base  = app === 'app2' ? 'http://localhost:3001' : 'http://localhost:3000';
    const path  = req.user.needsSetup ? '/setup-profile' : '/sso-callback';

    res.redirect(`${base}${path}?token=${token}`);
  }
);

// -------------------------------------------------------------------
// ---  Admin Dashboard Routes  (PostgreSQL version)                ---
// -------------------------------------------------------------------

/**
 *  GET /admin/users   – list every account + first / last login
 *  (adminGuard has already validated the bearer-token)
 */
app.get('/admin/users', adminGuard, async (_req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        u.id,
        u.username,
        u.email,
        u.department,
        u.role,
        u.idnumber       AS "idNumber",
        u.locked_until,
        MIN(e.ts)        AS "firstLogin",
        MAX(e.ts)        AS "lastLogin"
      FROM users u
      LEFT JOIN events e ON e.uid = u.id
      GROUP BY u.id
    `);

    const result = rows.map(u => ({
      id:          u.id,
      username:    u.username,
      email:       u.email,
      department:  u.department,
      role:        u.role,
      idNumber:    u.idNumber,
      isLocked:    u.locked_until > Date.now(),
      firstLogin:  u.firstLogin ? new Date(Number(u.firstLogin)).toLocaleString() : null,
      lastLogin:   u.lastLogin  ? new Date(Number(u.lastLogin)).toLocaleString()  : null
    }));

    res.json(result);

  } catch (err) {
    console.error('❌  Failed to fetch users:', err.message);
    res.status(500).json({ msg: 'failed-to-fetch-users' });
  }
});


/**
 *  PUT /admin/user/:id   – update a single account
 */
app.put('/admin/user/:id', adminGuard, async (req, res) => {
  const origin   = req.headers.origin;
  const appName  = getAppName(origin);
  const browser  = req.headers['user-agent'];
  const userId   = req.params.id;

  const {
    username   = '',
    email      = '',
    department = '',
    role       = '',
    idNumber   = ''
  } = req.body ?? {};

  try {
    /* ---------- conflict checks ------------------------------------- */
    const { rows: userRows } = await pool.query(
      `SELECT 1
         FROM users
        WHERE username ILIKE $1
          AND id <> $2`,
      [username.trim(), userId]
    );
    if (userRows.length) return res.status(409).json({ msg: 'username-taken' });

    const { rows: idRows } = await pool.query(
      `SELECT 1
         FROM users
        WHERE idnumber = $1
          AND id <> $2`,
      [idNumber, userId]
    );
    if (idRows.length) return res.status(409).json({ msg: 'idnumber-taken' });

    /* ---------- perform update -------------------------------------- */
    await pool.query(
      `UPDATE users
          SET username   = $1,
              email      = $2,
              department = $3,
              role       = $4,
              idnumber   = $5
        WHERE id = $6`,
      [
        username.trim(),
        email.trim().toLowerCase(),
        department,
        role,
        idNumber,
        userId
      ]
    );

    /* ---------- who made the change? -------------------------------- */
    let actor = 'unknown';
    const token = req.headers.authorization?.split(' ')[1];
    if (token) {
      try {
        const { sub } = jwt.verify(token, JWT_SECRET);
        const adminRow = await pool.query(
          `SELECT username FROM users WHERE id = $1`,
          [sub]
        );
        actor = adminRow.rows[0]?.username ?? 'unknown';
      } catch (err) {
        console.error('❌  Failed to decode admin token:', err.message);
      }
    }

    logEntry('ADMIN_UPDATE', {
      by:            actor,
      targetId:      userId,
      updatedFields: { username, email, department, role, idNumber },
      app:           appName,
      browser
    });

    res.json({ msg: 'updated' });

  } catch (err) {
    console.error('❌  Failed to update user:', err.message);
    res.status(500).json({ msg: 'update-failed' });
  }
});


/**
 *  DELETE /admin/user/:id   – remove account (+ events)
 */
app.delete('/admin/user/:id', adminGuard, async (req, res) => {
  const origin   = req.headers.origin;
  const appName  = getAppName(origin);
  const browser  = req.headers['user-agent'];
  const targetId = req.params.id;

  try {
    // 1️⃣ fetch target’s username/role (for richer context)
    const { username: targetUser, role: targetRole } = 
      (await one(
        `SELECT username, role FROM users WHERE id = $1`,
        [targetId]
      )) || { username: 'unknown', role: 'unknown' };

    // 2️⃣ actually delete
    await pool.query(`DELETE FROM users  WHERE id = $1`, [targetId]);
    await pool.query(`DELETE FROM events WHERE uid = $1`, [targetId]);

    // 3️⃣ who performed the deletion?
    let actor = 'unknown';
    const token = req.headers.authorization?.split(' ')[1];
    if (token) {
      try {
        const { sub } = jwt.verify(token, JWT_SECRET);
        actor = (await one(`SELECT username FROM users WHERE id=$1`, [sub]))?.username || 'unknown';
      } catch {}
    }

    // 4️⃣ log the admin-delete event
    logEntry('ADMIN_DELETE', {
      by:           actor,
      targetId,
      targetUser,
      targetRole,
      origin,
      app:          appName,
      browser
    });

    res.json({ msg: 'deleted' });
  } catch (err) {
    console.error('❌  Failed to delete user:', err.message);
    res.status(500).json({ msg: 'delete-failed' });
  }
});

 
// --------------------------------------------------------------------
// ---------- debug & ping  (PostgreSQL version)  ---------------------
// --------------------------------------------------------------------

/**
 *  GET /debug/users – dump every row in users (dev-only!)
 */
app.get('/debug/users', async (_req, res) => {
    try {
      const { rows } = await pool.query('SELECT * FROM users ORDER BY username');
      res.json(rows);
    } catch (err) {
      console.error('❌  Failed to fetch users for debug:', err.message);
      res.status(500).json({ msg: 'debug-fetch-users-failed' });
    }
  });
  
  
  /**
   *  GET /debug/events – dump login / logout events (joined with usernames)
   */
  app.get('/debug/events', async (_req, res) => {
    try {
      const { rows } = await pool.query(`
        SELECT
          e.id,
          u.username,
          e.ts,
          e.ip,
          to_char(to_timestamp(e.ts / 1000), 'YYYY-MM-DD HH24:MI:SS') AS "timeLocal"
        FROM events e
        JOIN users  u ON u.id = e.uid
        ORDER BY e.id DESC
      `);
      res.json(rows);
    } catch (err) {
      console.error('❌  Failed to fetch events for debug:', err.message);
      res.status(500).json({ msg: 'debug-fetch-events-failed' });
    }
  });
  
  
// --------------------------------------------------------------------
// GET /debug/totp/:user – quickly generate the current TOTP for a user
//                     – returns prev/current/next so you can verify ±30 s
//                     – disables caching so you always get a fresh code
// --------------------------------------------------------------------
app.get('/debug/totp/:user', async (req, res) => {
  const identifier = req.params.user?.trim();
  if (!identifier) {
    return res.status(400).send('missing user');
  }

  try {
    // 🚫 disable any HTTP caching
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');

    // 1️⃣ fetch the secret (all-lowercase column name)
    const { rows } = await pool.query(
      `SELECT mfasecret AS secret
         FROM users
        WHERE username ILIKE $1
           OR email    ILIKE $1
        LIMIT 1`,
      [identifier]
    );
    if (!rows.length) {
      return res.status(404).send('no such user');
    }

    const { secret } = rows[0];
    const step = 30;                         // 30-second TOTP window
    const now  = Math.floor(Date.now() / 1000);

    // 2️⃣ compute codes for previous, current, and next window
    const prev    = speakeasy.totp({ secret, encoding: 'base32', time: now - step });
    const current = speakeasy.totp({ secret, encoding: 'base32', time: now });
    const next    = speakeasy.totp({ secret, encoding: 'base32', time: now + step });

    // 3️⃣ return them all so you can compare in your Authenticator app
    res.json({ prev, current, next });
  } catch (err) {
    console.error('❌  Failed to generate TOTP:', err.message);
    res.status(500).send('failed to generate TOTP');
  }
});


  
  /**
   *  Simple ping route
   */
  app.get('/ping', (_req, res) => res.send('pong'));
  
  
  // --------------------------------------------------------------------
  // ---------- start server  -------------------------------------------
  // --------------------------------------------------------------------
  app.listen(PORT, () =>
    console.log(`✅  Auth-server listening on http://localhost:${PORT}`)
  );
  

// ⚠️ TEMPORARY: one-shot route that creates the first admin user.
//     –  DELETE (or comment-out) after you have at least one admin.
//
// app.get('/debug/init-admin', async (_req, res) => {
//   const username   = 'khaireddine';
//   const password   = 'dammak30spl';
//   const email      = 'kheireddinedamak@gmail.com';
//   const department = 'security';
//   const role       = 'admin';
//   const idNumber   = '11153935';
//
//   try {
//     // 1️⃣  Does an account with that username already exist?
//     const { rows: existing } = await pool.query(
//       `SELECT id FROM users WHERE username ILIKE $1 LIMIT 1`,
//       [username]
//     );
//     if (existing.length)
//       return res.send('⚠️  Admin user already exists.');
//
//     // 2️⃣  Insert new admin user
//     const id   = uuid();
//     const hash = await bcrypt.hash(password, 10);
//
//     await pool.query(
//       `INSERT INTO users
//          (id, username, hash, email, department, role, idNumber)
//        VALUES ($1,$2,$3,$4,$5,$6,$7)`,
//       [id, username, hash, email, department, role, idNumber]
//     );
//
//     res.send(`✅  Admin user created →  ${username} / ${password}`);
//   } catch (err) {
//     console.error('❌  Failed to create admin user:', err.message);
//     res.status(500).send('failed to create admin');
//   }
// });
