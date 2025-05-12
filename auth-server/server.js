// --------------------------------------------------------------
//  auth-server/server.js   (ESM, PostgreSQL)
// --------------------------------------------------------------
import dotenv from 'dotenv';
dotenv.config();
import { fileURLToPath } from 'url';
import path from 'path';

// ESM (__dirname) shim
const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);
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
import fs from 'fs';
import https from 'https';
import helmet    from 'helmet';
import morgan    from 'morgan';
import bcrypt    from 'bcryptjs';
import jwt       from 'jsonwebtoken';
import speakeasy from 'speakeasy';
import qrcode    from 'qrcode';
import { v4 as uuid } from 'uuid';
import { parse as uuidParse } from 'uuid';
import fetch     from 'node-fetch';
import { Buffer } from 'buffer';
import { logEntry } from '../shared/logger.js';
import session from 'express-session';
import passport from './passport.js'; 
/* ── WebAuthn ─────────────────────────────── */
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from '@simplewebauthn/server';
import base64url from 'base64url';

/* ── fingerprint settings ─────────────────── */
const REG_CHAL_TTL = 300;   // 5 min
const AUTH_CHAL_TTL = 180;  // 3 min
const AUTH_TIMEOUT  = Number(process.env.WEBAUTHN_TIMEOUT) || 60000;
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
/* --- Lock-out parameters  ----------------------------------------- */
/* ------------------------------------------------------------------ */
const WINDOW_MS = 15 * 60_000;   // look at last 15 min
const LOCK_MS   = 15 * 60_000;   // lock for   15 min
const MAX_FAILS = 5;             // after 5 bad tries

/* ------------------------------------------------------------------ */
/* --- Helper: Map origin → app name -------------------------------- */
/* ------------------------------------------------------------------ */
function getAppName(origin) {
  switch (origin) {
    case 'https://localhost:3000': return 'App1';
    case 'https://localhost:3001': return 'App2';
    case 'https://localhost:4001': return 'AdminPanel';
    default:                      return origin;
  }
}
/* ------------------------------------------------------------------ */
/* --- challenge helpers -------------------------------------------- */
/* ------------------------------------------------------------------ */
async function setChallenge(uid, type, challenge, ttlSec) {
  await pool.query(`
    INSERT INTO fingerprint_challenges(user_id, type, challenge, expires_at)
    VALUES ($1,$2,$3,NOW() + ($4||' seconds')::interval)
    ON CONFLICT (user_id,type)
    DO UPDATE SET challenge   = EXCLUDED.challenge,
                  expires_at = EXCLUDED.expires_at`,
    [uid, type, challenge, ttlSec]);
}

async function popChallenge(uid, type) {
  const { rows } = await pool.query(
    `DELETE FROM fingerprint_challenges
        WHERE user_id=$1 AND type=$2 AND expires_at>NOW()
     RETURNING challenge`,
    [uid, type]);
  return rows[0]?.challenge || null;   // null if missing / expired
}
/* ------------------------------------------------------------------ */
/* --- Middleware: brute‑force / lock‑out guard --------------------- */
/* ------------------------------------------------------------------ */
async function accountGuard(req, res, next) {
  try {
    // 0️⃣ grab identifier (username/email)
    const identifier = (req.body.identifier || req.body.username || '')
                       .trim().toLowerCase();
    if (!identifier) return next();  // nothing to do without an identifier

    // 1️⃣ normalize client IP
    let clientIp = (req.headers['x-forwarded-for'] || req.ip)
                     .split(',')[0].trim();
    if (clientIp === '::1' || clientIp.startsWith('::ffff:')) {
      clientIp = '127.0.0.1';
    }
    // 2️⃣ check existing lock
    const lockRow = await pool.query(
      `SELECT locked_until FROM users
         WHERE LOWER(username) = $1
            OR LOWER(email)    = $1`,
      [identifier]
    );
    const lockedUntil = lockRow.rows[0]
      ? Number(lockRow.rows[0].locked_until)
      : 0;

      if (lockedUntil > Date.now()) {
        // Is it the far‑future sentinel (admin lock) or a 30‑min brute‑force lock?
        const isAdminLock = lockedUntil - Date.now() > LOCK_MS;
      
        if (isAdminLock) {
          logEntry('ADMIN_LOCK_HIT', {
            identifier,
            ip:      clientIp,
            app:     getAppName(req.headers.origin),
            browser: req.headers['user-agent']
          });
          return res
            .status(423)                       // 423 Locked
            .json({ msg: 'admin-locked' });    // <‑‑ flag for the client
        }
        // Otherwise it’s the normal 30‑minute lock‑out
        const unlockAt = lockedUntil;
        const lockAt   = unlockAt - LOCK_MS;
        logEntry('LOCKOUT_HIT', {
          identifier,
          ip:      clientIp,
          app:     getAppName(req.headers.origin),
          browser: req.headers['user-agent'],
          lockAt:  new Date(lockAt ).toISOString(),
          unlockAt:new Date(unlockAt).toISOString()
        });
        return res
          .status(423)
          .json({ msg: 'account-locked', unlock: unlockAt });
      }
    // 3️⃣ count recent failures
    const since = Date.now() - WINDOW_MS;
    const { rows } = await pool.query(
      `SELECT COUNT(*)::int AS cnt
         FROM login_failures
        WHERE identifier = $1
          AND ts > $2`,
      [identifier, since]
    );
    const fails = rows[0]?.cnt || 0;
    // 4️⃣ if too many failures, set a new lock
    if (fails >= MAX_FAILS) {
      const lockAt   = Date.now();
      const unlockAt = lockAt + LOCK_MS;

      await pool.query(
        `UPDATE users
            SET locked_until = $1
          WHERE LOWER(username) = $2
             OR LOWER(email)    = $2`,
        [unlockAt, identifier]
      );

      logEntry('LOCKOUT_SET', {
        identifier,
        ip:        clientIp,
        app:       getAppName(req.headers.origin),
        browser:   req.headers['user-agent'],
        lockAt:    new Date(lockAt).toISOString(),
        unlockAt:  new Date(unlockAt).toISOString()
      });
      return res
        .status(429)                       // 429 Too Many Requests
        .json({ msg: 'too-many-attempts', unlock: unlockAt });
    }
    logEntry('LOGIN_GATE_ALLOWED', {
      identifier,
      ip: clientIp,
      app: getAppName(req.headers.origin),
      browser: req.headers['user-agent'],
      timestamp: new Date().toISOString()
    });
    // ✅ all clear: proceed to password check
    next();

  } catch (err) {
    console.error('accountGuard error:', err);
    res.status(500).json({ msg: 'internal-error' });
  }
}
/* ------------------------------------------------------------------ */
/* --- Middleware: admin-only guard --------------------------------- */
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
  logEntry('LOGIN_ISSUED', {
    uid,
    username:   user.username,
    role:       user.role,
    origin,
    app:        getAppName(origin),
    browser:    req.headers['user-agent'],
    ip: (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim(),
    loginCount,
    tokenTail: token.slice(-6),
    mfaUsed: true,               
    fingerprintUsed: false,      
    loginMethod: 'password+totp',
    timestamp: new Date().toISOString()
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
/* ---------- Express setup ----------------------------------------- */
/* ------------------------------------------------------------------ */
const app = express();
app.use(cors({
  origin: [
    'https://localhost:3000', // App1
    'https://localhost:3001', // App2
    'https://localhost:4001'  // Admin Panel
  ],
  credentials: true,
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization', 'X-Flow-Source']
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
  cookie: { secure: true } 
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
      logEntry('REGISTER_FAIL_USERNAME', { username, origin, app: appName, browser ,ip: (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim(),timestamp: new Date().toISOString()});
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
      logEntry('REGISTER_FAIL_IDNUMBER', { idNumber, origin, app: appName, browser ,ip: (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim(),timestamp: new Date().toISOString()});
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
      // console.log('📝 Kickbox response for', email, ':', kb);
      logEntry('EMAIL_VERIFY', {
        email,
        result:     kb.result,
        reason:     kb.reason,
        disposable: kb.disposable,
        role:       kb.role,
        free:       kb.free,
        app:        appName,
        browser,
        ip: (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim(),
        timestamp: new Date().toISOString()
      });

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
          browser,
          ip: (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim(),
          timestamp: new Date().toISOString()
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
    origin, app: appName, browser,
    ip: (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim(),
    timestamp: new Date().toISOString()
  });

  /* 5️⃣  Debug: display the newly-created user */
  {
    const { rows } = await pool.query(
      `SELECT id, username, email, department, role, idnumber AS "idNumber"
         FROM users
        WHERE id = $1`,
      [uid]
    );
    // console.log('🆕  New user registered:', rows[0]);
  }
  /* 6️⃣  Respond to client with a signed JWT */
  const { token, role: userRole } = await signAndLog(uid, req);
  return res.json({ token, role: userRole });
});
/* ------------------------------------------------------------------ */
/* setup-profile                                                      */
/* ------------------------------------------------------------------ */
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
      ip: (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim(),
      browser: req.headers['user-agent'],
      timestamp: new Date().toISOString()
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
/* ---------------------fingerprint--------------------------------- */
/* ------------------------------------------------------------------ */
/* 1️⃣  Registration OPTIONS — send browser the “create credential”    */
/* ------------------------------------------------------------------ */
app.get('/fingerprint/register/options', async (req, res) => {
    const flowSource = req.headers['x-flow-source'] || 'dashboard';
  // console.log('📥 /fingerprint/register/options');
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    logEntry('FINGERPRINT_REG_FAIL_TOKEN', {
      reason: 'missing Authorization header',
      ip: (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim(),
      origin: req.headers.origin,
      timestamp: new Date().toISOString()
    });
    return res.status(401).json({ msg: 'Missing Authorization token' });
  }

  const token = authHeader.split(' ')[1];
  let payload;
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    console.error('❌ Invalid token:', err.message);
    logEntry('FINGERPRINT_REG_FAIL_TOKEN', {
      reason: 'invalid or expired token',
      ip: (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim(),
      origin: req.headers.origin,
      timestamp: new Date().toISOString()
    });
    return res.status(401).json({ msg: 'Invalid or expired token' });
  }

  const uid = payload.sub;
  // console.log('🔐 Verified token for UID:', uid);

  const { rows } = await pool.query('SELECT username FROM users WHERE id = $1', [uid]);
  if (!rows.length) {
    logEntry('FINGERPRINT_REG_FAIL_DB_USER', {
      uid,
      reason: 'user not found',
      ip: (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim(),
      origin: req.headers.origin,
      timestamp: new Date().toISOString()
    });
    return res.status(404).json({ msg: 'User not found' });
  }

  const { username } = rows[0];
  // console.log('👤 Found username:', username);

  const userID = Buffer.from(uuidParse(uid)); // ✅ Raw UUID (16-byte Buffer)
  // console.log('🧬 userID (Buffer):', userID);

  let options;
  try {
    options = await generateRegistrationOptions({
      rpName: 'AI-SSO',
      rpID: process.env.RP_ID,
      userID,
      userName: username,
      timeout: 60000,
      attestationType: 'none',
      authenticatorSelection: {
        authenticatorAttachment: 'cross-platform',
        residentKey: 'preferred',
        userVerification: 'required',
      },
      extensions: { credProps: true },
    });
  } catch (err) {
    console.error('❌ Failed to generate registration options:', err.message);
    logEntry('FINGERPRINT_REG_FAIL_GENERATE_OPTIONS', {
      uid,
      username,
      error: err.message,
      ip: (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim(),
      origin: req.headers.origin,
      timestamp: new Date().toISOString()
    });
    return res.status(500).json({ msg: 'Failed to generate registration options' });
  }

  // console.log('🔍 Registration challenge:', options.challenge);

  if (!options.challenge) {
    logEntry('FINGERPRINT_REG_FAIL_NO_CHALLENGE', {
      uid,
      username,
      ip: (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim(),
      origin: req.headers.origin,
      timestamp: new Date().toISOString()
    });
    return res.status(500).json({ msg: 'Challenge missing in options' });
  }
  
  try {
    await setChallenge(uid, 'reg', options.challenge, 300); // 5 min TTL
  } catch (err) {
    console.error('❌ Failed to save challenge:', err.message);
    logEntry('FINGERPRINT_REG_FAIL_SAVE_CHAL', {
      uid,
      username,
      error: err.message,
      ip: (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim(),
      origin: req.headers.origin,
      timestamp: new Date().toISOString()
    });
    return res.status(500).json({ msg: 'Failed to save challenge' });
  }

  logEntry('FINGERPRINT_REG_START', {
    uid,
    username,
    app: getAppName(req.headers.origin),
    origin: req.headers.origin,
    browser: req.headers['user-agent'],
    ip: (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim(),
    flowSource,
    timestamp: new Date().toISOString()
  });

  return res.json(options);
});
/* ------------------------------------------------------------------ */
/* 2️⃣  Registration VERIFY — consume attestation & save credential    */
/* ------------------------------------------------------------------ */
app.post('/fingerprint/register/verify', async (req, res) => {
  const flowSource = req.headers['x-flow-source'] || 'dashboard';
  // 1️⃣ Auth + challenge
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    logEntry('FINGERPRINT_REG_VERIFY_FAIL', {
      reason: 'missing token',
      ip: (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim(),
      timestamp: new Date().toISOString()
    });
    return res.status(401).json({ verified: false, msg: 'Missing token' });
  }

  let payload;
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    logEntry('FINGERPRINT_REG_VERIFY_FAIL', {
      reason: 'invalid or expired token',
      ip: (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim(),
      timestamp: new Date().toISOString()
    });
    return res.status(401).json({ verified: false, msg: 'Invalid token' });
  }
  const uid = payload.sub;

  const expectedChallenge = await popChallenge(uid, 'reg');
  if (!expectedChallenge) {
    logEntry('FINGERPRINT_REG_VERIFY_FAIL', {
      uid,
      reason: 'missing or expired challenge',
      timestamp: new Date().toISOString()
    });
    return res.status(400).json({ verified: false, msg: 'No matching or expired challenge' });
  }

  const origin = req.headers.origin;
  if (!origin) {
    logEntry('FINGERPRINT_REG_VERIFY_FAIL', {
      uid,
      reason: 'missing origin header',
      timestamp: new Date().toISOString()
    });
    return res.status(400).json({ verified: false, msg: 'Missing Origin header' });
  }

  // 2️⃣ Get attestation
  const attestationResponse = req.body.attestation ?? req.body;

  // 3️⃣ Call the verifier
  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: attestationResponse,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: process.env.RP_ID,
      requireUserVerification: true,
    });
  } catch (err) {
    console.error('🛑 verifyRegistrationResponse error:', err);
    logEntry('FINGERPRINT_REG_VERIFY_FAIL', {
      uid,
      reason: 'verifier error',
      error: err.message,
      timestamp: new Date().toISOString()
    });
    return res.status(400).json({ verified: false, msg: err.message });
  }

  if (!verification.verified) {
    logEntry('FINGERPRINT_REG_VERIFY_FAIL', {
      uid,
      reason: 'attestation not verified',
      timestamp: new Date().toISOString()
    });
    return res.status(400).json({ verified: false, msg: 'Attestation not verified' });
  }

  const {
    credential: {
      id: credentialID,
      publicKey,
      counter,
      transports = []
    }
  } = verification.registrationInfo;

  const credentialRecord = {
    id:         credentialID,
    publicKey:  base64url.encode(Buffer.from(publicKey)),
    counter,
    transports,
  };

  try {
    await pool.query(
      `UPDATE users
         SET fingerprint_registered    = TRUE,
             fingerprint_registered_at = NOW(),
             fingerprint_credential    = $1
       WHERE id = $2`,
      [credentialRecord, uid]
    );
  } catch (err) {
    console.error('🛑 DB error saving credential:', err);
    logEntry('FINGERPRINT_REG_VERIFY_FAIL', {
      uid,
      reason: 'DB error saving credential',
      error: err.message,
      timestamp: new Date().toISOString()
    });
    return res.status(500).json({ verified: false, msg: 'Database error' });
  }

  logEntry('FINGERPRINT_REG_VERIFIED', {
    uid,
    credentialID,
    app: getAppName(origin),
    origin,
    browser: req.headers['user-agent'],
    ip: (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim(),
    flowSource,
    timestamp: new Date().toISOString()
  });

  console.log('✅ Stored credential ID:', credentialID);
  return res.json({ verified: true });
});
/* ------------------------------------------------------------------ */
/* 3️⃣  Authentication OPTIONS — tell browser which credential to use   */
/* ------------------------------------------------------------------ */
app.get('/fingerprint/auth/options', async (req, res) => {
  const username = req.query.username;
  if (!username) {
    logEntry('FINGERPRINT_AUTH_OPTIONS_FAIL', {
      reason: 'missing username',
      timestamp: new Date().toISOString()
    });
    return res.status(400).json({ msg: 'username required' });
  }

  // 1️⃣ Fetch user and saved credential
  const { rows } = await pool.query(
    `SELECT id, fingerprint_credential
       FROM users
      WHERE LOWER(username) = LOWER($1)
         OR LOWER(email) = LOWER($1)`,
    [username]
  );

  if (!rows.length || !rows[0].fingerprint_credential) {
    logEntry('FINGERPRINT_AUTH_OPTIONS_FAIL', {
      username,
      reason: 'no fingerprint registered',
      timestamp: new Date().toISOString()
    });
    return res.status(404).json({ msg: 'No fingerprint registered' });
  }

  const { id: userId, fingerprint_credential } = rows[0];
  const { id: credIdB64, transports = ['internal', 'hybrid'] } = fingerprint_credential;

  // ✅ Validate: credential ID must be base64url string
  if (typeof credIdB64 !== 'string') {
    logEntry('FINGERPRINT_AUTH_OPTIONS_FAIL', {
      userId,
      reason: 'invalid credential ID format',
      timestamp: new Date().toISOString()
    });
    return res.status(500).json({ msg: 'Stored credential ID is invalid' });
  }

  // 2️⃣ Define allowCredentials array properly
  const allowCredentials = [{
    id: credIdB64,
    type: 'public-key',
    transports: transports,
  }];

  // 3️⃣ Generate authentication options
  const opts = await generateAuthenticationOptions({
    rpID: process.env.RP_ID,
    timeout: 60000,
    userVerification: 'required',
    allowCredentials,
  });

  // 4️⃣ Save the challenge as usual
  await setChallenge(userId, 'auth', opts.challenge, 10 * 60); // or AUTH_CHAL_TTL

  logEntry('FINGERPRINT_AUTH_OPTIONS_SENT', {
    userId,
    username,
    transports,
    challenge: opts.challenge,
    timestamp: new Date().toISOString()
  });

  return res.json(opts);
});
/* ------------------------------------------------------------------ */
/* 4️⃣  Authentication VERIFY — check the browser’s assertion & login   */
/* ------------------------------------------------------------------ */
app.post('/fingerprint/auth/verify', async (req, res) => {
  const assertionResponse = req.body.assertion ?? req.body;

  // 1️⃣ Normalize and compare ID
  const rawIdBuf = base64url.toBuffer(assertionResponse.rawId);
  const credIdB64 = base64url.encode(rawIdBuf);

  // 2️⃣ Load stored credential
  const { rows } = await pool.query(
    `SELECT id AS "userId", fingerprint_credential FROM users WHERE fingerprint_credential->>'id' = $1`,
    [credIdB64]
  );

  if (!rows.length) {
    logEntry('FINGERPRINT_AUTH_VERIFY_FAIL', {
      reason: 'unknown credential',
      credIdB64,
      timestamp: new Date().toISOString()
    });
    return res.status(404).json({ verified: false, msg: 'Unknown credential' });
  }

  const { userId, fingerprint_credential } = rows[0];
  const { publicKey: pubKeyB64, counter, transports = [] } = fingerprint_credential;

  const credentialPublicKey = base64url.toBuffer(pubKeyB64);

  // 3️⃣ Pop expected challenge
  const expectedChallenge = await popChallenge(userId, 'auth');
  if (!expectedChallenge) {
    logEntry('FINGERPRINT_AUTH_VERIFY_FAIL', {
      userId,
      reason: 'challenge expired or missing',
      timestamp: new Date().toISOString()
    });
    return res.status(400).json({ verified: false, msg: 'challenge-expired' });
  }

  // 4️⃣ Build options
  const opts = {
    response: {
      ...assertionResponse,
      rawId: base64url.encode(rawIdBuf),
      id: base64url.encode(rawIdBuf),
    },
    expectedChallenge,
    expectedOrigin: req.headers.origin,
    expectedRPID: process.env.RP_ID,
    credential: {
      id: rawIdBuf,
      publicKey: new Uint8Array(credentialPublicKey),
      counter,
      transports,
    },
    requireUserVerification: true,
  };

  // 6️⃣ Verify
  let verification;
  try {
    verification = await verifyAuthenticationResponse(opts);
    console.log('✅ Verification result:', verification);
  } catch (err) {
    console.error('🛑 Verification failed:', err);
    logEntry('FINGERPRINT_AUTH_VERIFY_FAIL', {
      userId,
      reason: 'verifier error',
      error: err.message,
      timestamp: new Date().toISOString()
    });
    return res.status(400).json({ verified: false, msg: err.message });
  }

  if (!verification.verified) {
    logEntry('FINGERPRINT_AUTH_VERIFY_FAIL', {
      userId,
      reason: 'assertion not verified',
      timestamp: new Date().toISOString()
    });
    return res.status(400).json({ verified: false, msg: 'Assertion not verified' });
  }

  // 7️⃣ Update counter and return JWT
  await pool.query(
    `UPDATE users SET fingerprint_credential = jsonb_set(fingerprint_credential, '{counter}', to_jsonb($1::int)) WHERE id = $2`,
    [verification.authenticationInfo.newCounter, userId]
  );

  logEntry('FINGERPRINT_AUTH_SUCCESS', {
    userId,
    loginMethod: 'webauthn',
    fingerprintUsed: true,
    timestamp: new Date().toISOString()
  });

  const { token, role } = await signAndLog(userId, req);
  return res.json({ verified: true, token, role });
});
/* ------------------------------------------------------------------ */
/* 2a)  Login STEP‑1 ─ identifier + password                          */
/* ------------------------------------------------------------------ */
app.post('/login', accountGuard, async (req, res) => {
  const origin      = req.headers.origin;
  const appName     = getAppName(origin);
  const browser     = req.headers['user-agent'];
  const { identifier = '', password = '' } = req.body || {};

  // 0️⃣ missing fields
  if (!identifier || !password) {
    logEntry('LOGIN_FAIL_MISSING_FIELDS', { identifier, origin, app: appName, browser,ip: (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim(),timestamp: new Date().toISOString() });
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

  // 2️⃣ user not found → record failure & maybe lock
  if (!u) {
    await recordFailureAndLock(idClean, req, 'LOGIN_FAIL_USER_NOT_FOUND');
    return res.status(401).json({ msg: '❌ User not found' });
  }

  // 3️⃣ still locked? (double‑check)
  if (Number(u.locked_until) > Date.now()) {
    const unlockAt = Number(u.locked_until);
    return res.status(423).json({ msg: 'account-locked', unlock: unlockAt });
  }

  // 4️⃣ wrong password → record failure & maybe lock
  const match = await bcrypt.compare(password, u.hash);
  if (!match) {
    await recordFailureAndLock(idClean, req, 'LOGIN_FAIL_WRONG_PASSWORD', u.id);
    return res.status(401).json({ msg: '❌ Wrong password' });
  }
  // 5️⃣ success → clear failures, clear expired lock only
  console.log(`[LOGIN] Credentials valid for user id=${u.id}`);
  await pool.query(`DELETE FROM login_failures WHERE identifier = $1`, [idClean]);
  if (Number(u.locked_until) < Date.now()) {
    await pool.query(`UPDATE users SET locked_until = 0 WHERE id = $1`, [u.id]);
  }
  // 6️⃣ If user has enrolled a fingerprint, skip TOTP and require WebAuthn
  if (u.fingerprint_registered) {
    logEntry('LOGIN_FINGERPRINT_REQUIRED', {
      uid:        u.id,
      identifier: idClean,
      origin,
      app:        appName,
      browser,
      ip: (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim(),
      timestamp: new Date().toISOString()
    });
    // Front-end will see this and launch the WebAuthn flow
    return res.json({ fingerprintRequired: true });
  }

  // 7️⃣ Otherwise, continue your existing TOTP flow…
  // 7a) First-time MFA setup?
  if (!u.mfasecret) {
    const secret = speakeasy.generateSecret({ issuer: ISSUER, name: u.username });
    await pool.query(`UPDATE users SET mfasecret = $1 WHERE id = $2`, [secret.base32, u.id]);
    logEntry('MFA_SETUP_INIT', { uid: u.id, username: u.username, origin, app: appName, browser });
    const qrData = await qrcode.toDataURL(secret.otpauth_url);
    return res.json({ mfaRequired: true, qrData });
  }

  // 7b) Existing TOTP request
  console.log(`[LOGIN] MFA code requested for user id=${u.id}`);
  logEntry('TOTP_REQUESTED', {
    uid: u.id,
    username: u.username,
    origin,
    app: appName,
    browser,
    ip: (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim(),
    timestamp: new Date().toISOString()
  });

  res.json({ mfaRequired: true });
});
/* ------------------------------------------------------------------ */
/* helper: record a failed login, then lock if threshold reached      */
/* ------------------------------------------------------------------ */
async function recordFailureAndLock(identifier, req, eventType, uid = null) {
  const browser = req.headers['user-agent'];
  const origin  = req.headers.origin;
  const appName = getAppName(origin);
  const ip = (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim();
  const timestamp = new Date().toISOString();

  // log the failure event
  logEntry(eventType, {
    uid,
    identifier,
    origin,
    app: appName,
    browser,
    ip,
    timestamp
  });

  // insert failure
  await pool.query(
    `INSERT INTO login_failures (identifier, ip, ts)
     VALUES ($1, $2, $3)`,
    [identifier, req.ip, Date.now()]
  );

  // count recent failures
  const since = Date.now() - WINDOW_MS;
  const { rows } = await pool.query(
    `SELECT COUNT(*)::int AS cnt
       FROM login_failures
      WHERE identifier = $1
        AND ts > $2`,
    [identifier, since]
  );
  const fails = rows[0].cnt;

  // if over the limit and we have a valid user id, lock the account
  if (fails >= MAX_FAILS && uid) {
    const lockAt   = Date.now();
    const unlockAt = lockAt + LOCK_MS;

    await pool.query(
      `UPDATE users SET locked_until = $1 WHERE id = $2`,
      [unlockAt, uid]
    );

    logEntry('LOCKOUT_SET', {
      identifier,
      uid,
      app: appName,
      browser,
      ip,
      lockAt: new Date(lockAt).toISOString(),
      unlockAt: new Date(unlockAt).toISOString(),
      timestamp
    });
  }
}
/* ------------------------------------------------------------------ */
/* 2b)  Login STEP-2 ─ verify TOTP                                    */
/* ------------------------------------------------------------------ */
app.post('/verify-mfa', async (req, res) => {
  const origin  = req.headers.origin;
  const appName = getAppName(origin);
  const browser = req.headers['user-agent'];
  const ip = (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim();
  const timestamp = new Date().toISOString();

  const { identifier, token } = req.body || {};

  // 0️⃣  Missing fields
  if (!identifier || !token) {
    logEntry('TOTP_FAIL_MISSING_FIELDS', { identifier, origin, app: appName, browser, ip, timestamp });
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
    logEntry('TOTP_FAIL_USER_NOT_FOUND', { identifier, origin, app: appName, browser, ip, timestamp });
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
    logEntry('TOTP_FAIL_BAD_TOKEN', {
      uid: u.id,
      username: u.username,
      origin,
      app: appName,
      browser,
      ip,
      timestamp
    });
    console.log('[TOTP] Bad token');
    return res.status(401).json({ msg: 'bad TOTP' });
  }

  // 4️⃣  Success → record event & sign JWT
  await pool.query(
    'INSERT INTO events (uid, ts, ip, ua) VALUES ($1,$2,$3,$4)',
    [u.id, Date.now(), req.ip, browser]
  );

  const { token: jwtToken, role } = await signAndLog(u.id, req);
  return res.json({ token: jwtToken, role });
});
/* ------------------------------------------------------------------ */
/* 3)  POST /refresh  – renew token                                   */
/* ------------------------------------------------------------------ */
app.post('/refresh', async (req, res) => {
  const origin  = req.headers.origin;
  const appName = getAppName(origin);
  const browser = req.headers['user-agent'];
  const ip = (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim();
  const timestamp = new Date().toISOString();

  try {
    /* 0️⃣  Missing token in body? */
    const oldToken = req.body?.token;
    if (!oldToken) {
      logEntry('REFRESH_FAIL_MISSING_TOKEN', { origin, app: appName, browser, ip, timestamp });
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
      uid: sub,
      username,
      role,
      origin,
      app: appName,
      browser,
      ip,
      timestamp,
      loginCount,
      tokenTail: newToken.slice(-6)
    });

    /* 5️⃣  Respond with both token + role */
    res.json({ token: newToken, role });

  } catch (err) {
    console.error('❌  Refresh token error:', err.message);
    logEntry('REFRESH_FAIL', {
      error: err.message,
      origin,
      app: appName,
      browser,
      ip,
      timestamp
    });
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
      logEntry('PROFILE_FAIL_MISSING_TOKEN', { origin, app: appName, browser, ip: (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim(),timestamp: new Date().toISOString()});
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
         idnumber AS "idNumber",
         fingerprint_registered
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
        origin,
        ip: (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim(),
        timestamp: new Date().toISOString()
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
      logEntry('PROFILE_FAIL_MISSING_TOKEN', { origin, app: appName, browser,ip: (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim(),timestamp: new Date().toISOString() });
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
      browser,
      ip: (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim(),
      timestamp: new Date().toISOString()
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
  const origin    = req.headers.origin;
  const appName   = getAppName(origin);
  const browser   = req.headers['user-agent'];
  const token     = req.headers.authorization?.split(' ')[1];
  const ip        = (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim();
  const timestamp = new Date().toISOString();

  /* 0️⃣  Missing token? */
  if (!token) {
    logEntry('LOGOUT_FAIL_MISSING_TOKEN', {
      origin,
      app: appName,
      browser,
      ip,
      timestamp
    });
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
    const isAdminOrigin = origin?.startsWith('https://localhost:4001');
    const ctx           = isAdmin && isAdminOrigin
                          ? 'ADMIN_LOGOUT'
                          : 'LOGOUT';

    /* 4️⃣  Structured log entry */
    logEntry(ctx, {
      uid:      sub,
      username: user?.username ?? 'unknown',
      role:     user?.role     ?? 'unknown',
      origin,
      app: appName,
      browser,
      ip,
      timestamp
    });

    /* 5️⃣  Persist logout event */
    await pool.query(
      `INSERT INTO events (uid, ts, ip, ua)
       VALUES ($1,$2,$3,$4)`,
      [ sub, Date.now(), ip, browser ]
    );

    console.log(`🔒  User ${user?.username || sub} logged out (${ctx})`);

  } catch (err) {
    /* 6️⃣  Token invalid/expired */
    logEntry('LOGOUT_FAIL_INVALID_TOKEN', {
      origin,
      app: appName,
      browser,
      ip,
      timestamp,
      error: err.message
    });
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
    failureRedirect: 'https://localhost:3000/login'
  }),
  (req, res) => {
    const token     = issueJwt(req.user.id, req.user.role || 'user');
    const app       = req.session.app || 'app1';
    const base      = app === 'app2' ? 'https://localhost:3001' : 'https://localhost:3000';
    const path      = req.user.needsSetup ? '/setup-profile' : '/sso-callback';
    const redirect  = `${base}${path}?token=${token}`;
    const timestamp = new Date().toISOString();

    logEntry('OAUTH_LOGIN_SUCCESS', {
      uid: req.user.id,
      username: req.user.username,
      provider: 'google',
      app,
      redirectTo: redirect,
      timestamp
    });

    res.redirect(redirect);
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
// 2) Handle the callback
app.get(
  '/auth/github/callback',
  passport.authenticate('github', {
    session: false,
    failureRedirect: 'https://localhost:3000/login'
  }),
  (req, res) => {
    const token     = issueJwt(req.user.id, req.user.role || 'user');
    const app       = req.session.app || 'app1';
    const base      = app === 'app2' ? 'https://localhost:3001' : 'https://localhost:3000';
    const path      = req.user.needsSetup ? '/setup-profile' : '/sso-callback';
    const redirect  = `${base}${path}?token=${token}`;
    const timestamp = new Date().toISOString();

    logEntry('OAUTH_LOGIN_SUCCESS', {
      uid: req.user.id,
      username: req.user.username,
      provider: 'github',
      app,
      redirectTo: redirect,
      timestamp
    });

    res.redirect(redirect);
  }
);
// ──────────────────────────────────────────────────────────────────
// ── Admin Dashboard Routes (PostgreSQL + JWT.log)              ──
// ──────────────────────────────────────────────────────────────────
// 1) LIST USERS
app.get('/admin/users', adminGuard, async (req, res) => {
  res.set('Cache-Control', 'no-store');
  const token = req.headers.authorization?.split(' ')[1] || 'no-token';
  fs.appendFileSync(
    'JWT.log',
    `${new Date().toISOString()} [GET /admin/users] token: ${token}\n`
  );

  try {
    const { rows } = await pool.query(`
      SELECT
        u.id,
        u.username,
        u.email,
        u.department,
        u.role,
        u.idnumber       AS "idNumber",
        u.fingerprint_registered,
        u.locked_until,
        MIN(e.ts)        AS "firstLogin",
        MAX(e.ts)        AS "lastLogin"
      FROM users u
      LEFT JOIN events e ON e.uid = u.id
      GROUP BY u.id,
      u.username,
      u.email,
      u.department,
      u.role,
      u.idnumber,
      u.fingerprint_registered,
      u.locked_until
    `);

    const users = rows.map(u => ({
      id:         u.id,
      username:   u.username,
      email:      u.email,
      department: u.department,
      role:       u.role,
      idNumber:   u.idNumber,
      fingerprint_registered: u.fingerprint_registered,
      locked_until: Number(u.locked_until),
      isLocked:   Number(u.locked_until) > Date.now(),
      firstLogin: u.firstLogin
                    ? new Date(Number(u.firstLogin)).toLocaleString()
                    : null,
      lastLogin:  u.lastLogin
                    ? new Date(Number(u.lastLogin)).toLocaleString()
                    : null
    }));

    res.json(users);

  } catch (err) {
    console.error('❌ Failed to fetch users:', err.message);
    res.status(500).json({ msg: 'failed-to-fetch-users' });
  }
});
// 2) UPDATE USER
app.put('/admin/user/:id', adminGuard, async (req, res) => {
  const userId   = req.params.id;
  const origin   = req.headers.origin;
  const appName  = getAppName(origin);
  const browser  = req.headers['user-agent'];
  const { username = '', email = '', department = '', role = '', idNumber = '' } = req.body ?? {};

  try {
    // Conflict checks
    let q = await pool.query(
      `SELECT 1 FROM users WHERE username ILIKE $1 AND id <> $2`,
      [username.trim(), userId]
    );
    if (q.rows.length) return res.status(409).json({ msg: 'username-taken' });

    q = await pool.query(
      `SELECT 1 FROM users WHERE idnumber = $1 AND id <> $2`,
      [idNumber, userId]
    );
    if (q.rows.length) return res.status(409).json({ msg: 'idnumber-taken' });

    // Perform update
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

    // Who performed it?
    const token = req.headers.authorization?.split(' ')[1] || '';
    let actor = 'unknown';
    if (token) {
      try {
        const { sub } = jwt.verify(token, JWT_SECRET);
        const ar = await pool.query(
          `SELECT username FROM users WHERE id = $1`,
          [sub]
        );
        actor = ar.rows[0]?.username || 'unknown';
      } catch (e) {
        console.error('❌ Failed to decode admin token:', e.message);
      }
    }

    // Log to JWT.log
    fs.appendFileSync(
      'JWT.log',
      `${new Date().toISOString()} [PUT /admin/user/${userId}] token: ${token} actor: ${actor}\n`
    );

    logEntry('ADMIN_UPDATE', {
      by:            actor,
      targetId:      userId,
      updatedFields: { username, email, department, role, idNumber },
      app:           appName,
      browser,
      ip: (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim(),
      timestamp: new Date().toISOString()
    });

    res.json({ msg: 'updated' });

  } catch (err) {
    console.error('❌ Failed to update user:', err.message);
    res.status(500).json({ msg: 'update-failed' });
  }
});
// 3) DELETE USER
app.delete('/admin/user/:id', adminGuard, async (req, res) => {
  const targetId = req.params.id;
  const origin   = req.headers.origin;
  const browser  = req.headers['user-agent'];
  const token    = req.headers.authorization?.split(' ')[1] || '';

  // Decode actor
  let actor = 'unknown';
  try {
    const { sub } = jwt.verify(token, JWT_SECRET);
    actor = (await one(
      `SELECT username FROM users WHERE id = $1`,
      [sub]
    ))?.username || 'unknown';
  } catch {}

  // Log to JWT.log
  fs.appendFileSync(
    'JWT.log',
    `${new Date().toISOString()} [DELETE /admin/user/${targetId}] token: ${token} actor: ${actor}\n`
  );

  try {
    // Fetch target details
    const targ = await one(
      `SELECT username, role FROM users WHERE id = $1`,
      [targetId]
    ) || { username: 'unknown', role: 'unknown' };

    // Delete
    await pool.query(`DELETE FROM users  WHERE id = $1`, [targetId]);
    await pool.query(`DELETE FROM events WHERE uid = $1`, [targetId]);

    logEntry('ADMIN_DELETE', {
      by:           actor,
      targetId,
      targetUser:   targ.username,
      targetRole:   targ.role,
      origin,
      app:          getAppName(origin),
      browser,
      ip: (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim(),
      timestamp: new Date().toISOString()
    });

    res.json({ msg: 'deleted' });

  } catch (err) {
    console.error('❌ Failed to delete user:', err.message);
    res.status(500).json({ msg: 'delete-failed' });
  }
});
// 4) LOCK / UNLOCK USER
app.patch('/admin/user/:id/lock', adminGuard, async (req, res) => {
  const userId  = req.params.id;
  const origin  = req.headers.origin;
  const browser = req.headers['user-agent'];
  const token   = req.headers.authorization?.split(' ')[1] || '';

  /* identify the admin performing the action */
  let actor = 'unknown';
  try {
    const { sub } = jwt.verify(token, JWT_SECRET);
    const { rows } = await pool.query(
      'SELECT username FROM users WHERE id = $1',
      [sub]
    );
    actor = rows[0]?.username || 'unknown';
  } catch {}

  /* JWT.log entry */
  fs.appendFileSync(
    'JWT.log',
    `${new Date().toISOString()} [PATCH /admin/user/${userId}/lock] token: ${token} actor: ${actor}\n`
  );

  try {
    /* fetch current lock state + identifier for login_failures */
    const { rows } = await pool.query(
      `SELECT username, email, locked_until
         FROM users
        WHERE id = $1`,
      [userId]
    );
    if (!rows.length) return res.status(404).json({ msg: 'not-found' });

    const { username, email, locked_until } = rows[0];
    const currentlyLocked = Number(locked_until) > Date.now();

    /* toggle */
    const nextValue = currentlyLocked ? 0 : 253402300799000; // year‑9999

    await pool.query(
      'UPDATE users SET locked_until = $1 WHERE id = $2',
      [nextValue, userId]
    );

    /* if we UN‑lock, clear login_failures so the account isn’t re‑locked */
    if (currentlyLocked) {
      await pool.query(
        `DELETE FROM login_failures
          WHERE identifier ILIKE $1
             OR identifier ILIKE $2`,
        [username.toLowerCase(), email.toLowerCase()]
      );
    }

    /* structured audit log */
    logEntry('ADMIN_LOCK_TOGGLE', {
      by:       actor,
      targetId: userId,
      action:   currentlyLocked ? 'unlock' : 'lock',
      app:      getAppName(origin),
      browser,
      ip: (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim(),
      timestamp: new Date().toISOString()
    });

    return res.sendStatus(204);              // success, no body
  } catch (err) {
    console.error('❌ Failed to toggle lock:', err);
    return res.status(500).json({ msg: 'toggle-failed' });
  }
});
// --------------------------------------------------------------------
// ---------- debug & ping  (PostgreSQL version)  ---------------------
// --------------------------------------------------------------------
/*  GET /debug/users – dump every row in users (dev-only!)*/
app.get('/debug/users', async (_req, res) => {
    try {
      const { rows } = await pool.query('SELECT * FROM users ORDER BY username');
      res.json(rows);
    } catch (err) {
      console.error('❌  Failed to fetch users for debug:', err.message);
      res.status(500).json({ msg: 'debug-fetch-users-failed' });
    }
  });

  /* GET /debug/events – dump login / logout events (joined with usernames)*/
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

  /*----------Simple ping route-----------------------------------------*/
  app.get('/ping', (_req, res) => res.send('pong'));
  
  // --------------------------------------------------------------------
  // ---------- start server  -------------------------------------------
  // --------------------------------------------------------------------
  const cert = fs.readFileSync(path.join(__dirname, '..', 'certs', 'localhost.pem'));
  const key  = fs.readFileSync(path.join(__dirname, '..', 'certs', 'localhost-key.pem'));
  https.createServer({ key, cert }, app)
       .listen(PORT, () => {
         console.log(`✅ Auth-server listening on https://localhost:${PORT}`);
       });

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
