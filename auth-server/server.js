// auth-server/server.js  (ESM)
import dotenv from 'dotenv';
dotenv.config();

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { logEntry } = require('../shared/logger.js');

import express   from 'express';
import cors      from 'cors';
import helmet    from 'helmet';
import morgan    from 'morgan';
import bcrypt    from 'bcryptjs';
import jwt       from 'jsonwebtoken';
import speakeasy from 'speakeasy';
import qrcode    from 'qrcode';
import { v4 as uuid } from 'uuid';
import Database  from 'better-sqlite3';
import path      from 'path';
import { fileURLToPath } from 'url';
import fetch from 'node-fetch';


/* ---------- config --------------------------------------------------- */
const PORT       = process.env.PORT       || 4000;
const JWT_SECRET = process.env.JWT_SECRET || '';
const ISSUER     = process.env.ISSUER     || 'AI-SSO';
if (!JWT_SECRET) {
  console.error('❌  Missing JWT_SECRET in .env');
  process.exit(1);
}

// --- __dirname for ESM ---
const __dirname = path.dirname(fileURLToPath(import.meta.url));

// --- sqlite DB setup ---
const db = new Database(path.join(__dirname, 'auth.db'), { timeout: 5000 });
db.pragma('journal_mode = WAL');

// --- DB Migration (Create tables if not exists) ---
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE,
    hash TEXT,
    mfaSecret TEXT,
    email TEXT,
    department TEXT,
    role TEXT,
    idNumber TEXT,
    locked_until INTEGER DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uid TEXT,
    ts INTEGER,
    ip TEXT,
    ua TEXT
  );
  CREATE TABLE IF NOT EXISTS login_failures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identifier TEXT,
    ip TEXT,
    ts INTEGER
  );
`);

// --- Auto-migrate: Add missing columns to users table ---
const existingColumns = db.prepare("PRAGMA table_info(users)").all().map(col => col.name);

const requiredColumns = {
  email:        "TEXT",
  department:   "TEXT",
  role:         "TEXT",
  idNumber:     "TEXT",
  locked_until: "INTEGER DEFAULT 0"
};

for (const [column, type] of Object.entries(requiredColumns)) {
  if (!existingColumns.includes(column)) {
    db.exec(`ALTER TABLE users ADD COLUMN ${column} ${type}`);
  }
}

/* --- Prepared Statements --- */

// Find user by username OR email (case-insensitive)
const findUser = db.prepare(`
  SELECT * FROM users
   WHERE username = ? COLLATE NOCASE
      OR email    = ? COLLATE NOCASE
`);

// Insert a new extended user
const insertUserExtended = db.prepare(`
  INSERT INTO users (id, username, hash, email, department, role, idNumber)
  VALUES (?, ?, ?, ?, ?, ?, ?)
`);

// Set MFA secret for a user
const setMfa = db.prepare(`
  UPDATE users SET mfaSecret = ? WHERE id = ?
`);

// Insert a login/logout event
const logEvent = db.prepare(`
  INSERT INTO events (uid, ts, ip, ua) VALUES (?, ?, ?, ?)
`);


/* --- Lockout Parameters --- */
// Login protection: time windows and max attempts
const WINDOW_MS = 15 * 60_000; // Look at last 15 minutes for failed attempts
const LOCK_MS   = 15 * 60_000; // Lock account for 15 minutes
const MAX_FAILS = 5;           // Maximum 5 bad tries before lock


/* --- Helper Functions --- */

// Maps request origin to known application name
function getAppName(origin) {
  switch (origin) {
    case 'http://localhost:3000': return 'App1';
    case 'http://localhost:3001': return 'App2';
    default:                      return origin;
  }
}

/* --- Middleware: Protect against brute force attacks --- */
function accountGuard(req, res, next) {
  const identifier = (req.body.identifier || req.body.username || '').trim().toLowerCase();
  if (!identifier) return next(); // Let downstream handlers manage empty fields

  let clientIp = (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim();
  if (clientIp === '::1' || clientIp === '::ffff:127.0.0.1') clientIp = '127.0.0.1';

  // Check if account is currently locked
  const row = db.prepare(`
    SELECT locked_until
    FROM users
    WHERE username = ? COLLATE NOCASE
       OR email    = ? COLLATE NOCASE
  `).get(identifier, identifier);

  if (row && row.locked_until > Date.now()) {
    const unlockAt = row.locked_until;
    const lockAt = unlockAt - LOCK_MS;

    logEntry('LOCKOUT_HIT', {
      identifier,
      ip: clientIp,
      app: getAppName(req.headers.origin),
      browser: req.headers['user-agent'],
      lockAt: new Date(lockAt).toISOString(),
      unlockAt: new Date(unlockAt).toISOString()
    });

    return res.status(423).json({
      msg: 'account-locked',
      unlock: unlockAt
    });
  }

  // Count recent failed login attempts
  const since = Date.now() - WINDOW_MS;
  const { cnt } = db.prepare(`
    SELECT COUNT(*) AS cnt
    FROM login_failures
    WHERE identifier = ? AND ts > ?
  `).get(identifier, since);

  if (cnt >= MAX_FAILS) {
    // Too many failures → lock account
    if (row) {
      const lockAt = Date.now();
      const unlockAt = lockAt + LOCK_MS;

      db.prepare(`
        UPDATE users
        SET locked_until = ?
        WHERE username = ? COLLATE NOCASE
           OR email    = ? COLLATE NOCASE
      `).run(unlockAt, identifier, identifier);

      logEntry('LOCKOUT_SET', {
        identifier,
        ip: clientIp,
        app: getAppName(req.headers.origin),
        browser: req.headers['user-agent'],
        lockAt: new Date(lockAt).toISOString(),
        unlockAt: new Date(unlockAt).toISOString()
      });
    }

    return res.status(429).json({ msg: 'too-many-attempts' });
  }

  // Not locked, not exceeding failures → continue to next middleware
  next();
}
// --- Middleware: Protect admin-only routes ---
function adminGuard(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ msg: 'no token provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'admin') {
      return res.status(403).json({ msg: 'admins only' });
    }
    next(); // ✅ token is valid and user is admin
  } catch (err) {
    console.error('❌ Failed to verify token in adminGuard:', err.message);
    return res.status(401).json({ msg: 'invalid token' });
  }
}

/* --- Sign JWT token + Log login event --- */
function signAndLog(uid, req) {
  const user = db.prepare('SELECT username, role FROM users WHERE id = ?').get(uid);

  const token = jwt.sign(
    { sub: uid, role: user.role },  // Include user ID and role
    JWT_SECRET,
    { issuer: ISSUER, expiresIn: '30m' }  // Token valid for 30 minutes
  );

  const { cnt: loginCount } = db.prepare('SELECT COUNT(*) AS cnt FROM events WHERE uid = ?').get(uid);
  const origin = req.headers.origin;

  logEntry('SIGN', {
    uid,
    username: user.username,
    role: user.role,
    origin,
    app: getAppName(origin),
    browser: req.headers['user-agent'],
    loginCount,
    token
  });

  return token;
}


/* ---------- Express setup -------------------------------------------- */
const app = express();
app.use(cors({
  origin:        ['http://localhost:3000','http://localhost:3001', 'http://localhost:4001'],
  credentials:   true,
  methods:       'GET,POST,PUT,DELETE,OPTIONS',
  allowedHeaders:'Content-Type,Authorization'
}));
app.use(express.json());
app.use(helmet());
app.use(morgan('dev'));

/* ---------- ROUTES --------------------------------------------------- */

// 1) Register: collects username, email, password, department, role, idNumber
app.post('/register', async (req, res) => {
  const origin = req.headers.origin;
  const { username, email, password, department, role, idNumber } = req.body;

  const appName = getAppName(origin);
  const browser = req.headers['user-agent'];

  // Check for existing username
  const existingUsername = db.prepare(`
    SELECT id FROM users WHERE username = ? COLLATE NOCASE
  `).get(username.trim());

  if (existingUsername) {
    logEntry('REGISTER_FAIL_USERNAME', {
      username,
      origin,
      app: appName,
      browser
    });
    return res.status(409).json({ msg: 'username-taken' });
  }

  // Check for existing ID number
  const existingIdNumber = db.prepare(`
    SELECT id FROM users WHERE idNumber = ?
  `).get(idNumber);

  if (existingIdNumber) {
    logEntry('REGISTER_FAIL_IDNUMBER', {
      idNumber,
      origin,
      app: appName,
      browser
    });
    return res.status(409).json({ msg: 'idnumber-taken' });
  }

  // ✅ Kickbox email verification
  const kickboxUrl = `https://api.kickbox.com/v2/verify?email=${encodeURIComponent(email)}&apikey=${process.env.KICKBOX_API_KEY}`;
  const response = await fetch(kickboxUrl);
  const result = await response.json();

  logEntry('EMAIL_VERIFY', {
    email,
    result: result.result, // deliverable, risky, undeliverable
    reason: result.reason,
    disposable: result.disposable,
    role: result.role,
    app: appName,
    browser
  });

  if (result.result === 'undeliverable' || result.disposable || result.role) {
    logEntry('REGISTER_FAIL_SUSPICIOUS_EMAIL', {
      username,
      email,
      reason: result.reason,
      result: result.result,
      disposable: result.disposable,
      role: result.role,
      origin,
      app: appName,
      browser
    });
    return res.status(400).json({ msg: 'invalid-email', reason: result.reason });
  }

  // Insert the new user
  const id = uuid();
  await insertUserExtended.run(
    id,
    username.trim(),
    await bcrypt.hash(password, 10),
    email.trim().toLowerCase(),
    department,
    role,
    idNumber
  );

  logEntry('REGISTER_SUCCESS', {
    uid: id,
    username,
    email: email.trim().toLowerCase(),
    department,
    role,
    idNumber,
    origin,
    app: appName,
    browser
  });

  res.json({ msg: 'registered' });
});


// 2a) Login Step 1: accept identifier (username OR email) + password
app.post('/login', accountGuard, async (req, res) => {
  const origin = req.headers.origin;
  const { identifier, password } = req.body;
  const appName = getAppName(origin);
  const browser = req.headers['user-agent'];

  if (!identifier || !password) {
    logEntry('LOGIN_FAIL_MISSING_FIELDS', { identifier, origin, app: appName, browser });
    return res.status(400).json({ msg: 'missing fields' });
  }

  const idClean = identifier.trim();

  const u = db.prepare(`
    SELECT * FROM users
    WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE
  `).get(idClean, idClean);

  if (!u || !(await bcrypt.compare(password, u.hash))) {
    logEntry('LOGIN_FAIL_BAD_CREDS', { identifier, origin, app: appName, browser });

    db.prepare(`
      INSERT INTO login_failures (identifier, ip, ts)
      VALUES (?, ?, ?)
    `).run(idClean, req.ip, Date.now());

    return res.status(401).json({ msg: 'bad creds' });
  }

  // Successful login: clear login failures and reset lock
  db.prepare(`DELETE FROM login_failures WHERE identifier = ?`).run(idClean);
  db.prepare(`UPDATE users SET locked_until = 0 WHERE id = ?`).run(u.id);

  // ✅ Now, for EVERYONE (admin or user):
  if (!u.mfaSecret) {
    const secret = speakeasy.generateSecret({ issuer: ISSUER, name: u.username });
    setMfa.run(secret.base32, u.id);

    logEntry('MFA_SETUP_INIT', {
      uid: u.id,
      username: u.username,
      origin,
      app: appName,
      browser: req.headers['user-agent']
    });

    const qrData = await qrcode.toDataURL(secret.otpauth_url);
    return res.json({ mfaRequired: true, qrData }); // ✅ Send QR
  }

  // Otherwise, just ask for the 6-digit code
  res.json({ mfaRequired: true });
});



// 2b) Login Step 2: verify TOTP
app.post('/verify-mfa', (req, res) => {
  const { identifier, token } = req.body;
  const origin = req.headers.origin;
  const appName = getAppName(origin);
  const browser = req.headers['user-agent'];

  if (!identifier || !token) {
    logEntry('TOTP_FAIL_MISSING_FIELDS', { identifier, origin, app: appName, browser });
    return res.status(400).json({ msg: 'missing fields' });
  }

  const idClean = identifier.trim();
  const tokenClean = token.trim();

  const u = db.prepare(`
    SELECT * FROM users
    WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE
  `).get(idClean, idClean);

  if (!u) {
    logEntry('TOTP_FAIL_USER_NOT_FOUND', { identifier, origin, app: appName, browser });
    return res.status(401).json({ msg: 'bad credentials' });
  }

  const verified = speakeasy.totp.verify({
    secret: u.mfaSecret,
    encoding: 'base32',
    token: tokenClean,
    window: 1
  });

  if (!verified) {
    logEntry('TOTP_FAIL_BAD_TOKEN', { uid: u.id, username: u.username, origin, app: appName, browser });
    return res.status(401).json({ msg: 'bad TOTP' });
  }

  logEvent.run(u.id, Date.now(), req.ip, browser);
  const jwtToken = signAndLog(u.id, req);
  res.json({ token: jwtToken, role: u.role }); // ✅ return token + role
});


// 3) Refresh
app.post('/refresh', (req, res) => {
  const origin = req.headers.origin;
  const appName = getAppName(origin);
  const browser = req.headers['user-agent'];

  try {
    const oldToken = req.body.token;
    if (!oldToken) {
      return res.status(400).json({ msg: 'missing token' });
    }

    const { sub, role } = jwt.verify(oldToken, JWT_SECRET, { ignoreExpiration: true });

    // Create a new token with sub and role
    const newToken = jwt.sign({ sub, role }, JWT_SECRET, {
      issuer: ISSUER,
      expiresIn: '30m' // ✅ updated expiration time
    });

    const loginCount = db.prepare('SELECT COUNT(*) AS cnt FROM events WHERE uid = ?').get(sub).cnt;
    const user = db.prepare('SELECT username FROM users WHERE id = ?').get(sub);

    logEntry('REFRESH_SUCCESS', {
      uid: sub,
      username: user?.username || 'unknown',
      role,
      origin,
      app: appName,
      browser,
      loginCount,
      newToken
    });

    res.json({ token: newToken });
  } catch (err) {
    console.error('❌ Refresh token error:', err.message);
    res.status(400).json({ msg: 'invalid or expired token' });
  }
});


// 4) Protected
// 4a) Get my own profile
app.get('/profile', (req, res) => {
  const origin = req.headers.origin;
  const appName = getAppName(origin);
  const browser = req.headers['user-agent'];

  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ msg: 'missing token' });

    const { sub } = jwt.verify(token, JWT_SECRET);

    const user = db.prepare(`
      SELECT username, department, role, idNumber, email
      FROM users
      WHERE id = ?
    `).get(sub);

    if (!user) {
      return res.status(404).json({ msg: 'user not found' });
    }

    res.json(user);
  } catch (err) {
    console.error('❌ Failed to fetch profile:', err.message);
    res.status(401).json({ msg: 'invalid or expired token' });
  }
});
// 4b) Get my own profile via /me
app.get('/me', (req, res) => {
  const origin = req.headers.origin;
  const appName = getAppName(origin);
  const browser = req.headers['user-agent'];

  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ msg: 'missing token' });

    const { sub } = jwt.verify(token, JWT_SECRET);

    const user = db.prepare(`
      SELECT username, department, role, idNumber, email
      FROM users
      WHERE id = ?
    `).get(sub);

    if (!user) {
      return res.status(404).json({ msg: 'user not found' });
    }

    res.json(user);
  } catch (err) {
    console.error('❌ Failed to fetch profile:', err.message);
    res.status(401).json({ msg: 'invalid or expired token' });
  }
});

// 4b) Update my own profile
app.put('/profile', (req, res) => {
  const origin = req.headers.origin;
  const appName = getAppName(origin);
  const browser = req.headers['user-agent'];

  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ msg: 'missing token' });

    const { sub: userId } = jwt.verify(token, JWT_SECRET);

    const {
      username = '',
      email = '',
      department = '',
      role = '',
      idNumber = ''
    } = req.body;

    // Check for existing username conflict
    const usernameExists = db.prepare(`
      SELECT id FROM users WHERE username = ? COLLATE NOCASE AND id != ?
    `).get(username.trim(), userId);

    if (usernameExists) {
      return res.status(409).json({ msg: 'username-taken' });
    }

    // Check for existing ID number conflict
    const idNumberExists = db.prepare(`
      SELECT id FROM users WHERE idNumber = ? AND id != ?
    `).get(idNumber, userId);

    if (idNumberExists) {
      return res.status(409).json({ msg: 'idnumber-taken' });
    }

    // Update user
    db.prepare(`
      UPDATE users
      SET username = ?, email = ?, department = ?, role = ?, idNumber = ?
      WHERE id = ?
    `).run(
      typeof username === 'string' ? username.trim() : '',
      typeof email === 'string' ? email.trim().toLowerCase() : '',
      department || '',
      role || '',
      idNumber || '',
      userId
    );
    

    logEntry('PROFILE_UPDATE', {
      uid: userId,
      updatedFields: { username, email, department, role, idNumber },
      app: appName,
      browser
    });

    res.json({ msg: 'profile-updated' });
  } catch (err) {
    console.error('❌ Failed to update profile:', err.message);
    res.status(500).json({ msg: 'profile-update-failed' });
  }
});
// 4c) Update my own profile via /me
app.put('/me', (req, res) => {
  const origin = req.headers.origin;
  const appName = getAppName(origin);
  const browser = req.headers['user-agent'];

  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ msg: 'missing token' });

    const { sub: userId } = jwt.verify(token, JWT_SECRET);

    const {
      username = '',
      email = '',
      department = '',
      role = '',
      idNumber = ''
    } = req.body;

    // Check for existing username conflict
    const usernameExists = db.prepare(`
      SELECT id FROM users WHERE username = ? COLLATE NOCASE AND id != ?
    `).get(username.trim(), userId);

    if (usernameExists) {
      return res.status(409).json({ msg: 'username-taken' });
    }

    // Check for existing ID number conflict
    const idNumberExists = db.prepare(`
      SELECT id FROM users WHERE idNumber = ? AND id != ?
    `).get(idNumber, userId);

    if (idNumberExists) {
      return res.status(409).json({ msg: 'idnumber-taken' });
    }

    // Update user
    db.prepare(`
      UPDATE users
      SET username = ?, email = ?, department = ?, role = ?, idNumber = ?
      WHERE id = ?
    `).run(
      typeof username === 'string' ? username.trim() : '',
      typeof email === 'string' ? email.trim().toLowerCase() : '',
      department || '',
      role || '',
      idNumber || '',
      userId
    );
    

    logEntry('PROFILE_UPDATE', {
      uid: userId,
      updatedFields: { username, email, department, role, idNumber },
      app: appName,
      browser
    });

    res.json({ msg: 'profile-updated' });
  } catch (err) {
    console.error('❌ Failed to update profile:', err.message);
    res.status(500).json({ msg: 'profile-update-failed' });
  }
});


// 5) Logout
app.post('/logout', (req, res) => {
  const origin = req.headers.origin;
  const appName = getAppName(origin);
  const browser = req.headers['user-agent'];

  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    console.warn('⚠️ Logout called without token.');
    return res.json({ msg: 'logged out (no token)' }); // still safe
  }

  try {
    const { sub } = jwt.verify(token, JWT_SECRET);
    const user = db.prepare('SELECT username, role FROM users WHERE id = ?').get(sub);

    const isAdmin = user?.role === 'admin';
    const isAdminOrigin = origin?.startsWith('http://localhost:4001');

    const context = (isAdmin && isAdminOrigin) ? 'ADMIN_LOGOUT' : 'LOGOUT';

    logEntry(context, {
      uid: sub,
      username: user?.username || 'unknown',
      role: user?.role || 'unknown',
      origin,
      app: appName,
      browser
    });

  } catch (err) {
    console.error('❌ Token verification failed during logout:', err.message);
  }

  res.json({ msg: 'logged out' });
});



/* --- Admin Dashboard Routes --- */

// GET all users (admin only)
app.get('/admin/users', adminGuard, (req, res) => {
  try {
    const rows = db.prepare(`
      SELECT 
        u.id, username, hash, email, department, role, idNumber, locked_until,
        MIN(e.ts) AS firstLogin,
        MAX(e.ts) AS lastLogin
      FROM users u
      LEFT JOIN events e ON u.id = e.uid
      GROUP BY u.id
    `).all();

    const result = rows.map(u => ({
      ...u,
      isLocked: u.locked_until && u.locked_until > Date.now(),
      firstLogin: u.firstLogin ? new Date(u.firstLogin).toLocaleString() : null,
      lastLogin: u.lastLogin ? new Date(u.lastLogin).toLocaleString() : null
    }));

    res.json(result);
  } catch (err) {
    console.error('❌ Failed to fetch users:', err.message);
    res.status(500).json({ msg: 'failed-to-fetch-users' });
  }
});

// PUT update user (admin only)
app.put('/admin/user/:id', adminGuard, (req, res) => {
  const origin = req.headers.origin;
  const appName = getAppName(origin);
  const browser = req.headers['user-agent'];

  try {
    const { username = '', email = '', department = '', role = '', idNumber = '' } = req.body;
    const userId = req.params.id;

    // Check username conflict
    const usernameExists = db.prepare(`
      SELECT id FROM users WHERE username = ? COLLATE NOCASE AND id != ?
    `).get(username.trim(), userId);

    if (usernameExists) {
      return res.status(409).json({ msg: 'username-taken' });
    }

    // Check ID number conflict
    const idNumberExists = db.prepare(`
      SELECT id FROM users WHERE idNumber = ? AND id != ?
    `).get(idNumber, userId);

    if (idNumberExists) {
      return res.status(409).json({ msg: 'idnumber-taken' });
    }

    // Update user
    db.prepare(`
      UPDATE users
      SET username = ?, email = ?, department = ?, role = ?, idNumber = ?
      WHERE id = ?
    `).run(
      username.trim(),
      email.trim().toLowerCase(),
      department,
      role,
      idNumber,
      userId
    );

    // Who made the update?
    let actor = 'unknown';
    const token = req.headers.authorization?.split(' ')[1];
    if (token) {
      try {
        const { sub } = jwt.verify(token, JWT_SECRET);
        const adminUser = db.prepare('SELECT username FROM users WHERE id = ?').get(sub);
        actor = adminUser?.username || 'unknown';
      } catch (err) {
        console.error('❌ Failed to decode admin token:', err.message);
      }
    }

    logEntry('ADMIN_UPDATE', {
      by: actor,
      targetId: userId,
      updatedFields: { username, email, department, role, idNumber },
      app: appName,
      browser
    });

    res.json({ msg: 'updated' });
  } catch (err) {
    console.error('❌ Failed to update user:', err.message);
    res.status(500).json({ msg: 'update-failed' });
  }
});

// DELETE a user (admin only)
app.delete('/admin/user/:id', adminGuard, (req, res) => {
  try {
    const userId = req.params.id;

    db.prepare(`DELETE FROM users WHERE id = ?`).run(userId);
    db.prepare(`DELETE FROM events WHERE uid = ?`).run(userId); // Optional: clean up events

    res.json({ msg: 'deleted' });
  } catch (err) {
    console.error('❌ Failed to delete user:', err.message);
    res.status(500).json({ msg: 'delete-failed' });
  }
});



/* ---------- debug & ping --------------------------------------------- */
// List all users
app.get('/debug/users', (_, res) => {
  try {
    const users = db.prepare('SELECT * FROM users').all();
    res.json(users);
  } catch (err) {
    console.error('❌ Failed to fetch users for debug:', err.message);
    res.status(500).json({ msg: 'debug-fetch-users-failed' });
  }
});

// List all login/logout events
app.get('/debug/events', (_, res) => {
  try {
    const events = db.prepare(`
      SELECT e.id, u.username,
             datetime(e.ts/1000,'unixepoch','localtime') AS time,
             e.ip
      FROM events e
      JOIN users u ON u.id = e.uid
      ORDER BY e.id DESC
    `).all();
    res.json(events);
  } catch (err) {
    console.error('❌ Failed to fetch events for debug:', err.message);
    res.status(500).json({ msg: 'debug-fetch-events-failed' });
  }
});

// Generate TOTP code for a user (testing MFA)
app.get('/debug/totp/:user', (req, res) => {
  const identifier = req.params.user.trim();
  if (!identifier) return res.status(400).send('missing user');

  const user = db.prepare(`
    SELECT * FROM users
    WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE
  `).get(identifier, identifier);

  if (!user) {
    return res.status(404).send('no such user');
  }

  try {
    const code = speakeasy.totp({ secret: user.mfaSecret, encoding: 'base32' });
    res.send(code);
  } catch (err) {
    console.error('❌ Failed to generate TOTP:', err.message);
    res.status(500).send('failed to generate TOTP');
  }
});

// Simple ping route
app.get('/ping', (_, res) => res.send('pong'));


/* ---------- start ----------------------------------------------------- */
app.listen(PORT,()=>console.log(`✅  Auth‑server listening on http://localhost:${PORT}`));

// ⚠️ Temporary route to create a new admin user
// app.get('/debug/init-admin', async (req, res) => {
//   const username   = 'khaireddine';
//   const password   = 'dammak30spl';
//   const email      = 'kheireddinedamak@gmail.com';
//   const department = 'security';
//   const role       = 'admin';
//   const idNumber   = '11153935';

//   const existing = findUser.get(username);
//   if (existing) return res.send('⚠️ Admin user already exists.');

//   const id  = uuid();
//   const hash = await bcrypt.hash(password, 10);

//   insertUserExtended.run(
//     id, username, hash,
//     email, department, role, idNumber
//   );

//   res.send(`✅ Admin user created: ${username} / ${password}`);
// });
