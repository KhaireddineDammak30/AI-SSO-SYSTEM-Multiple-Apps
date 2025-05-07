// auth-server/passport.js

import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as GitHubStrategy } from 'passport-github2';
import { pool } from './db.js';
import { logEntry } from '../shared/logger.js';

// Serialize and Deserialize User
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    done(null, rows[0] || null);
  } catch (err) {
    done(err);
  }
});

// Helper to create minimal user object
async function findOrCreateUser({ email, username, provider, req }) {
  const client = pool;
  const { rows } = await client.query(
    'SELECT * FROM users WHERE email = $1',
    [email]
  );

  if (rows.length) {
    return { user: rows[0], isNew: false };
  }

  const insert = await client.query(`
    INSERT INTO users (id, username, email)
    VALUES (gen_random_uuid(), $1, $2)
    RETURNING *
  `, [username, email]);

  return { user: insert.rows[0], isNew: true };
}

// ──────────────────────────────────────────────────────────────
// Google Strategy
// ──────────────────────────────────────────────────────────────
passport.use(new GoogleStrategy({
  clientID:            process.env.GOOGLE_CLIENT_ID,
  clientSecret:        process.env.GOOGLE_CLIENT_SECRET,
  callbackURL:         '/auth/google/callback',
  passReqToCallback:   true
}, async (req, accessToken, refreshToken, profile, done) => {
  try {
    const email    = profile.emails[0].value;
    const username = profile.displayName || profile.username;
    const app      = req.session.app || 'app1';
    const ip       = req.ip;
    const browser  = req.headers['user-agent'];

    // 1️⃣ Log initiation
    logEntry('OAUTH_LOGIN_INIT_GOOGLE', { email, app, ip, browser });

    // 2️⃣ Find or create
    const { user, isNew } = await findOrCreateUser({ email, username, provider: 'google', req });

    if (isNew) {
      // 3️⃣ Log new registration
      logEntry('REGISTER_GOOGLE', {
        uid: user.id, email, username, app, ip, browser
      });
      user.needsSetup = true;
    } else {
      // 4️⃣ Log returning login
      logEntry('LOGIN_GOOGLE', {
        uid: user.id, email, app, ip, browser
      });
    }

    done(null, user);
  } catch (err) {
    done(err);
  }
}));

// ──────────────────────────────────────────────────────────────
// GitHub Strategy
// ──────────────────────────────────────────────────────────────
passport.use(new GitHubStrategy({
  clientID:            process.env.GITHUB_CLIENT_ID,
  clientSecret:        process.env.GITHUB_CLIENT_SECRET,
  callbackURL:         '/auth/github/callback',
  passReqToCallback:   true
}, async (req, accessToken, refreshToken, profile, done) => {
  try {
    const email    = profile.emails[0].value;
    const username = profile.username;
    const app      = req.session.app || 'app1';
    const ip       = req.ip;
    const browser  = req.headers['user-agent'];

    // 1️⃣ Log initiation
    logEntry('OAUTH_LOGIN_INIT_GITHUB', { email, app, ip, browser });

    // 2️⃣ Find or create
    const { user, isNew } = await findOrCreateUser({ email, username, provider: 'github', req });

    if (isNew) {
      // 3️⃣ Log new registration
      logEntry('REGISTER_GITHUB', {
        uid: user.id, email, username, app, ip, browser
      });
      user.needsSetup = true;
    } else {
      // 4️⃣ Log returning login
      logEntry('LOGIN_GITHUB', {
        uid: user.id, email, app, ip, browser
      });
    }

    done(null, user);
  } catch (err) {
    done(err);
  }
}));

export default passport;
