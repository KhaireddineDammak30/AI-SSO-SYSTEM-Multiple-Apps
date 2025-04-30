// src/auth.js

import { jwtDecode } from 'jwt-decode';
const API = process.env.REACT_APP_AUTH || 'http://localhost:4000';

/**
 * Login Step 1: POST username/password.
 * Throws if not 200 OK.
 * Returns { token, role } or { mfaRequired, qrData? } on success.
 */
export async function login(identifier, password) {
  const r = await fetch(`${API}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ identifier, password })
  });

  let data = {};
  try {
    data = await r.json();
  } catch {
    // ignore parse errors
  }

  if (!r.ok) {
    const err = new Error(data.msg || 'Login failed');
    err.status = r.status;
    if (data.unlock) err.unlock = data.unlock; // for 423 Locked accounts
    throw err;
  }

  return data; // either { mfaRequired, qrData } OR { token, role }
}

/**
 * Login Step 2: POST username + TOTP (MFA code).
 * Throws if not 200 OK.
 * Returns { token, role } on success and stores them in localStorage.
 */
export async function verifyMfa(identifier, code) {
  const r = await fetch(`${API}/verify-mfa`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ identifier, token: code })
  });

  let data = {};
  try {
    data = await r.json();
  } catch {
    // ignore parse errors
  }

  if (!r.ok) {
    let err = 'TOTP verification failed';
    try { ({ msg: err } = data); } catch {}
    throw new Error(err);
  }

  const { token, role } = data;

  if (!token || !role) {
    throw new Error('Invalid server response after MFA');
  }

  localStorage.setItem('token', token);
  localStorage.setItem('role', role);
  window.dispatchEvent(new Event('sso-login'));

  return { token, role };
}

/** Returns the raw token or null */
export function getToken() {
  return localStorage.getItem('token');
}

/** Returns the stored role or null */
export function getRole() {
  return localStorage.getItem('role');
}

/** Clears token and role from storage */
export function logout() {
  localStorage.removeItem('token');
  localStorage.removeItem('role');
  window.dispatchEvent(new Event('sso-logout'));
}

/** Decodes token payload or returns null */
export function userInfo() {
  const t = getToken();
  return t ? jwtDecode(t) : null;
}
