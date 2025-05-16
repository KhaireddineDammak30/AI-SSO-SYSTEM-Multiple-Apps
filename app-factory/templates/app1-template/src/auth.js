import { jwtDecode } from 'jwt-decode';
import {
  startRegistration,
  startAuthentication,
} from '@simplewebauthn/browser';

const API = import.meta.env.VITE_AUTH || 'https://localhost:4000'; // ✅ Vite-compatible

/* helper to create rich Error objects */
function buildError(res, body = {}) {
  const e = new Error(body.msg || res.statusText || 'Request failed');
  e.status = res.status;
  e.msg = body.msg;
  if (body.unlock) e.unlock = body.unlock;
  return e;
}

/* ───────── Login STEP-1 ───────── */
export async function login(identifier, password) {
  const res = await fetch(`${API}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ identifier, password }),
  });

  let data = {};
  try { data = await res.json(); } catch {}
  if (!res.ok) throw buildError(res, data);
  return data; // { mfaRequired… } or { token, role }
}

/* ───────── Login STEP-2 (TOTP) ───────── */
export async function verifyMfa(identifier, code) {
  const res = await fetch(`${API}/verify-mfa`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ identifier, token: code }),
  });

  let data = {};
  try { data = await res.json(); } catch {}
  if (!res.ok) throw buildError(res, data);
  const { token, role } = data;
  if (!token || !role) throw new Error('Invalid server response after MFA');
  setToken(token, role);
  return { token, role };
}

/* ───────── token helpers ───────── */
export function setToken(token, role = '') {
  localStorage.setItem('token', token);
  role && localStorage.setItem('role', role);
  window.dispatchEvent(new Event('sso-login'));
}

export const getToken = () => localStorage.getItem('token');
export const getRole  = () => localStorage.getItem('role');

export function logout() {
  localStorage.removeItem('token');
  localStorage.removeItem('role');
  window.dispatchEvent(new Event('sso-logout'));
}

export function userInfo() {
  const t = getToken();
  return t ? jwtDecode(t) : null;
}

/* ─── Register a new phone fingerprint (passkey) ───────────── */
export async function registerFingerprint(token, flowSource = 'dashboard') {
  const optsRes = await fetch(`${API}/fingerprint/register/options`, {
    headers: {
      Authorization: `Bearer ${token}`,
      'X-Flow-Source': flowSource,
    },
  });
  const optsBody = await optsRes.json().catch(() => ({}));
  if (!optsRes.ok) throw buildError(optsRes, optsBody);

  const attestation = await startRegistration(optsBody);

  const verifyRes = await fetch(`${API}/fingerprint/register/verify`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
      'X-Flow-Source': flowSource,
    },
    body: JSON.stringify({ attestation }),
  });
  const verifyBody = await verifyRes.json().catch(() => ({}));
  if (!verifyRes.ok || !verifyBody.verified) {
    throw buildError(verifyRes, verifyBody);
  }
}

/* ───  Login with phone fingerprint ──────────────────── */
export async function loginWithFingerprint(username) {
  const optsRes = await fetch(
    `${API}/fingerprint/auth/options?username=${encodeURIComponent(username)}`
  );
  const optsBody = await optsRes.json().catch(() => ({}));
  if (!optsRes.ok) throw buildError(optsRes, optsBody);

  const assertion = await startAuthentication(optsBody);

  const verifyRes = await fetch(`${API}/fingerprint/auth/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(assertion),
  });
  const verifyBody = await verifyRes.json().catch(() => ({}));
  if (!verifyRes.ok || !verifyBody.verified) {
    throw buildError(verifyRes, verifyBody);
  }

  return {
    token: verifyBody.token,
    role: verifyBody.role,
  };
}
