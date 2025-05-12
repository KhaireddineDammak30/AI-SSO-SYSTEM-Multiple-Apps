// src/components/Login.js

import { useState } from 'react';
import ReCAPTCHA from 'react-google-recaptcha';
import { useNavigate, Link } from 'react-router-dom';
import {login,verifyMfa,loginWithFingerprint,setToken,} from '../auth';
import '../login.css';

const SITE_KEY = process.env.REACT_APP_RECAPTCHA_SITE;

export default function Login() {
  const navigate = useNavigate();
  // 0 = credentials, 1 = fingerprint, 2 = TOTP
  const [step, setStep] = useState(0);
  const [form, setForm] = useState({ identifier: '', p: '', code: '' });
  const [captcha, setCaptcha] = useState(null);
  const [qr, setQr] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError('');

    try {
      // ─── Step 0: Credentials ───────────────────────────
      if (step === 0) {
        const res = await login(form.identifier.trim(), form.p, captcha);

        // If fingerprint is enrolled, go to fingerprint step
        if (res.fingerprintRequired) {
          setStep(1);
          setCaptcha(null);
          return;
        }

        // Otherwise, prepare TOTP (qrData if setting up MFA, or existing MFA)
        if (res.qrData) {
          setQr(res.qrData);
        }
        setStep(2);
        setCaptcha(null);
        return;
      }

      // ─── Step 1: Fingerprint ───────────────────────────
      if (step === 1) {
        const { token, role } = await loginWithFingerprint(form.identifier.trim());
        // Store JWT and role
        setToken(token, role);
        // Redirect based on role
        if (role === 'admin') {
          window.location.href = 
            `https://localhost:4001/admin-dashboard?token=${token}&role=${role}&origin=${encodeURIComponent(window.location.origin)}`;
        } else {
          navigate('/dashboard');
        }
        return;
      }

      // ─── Step 2: TOTP ───────────────────────────────────
      if (step === 2) {
        const res = await verifyMfa(
          form.identifier.trim(),
          form.code.replace(/\s+/g, '')
        );
        setToken(res.token, res.role);
        if (res.role === 'admin') {
          window.location.href = 
            `https://localhost:4001/admin-dashboard?token=${res.token}&role=${res.role}&origin=${encodeURIComponent(window.location.origin)}`;
        } else {
          navigate('/dashboard');
        }
        return;
      }

    } catch (err) {
      // handle specific statuses
      if (err.status === 429 && err.unlock) {
        const when = new Date(err.unlock).toLocaleString();
        setError(`⚠️ Too many failed attempts. Locked until ${when}`);
        return;
      }
      if (err.status === 423) {
        if (err.msg === 'admin-locked') {
          setError('🚫 Account has been locked by an administrator.');
        } else if (err.unlock) {
          const when = new Date(err.unlock).toLocaleString();
          setError(`⏳ Account locked until ${when}`);
        } else {
          setError('⏳ Account is currently locked.');
        }
        return;
      }
      // fallback error
      setError(err.message || '❌ Login failed. Please try again.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="login-container">
      <h2>
        {step === 0
          ? 'Sign In'
          : step === 1
          ? 'Confirm Fingerprint'
          : 'Two-Factor Authentication'}
      </h2>

      {step === 0 && (
        <>
          <input
            placeholder="Username or email"
            value={form.identifier}
            onChange={(e) =>
              setForm({ ...form, identifier: e.target.value })
            }
            required
          />
          <input
            type="password"
            placeholder="Password"
            value={form.p}
            onChange={(e) => setForm({ ...form, p: e.target.value })}
            required
          />
          <ReCAPTCHA
            sitekey={SITE_KEY}
            onChange={(token) => setCaptcha(token)}
            className="recaptcha"
          />
          <button
            type="submit"
            disabled={busy || !captcha}
            className="login-button"
          >
            {busy ? 'Signing in…' : 'Next'}
          </button>

          <div className="oauth-buttons">
            <p>or continue with</p>
            <a
              href="https://localhost:4000/auth/google?app=app2"
              className="oauth-btn google"
            >
              Login with Google
            </a>
            <a
              href="https://localhost:4000/auth/github?app=app2"
              className="oauth-btn github"
            >
              Login with GitHub
            </a>
          </div>

          <div className="signup-link">
            Need an account? <Link to="/register">Sign up</Link>
          </div>
        </>
      )}

      {step === 1 && (
        <>
          <p className="fingerprint-prompt">
            🔒 Please confirm your fingerprint on your device
          </p>
          <button
            type="submit"
            disabled={busy}
            className="login-button"
          >
            {busy ? 'Waiting for device…' : 'Use Fingerprint'}
          </button>
        </>
      )}

      {step === 2 && (
        <>
          {qr && (
            <img
              src={qr}
              alt="Scan QR code in your Authenticator app"
              className="qr-code"
            />
          )}
          <input
            placeholder="6-digit code"
            value={form.code}
            onChange={(e) =>
              setForm({ ...form, code: e.target.value })
            }
            required
          />
          <button
            type="submit"
            disabled={busy}
            className="login-button"
          >
            {busy ? 'Verifying…' : 'Verify'}
          </button>
        </>
      )}

      {error && <div className="error">{error}</div>}
    </form>
  );
}
