// src/components/Login.js

import { useState } from 'react';
import ReCAPTCHA from 'react-google-recaptcha';
import { login, verifyMfa } from '../auth';
import { useNavigate, Link } from 'react-router-dom';
import '../login.css';

const SITE_KEY = process.env.REACT_APP_RECAPTCHA_SITE;

export default function Login() {
  const navigate = useNavigate();
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
      if (step === 0) {
        // Step 0: Login with username/password
        const res = await login(form.identifier.trim(), form.p, captcha);

        if (res.qrData) {
          // New MFA setup (QR code for first time)
          setQr(res.qrData);
          setStep(1);
          setCaptcha(null);
        } else if (res.mfaRequired) {
          // Existing MFA, no QR needed
          setStep(1);
          setCaptcha(null);
        } else if (res.token && res.role) {
          // Direct login success
          localStorage.setItem('token', res.token);
          localStorage.setItem('role', res.role);
          localStorage.setItem('origin', window.location.origin);

          if (res.role === 'admin') {
            const origin = window.location.origin;
            window.location.href = `http://localhost:4001/admin-dashboard?token=${res.token}&role=${res.role}&origin=${encodeURIComponent(origin)}`;
          } else {
            navigate('/dashboard');
          }
        } else {
          throw new Error('❌ Invalid server response');
        }
      } else {
        // Step 1: Verify MFA code (6-digit TOTP)
        const res = await verifyMfa(
          form.identifier.trim(),
          form.code.replace(/\s+/g, '')
        );

        if (res.token && res.role) {
          localStorage.setItem('token', res.token);
          localStorage.setItem('role', res.role);
          localStorage.setItem('origin', window.location.origin);

          if (res.role === 'admin') {
            const origin = window.location.origin;
            window.location.href = `http://localhost:4001/admin-dashboard?token=${res.token}&role=${res.role}&origin=${encodeURIComponent(origin)}`;
          } else {
            navigate('/dashboard');
          }
        } else {
          throw new Error('❌ Invalid server response after MFA');
        }
      }
    } catch (err) {
      if (err.status === 423) {
        const when = new Date(err.unlock).toLocaleTimeString();
        setError(`⏳ Account locked until ${when}`);
      } else if (err.status === 429) {
        setError('⚠️ Too many failed attempts. Try again later.');
      } else {
        setError(err.message || '❌ Login failed. Please try again.');
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="login-container">
      <h2>{step === 0 ? 'Sign In' : 'Two-Factor Authentication'}</h2>

      {step === 0 ? (
        <>
          <input
            placeholder="Username or email"
            value={form.identifier}
            onChange={(e) => setForm({ ...form, identifier: e.target.value })}
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
          <button type="submit" disabled={busy || !captcha} className="login-button">
            {busy ? 'Signing in…' : 'Next'}
          </button>

          <div className="oauth-buttons">
            <p>or continue with</p>

            <a href="http://localhost:4000/auth/google?app=app1" className="oauth-btn google">Login with Google</a>
            <a href="http://localhost:4000/auth/github?app=app1" className="oauth-btn github">Login with GitHub</a>

          </div>

          <div className="signup-link">
            Need an account? <Link to="/register">Sign up</Link>
          </div>
        </>
      ) : (
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
            onChange={(e) => setForm({ ...form, code: e.target.value })}
            required
          />
          <button type="submit" disabled={busy} className="login-button">
            {busy ? 'Verifying…' : 'Verify'}
          </button>
        </>
      )}

      {error && <div className="error">{error}</div>}
    </form>
  );
}
