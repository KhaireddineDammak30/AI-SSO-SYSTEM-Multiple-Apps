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
        const res = await login(form.identifier.trim(), form.p, captcha);

        if (res.qrData) {
          setQr(res.qrData);
          setStep(1);
          setCaptcha(null);
          return;
        }

        if (res.mfaRequired) {
          setStep(1);
          setCaptcha(null);
          return;
        }

        // Direct login
        localStorage.setItem('token', res.token);
        localStorage.setItem('role',  res.role);
        localStorage.setItem('origin', window.location.origin);

        if (res.role === 'admin') {
          window.location.href =
            `http://localhost:4001/admin-dashboard?token=${res.token}&role=${res.role}&origin=${encodeURIComponent(window.location.origin)}`;
        } else {
          navigate('/dashboard');
        }

      } else {
        const res = await verifyMfa(
          form.identifier.trim(),
          form.code.replace(/\s+/g, '')
        );

        // MFA success
        localStorage.setItem('token', res.token);
        localStorage.setItem('role',  res.role);
        localStorage.setItem('origin', window.location.origin);

        if (res.role === 'admin') {
          window.location.href =
            `http://localhost:4001/admin-dashboard?token=${res.token}&role=${res.role}&origin=${encodeURIComponent(window.location.origin)}`;
        } else {
          navigate('/dashboard');
        }
      }

    } catch (err) {
      // 429 ─ Too many wrong passwords in the last window
      if (err.status === 429 && err.unlock) {
        const when = new Date(err.unlock).toLocaleString();
        setError(`⚠️ Too many failed attempts. Locked until ${when}`);
        return;
      }
    
      // 423 ─ Account is locked
      if (err.status === 423) {
        if (err.msg === 'admin-locked') {
          // indefinitely locked by an admin – no timestamp
          setError('🚫 Account has been locked by an administrator.');
        } else if (err.unlock) {
          // normal 30‑minute brute‑force lock‑out (unlock supplied)
          const when = new Date(err.unlock).toLocaleString();
          setError(`⏳ Account locked until ${when}`);
        } else {
          // fallback if server didn’t provide unlock
          setError('⏳ Account is currently locked.');
        }
        return;
      }
    
      // All other errors
      setError(err.message || '❌ Login failed. Please try again.');
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
          {qr && <img src={qr} alt="Scan QR code in your Authenticator app" className="qr-code" />}
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
