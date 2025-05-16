import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { setToken, registerFingerprint } from '../auth';
import '../register.css';

const API = import.meta.env.VITE_AUTH || 'https://localhost:4000'; // ✅ Vite-compatible

export default function Register() {
  const navigate = useNavigate();

  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [department, setDepartment] = useState('cloud');
  const [role, setRole] = useState('engineer');
  const [idNumber, setIdNumber] = useState('');
  const [registerFp, setRegisterFp] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);

  const handleSubmit = async e => {
    e.preventDefault();
    setError('');
    setMessage('');

    if (password !== confirm) {
      setError('⚠️ Passwords do not match.');
      return;
    }

    if (!/^\d{8}$/.test(idNumber)) {
      setError('⚠️ ID Number must be exactly 8 digits.');
      return;
    }

    setBusy(true);
    try {
      const res = await fetch(`${API}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: username.trim(),
          email: email.trim().toLowerCase(),
          password,
          department,
          role,
          idNumber
        })
      });

      if (!res.ok) {
        if (res.status === 409) {
          const data = await res.json().catch(() => ({}));
          if (data.msg === 'username-taken') {
            setError('⚠️ Username already taken.');
          } else if (data.msg === 'idnumber-taken') {
            setError('⚠️ ID Number already in use.');
          } else {
            setError('⚠️ Conflict – please try again.');
          }
        } else if (res.status === 400) {
          const data = await res.json().catch(() => ({}));
          const reason = data.reason || 'unknown';
          const msgMap = {
            low_deliverability: '📬 This email seems unreliable or likely to bounce.',
            invalid_domain: '❌ The domain of this email address is not valid.',
            no_connect: '🔌 We couldn’t reach this email provider.',
            rejected_email: '🚫 This email was rejected by the mail server.',
            invalid_email: '⚠️ Please use a valid email address.',
            disposable: '⏳ Temporary email addresses are not allowed.',
            role: '📮 Role-based emails (like admin@) are not accepted.',
            unknown: '⚠️ This email looks suspicious.'
          };
          setError(msgMap[reason] || '⚠️ Please use a valid, personal email address.');
        } else {
          setError(`❌ Registration failed (${res.status})`);
        }
        return;
      }

      const { token, role: userRole } = await res.json();
      setToken(token, userRole);

      if (registerFp) {
        try {
          setMessage('🔒 Enrolling fingerprint… please confirm on your device');
          await registerFingerprint(token, 'register');
          setMessage('🎉 Fingerprint saved! Redirection…');
        } catch (err) {
          console.error(err);
          setError('⚠️ Fingerprint registration failed: ' + err.message);
        }
      } else {
        setMessage('✅ Account created! Redirecting to login…');
      }

      setTimeout(() => navigate('/login'), 1200);
    } catch (err) {
      console.error(err);
      setError(`❌ Cannot connect to auth-server at ${API}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="register-container">
      <h2>Create Account on {import.meta.env.VITE_APP_NAME || 'My App'}</h2>

      <input type="email" placeholder="Email address" value={email} onChange={e => setEmail(e.target.value)} required />
      <input placeholder="Username" value={username} onChange={e => setUsername(e.target.value)} required />
      <input type="password" placeholder="Password" value={password} onChange={e => setPassword(e.target.value)} required />
      <input type="password" placeholder="Confirm Password" value={confirm} onChange={e => setConfirm(e.target.value)} required />
      <input type="text" placeholder="ID Number (8 digits)" value={idNumber} onChange={e => setIdNumber(e.target.value)} pattern="\d{8}" required />

      <label>
        Department:
        <select value={department} onChange={e => setDepartment(e.target.value)}>
          <option value="cloud">Cloud</option>
          <option value="network">Network</option>
          <option value="security">Security</option>
          <option value="maintenance">Maintenance</option>
        </select>
      </label>

      <label>
        Role:
        <select value={role} onChange={e => setRole(e.target.value)}>
          <option value="head">Head of Department</option>
          <option value="manager">Manager</option>
          <option value="engineer">Engineer</option>
          <option value="technician">Technician</option>
        </select>
      </label>

      <label className="fp-register">
        <input type="checkbox" checked={registerFp} onChange={e => setRegisterFp(e.target.checked)} />
        Register phone fingerprint now
      </label>

      <button type="submit" disabled={busy} className="register-button">
        {busy ? 'Creating…' : 'Create Account'}
      </button>

      {error && <div className="error">{error}</div>}
      {message && <div className="success">{message}</div>}

      <div className="signup-link">
        Already have an account? <Link to="/login">Log in</Link>
      </div>
    </form>
  );
}
