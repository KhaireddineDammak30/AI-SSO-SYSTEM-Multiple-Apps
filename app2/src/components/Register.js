// src/components/Register.js

import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import '../register.css';

const API = process.env.REACT_APP_AUTH || 'http://localhost:4000';

export default function Register() {
  const navigate = useNavigate();

  const [username,   setUsername]   = useState('');
  const [email,      setEmail]      = useState('');
  const [password,   setPassword]   = useState('');
  const [confirm,    setConfirm]    = useState('');
  const [department, setDepartment] = useState('cloud');
  const [role,       setRole]       = useState('engineer');
  const [idNumber,   setIdNumber]   = useState('');
  const [error,      setError]      = useState('');
  const [message,    setMessage]    = useState('');
  const [busy,       setBusy]       = useState(false);

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
          username:   username.trim(),
          email:      email.trim().toLowerCase(),
          password,
          department,
          role,
          idNumber
        })
      });

      if (res.ok) {
        setMessage('✅ Account created! Redirecting to login...');
        setTimeout(() => navigate('/login'), 1200);
      } else if (res.status === 409) {
        setError('⚠️ Username already taken.');
      } else {
        let data = {};
        try { data = await res.json(); } catch {}

        if (data.msg === 'invalid-email') {
          const reason = data.reason || 'unknown';
          const msgMap = {
            low_deliverability: '📬 This email seems unreliable or likely to bounce.',
            invalid_domain:     '❌ The domain of this email address is not valid.',
            no_connect:         '🔌 We couldn’t reach this email provider.',
            rejected_email:     '🚫 This email was rejected by the mail server.',
            invalid_email:      '⚠️ Please use a valid email address.',
            disposable:         '⏳ Temporary email addresses are not allowed.',
            role:               '📮 Role-based emails (like admin@) are not accepted.',
            unknown:            '⚠️ This email looks suspicious.'
          };
          setError(msgMap[reason] || '⚠️ Please use a valid, personal email address.');
        } else {
          setError(`❌ Registration failed (${res.status})`);
        }
      }
    } catch (err) {
      setError(`❌ Cannot connect to auth‑server at ${API}`);
      console.error(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="register-container">
      <h2>Create Account</h2>

      <input
        type="email"
        placeholder="Email address"
        value={email}
        onChange={e => setEmail(e.target.value)}
        required
      />
      <input
        placeholder="Username"
        value={username}
        onChange={e => setUsername(e.target.value)}
        required
      />
      <input
        type="password"
        placeholder="Password"
        value={password}
        onChange={e => setPassword(e.target.value)}
        required
      />
      <input
        type="password"
        placeholder="Confirm Password"
        value={confirm}
        onChange={e => setConfirm(e.target.value)}
        required
      />
      <input
        type="text"
        placeholder="ID Number (8 digits)"
        value={idNumber}
        onChange={e => setIdNumber(e.target.value)}
        pattern="\d{8}"
        required
      />

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

      <button
        type="submit"
        disabled={
          busy ||
          !username.trim() ||
          !email.trim() ||
          !password ||
          password !== confirm ||
          !/^\d{8}$/.test(idNumber)
        }
        className="register-button"
      >
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
