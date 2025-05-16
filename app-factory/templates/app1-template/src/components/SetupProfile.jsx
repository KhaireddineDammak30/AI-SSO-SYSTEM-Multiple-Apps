// src/components/SetupProfile.js
import { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { getToken, registerFingerprint } from '../auth';
import '../register.css'; // reuse styles from Register

const API = import.meta.env.VITE_AUTH || 'https://localhost:4000';

export default function SetupProfile() {
  const navigate = useNavigate();
  const [params] = useSearchParams();

  const [idNumber, setIdNumber]     = useState('');
  const [department, setDepartment] = useState('cloud');
  const [role, setRole]             = useState('engineer');

  const [registerFp, setRegisterFp] = useState(false);
  const [fpMsg,      setFpMsg]      = useState('');

  const [error, setError]           = useState('');
  const [message, setMessage]       = useState('');
  const [busy, setBusy]             = useState(false);


  useEffect(() => {
    const token = params.get('token');
    if (token) localStorage.setItem('token', token);
  }, [params]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    // setMessage('');

    // Validate ID number
    if (!/^\d{8}$/.test(idNumber)) {
      setError('⚠️ ID Number must be exactly 8 digits.');
      return;
    }

    setBusy(true);
    const token = getToken();

    try {
      // 2️⃣ save profile
      const res = await fetch(`${API}/setup-profile`, {
        method:  'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ idNumber, department, role })
      });

      if (!res.ok) {
        // conflict or other error
        if (res.status === 409) {
          const data = await res.json().catch(() => ({}));
          setError(data.msg === 'idnumber-taken'
            ? '⚠️ ID Number already in use.'
            : '⚠️ Conflict – please try again.');
        } else {
          setError('❌ Failed to update profile.');
        }
        return;
      }

      // 3️⃣ profile saved!
      if (registerFp) {
        // 4️⃣ user opted in → enroll fingerprint
        setMessage('✅ Profile saved! Enrolling fingerprint…');
        try {
          setFpMsg('🔒 Please confirm on your device…');
          await registerFingerprint(token);
          setFpMsg('🎉 Fingerprint enrolled! Redirecting to dashboard…');
        } catch (err) {
          console.error(err);
          setError('⚠️ Fingerprint enrollment failed: ' + err.message);
        }
      } else {
        // no fingerprint: finish up
        setMessage('✅ Profile completed! Redirecting to dashboard…');
      }

      // 5️⃣ final redirect
      setTimeout(() => navigate('/dashboard'), 1200);

    } catch (err) {
      console.error(err);
      setError('❌ Connection error');
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="register-container">
      <h1 className="app-name">{import.meta.env.VITE_APP_NAME || 'My App'}</h1>
      <h2>Complete Your Profile</h2>

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

      {/* ─── Optional fingerprint registration toggle ─────────── */}
      <label className="fp-register">
        <input
          type="checkbox"
          checked={registerFp}
          onChange={e => setRegisterFp(e.target.checked)}
        />
        <span>Register phone fingerprint now</span>
      </label>
      {/* {fpMsg && <div className="success">{fpMsg}</div>} */}
      {/* Submit button */}
      <button
        type="submit"
        disabled={busy}
        className="register-button"
      >
        {busy ? 'Submitting…' : 'Finish Setup'}
      </button>

      {/* Feedback messages */}
      {error   && <div className="error">{error}</div>}
      {message && <div className="success">{message}</div>}
      {fpMsg   && <div className="success">{fpMsg}</div>}
    </form>
  );
}
