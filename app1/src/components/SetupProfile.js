import { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { getToken } from '../auth';
import '../register.css'; // reuse styles from Register

export default function SetupProfile() {
  const navigate = useNavigate();
  const [params] = useSearchParams();

  const [idNumber, setIdNumber]     = useState('');
  const [department, setDepartment] = useState('cloud');
  const [role, setRole]             = useState('engineer');
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
    setMessage('');

    // Validate ID number
    if (!/^\d{8}$/.test(idNumber)) {
      setError('⚠️ ID Number must be exactly 8 digits.');
      return;
    }

    setBusy(true);
    try {
      const res = await fetch('http://localhost:4000/setup-profile', {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer ' + getToken(),
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ idNumber, department, role })
      });

      if (res.ok) {
        setMessage('✅ Profile completed! Redirecting...');
        setTimeout(() => navigate('/dashboard'), 1000);
      } else if (res.status === 409) {
        const data = await res.json().catch(() => ({}));
        if (data.msg === 'idnumber-taken') {
          setError('⚠️ ID Number already in use.');
        } else {
          setError('⚠️ Conflict – please try again.');
        }
      } else {
        setError('❌ Failed to update profile.');
      }
    } catch (err) {
      console.error(err);
      setError('❌ Connection error');
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="register-container">
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

      <button type="submit" disabled={busy} className="register-button">
        {busy ? 'Submitting…' : 'Finish Setup'}
      </button>

      {error   && <div className="error">{error}</div>}
      {message && <div className="success">{message}</div>}
    </form>
  );
}
