import { useCallback, useEffect, useState } from 'react';
import { getToken, logout as clientLogout, registerFingerprint } from '../auth';
import { useNavigate } from 'react-router-dom';
import '../Dashboard.css';

const API = process.env.REACT_APP_AUTH || 'https://localhost:4000';

// ✏️ Modal to edit user info
function EditModal({ user, onClose, onSave }) {
  const [form, setForm] = useState({ ...user });

  const handleChange = (field) => (e) =>
    setForm({ ...form, [field]: e.target.value });

  return (
    <div className="edit-modal-overlay">
      <div className="edit-modal">
        <h3>Edit Your Info</h3>
        {['username', 'email', 'idNumber'].map(field => (
          <div key={field}>
            <label>{field}</label>
            <input value={form[field]} onChange={handleChange(field)} />
          </div>
        ))}
        <div>
          <label>Department</label>
          <select value={form.department} onChange={handleChange('department')}>
            <option value="cloud">Cloud</option>
            <option value="network">Network</option>
            <option value="security">Security</option>
            <option value="maintenance">Maintenance</option>
          </select>
        </div>
        <div>
          <label>Role</label>
          <select value={form.role} onChange={handleChange('role')}>
            <option value="head">Head of Department</option>
            <option value="manager">Manager</option>
            <option value="engineer">Engineer</option>
            <option value="technician">Technician</option>
          </select>
        </div>
        <div style={{ marginTop: 16, textAlign: 'right' }}>
          <button onClick={onClose}>Cancel</button>
          <button onClick={() => onSave(form)}>Save</button>
        </div>
      </div>
    </div>
  );
}

// 🧠 Main Dashboard component
export default function Dashboard() {
  const [me, setMe] = useState(null);
  const [editing, setEditing] = useState(false);
  const [message, setMessage] = useState('');
  const [messageType, setMessageType] = useState('');
  const navigate = useNavigate();

  // 🔐 Load user profile from /me
  const loadUser = useCallback(async () => {
  const token = getToken();
  if (!token) return navigate('/login');

  try {
    const res = await fetch(`${API}/me`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!res.ok) {
      clientLogout();
      return navigate('/login');
    }

    const user = await res.json();
    setMe(user);
  } catch (err) {
    clientLogout();
    navigate('/login');
  }
}, [navigate]); // ✅ only depends on navigate

useEffect(() => {
  loadUser();
}, [loadUser]);

  // 📢 UI message display helper
  const showMessage = (msg, type = 'success') => {
    setMessage(msg);
    setMessageType(type);
    setTimeout(() => {
      setMessage('');
      setMessageType('');
    }, 2000);
  };

  // 🚪 Handle logout
  const handleLogout = async () => {
    const token = getToken();
    if (token) {
      await fetch(`${API}/logout`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` }
      }).catch(() => {});
    }
    clientLogout();
    navigate('/login');
  };

  // 💾 Save profile edits
  const handleSave = (data) => {
    const token = getToken();
    fetch(`${API}/me`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify(data)
    }).then(async res => {
      if (res.ok) {
        setMe(data);
        setEditing(false);
        showMessage('✅ Profile updated');
      } else {
        const { msg } = await res.json();
        if (msg === 'username-taken' || msg === 'idnumber-taken') {
          showMessage('🚫 Username or ID already exists', 'error');
        } else {
          showMessage('❌ Update failed', 'error');
        }
      }
    });
  };

  // 🖐️ Handle fingerprint registration
  const handleFingerprintRegistration = async () => {
    const token = getToken();
    setMessage('');
    setMessageType('');
    try {
      setMessage('🔒 Enrolling fingerprint… please confirm on your device');
      await registerFingerprint(token, 'dashboard');
      await loadUser(); // 🔄 refresh user data without reload
      setMessage('🎉 Fingerprint saved and synced!');
      setMessageType('success');
      setTimeout(() => {
        setMessage('');
        setMessageType('');
      }, 3000);
    } catch (err) {
      console.error(err);
      const msg = err?.message || '';
      if (msg.includes('timed out') || msg.includes('not allowed')) {
        setMessage('🛑 Fingerprint registration was cancelled or blocked. Please try again.');
      } else {
        setMessage('❌ Fingerprint registration failed: ' + msg);
      }
      setMessageType('error');
    }
  };

  if (!me) return <>Loading…</>;

  return (
    <div className="dashboard-container">
      <button className="logout-button" onClick={handleLogout}>🚪 Logout</button>

      {/* ✅ Message Banner */}
      {message && (
        <div className={`admin-message ${messageType === 'error' ? 'error' : 'success'}`}>
          {message}
        </div>
      )}

      <h2>Welcome {me.username} to <strong>App2 🎉</strong></h2>

      {/* 👤 User Info Card */}
      <div className="dashboard-card">
        <div><strong>📧 Email:</strong> {me.email}</div>
        <div><strong>🏢 Department:</strong> {me.department}</div>
        <div><strong>🧑‍💼 Role:</strong> {me.role}</div>
        <div><strong>🆔 ID Number:</strong> {me.idNumber}</div>
        <div className="fingerprint-status">
          <strong>🖐️ Fingerprint:</strong>{' '}
          {me.fingerprint_registered ? (
            <span className="registered">Registered ✅</span>
          ) : (
            <span className="not-registered">Not registered ❌</span>
          )}
        </div>
      </div>

      {/* ✏️ Action Buttons */}
      <div className="dashboard-actions">
        <button className="update-button" onClick={() => setEditing(true)}>✏️ Update Info</button>
      </div>

      {/* 🖐️ Fingerprint Button */}
      {!me.fingerprint_registered && (
        <button
          className="register-fp-button"
          onClick={handleFingerprintRegistration}
        >
          🖐️ Register Fingerprint
        </button>
      )}

      {/* ✏️ Edit Modal */}
      {editing && (
        <EditModal
          user={me}
          onClose={() => setEditing(false)}
          onSave={handleSave}
        />
      )}
    </div>
  );
}
