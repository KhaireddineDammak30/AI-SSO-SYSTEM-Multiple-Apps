import { useEffect, useState } from 'react';
import { getToken, logout as clientLogout } from '../auth';
import { useNavigate } from 'react-router-dom';
import '../Dashboard.css';

const API = process.env.REACT_APP_AUTH || 'http://localhost:4000';

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
          <label>department</label>
          <select value={form.department} onChange={handleChange('department')}>
            <option value="cloud">Cloud</option>
            <option value="network">Network</option>
            <option value="security">Security</option>
            <option value="maintenance">Maintenance</option>
          </select>
        </div>
        <div>
          <label>role</label>
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

export default function Dashboard() {
  const [me, setMe] = useState(null);
  const [editing, setEditing] = useState(false);
  const [message, setMessage] = useState('');
  const [messageType, setMessageType] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    const token = getToken();
    if (!token) return navigate('/login');

    fetch(`${API}/me`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then(r => {
        if (!r.ok) {
          clientLogout();
          navigate('/login');
        }
        return r.json();
      })
      .then(setMe)
      .catch(() => {
        clientLogout();
        navigate('/login');
      });
  }, [navigate]);

  const showMessage = (msg, type = 'success') => {
    setMessage(msg);
    setMessageType(type);
    setTimeout(() => {
      setMessage('');
      setMessageType('');
    }, 2000);
  };

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

  if (!me) return <>Loading…</>;

  return (
    <div className="dashboard-container">
      <button className="logout-button" onClick={handleLogout}>🚪 Logout</button>

      {message && (
        <div className={`admin-message ${messageType === 'error' ? 'error' : 'success'}`}>
          {message}
        </div>
      )}

      <h2>Welcome {me.username} to <strong>App1 🎉</strong></h2>
      <div className="dashboard-card">
        <div><strong>Email:</strong> {me.email}</div>
        <div><strong>Department:</strong> {me.department}</div>
        <div><strong>Role:</strong> {me.role}</div>
        <div><strong>ID Number:</strong> {me.idNumber}</div>
      </div>

      <div className="dashboard-actions">
        <button className="update-button" onClick={() => setEditing(true)}>✏️ Update Info</button>
      </div>

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
