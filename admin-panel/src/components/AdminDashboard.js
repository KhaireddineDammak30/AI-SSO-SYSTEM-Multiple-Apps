import { useEffect, useState } from 'react';
import { useLocation } from 'react-router-dom';
import '../AdminDashboard.css';

const API = process.env.REACT_APP_AUTH || 'http://localhost:4000';

function EditModal({ user, onClose, onSave }) {
  const [form, setForm] = useState({ ...user });

  const handleChange = (field) => (e) =>
    setForm({ ...form, [field]: e.target.value });

  return (
    <div className="edit-modal-overlay">
      <div className="edit-modal">
        <h3>Edit User: {user.username}</h3>

        {['username', 'email', 'idNumber'].map(field => (
          <div key={field}>
            <label>{field}</label>
            <input
              value={form[field]}
              onChange={handleChange(field)}
              style={{ width: '100%' }}
            />
          </div>
        ))}

        <div>
          <label>Department</label>
          <select value={form.department} onChange={handleChange('department')} style={{ width: '100%' }}>
            <option value="cloud">Cloud</option>
            <option value="network">Network</option>
            <option value="security">Security</option>
            <option value="maintenance">Maintenance</option>
          </select>
        </div>

        <div>
          <label>Role</label>
          <select value={form.role} onChange={handleChange('role')} style={{ width: '100%' }}>
            <option value="head">Head of Department</option>
            <option value="manager">Manager</option>
            <option value="engineer">Engineer</option>
            <option value="technician">Technician</option>
          </select>
        </div>

        <div style={{ marginTop: 16, textAlign: 'right' }}>
          <button onClick={onClose} className="cancel-button">Cancel</button>
          <button onClick={() => onSave(form)} className="save-button">Save</button>
        </div>
      </div>
    </div>
  );
}

export default function AdminDashboard() {
  const [users, setUsers] = useState([]);
  const [me, setMe] = useState(null);
  const [editingUser, setEditingUser] = useState(null);
  const [message, setMessage] = useState('');
  const [messageType, setMessageType] = useState('');
  const location = useLocation();

  useEffect(() => {
    const queryParams = new URLSearchParams(location.search);
    const tokenFromQuery = queryParams.get('token');
    const roleFromQuery = queryParams.get('role');
    const originFromQuery = queryParams.get('origin');
  
    if (tokenFromQuery && roleFromQuery) {
      localStorage.setItem('token', tokenFromQuery);
      localStorage.setItem('role', roleFromQuery);
    }
    if (originFromQuery) {
      localStorage.setItem('origin', decodeURIComponent(originFromQuery));
    }
  
    const fetchMe = async () => {
      const token = localStorage.getItem('token');
  
      // ✅ NEW IMPORTANT: Check immediately if token exists
      if (!token) {
        setMessage('🚫 You have been logged out. Please login again.');
        setMessageType('error');
        return;
      }
  
      try {
        const res = await fetch(`${API}/me`, {
          headers: { Authorization: `Bearer ${token}` }
        });
  
        if (!res.ok) throw new Error('Unauthorized');
  
        const data = await res.json();
        if (data.role !== 'admin') {
          throw new Error('Not an admin');
        }
  
        setMe(data);
        refreshUsers();
      } catch (err) {
        console.error(err);
        setMessage('🚫 You have been logged out. Please login again.');
        setMessageType('error');
      }
    };
  
    fetchMe();
  }, [location]);
  

  const refreshUsers = async () => {
    const token = localStorage.getItem('token');
    try {
      const res = await fetch(`${API}/admin/users`, {
        headers: { Authorization: `Bearer ${token}` }
      });

      if (!res.ok) throw new Error('Failed to fetch users');

      const data = await res.json();
      setUsers(data);
    } catch (err) {
      console.error(err);
      setMessage('Failed to load users');
      setMessageType('error');
    }
  };

  const handleLogout = async () => {
    const token = localStorage.getItem('token');
    const origin = localStorage.getItem('origin') || 'http://localhost:3000'; // fallback
  
    if (token) {
      try {
        await fetch(`${API}/logout`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}` }
        });
      } catch (err) {
        console.error('Logout failed:', err.message);
      }
    }
  
    // ✅ Remove token/role/origin safely
    localStorage.removeItem('token');
    localStorage.removeItem('role');
    localStorage.removeItem('origin');
  
    // ✅ After removing, prevent double logout
    if (!token) {
      console.log('Already logged out, skipping logout request.');
    }
  
    window.location.replace(`${origin}/login`);
  };
  

  const handleEdit = (user) => {
    setEditingUser(user);
  };

  const handleSave = async (updatedUser) => {
    const token = localStorage.getItem('token');
    try {
      const res = await fetch(`${API}/admin/user/${updatedUser.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(updatedUser)
      });

      if (!res.ok) {
        const { msg } = await res.json();
        if (msg === 'username-taken' || msg === 'idnumber-taken') {
          showMessage('🚫 Username or ID already exists', 'error');
        } else {
          showMessage('❌ Failed to update user', 'error');
        }
      } else {
        setEditingUser(null);
        showMessage('✅ User updated successfully', 'success');
        refreshUsers();
      }
    } catch (err) {
      showMessage('❌ Failed to update user', 'error');
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Are you sure you want to delete this user?')) return;
    const token = localStorage.getItem('token');
    try {
      await fetch(`${API}/admin/user/${id}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` }
      });

      showMessage('🗑️ User deleted successfully', 'success');
      refreshUsers();
    } catch (err) {
      showMessage('❌ Failed to delete user', 'error');
    }
  };

  const showMessage = (msg, type = 'success') => {
    setMessage(msg);
    setMessageType(type);
    setTimeout(() => {
      setMessage('');
      setMessageType('');
    }, 2000);
  };

  // if (messageType === 'error' && !me) {
  //   const origin = localStorage.getItem('origin') || 'http://localhost:3000';
  //   window.location.href = `${origin}/login`;
  //   return null; // stop rendering AdminDashboard
  // }

  if (!me) return <p style={{ padding: 40 }}>⏳ Loading admin data…</p>;

  return (
    <div className="admin-dashboard">
      <button onClick={handleLogout} className="logout-button">🚪 Logout</button>

      {message && (
        <div className={`admin-message ${messageType === 'error' ? 'error' : 'success'}`}>
          {message}
        </div>
      )}

      <h1>📊 Admin Dashboard</h1>
      <p>Welcome, <strong>{me.username}</strong></p>

      <table border="1" cellPadding="8" style={{ marginTop: 24, width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr>
            <th>Username</th>
            <th>Hashed Password</th>
            <th>Email</th>
            <th>Department</th>
            <th>Role</th>
            <th>ID Number</th>
            <th>First Login</th>
            <th>Last Login</th>
            <th>Locked</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {users.map(u => (
            <tr key={u.id}>
              <td>{u.username}</td>
              <td style={{ fontSize: '0.75em', wordBreak: 'break-all' }}>{u.hash}</td>
              <td>{u.email}</td>
              <td>{u.department}</td>
              <td>{u.role}</td>
              <td>{u.idNumber}</td>
              <td>{u.firstLogin || '—'}</td>
              <td>{u.lastLogin || '—'}</td>
              <td style={{ color: u.isLocked ? 'crimson' : 'green' }}>
                {u.isLocked ? '🔒 Locked' : '✅ Active'}
              </td>
              <td className="actions-cell">
                <button onClick={() => handleEdit(u)} className="edit-button">✏️ Edit</button>
                <button onClick={() => handleDelete(u.id)} className="delete-button">🗑️ Delete</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {editingUser && (
        <EditModal
          user={editingUser}
          onClose={() => setEditingUser(null)}
          onSave={handleSave}
        />
      )}
    </div>
  );
}
