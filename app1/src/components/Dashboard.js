import { useCallback, useEffect, useState, useRef } from 'react';
import { getToken, logout as clientLogout, registerFingerprint } from '../auth';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
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

  const [chatOpen, setChatOpen] = useState(false);
  const [chat, setChat] = useState([]);
  const chatBottomRef = useRef(null);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);

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
useEffect(() => {
  if (chatBottomRef.current) {
    chatBottomRef.current.scrollIntoView({ behavior: 'smooth' });
  }
}, [chat]);


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

  // 💬 Send user input to department-based AI agent, receive response, and update chat history
  const handleSend = async () => {
    if (!input.trim()) return;

    const message = input;
    const userTime = new Date().toLocaleTimeString();

    // Show user message immediately
    setChat(prev => [...prev, { role: 'user', content: message, time: userTime }]);
    setInput('');
    setLoading(true);

    try {
      const res = await axios.post('https://localhost:5000/agent/ask', {
        userId: me.id,
        department: me.department?.toLowerCase() || 'general',
        prompt: message
      });

      const agentTime = new Date().toLocaleTimeString();

      // Append agent response
      setChat(prev => [...prev, { role: 'agent', content: res.data.answer, time: agentTime }]);
    } catch (err) {
      const errorTime = new Date().toLocaleTimeString();

      setChat(prev => [
        ...prev,
        { role: 'agent', content: '⚠️ Error: could not contact AI agent.', time: errorTime }
      ]);
    } finally {
      setLoading(false);
    }
  };
  
  if (!me) return <>Loading…</>;

  return (
    <div className="dashboard-wrapper">
      <button className="logout-button" onClick={handleLogout}>🚪 Logout</button>

      {/* ✅ Message Banner */}
      {message && (
        <div className={`admin-message ${messageType === 'error' ? 'error' : 'success'}`}>
          {message}
        </div>
      )}

      <h1 className="dashboard-title">
        Welcome {me.username} to <span className="highlighted">App1 🎉</span>
      </h1>

      {/* 👤 User Info Card */}
      <div className="dashboard-card">
        <div className="dashboard-info">
          <p>📧 <strong>Email:</strong> {me.email}</p>
          <p>🏢 <strong>Department:</strong> {me.department}</p>
          <p>🧑‍💼 <strong>Role:</strong> {me.role}</p>
          <p>🆔 <strong>ID Number:</strong> {me.idNumber}</p>
          <p>🖐️ <strong>Fingerprint:</strong> {me.fingerprint_registered ? 'Registered ✅' : 'Not registered ❌'}</p>
        </div>
      </div>

      {/* ✏️ Action Buttons */}
      <div className="dashboard-actions">
        <button className="update-button" onClick={() => setEditing(true)}>✏️ Update Info</button>
        {!me.fingerprint_registered && (
          <button className="register-fp-button" onClick={handleFingerprintRegistration}>
            🖐️ Register Fingerprint
          </button>
        )}
      </div>


      {/* ✏️ Edit Modal */}
      {editing && (
        <EditModal
          user={me}
          onClose={() => setEditing(false)}
          onSave={handleSave}
        />
      )}
      {/* Floating Chat Button */}
      <div className="chat-float-button" onClick={() => setChatOpen(!chatOpen)}>
        {chatOpen ? '╳' : '💬'}
      </div>

      {/* Floating Chat Panel */}
      {chatOpen && (
        <div className="chat-panel">
          <div className="chat-header">
            <span> AI Assistant</span>
            <button className="clear-chat-btn" onClick={() => setChat([])}>🗑 Clear</button>
          </div>

          <div className="chat-history">
            {chat.map((entry, idx) => (
              <div key={idx} className={`chat-msg ${entry.role}`}>
                <div className="chat-meta">
                  <strong>{entry.role === 'user' ? 'You' : 'Agent'}</strong>
                  <span className="chat-time">{entry.time}</span>
                </div>
                <div className="chat-content">{entry.content}</div>
              </div>
            ))}
            {loading && (
              <div className="chat-msg agent">
                <div className="chat-meta">
                  <strong>Agent</strong>
                  <span className="chat-time">typing…</span>
                </div>
                <div className="chat-content">...</div>
              </div>
            )}
            <div ref={chatBottomRef} />
          </div>

          <div className="chat-controls">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSend()}
              placeholder="Ask something..."
            />
            <button onClick={handleSend}>Send</button>
          </div>
        </div>
      )}

    </div>
  );
}
