// src/components/AdminDashboard.js
import { useEffect, useMemo, useState, useCallback } from 'react';
import { useLocation } from 'react-router-dom';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip,
  PieChart, Pie, Cell,
  LineChart, Line,
  ResponsiveContainer
} from 'recharts';
import axios from 'axios';
import '../AdminDashboard.css';

const API              = process.env.REACT_APP_AUTH || 'https://localhost:4000';
const LOCK_DURATION_MS = 30 * 60 * 1000;   // 30-min brute-force lock window
const colors           = ['#4f46e5','#0ea5e9','#10b981','#facc15','#f472b6'];

/* ───────────────────────── Edit-modal ───────────────────────── */
function EditModal({ user, onClose, onSave }) {
  const [form, setForm] = useState({ ...user });
  const onChange = f => e => setForm({ ...form, [f]: e.target.value });

  return (
    <div className="edit-modal-overlay">
      <div className="edit-modal">
        <h3>Edit User: {user.username}</h3>

        {['username','email','idNumber'].map(f => (
          <div key={f}>
            <label>{f}</label>
            <input value={form[f]} onChange={onChange(f)} style={{ width:'100%' }} />
          </div>
        ))}

        <div>
          <label>Department</label>
          <select value={form.department} onChange={onChange('department')} style={{ width:'100%' }}>
            {['cloud','network','security','maintenance'].map(d =>
              <option key={d} value={d}>{d[0].toUpperCase()+d.slice(1)}</option>)}
          </select>
        </div>

        <div>
          <label>Role</label>
          <select value={form.role} onChange={onChange('role')} style={{ width:'100%' }}>
            {['head','manager','engineer','technician'].map(r =>
              <option key={r} value={r}>{r}</option>)}
          </select>
        </div>

        <div style={{ marginTop:16, textAlign:'right' }}>
          <button onClick={onClose}           className="cancel-button">Cancel</button>
          <button onClick={()=>onSave(form)} className="save-button">Save</button>
        </div>
      </div>
    </div>
  );
}

/* ─────────────────────── Main dashboard ───────────────────────── */
export default function AdminDashboard() {
  const [users, setUsers]     = useState([]);
  const [me, setMe]           = useState(null);
  const [editing, setEditing] = useState(null);
  const [toast, setToast]     = useState({ msg:'', type:'' });
  const loc                   = useLocation();
  const [lastRefreshed, setLastRefreshed] = useState(null); 
  // Add Agent State
  const [agents, setAgents] = useState([]);
  const [newAgent, setNewAgent] = useState({
    name: '',
    description: ''
  });
// Load Agents
  useEffect(() => {
    axios.get('https://localhost:5000/admin/agents')
      .then(res => setAgents(res.data))
      .catch(err => console.error('Failed to fetch agents:', err));
  }, []);

  const [apps, setApps] = useState([]);
  const [newApp, setNewApp] = useState({
    name: '',
    port: '',
    description: ''
  });
  const [launchedApps, setLaunchedApps] = useState([]); // Track launched app IDs
  const [openWindows, setOpenWindows] = useState({});   // Track open window handles by app ID


  const loadUsers = useCallback(async () => {
    const r = await fetch(`${API}/admin/users`, {
      method: 'GET',
      headers: tokenHdr(),
      cache: 'no-store'
    });
    if (!r.ok) throw new Error();
    const data = await r.json();
    setUsers(data);
    setLastRefreshed(new Date().toLocaleTimeString());
  }, []);
  // ✅ ADDED: Load apps from backend
  const loadApps = useCallback(async () => {
    try {
      const res = await fetch(`${API}/admin/apps`, {
        headers: tokenHdr()
      });
      if (!res.ok) throw new Error('Failed to load apps');
      const data = await res.json();
      setApps(data);
    } catch (err) {
      toastMsg('❌ Failed to fetch apps', 'error');
    }
  }, []);

  /* ─── initial auth + users load ─────────────────────────────── */
  useEffect(() => {
    const qp = new URLSearchParams(loc.search);
    qp.get('token')  && localStorage.setItem('token', qp.get('token'));
    qp.get('role')   && localStorage.setItem('role',  qp.get('role'));
    qp.get('origin') && localStorage.setItem('origin', decodeURIComponent(qp.get('origin')));

    (async () => {
      const t = localStorage.getItem('token');
      if (!t) return kickOut('🚫 You have been logged out. Please login again.');
      try {
        const r = await fetch(`${API}/me`, { headers:{ Authorization:`Bearer ${t}` }});
        if (!r.ok) throw new Error();
        const me  = await r.json();
        if (me.role !== 'admin') throw new Error();
        setMe(me);
        await loadUsers();
        await loadApps();  // ✅ ADDED
      } catch { kickOut('🚫 You have been logged out. Please login again.'); }
    })();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
    // 🔁 Auto-refresh users every 30 seconds
  useEffect(() => {
    const interval = setInterval(() => {
      loadUsers().catch(() => {
        toastMsg('⚠️ Auto-refresh failed. Retrying...', 'error');
      });
    }, 30000); // 30 seconds

    return () => clearInterval(interval); // cleanup on unmount
  }, [loadUsers]);

  /* ─── helpers ──────────────────────────────────────────────── */
  const toastMsg = (msg,type='success') =>
    { setToast({msg,type}); setTimeout(()=>setToast({msg:'',type:''}),2000); };

  const kickOut = msg =>
    { toastMsg(msg,'error'); setTimeout(()=>handleLogout(),1500); };

  const tokenHdr = () => ({ Authorization:`Bearer ${localStorage.getItem('token')}` });

  const openApp = (app) => {
    const win = window.open(`https://localhost:${app.port}`, '_blank');
    setOpenWindows(prev => ({ ...prev, [app.id]: win }));
  };

  const closeApp = (appId) => {
    const win = openWindows[appId];
    if (win && !win.closed) win.close();
    setOpenWindows(prev => {
      const updated = { ...prev };
      delete updated[appId];
      return updated;
    });
  };


  /* ─── CRUD / auth actions ──────────────────────────────────── */
  const handleLogout = async () => {
    const t = localStorage.getItem('token');
    t && await fetch(`${API}/logout`,{method:'POST',headers:tokenHdr()}).catch(()=>{});
    const origin = localStorage.getItem('origin') || 'https://localhost:3000';
    ['token','role','origin'].forEach(k=>localStorage.removeItem(k));
    window.location.replace(`${origin}/login`);
  };

  const handleSave = async u => {
    try {
      const r = await fetch(`${API}/admin/user/${u.id}`,{
        method:'PUT',
        headers:{...tokenHdr(),'Content-Type':'application/json'},
        body:JSON.stringify(u)
      });
      if (!r.ok) throw new Error((await r.json()).msg);
      toastMsg('✅ User updated');
      setEditing(null);
      await loadUsers();
    } catch(e){
      toastMsg(
        e.message.includes('taken') ? '🚫 Username or ID already exists'
                                    : '❌ Failed to update user','error');
    }
  };

  const handleDelete = async id => {
    if(!window.confirm('Delete this user?')) return;
    try{
      const r = await fetch(`${API}/admin/user/${id}`,{method:'DELETE',headers:tokenHdr()});
      if(!r.ok) throw new Error();
      toastMsg('🗑️ User deleted');
      await loadUsers();
    }catch{ toastMsg('❌ Failed to delete user','error'); }
  };

  const toggleLock = async u => {
    try{
      const r = await fetch(`${API}/admin/user/${u.id}/lock`,{method:'PATCH',headers:tokenHdr()});
      if(!r.ok) throw new Error();
      toastMsg(Number(u.locked_until)>Date.now() ? '🔓 User unlocked' : '🔒 User locked');
      await loadUsers();
    }catch{ toastMsg('❌ Could not change lock status','error'); }
  };

  /* ─── derived stats ────────────────────────────────────────── */
  const byDept = useMemo(()=>{
    const obj={}; users.forEach(u=>obj[u.department]=(obj[u.department]||0)+1);
    return Object.entries(obj).map(([department,count])=>({department,count}));
  },[users]);

  const byRole = useMemo(()=>{
    const obj={}; users.forEach(u=>obj[u.role]=(obj[u.role]||0)+1);
    return Object.entries(obj).map(([role,count])=>({role,count}));
  },[users]);

  const registrations = useMemo(()=>{
    const obj={};
    users.forEach(u=>{
      const raw = u.firstLogin || u.first_login;
      if(!raw) return;
      const dt = new Date(raw);
      if(Number.isNaN(dt.getTime())) return;
      const day = dt.toISOString().slice(0,10);
      obj[day]=(obj[day]||0)+1;
    });
    return Object.entries(obj)
                 .sort((a,b)=>a[0].localeCompare(b[0]))
                 .map(([day,count])=>({day,count}));
  },[users]);

  const lockStats = useMemo(()=>{
    const locked   = users.filter(u => Number(u.locked_until) > Date.now()).length;
    const unlocked = users.length - locked;
    return [
      { name:'Locked', value:locked },
      { name:'Active', value:unlocked }
    ];
  },[users]);

  const fmtDate = d => {
    if(!d) return '—';
    const dt = new Date(d);
    return Number.isNaN(dt.getTime()) ? '—' : dt.toLocaleString();
  };

  const createAgent = () => {
    axios.post('https://localhost:5000/admin/agents', newAgent)
      .then(res => {
        setAgents([res.data, ...agents]);
        setNewAgent({ name: '', description: '' });  
        toastMsg(`✅ Agent "${res.data.name}" created`, 'success');
      })
      .catch(err => 
        toastMsg(`❌ ${err.response?.data?.error || 'Failed to create agent'}`, 'error')
      );  
    };

  const deleteAgent = (id) => {
    if (!window.confirm('Delete this AI agent?')) return;
    axios.delete(`https://localhost:5000/admin/agents/${id}`)
      .then(() => {
        setAgents(agents.filter(a => a.id !== id));
        toastMsg('🗑️ Agent deleted', 'success');
      })
      .catch(err => toastMsg('❌ Failed to delete agent', 'error'))
  };

 // ✅ ADDED: Create app
  const createApp = async () => {
    if (!newApp.name || !newApp.port || !newApp.description) {
      toastMsg('⚠️ Please fill in name, port, and description', 'error');
      return;
    }

    toastMsg(`⏳ "${newApp.name}" is being created. This may take a minute...`, 'info'); // ✅ show pre-creation message

    try {
      const res = await fetch(`${API}/admin/apps`, {
        method: 'POST',
        headers: { ...tokenHdr(), 'Content-Type': 'application/json' },
        body: JSON.stringify(newApp)
      });

      if (res.status === 409) {
        toastMsg('⚠️ Port or name already in use', 'error');
        return;
      }

      if (!res.ok) {
        toastMsg('❌ Failed to create app (server error)', 'error');
        return;
      }

      const app = await res.json();
      setApps(prev => [app, ...prev]);
      setNewApp({ name: '', port: '', description: '' }); // ✅ Clear form
      toastMsg(`✅ App "${app.name}" created`, 'success'); // ✅ Post-creation message

    } catch (err) {
      toastMsg('❌ Failed to create app', 'error');
      console.error(err);
    }
  };
  // Add the launchApp handler
  const launchApp = async (id) => {
    const app = apps.find(a => a.id === id);
    if (!app) return toastMsg('❌ App not found', 'error');

    try {
      const res = await fetch(`${API}/admin/apps/${id}/launch`, {
        method: 'POST',
        headers: tokenHdr()
      });

      if (!res.ok) throw new Error();

      setLaunchedApps(prev => [...prev, id]);
      toastMsg(`🚀 "${app.name}" launched`);
    } catch {
      toastMsg('❌ Failed to launch app', 'error');
    }
  };


  // ✅ ADDED: Delete app
  const deleteApp = async (id) => {
    if (!id) {
      toastMsg('❌ Invalid app ID', 'error');
      return;
    }

    if (!window.confirm('Delete this app?')) return;

    try {
      const res = await fetch(`${API}/admin/apps/${id}`, {
        method: 'DELETE',
        headers: tokenHdr()
      });

      if (!res.ok) {
        toastMsg('❌ Failed to delete app (server error)', 'error');
        return;
      }

      setApps(apps.filter(app => app.id !== id));
      toastMsg('🗑 App deleted');
    } catch {
      toastMsg('❌ Failed to delete app', 'error');
    }
  };
 
  /* ─── UI ───────────────────────────────────────────────────── */
  if (!me) return <p style={{padding:40}}>⏳ Loading admin data…</p>;

  return (
    <div className="admin-dashboard">
      <button onClick={handleLogout} className="logout-button">🚪 Logout</button>
      {toast.msg && <div className={`admin-message ${toast.type}`}>{toast.msg}</div>}

      <h1>📊 Admin Dashboard</h1>
      <p>Welcome, <strong>{me.username}</strong></p>
      {lastRefreshed && (
        <p className="last-refresh">🔄 Last updated at {lastRefreshed}</p>
      )}
      {/* ─────── User table ─────── */}
      <table cellPadding={8} style={{marginTop:24,width:'100%',borderCollapse:'collapse'}}>
        <thead>
          <tr>
            {['Username','Email','Department','Role','ID Number','First Login','Last Login','Fingerprint','Locked Status','Actions']
              .map(h=> <th key={h}>{h}</th>)}
          </tr>
        </thead>
        <tbody>
          {users.map(u=>{
            const now      = Date.now();
            const until    = Number(u.locked_until);
            const locked   = until > now;
            const adminLock= locked && (until - now > LOCK_DURATION_MS);
            const status   = locked
              ? adminLock
                ? '🔒 Locked by admin'
                : `🔒 Locked until ${new Date(until).toLocaleString()}`
              : '✅ Active';

            return (
              <tr key={u.id}>
                <td>{u.username}</td>
                <td>{u.email}</td>
                <td>{u.department}</td>
                <td>{u.role}</td>
                <td>{u.idNumber}</td>
                <td>{fmtDate(u.firstLogin || u.first_login)}</td>
                <td>{fmtDate(u.lastLogin  || u.last_login )}</td>
                <td className="fingerprint-cell">
                  <span className="fp-icon">
                    {u.fingerprint_registered ? '✅' : '❌'}
                  </span>
                </td>
                <td style={{color:locked?'crimson':'green'}}>{status}</td>
                <td className="actions-cell">
                  <button onClick={()=>setEditing(u)}           className="edit-button">✏️ Edit</button>
                  <button onClick={()=>handleDelete(u.id)}     className="delete-button">🗑️ Delete</button>
                  <button
                    onClick={() => toggleLock(u)}
                    className={`lock-button ${locked ? 'locked' : ''}`}
                  >
                    {locked ? '🔓 Unlock' : '🔒 Lock'}
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>

      {/* ─────── Agent Management ─────── */}
      <div className="agent-section">
        <h2>🧠 AI Agent Management</h2>

        <div className="agent-form-row">
          <input
            placeholder="Agent name (e.g., Network)"
            value={newAgent.name}
            onChange={e => setNewAgent({ ...newAgent, name: e.target.value })}
          />
          <textarea
            className="agent-description-input"
            placeholder="Description"
            value={newAgent.description}
            onChange={e => setNewAgent({ ...newAgent, description: e.target.value })}
            rows={2}
          />
        
          <button onClick={createAgent}>➕ Create Agent</button>
        </div>

        <div className="agent-list">
          <h3>Existing Agents</h3>
          {agents.map(agent => {
            const icons = {
              network: '🌐',
              security: '🛡️',
              cloud: '☁️',
              maintenance: '🛠️',
              hr: '👥',
              finance: '💰',
              legal: '⚖️'
            };

            const normalizedName = agent.name.trim().toLowerCase();
            const icon = icons[normalizedName] || '🤖';
            const displayName = agent.name
              .trim()
              .toLowerCase()
              .split(' ')
              .map(word => word.charAt(0).toUpperCase() + word.slice(1))
              .join(' ');

            return (
              <div key={agent.id} className="agent-item">
                <div className="agent-icon">{icon}</div>
                <div className="agent-details">
                  <strong>{displayName}</strong> – <span className="agent-description">{agent.description}</span>
                  <div className="agent-prompt">{agent.display_description}</div>
                </div>
                <div style={{ alignSelf: 'center' }}>
                  <button className="delete-button" onClick={() => deleteAgent(agent.id)}>🗑 Delete</button>
                </div>
              </div>
            );
          })}
        </div>
      </div>
      {/* ─────── App Management Section ─────── */}
      <div className="admin-section app-management-section">
        <h2 className="section-title">💠 App Management</h2>

        {/* App Creation Form */}
        <div className="app-form">
          <input
            className="app-input"
            placeholder="App name (e.g., Security Hub)"
            value={newApp.name}
            onChange={e => setNewApp({ ...newApp, name: e.target.value })}
          />
          <input
            className="app-input"
            type="number"
            placeholder="Port (e.g., 3004)"
            value={newApp.port}
            onChange={e => setNewApp({ ...newApp, port: e.target.value })}
          />
          <textarea
            className="app-textarea"
            placeholder="Description"
            value={newApp.description}
            onChange={e => setNewApp({ ...newApp, description: e.target.value })}
            rows={2}
          />
          <button 
            className="app-button create-button"
            onClick={createApp}
            disabled={!newApp.name || !newApp.port || !newApp.description}
          >
            ➕ Create App
          </button>
        </div>

        {/* App List */}
        <div className="app-list">
          <h3 className="subsection-title">Registered Apps</h3>
          {apps.map(app => (
            <div key={app.id} className="app-item">
              <div className="app-details">
                <span className="app-name">{app.name}</span>
                <span className="app-port">Port: {app.port}</span>
                <span className="app-description">{app.description}</span>
                {app.is_fixed && <span className="app-badge">Fixed</span>}
              </div>

              <div className="app-actions">
                {app.is_fixed ? (
                  <a
                    className="app-visit-button"
                    href={`https://localhost:${app.port}`}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    🔗 Open
                  </a>
                ) : (
                  <>
                    {!launchedApps.includes(app.id) ? (
                      <>
                        <button
                          className="app-launch-button"
                          onClick={() => launchApp(app.id)}
                        >
                          🚀 Launch
                        </button>
                        <button
                          className="app-delete-button"
                          onClick={() => deleteApp(app.id)}
                        >
                          🗑 Delete
                        </button>
                      </>
                    ) : openWindows[app.id] && !openWindows[app.id].closed ? (
                      <>
                        <button
                          className="app-delete-button"
                          onClick={() => closeApp(app.id)}
                        >
                          ❌ Close
                        </button>
                        <button
                          className="app-delete-button"
                          onClick={() => deleteApp(app.id)}
                        >
                          🗑 Delete
                        </button>
                      </>
                    ) : (
                      <>
                        <button
                          className="app-visit-button"
                          onClick={() => openApp(app)}
                        >
                          🔗 Open
                        </button>
                        <button
                          className="app-delete-button"
                          onClick={() => deleteApp(app.id)}
                        >
                          🗑 Delete
                        </button>
                      </>
                    )}
                  </>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ─────── Analytics ─────── */}
      <div className="stats-section" style={{marginTop:48}}>
        {/* ROW 1: Department & Role */}
        <div className="stats-row" style={{display:'flex',gap:32,flexWrap:'wrap',marginBottom:32}}>
          {/* Users by Department */}
          <div className="chart-card" style={{height:260}}>
            <h3 className="chart-title">Users by Department</h3>
            <ResponsiveContainer width="95%" height="80%">
              <BarChart data={byDept}>
                <XAxis dataKey="department" axisLine={false} tickLine={false}/>
                <YAxis allowDecimals={false} axisLine={false} tickLine={false}/>
                <Tooltip />
                <Bar dataKey="count">
                  {byDept.map((_,i)=><Cell key={i} fill={colors[i%colors.length]}/>)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Users by Role */}
          <div className="chart-card" style={{height:260}}>
            <h3 className="chart-title">Users by Role</h3>
            <ResponsiveContainer width="95%" height="80%">
              <PieChart>
                <Pie
                  data={byRole}
                  dataKey="count"
                  nameKey="role"
                  innerRadius={45}
                  outerRadius={80}
                  label
                  labelLine={false}
                >
                  {byRole.map((_,i)=><Cell key={i} fill={colors[i%colors.length]}/>)}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* ROW 2: Registrations & Account Status */}
        <div className="stats-row" style={{display:'flex',gap:32,flexWrap:'wrap'}}>
          {/* Daily registrations */}
          <div className="chart-card" style={{height:260}}>
            <h3 className="chart-title">Daily Registrations</h3>
            <ResponsiveContainer width="95%" height="80%">
              <LineChart data={registrations}>
                <XAxis
                  dataKey="day"
                  tickFormatter={d=>new Date(d).toLocaleDateString()}
                  axisLine={false} tickLine={false}
                />
                <YAxis allowDecimals={false} axisLine={false} tickLine={false}/>
                <Tooltip labelFormatter={d=>new Date(d).toLocaleDateString()}/>
                <Line type="monotone" dataKey="count" stroke={colors[0]} dot />
              </LineChart>
            </ResponsiveContainer>
          </div>

          {/* Locked vs Active */}
          <div className="chart-card" style={{height:260,maxWidth:300}}>
            <h3 className="chart-title">Account Status</h3>
            <ResponsiveContainer width="95%" height="80%">
              <PieChart>
                <Pie
                  data={lockStats}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={45}
                  outerRadius={80}
                  label
                  labelLine={false}
                >
                  <Cell fill="#ef4444"/>  {/* Locked */}
                  <Cell fill="#10b981"/>  {/* Active */}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* edit modal */}
      {editing && <EditModal user={editing} onClose={()=>setEditing(null)} onSave={handleSave} />}
    </div>
  );
}
