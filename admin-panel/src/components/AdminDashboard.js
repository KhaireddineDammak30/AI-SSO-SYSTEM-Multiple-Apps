// src/components/AdminDashboard.js
import { useEffect, useState } from 'react';
import { useLocation } from 'react-router-dom';
import '../AdminDashboard.css';

const API               = process.env.REACT_APP_AUTH || 'http://localhost:4000';
const LOCK_DURATION_MS  = 30 * 60 * 1000;          // 30‑minute brute‑force lock window

/* ───────────────────────── Edit‑in‑modal ───────────────────────── */
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
  const [users, setUsers]           = useState([]);
  const [me, setMe]                 = useState(null);
  const [editing, setEditing]       = useState(null);
  const [toast, setToast]           = useState({ msg:'', type:'' });
  const loc                         = useLocation();

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
      } catch { kickOut('🚫 You have been logged out. Please login again.'); }
    })();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /* ─── helpers ──────────────────────────────────────────────── */
  const toastMsg   = (msg,type='success') => { setToast({msg,type}); setTimeout(()=>setToast({msg:'',type:''}),2000); };
  const kickOut    = msg => { toastMsg(msg,'error'); setTimeout(()=>handleLogout(),1500); };
  const tokenHdr   = () => ({ Authorization:`Bearer ${localStorage.getItem('token')}` });

  const loadUsers  = async () => {
    const r = await fetch(`${API}/admin/users`,{
      method:'GET', headers:tokenHdr(), cache:'no-store'   // <-- bypass cache
    });
    if (!r.ok) throw new Error();
    setUsers(await r.json());
  };

  /* ─── CRUD / auth actions ──────────────────────────────────── */
  const handleLogout = async () => {
    const t = localStorage.getItem('token');
    t && await fetch(`${API}/logout`,{method:'POST',headers:tokenHdr()}).catch(()=>{});
    const origin = localStorage.getItem('origin') || 'http://localhost:3000';
    ['token','role','origin'].forEach(k=>localStorage.removeItem(k));
    window.location.replace(`${origin}/login`);
  };

  const handleSave = async u => {
    try {
      const r = await fetch(`${API}/admin/user/${u.id}`,{
        method:'PUT', headers:{...tokenHdr(),'Content-Type':'application/json'}, body:JSON.stringify(u)
      });
      if (!r.ok) throw new Error((await r.json()).msg);
      toastMsg('✅ User updated');
      setEditing(null);
      await loadUsers();
    } catch(e){
      toastMsg(e.message.includes('taken')?'🚫 Username or ID already exists':'❌ Failed to update user','error');
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
      toastMsg(Number(u.locked_until)>Date.now()?'🔓 User unlocked':'🔒 User locked');
      await loadUsers();
    }catch{ toastMsg('❌ Could not change lock status','error'); }
  };

  /* ─── UI ───────────────────────────────────────────────────── */
  if (!me) return <p style={{padding:40}}>⏳ Loading admin data…</p>;

  return (
    <div className="admin-dashboard">
      <button onClick={handleLogout} className="logout-button">🚪 Logout</button>
      {toast.msg && <div className={`admin-message ${toast.type}`}>{toast.msg}</div>}

      <h1>📊 Admin Dashboard</h1>
      <p>Welcome, <strong>{me.username}</strong></p>

      <table cellPadding={8} style={{marginTop:24,width:'100%',borderCollapse:'collapse'}}>
        <thead>
          <tr>
            {['Username','Email','Department','Role','ID Number','First Login','Last Login','Locked Status','Actions']
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
                : `🔒 Locked due to 5 failed attempts until ${new Date(until).toLocaleString()}`
              : '✅ Active';

            return (
              <tr key={u.id}>
                <td>{u.username}</td>
                <td>{u.email}</td>
                <td>{u.department}</td>
                <td>{u.role}</td>
                <td>{u.idNumber}</td>
                <td>{u.firstLogin||'—'}</td>
                <td>{u.lastLogin||'—'}</td>
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

      {editing && <EditModal user={editing} onClose={()=>setEditing(null)} onSave={handleSave} />}
    </div>
  );
}
