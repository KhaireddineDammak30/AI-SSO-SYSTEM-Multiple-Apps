import { useEffect } from 'react';
import { getToken, logout } from '../auth';

export default function SSOListener() {
  const check = () => { if(!getToken()) window.location='/login'; };

  useEffect(()=>{
    check();                               // run at mount
    window.addEventListener('storage',   check);      // changes from another tab
    window.addEventListener('sso-login', check);      // custom
    window.addEventListener('sso-logout', logout);    // custom
    return ()=> {
      window.removeEventListener('storage',   check);
      window.removeEventListener('sso-login', check);
      window.removeEventListener('sso-logout', logout);
    };
  },[]);

  return null; // just side‑effects
}
