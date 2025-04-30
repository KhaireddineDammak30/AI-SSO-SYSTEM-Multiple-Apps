import { useEffect } from 'react';
import { getToken, logout } from '../auth';

export default function SSOListener() {
  const check = () => { if(!getToken()) window.location='/login'; };

  useEffect(() => {
    check();
    window.addEventListener('storage',   check);
    window.addEventListener('sso-login', check);
    window.addEventListener('sso-logout', logout);
    return () => {
      window.removeEventListener('storage',   check);
      window.removeEventListener('sso-login', check);
      window.removeEventListener('sso-logout', logout);
    };
  }, []);

  return null;
}
