import { useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { getToken, setToken, logout } from '../auth';

export default function SSOListener() {
  const [params] = useSearchParams();
  const navigate = useNavigate();

  useEffect(() => {
    const tokenFromUrl = params.get('token');

    if (tokenFromUrl) {
      // 🌐 OAuth SSO case
      setToken(tokenFromUrl);
      window.dispatchEvent(new Event('sso-login'));
      navigate('/dashboard');
    } else if (!getToken()) {
      // 🔒 No token stored
      window.location = '/login';
    }

    const check = () => { if (!getToken()) window.location = '/login'; };
    window.addEventListener('storage',   check);
    window.addEventListener('sso-login', check);
    window.addEventListener('sso-logout', logout);

    return () => {
      window.removeEventListener('storage',   check);
      window.removeEventListener('sso-login', check);
      window.removeEventListener('sso-logout', logout);
    };
  }, [params, navigate]);

  return null; // just handles auth side effects
}
