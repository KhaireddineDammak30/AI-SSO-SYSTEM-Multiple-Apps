import React, { useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Login from './components/Login.jsx';
import Register from './components/Register.jsx';
import Dashboard from './components/Dashboard.jsx';
import SSOListener from './components/SSOListener.jsx';
import SetupProfile from './components/SetupProfile.jsx';

/** Wraps protected UI with the SSOListener guard */
function RequireAuth({ children }) {
  return (
    <>
      <SSOListener />
      {children}
    </>
  );
}

export default function App() {
  // ✅ Optional: set title based on env (useful fallback from index.js)
  useEffect(() => {
    document.title = import.meta.env.VITE_APP_NAME || 'My App';
  }, []);

  return (
    <BrowserRouter>
      <Routes>
        {/* 1) Always start at the login page */}
        <Route path="/" element={<Navigate to="/login" replace />} />

        {/* 2) Public routes */}
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/sso-callback" element={<SSOListener />} /> {/* 👈 Handles SSO redirect */}
        <Route path="/setup-profile" element={<SetupProfile />} />

        {/* 3) Protected dashboard */}
        <Route
          path="/dashboard"
          element={
            <RequireAuth>
              <Dashboard />
            </RequireAuth>
          }
        />

        {/* 4) Any unknown route → redirect to login */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
