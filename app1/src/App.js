// src/App.js

import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Login       from './components/Login';
import Register    from './components/Register';
import Dashboard   from './components/Dashboard';
import SSOListener from './components/SSOListener';

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
  return (
    <BrowserRouter>
      <Routes>
        {/* 1) Always start at the login page */}
        <Route path="/" element={<Navigate to="/login" replace />} />

        {/* 2) Public routes */}
        <Route path="/login"    element={<Login />} />
        <Route path="/register" element={<Register />} />

        {/* 3) Protected dashboard */}
        <Route
          path="/dashboard"
          element={
            <RequireAuth>
              <Dashboard />
            </RequireAuth>
          }
        />

        {/* 4) Any other URL → back to home (login) */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
