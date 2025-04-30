import { Routes, Route, Navigate } from 'react-router-dom';
import AdminDashboard from './components/AdminDashboard';

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/admin-dashboard" />} />
      <Route path="/admin-dashboard" element={<AdminDashboard />} />
    </Routes>
  );
}
