import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";    // ← import this
import App from "./App";
import "./index.css";

const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(
  <React.StrictMode>
    {/* Wrap App in BrowserRouter so your <Routes> work */}
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>
);
