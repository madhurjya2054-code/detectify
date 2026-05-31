'use strict';

const API_BASE  = window.location.origin;
const TOKEN_KEY = 'detectify_token';
const USER_KEY  = 'detectify_user';

/* ─── Token helpers ─────────────────────────────────────────────────────── */
function decodeTokenPayload(token) {
  try {
    const base64 = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded  = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '=');
    return JSON.parse(atob(padded));
  } catch { return null; }
}

function isLoggedIn() {
  const token = localStorage.getItem(TOKEN_KEY);
  if (!token) return false;
  const payload = decodeTokenPayload(token);
  if (!payload) { _clearSession(); return false; }
  if (payload.exp && payload.exp * 1000 < Date.now()) { _clearSession(); return false; }
  return true;
}

function getCurrentUser() {
  if (!isLoggedIn()) return null;
  try { return JSON.parse(localStorage.getItem(USER_KEY)); } catch { return null; }
}

function getAuthHeaders() {
  const token = localStorage.getItem(TOKEN_KEY);
  return token ? { Authorization: `Bearer ${token}` } : {};
}

function _saveSession(data) {
  localStorage.setItem(TOKEN_KEY, data.token);
  localStorage.setItem(USER_KEY, JSON.stringify(data.user));
}

function _clearSession() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

/* ─── UI helpers ─────────────────────────────────────────────────────────── */
function showAuthError(msg) {
  const el = document.getElementById('auth-error');
  if (!el) return;
  el.textContent = msg;
  el.style.display = 'block';
}

function clearAuthError() {
  const el = document.getElementById('auth-error');
  if (!el) return;
  el.textContent = '';
  el.style.display = 'none';
}

function switchAuthTab(tab) {
  document.getElementById('login-form').style.display    = tab === 'login'    ? '' : 'none';
  document.getElementById('register-form').style.display = tab === 'register' ? '' : 'none';
  document.querySelectorAll('.auth-tab').forEach(b => {
    b.classList.toggle('active', b.dataset.tab === tab);
  });
  clearAuthError();
}

/* ─── Auth handlers (called by onclick in HTML) ──────────────────────────── */
async function handleLogin() {
  clearAuthError();
  const email    = document.getElementById('login-email')?.value.trim()    || '';
  const password = document.getElementById('login-password')?.value        || '';
  const btn      = document.querySelector('#login-form .auth-btn');

  if (!email || !password) { showAuthError('Email and password are required.'); return; }

  btn && (btn.disabled = true, btn.innerHTML = '<i class="ti ti-loader"></i> Signing in…');
  try {
    const res  = await fetch(`${API_BASE}/api/auth/login`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ email, password }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Login failed.');
    _saveSession(data);
    applyAuthState();
  } catch (err) {
    showAuthError(err.message);
  } finally {
    btn && (btn.disabled = false, btn.innerHTML = '<i class="ti ti-login"></i> Sign In');
  }
}

async function handleRegister() {
  clearAuthError();
  const name     = document.getElementById('reg-name')?.value.trim()     || '';
  const email    = document.getElementById('reg-email')?.value.trim()    || '';
  const password = document.getElementById('reg-password')?.value        || '';
  const btn      = document.querySelector('#register-form .auth-btn');

  if (!name || !email || !password) { showAuthError('All fields are required.'); return; }

  btn && (btn.disabled = true, btn.innerHTML = '<i class="ti ti-loader"></i> Creating account…');
  try {
    const res  = await fetch(`${API_BASE}/api/auth/register`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ name, email, password }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Registration failed.');
    _saveSession(data);
    applyAuthState();
  } catch (err) {
    showAuthError(err.message);
  } finally {
    btn && (btn.disabled = false, btn.innerHTML = '<i class="ti ti-user-plus"></i> Create Account');
  }
}

function logout() {
  _clearSession();
  applyAuthState();
}

/* ─── Page state ─────────────────────────────────────────────────────────── */
function applyAuthState() {
  const authModal = document.getElementById('auth-modal');
  const mainApp   = document.getElementById('main-app');
  const navUser   = document.getElementById('nav-user');

  if (isLoggedIn()) {
    authModal && (authModal.style.display = 'none');
    mainApp  && (mainApp.style.display   = '');
    const user = getCurrentUser();
    if (navUser && user) {
      navUser.innerHTML = `
        <span class="nav-username">${user.name || user.email}</span>
        <button class="nav-logout-btn" onclick="logout()">
          <i class="ti ti-logout"></i> Logout
        </button>`;
    }
  } else {
    authModal && (authModal.style.display = '');
    mainApp  && (mainApp.style.display   = 'none');
  }
}

/* ─── Bootstrap ──────────────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', applyAuthState);

/* ─── Public API ─────────────────────────────────────────────────────────── */
window.DetectifyAuth = { handleLogin, handleRegister, logout, getCurrentUser, isLoggedIn, getAuthHeaders };
