// ================================
//  auth.js — User Auth (localStorage)
// ================================

const AUTH_KEY = 'detectify_user';
const USERS_KEY = 'detectify_users';

function getUsers() {
  return JSON.parse(localStorage.getItem(USERS_KEY) || '{}');
}

function saveUsers(users) {
  localStorage.setItem(USERS_KEY, JSON.stringify(users));
}

function getCurrentUser() {
  return JSON.parse(localStorage.getItem(AUTH_KEY) || 'null');
}

function saveCurrentUser(user) {
  localStorage.setItem(AUTH_KEY, JSON.stringify(user));
}

function registerUser(name, email, password) {
  const users = getUsers();
  if (users[email]) return { success: false, message: 'Email already registered.' };
  users[email] = { name, email, password: btoa(password), joined: new Date().toISOString() };
  saveUsers(users);
  saveCurrentUser({ name, email });
  return { success: true };
}

function loginUser(email, password) {
  const users = getUsers();
  const user = users[email];
  if (!user) return { success: false, message: 'Email not found.' };
  if (user.password !== btoa(password)) return { success: false, message: 'Incorrect password.' };
  saveCurrentUser({ name: user.name, email });
  return { success: true };
}

function logoutUser() {
  localStorage.removeItem(AUTH_KEY);
  showAuthModal();
  document.getElementById('main-app').style.display = 'none';
}

// ---- Show/hide auth modal ----
function showAuthModal(tab = 'login') {
  document.getElementById('auth-modal').style.display = 'flex';
  switchAuthTab(tab);
}

function hideAuthModal() {
  document.getElementById('auth-modal').style.display = 'none';
  document.getElementById('main-app').style.display = 'block';
}

function switchAuthTab(tab) {
  document.getElementById('login-form').style.display  = tab === 'login'    ? 'block' : 'none';
  document.getElementById('register-form').style.display = tab === 'register' ? 'block' : 'none';
  document.querySelectorAll('.auth-tab').forEach(t => t.classList.remove('active'));
  document.querySelector(`.auth-tab[data-tab="${tab}"]`).classList.add('active');
  document.getElementById('auth-error').textContent = '';
}

function handleLogin() {
  const email    = document.getElementById('login-email').value.trim();
  const password = document.getElementById('login-password').value;
  if (!email || !password) { showAuthError('Please fill in all fields.'); return; }
  const result = loginUser(email, password);
  if (result.success) {
    hideAuthModal();
    updateNavUser();
  } else {
    showAuthError(result.message);
  }
}

function handleRegister() {
  const regEmail = document.getElementById('reg-email').value;
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(regEmail)) {
    document.getElementById('auth-error').textContent = 'Please enter a valid email address.';
    return;
  }
  const regEmail = document.getElementById("reg-email").value;
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(regEmail)) { document.getElementById("auth-error").textContent = "Please enter a valid email address."; return; }
  const name     = document.getElementById('reg-name').value.trim();
  const email    = document.getElementById('reg-email').value.trim();
  const password = document.getElementById('reg-password').value;
  if (!name || !email || !password) { showAuthError('Please fill in all fields.'); return; }
  if (password.length < 6) { showAuthError('Password must be at least 6 characters.'); return; }
  const result = registerUser(name, email, password);
  if (result.success) {
    hideAuthModal();
    updateNavUser();
  } else {
    showAuthError(result.message);
  }
}

function showAuthError(msg) {
  document.getElementById('auth-error').textContent = msg;
}

function updateNavUser() {
  const user = getCurrentUser();
  const el   = document.getElementById('nav-user');
  if (!el) return;
  if (user) {
    el.innerHTML = `
      <span class="nav-avatar">${user.name.charAt(0).toUpperCase()}</span>
      <span class="nav-username">${user.name}</span>
      <button class="nav-logout" onclick="logoutUser()"><i class="ti ti-logout"></i> Logout</button>`;
  }
}

// ---- On page load ----
document.addEventListener('DOMContentLoaded', () => {
  const user = getCurrentUser();
  if (!user) {
    showAuthModal('login');
    document.getElementById('main-app').style.display = 'none';
  } else {
    hideAuthModal();
    updateNavUser();
  }

  // Enter key support
  ['login-password','reg-password'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('keydown', e => {
      if (e.key === 'Enter') id.startsWith('login') ? handleLogin() : handleRegister();
    });
  });
});
