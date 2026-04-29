import { getDevice, getLocation, setTok, setUsr } from "./utils.js";
const page = document.body.dataset.page;

if (page === "login") {
  const btn   = document.getElementById("login-btn");
  const msgEl = document.getElementById("msg");
  btn.addEventListener("click", doLogin);
  document.getElementById("password").addEventListener("keydown", e => {
    if (e.key === "Enter") doLogin();
  });

  async function doLogin() {
    const email = document.getElementById("email").value.trim().toLowerCase();
    const pw    = document.getElementById("password").value;
    if (!email || !pw) { msgEl.textContent = "Please enter your email and password."; return; }

    const fa = parseInt(sessionStorage.getItem(email + "_fa") || "0");
    if (fa >= 5) {
      msgEl.textContent = "Too many attempts. Please refresh the page and try again.";
      return;
    }

    btn.disabled = true;
    msgEl.textContent = "Verifying credentials...";

    try {
      msgEl.textContent = "Detecting location...";
      const device     = getDevice();
      const location   = await getLocation();
      const time       = new Date().toLocaleTimeString();
      const lcKey      = email + "_lc";
      const loginCount = parseInt(localStorage.getItem(lcKey) || "0") + 1;

      msgEl.textContent = "Analysing risk...";

      const res  = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email, password: pw,
          context: { device, location, loginCount, time, failedAttempts: fa }
        })
      });
      const data = await res.json();

      // ── Blocked account ──────────────────────────────────────────────────
      if (data.status === "blocked") {
        sessionStorage.setItem("blocked_info", JSON.stringify({
          blocked_by: data.blocked_by || "System Administrator",
          email:      email
        }));
        window.location.href = "/blocked";
        return;
      }

      // ── Deleted account ──────────────────────────────────────────────────
      if (data.status === "deleted") {
        sessionStorage.setItem("deleted_info", JSON.stringify({
          deleted_by: data.deleted_by || "System Administrator",
          deleted_at: data.deleted_at || ""
        }));
        window.location.href = "/account-deleted";
        return;
      }

      // ── Other errors ─────────────────────────────────────────────────────
      if (!res.ok) {
        const nfa = fa + 1;
        sessionStorage.setItem(email + "_fa", nfa);
        if (nfa >= 5) {
          msgEl.textContent = "Too many failed attempts. Please refresh and try again.";
        } else {
          msgEl.textContent = `Invalid credentials. (Attempt ${nfa}/5)`;
        }
        btn.disabled = false;
        return;
      }

      // ── OTP required ─────────────────────────────────────────────────────
      if (data.status === "otp_required") {
        msgEl.textContent = "High risk detected — sending verification code...";
        sessionStorage.setItem("otp_p", JSON.stringify({
          user_id: data.user_id, email: data.email
        }));
        setTimeout(() => window.location.href = "/otp", 1500);
        return;
      }

      // ── Success ───────────────────────────────────────────────────────────
      msgEl.textContent = "Login successful — redirecting...";
      sessionStorage.setItem(email + "_fa", 0);
      sessionStorage.removeItem("_loc_cache");
      localStorage.setItem(lcKey, loginCount);
      setTok(data.token);
      setUsr({ role: data.role, email: data.email, name: data.name });
      const map = { super_admin: "/super-admin", admin: "/admin", user: "/user" };
      setTimeout(() => window.location.href = map[data.role] || "/user", 1200);

    } catch (err) {
      msgEl.textContent = "Connection error: " + err.message;
      btn.disabled = false;
    }
  }
}

if (page === "signup") {
  document.getElementById("signup-btn").addEventListener("click", async () => {
    const msgEl = document.getElementById("msg");
    const btn   = document.getElementById("signup-btn");
    const name  = document.getElementById("name").value.trim();
    const email = document.getElementById("email").value.trim().toLowerCase();
    const pw    = document.getElementById("password").value;
    const cf    = document.getElementById("confirm").value;
    if (!name || !email || !pw) { msgEl.textContent = "All fields are required."; return; }
    if (pw !== cf)               { msgEl.textContent = "Passwords do not match."; return; }
    if (pw.length < 6)           { msgEl.textContent = "Password must be at least 6 characters."; return; }
    btn.disabled = true; btn.textContent = "Creating...";
    try {
      const r = await fetch("/api/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, email, password: pw })
      });
      const d = await r.json();
      if (!r.ok) { msgEl.textContent = d.error; btn.disabled = false; btn.textContent = "Create Account"; return; }
      msgEl.className = "ok";
      msgEl.textContent = "Account created. Redirecting to sign in...";
      setTimeout(() => window.location.href = "/", 1500);
    } catch (e) {
      msgEl.textContent = e.message;
      btn.disabled = false; btn.textContent = "Create Account";
    }
  });
}
