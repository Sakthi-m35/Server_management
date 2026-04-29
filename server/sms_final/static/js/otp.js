import { setTok, setUsr } from "./utils.js";

const raw = sessionStorage.getItem("otp_p");
if (!raw) { window.location.href = "/"; throw 0; }
const pend = JSON.parse(raw);

const emailEl = document.getElementById("otp-email");
if (emailEl) emailEl.textContent = pend.email;

const inp     = document.getElementById("otpInput");
const verBtn  = document.getElementById("verifyBtn");
const resBtn  = document.getElementById("resendBtn");
const msgEl   = document.getElementById("msg");
const timerEl = document.getElementById("timer");

let cd = 60, iv;

function startTimer() {
  clearInterval(iv);
  cd = 60;
  iv = setInterval(() => {
    cd--;
    const m = String(Math.floor(cd / 60)).padStart(2, "0");
    const s = String(cd % 60).padStart(2, "0");
    if (timerEl) timerEl.textContent = `${m}:${s}`;
    if (cd <= 0) {
      clearInterval(iv);
      if (msgEl)  msgEl.textContent = "Code expired. Click Resend to get a new code.";
      if (verBtn) verBtn.disabled   = true;
    }
  }, 1000);
}
startTimer();

async function verifyOTP() {
  const entered = (inp ? inp.value : "").trim();
  if (!entered) { if (msgEl) msgEl.textContent = "Please enter the 6-digit code."; return; }
  if (verBtn) { verBtn.disabled = true; verBtn.textContent = "Verifying..."; }
  if (msgEl) msgEl.textContent = "";

  try {
    const r = await fetch("/api/verify-otp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ user_id: pend.user_id, otp: entered })
    });
    const d = await r.json();

    if (!r.ok) {
      if (msgEl) msgEl.textContent = d.error || "Incorrect code. Please try again.";
      if (verBtn) { verBtn.disabled = false; verBtn.textContent = "Verify Code"; }
      return;
    }

    if (msgEl) { msgEl.className = "ok"; msgEl.textContent = "Verification successful. Redirecting..."; }
    clearInterval(iv);

    const email = pend.email;
    const lc    = parseInt(localStorage.getItem(email + "_lc") || "0") + 1;
    localStorage.setItem(email + "_lc", lc);
    sessionStorage.setItem(email + "_fa", 0);
    sessionStorage.removeItem("otp_p");

    setTok(d.token);
    setUsr({ role: d.role, email: d.email, name: d.name });

    const map = { super_admin: "/super-admin", admin: "/admin", user: "/user" };
    setTimeout(() => window.location.href = map[d.role] || "/user", 1200);

  } catch (e) {
    if (msgEl) msgEl.textContent = "Connection error: " + e.message;
    if (verBtn) { verBtn.disabled = false; verBtn.textContent = "Verify Code"; }
  }
}

async function resendOTP() {
  const email = pend.email;
  if (!email) {
    if (msgEl) msgEl.textContent = "Session expired. Please log in again.";
    setTimeout(() => window.location.href = "/", 2000);
    return;
  }
  if (resBtn) resBtn.textContent = "Sending...";
  try {
    await fetch("/api/resend-otp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ user_id: pend.user_id, email })
    });
    if (msgEl) { msgEl.className = "ok"; msgEl.textContent = "New code sent. Check your inbox."; }
  } catch {
    if (msgEl) msgEl.textContent = "Failed to resend. Please try again.";
  }
  startTimer();
  if (resBtn) resBtn.textContent = "Resend Code";
  if (verBtn) verBtn.disabled = false;
}

if (verBtn) verBtn.addEventListener("click", verifyOTP);
if (resBtn) resBtn.addEventListener("click", resendOTP);
if (inp)    inp.addEventListener("keydown", e => { if (e.key === "Enter") verifyOTP(); });
