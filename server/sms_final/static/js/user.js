import { api, guard, getUsr, clrAuth, toast, fmtDate, riskBadge, statusBadge, loadingRow } from "./utils.js";
if (!guard("user")) throw 0;
const usr = getUsr();
document.getElementById("sb-uname").textContent = usr.name || usr.email.split("@")[0];

document.querySelectorAll(".nav-item[data-s]").forEach(n => {
  n.addEventListener("click", () => {
    document.querySelectorAll(".nav-item[data-s]").forEach(x => x.classList.remove("active"));
    document.querySelectorAll(".sec").forEach(x => x.classList.remove("active"));
    n.classList.add("active");
    const sec = document.getElementById("s-" + n.dataset.s);
    if (sec) sec.classList.add("active");
    load(n.dataset.s);
  });
});

function load(name) {
  if (name === "profile")  loadProfile();
  if (name === "activity") loadActivity();
  if (name === "security") loadSecurity();
}

async function loadProfile() {
  try {
    const d = await api("/api/user/profile");
    const p = d.profile;
    const init = (p.name || p.email || "U")[0].toUpperCase();
    document.getElementById("pav").textContent   = init;
    document.getElementById("pname").textContent = p.name || "—";
    document.getElementById("pemail").textContent= p.email;
    document.getElementById("prole").innerHTML   = `<span class="badge b-${p.role}">${p.role}</span>`;
    document.getElementById("pstat").innerHTML   = `<span class="badge b-${p.status}">${p.status}</span>`;
    document.getElementById("i-email").textContent = p.email;
    document.getElementById("i-name").textContent  = p.name || "—";
    document.getElementById("i-role").textContent  = p.role;
    document.getElementById("i-stat").textContent  = p.status;
    document.getElementById("i-since").textContent = fmtDate(p.created_at);
  } catch(e) { toast(e.message, "error"); }
}

document.getElementById("edit-btn")?.addEventListener("click", () => {
  const f = document.getElementById("edit-form");
  f.style.display = f.style.display === "none" ? "flex" : "none";
});
document.getElementById("save-name")?.addEventListener("click", async () => {
  const n = document.getElementById("new-name").value;
  try {
    await api("/api/user/profile", { method:"PUT", body:JSON.stringify({name:n}) });
    toast("Name updated", "success");
    document.getElementById("edit-form").style.display = "none";
    loadProfile();
  } catch(e) { toast(e.message, "error"); }
});

async function loadActivity() {
  loadingRow("act-tb", 5);
  try {
    const d  = await api("/api/user/logs");
    const tb = document.getElementById("act-tb");
    if (!d.logs.length) {
      tb.innerHTML = `<tr><td colspan="5" style="text-align:center;padding:18px;color:var(--mut)">No activity yet</td></tr>`;
      return;
    }
    tb.innerHTML = d.logs.map(l => `<tr>
      <td style="font-size:12px">${l.action || "—"}</td>
      <td>${riskBadge(l.risk_label || "low")}</td>
      <td>${statusBadge(l.status || "—")}</td>
      <td style="font-size:12px;color:var(--mut)">${l.device || "—"}</td>
      <td style="font-size:11px;color:var(--mut)">${fmtDate(l.timestamp)}</td>
    </tr>`).join("");
  } catch(e) { toast(e.message, "error"); }
}

async function loadSecurity() {
  try {
    const d    = await api("/api/user/logs");
    const logs = d.logs;

    // ── Find the right log for each field ────────────────────────────────
    // Last login_attempt → has device, location, risk_label
    const lastAttempt = logs.find(l =>
      l.action === "login_attempt" || l.action === "login_success"
    );

    // Last completed login (otp_verified or login_success) → shows real login time
    const lastLogin = logs.find(l =>
      l.action === "otp_verified" || l.action === "login_success"
    );

    // Device & Location: from last login_attempt (only that action stores them)
    const deviceLog  = logs.find(l => l.device && l.device !== "");
    const locationLog= logs.find(l => l.location && l.location !== "");

    // ── Risk: show the actual login risk from login_attempt ───────────────
    const riskEntry = lastAttempt || logs[0];
    const riskLabel = riskEntry ? (riskEntry.risk_label || "low") : "low";

    // ── Display ───────────────────────────────────────────────────────────
    const riskEl = document.getElementById("sec-risk");
    if (riskEl) {
      if (riskLabel === "high") {
        riskEl.innerHTML = `<span class="rh">High Risk — OTP Required</span>`;
      } else {
        riskEl.innerHTML = `<span class="rl">Safe</span>`;
      }
    }

    // Last login time — show when you actually got in
    const timeEl = document.getElementById("sec-time");
    if (timeEl) {
      timeEl.textContent = lastLogin ? fmtDate(lastLogin.timestamp)
                         : lastAttempt ? fmtDate(lastAttempt.timestamp)
                         : "—";
    }

    // Login method — make it human readable
    const actionEl = document.getElementById("sec-action");
    if (actionEl) {
      if (!lastLogin && !lastAttempt) {
        actionEl.textContent = "—";
      } else {
        const action = (lastLogin || lastAttempt).action;
        const labels = {
          "login_success": "Direct login (Safe)",
          "otp_verified":  "Login via OTP verification",
          "login_attempt": "Login attempt",
          "login_failed":  "Login failed"
        };
        actionEl.textContent = labels[action] || action;
      }
    }

    // Device — from the attempt log that has it
    const devEl = document.getElementById("sec-device");
    if (devEl) devEl.textContent = deviceLog ? (deviceLog.device || "—") : "—";

    // Location — from the attempt log that has it
    const locEl = document.getElementById("sec-loc");
    if (locEl) locEl.textContent = locationLog ? (locationLog.location || "—") : "—";

    // MFA Status — dynamic based on actual last login method
    const mfaEl = document.getElementById("sec-mfa");
    if (mfaEl) {
      const usedOTP = logs.find(l => l.action === "otp_verified");
      if (usedOTP) {
        mfaEl.innerHTML = `<span style="color:var(--ok)">OTP Verified on High-Risk Login</span>`;
      } else if (lastLogin && lastLogin.action === "login_success") {
        mfaEl.innerHTML = `<span style="color:var(--ok)">Direct Login — Risk Was Low</span>`;
      } else {
        mfaEl.innerHTML = `<span style="color:var(--mut)">OTP triggered on high-risk logins</span>`;
      }
    }

  } catch(e) { toast(e.message, "error"); }
}

document.getElementById("logout-btn").addEventListener("click", async () => {
  try { await api("/api/logout", { method:"POST" }); } catch {}
  clrAuth(); window.location.href = "/";
});

load("profile");
