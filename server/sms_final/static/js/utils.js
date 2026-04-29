export function toast(msg, type="info") {
  let c = document.getElementById("toast");
  if (!c) { c = document.createElement("div"); c.id = "toast"; document.body.appendChild(c); }
  const t = document.createElement("div");
  t.className = `toast t-${type==="success"?"ok":type==="error"?"err":"info"}`;
  t.textContent = msg; c.appendChild(t);
  setTimeout(() => t.remove(), 3000);
}
export const getTok  = () => localStorage.getItem("sms_token");
export const setTok  = t  => localStorage.setItem("sms_token", t);
export const getUsr  = () => { try { return JSON.parse(localStorage.getItem("sms_user")||"null"); } catch { return null; } };
export const setUsr  = u  => localStorage.setItem("sms_user", JSON.stringify(u));
export const clrAuth = () => { localStorage.removeItem("sms_token"); localStorage.removeItem("sms_user"); };

export function guard(role=null) {
  const tok = getTok(), usr = getUsr();
  if (!tok || !usr) { window.location.href = "/"; return false; }
  if (role && usr.role !== role) {
    const m = { super_admin:"/super-admin", admin:"/admin", user:"/user" };
    window.location.href = m[usr.role] || "/"; return false;
  }
  return true;
}

export async function api(url, opts={}) {
  const tok = getTok();
  const h = {
    "Content-Type": "application/json",
    ...(tok ? { Authorization: `Bearer ${tok}` } : {}),
    ...(opts.headers || {})
  };
  const r = await fetch(url, { ...opts, headers: h });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
  return d;
}

export function fmtDate(ts) {
  if (!ts) return "—";
  let d;
  if (ts.includes("T")) { d = new Date(ts); }
  else { d = new Date(ts.replace(" ", "T") + "Z"); }
  if (isNaN(d)) return ts;
  const dd   = String(d.getDate()).padStart(2,"0");
  const mm   = String(d.getMonth()+1).padStart(2,"0");
  const yyyy = d.getFullYear();
  const hh   = String(d.getHours()).padStart(2,"0");
  const min  = String(d.getMinutes()).padStart(2,"0");
  return `${dd}/${mm}/${yyyy} ${hh}:${min}`;
}

export const riskBadge   = l => l==="high"
  ? `<span class="rh">High Risk</span>`
  : `<span class="rl">Safe</span>`;
export const roleBadge   = r => `<span class="badge b-${r==="super_admin"?"sa":r}">${r.replace("_"," ")}</span>`;
export const statusBadge = s => `<span class="badge b-${s}">${s}</span>`;
export const loadingRow  = (id, cols) => {
  const e = document.getElementById(id);
  if (e) e.innerHTML = `<tr><td colspan="${cols}" style="text-align:center;padding:20px"><span class="spin"></span></td></tr>`;
};

export function getDevice() {
  if (navigator.userAgentData?.mobile ||
      /Android|iPhone|iPad|iPod/i.test(navigator.userAgent) ||
      window.innerWidth <= 768) return "Mobile";
  return "Laptop";
}

export async function getLocation() {
  let ip = null;
  try {
    const r = await fetch("https://api.ipify.org?format=json", { signal: AbortSignal.timeout(5000) });
    ip = (await r.json()).ip;
  } catch {}
  if (!ip) {
    try {
      const r = await fetch("https://api64.ipify.org?format=json", { signal: AbortSignal.timeout(5000) });
      ip = (await r.json()).ip;
    } catch {}
  }
  let country = null;
  if (ip) {
    try {
      const r = await fetch("https://ipwho.is/" + ip, { signal: AbortSignal.timeout(5000) });
      const d = await r.json();
      if (d.success && d.country) country = d.country;
    } catch {}
    if (!country) {
      try {
        const r = await fetch("https://freeipapi.com/api/json/" + ip, { signal: AbortSignal.timeout(5000) });
        const d = await r.json();
        if (d.countryName && d.countryName !== "-") country = d.countryName;
      } catch {}
    }
    if (!country) {
      try {
        const r = await fetch("https://get.geojs.io/v1/ip/country/" + ip + ".json", { signal: AbortSignal.timeout(5000) });
        const d = await r.json();
        if (d.name) country = d.name;
      } catch {}
    }
    if (!country) {
      try {
        const r = await fetch("https://ipapi.co/" + ip + "/country_name/", { signal: AbortSignal.timeout(5000) });
        const text = (await r.text()).trim();
        if (text && !text.includes("{") && !text.toLowerCase().includes("error") && text.length < 60) {
          country = text;
        }
      } catch {}
    }
  }
  if (!country) {
    try {
      const r = await fetch("https://ipwho.is/", { cache:"no-store", signal: AbortSignal.timeout(5000) });
      const d = await r.json();
      if (d.success && d.country) country = d.country;
    } catch {}
  }
  return country || "Unknown";
}
