import { api, guard, getUsr, clrAuth, toast, fmtDate, riskBadge, roleBadge, statusBadge, loadingRow } from "./utils.js";
if (!guard("super_admin")) throw 0;
const usr = getUsr();
document.getElementById("sb-uname").textContent = usr.name || usr.email.split("@")[0];

// ── NAV ────────────────────────────────────────────────────────────────────
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
  if (name === "overview")  loadStats();
  if (name === "users")     loadUsers();
  if (name === "logs")      loadLogs();
  if (name === "security")  loadSecurity();
  if (name === "analytics") loadAnalytics();
  if (name === "controls")  loadControls();
  if (name === "firewall")  loadFirewall();
}

// ── STATS ──────────────────────────────────────────────────────────────────
async function loadStats() {
  try {
    const d = await api("/api/sa/stats");
    Object.entries(d).forEach(([k, v]) => {
      const el = document.getElementById("st-" + k);
      if (el) el.textContent = v;
    });
  } catch(e) { toast(e.message, "error"); }
}

// ── DRILL DOWN ─────────────────────────────────────────────────────────────
window.drillDown = async (type) => {
  const modal   = document.getElementById("drill-modal");
  const titleEl = document.getElementById("modal-title");
  const bodyEl  = document.getElementById("modal-body");
  bodyEl.innerHTML = `<div style="text-align:center;padding:20px"><span class="spin"></span></div>`;
  modal.classList.add("open");
  try {
    if (["total_users","admins","users"].includes(type)) {
      const d = await api("/api/sa/users");
      let list = d.users;
      if (type === "admins") list = list.filter(u => u.role === "admin");
      if (type === "users")  list = list.filter(u => u.role === "user");
      titleEl.textContent = type === "admins" ? "Admins" : type === "users" ? "Users" : "All Users";
      bodyEl.innerHTML = `<table style="width:100%;border-collapse:collapse">
        <thead><tr>
          <th style="padding:8px;text-align:left;color:var(--mut);font-size:11px;text-transform:uppercase">Email</th>
          <th style="padding:8px;text-align:left;color:var(--mut);font-size:11px;text-transform:uppercase">Role</th>
          <th style="padding:8px;text-align:left;color:var(--mut);font-size:11px;text-transform:uppercase">Status</th>
          <th style="padding:8px;text-align:left;color:var(--mut);font-size:11px;text-transform:uppercase">Created</th>
        </tr></thead>
        <tbody>${list.map(u => `<tr style="border-bottom:1px solid rgba(35,45,69,.5)">
          <td style="padding:8px;font-size:13px;color:var(--dt)">${u.email}</td>
          <td style="padding:8px">${roleBadge(u.role)}</td>
          <td style="padding:8px">${statusBadge(u.status)}</td>
          <td style="padding:8px;font-size:11px;color:var(--mut)">${fmtDate(u.created_at)}</td>
        </tr>`).join("")}</tbody></table>`;
    } else if (["active_users","blocked_users"].includes(type)) {
      const d  = await api("/api/sa/users");
      const st = type === "active_users" ? "active" : "blocked";
      const list = d.users.filter(u => u.status === st);
      titleEl.textContent = type === "active_users" ? "Active Users" : "Blocked Users";
      bodyEl.innerHTML = `<table style="width:100%;border-collapse:collapse">
        <thead><tr>
          <th style="padding:8px;text-align:left;color:var(--mut);font-size:11px;text-transform:uppercase">Email</th>
          <th style="padding:8px;text-align:left;color:var(--mut);font-size:11px;text-transform:uppercase">Name</th>
          <th style="padding:8px;text-align:left;color:var(--mut);font-size:11px;text-transform:uppercase">Role</th>
        </tr></thead>
        <tbody>${list.map(u=>`<tr style="border-bottom:1px solid rgba(35,45,69,.5)">
          <td style="padding:8px;font-size:13px;color:var(--dt)">${u.email}</td>
          <td style="padding:8px;font-size:13px;color:var(--mut)">${u.name||"—"}</td>
          <td style="padding:8px">${roleBadge(u.role)}</td>
        </tr>`).join("")}
        ${!list.length?`<tr><td colspan="3" style="padding:16px;text-align:center;color:var(--mut)">None found</td></tr>`:""}
        </tbody></table>`;
    } else if (["success_logins","failed_logins"].includes(type)) {
      const st = type === "success_logins" ? "success" : "failed";
      const d  = await api("/api/sa/logs?limit=200");
      const list = d.logs.filter(l => l.status === st);
      titleEl.textContent = type === "success_logins" ? "Successful Logins" : "Failed Logins";
      bodyEl.innerHTML = `<table style="width:100%;border-collapse:collapse">
        <thead><tr>
          <th style="padding:8px;text-align:left;color:var(--mut);font-size:11px">Email</th>
          <th style="padding:8px;text-align:left;color:var(--mut);font-size:11px">Action</th>
          <th style="padding:8px;text-align:left;color:var(--mut);font-size:11px">Risk</th>
          <th style="padding:8px;text-align:left;color:var(--mut);font-size:11px">Time</th>
        </tr></thead>
        <tbody>${list.slice(0,50).map(l=>`<tr style="border-bottom:1px solid rgba(35,45,69,.5)">
          <td style="padding:8px;font-size:12px;color:var(--dt)">${l.email||"—"}</td>
          <td style="padding:8px;font-size:12px;color:var(--mut)">${l.action||"—"}</td>
          <td style="padding:8px">${riskBadge(l.risk_label||"low")}</td>
          <td style="padding:8px;font-size:11px;color:var(--mut)">${fmtDate(l.timestamp)}</td>
        </tr>`).join("")}</tbody></table>`;
    } else if (type === "high_risk") {
      const d = await api("/api/sa/security");
      titleEl.textContent = "High Risk Events";
      bodyEl.innerHTML = `<table style="width:100%;border-collapse:collapse">
        <thead><tr>
          <th style="padding:8px;text-align:left;color:var(--mut);font-size:11px">Email</th>
          <th style="padding:8px;text-align:left;color:var(--mut);font-size:11px">Action</th>
          <th style="padding:8px;text-align:left;color:var(--mut);font-size:11px">Device</th>
          <th style="padding:8px;text-align:left;color:var(--mut);font-size:11px">Location</th>
          <th style="padding:8px;text-align:left;color:var(--mut);font-size:11px">Time</th>
        </tr></thead>
        <tbody>${d.alerts.map(l=>`<tr style="border-bottom:1px solid rgba(35,45,69,.5)">
          <td style="padding:8px;font-size:12px;color:var(--dt)">${l.email||"—"}</td>
          <td style="padding:8px;font-size:12px;color:var(--mut)">${l.action||"—"}</td>
          <td style="padding:8px;font-size:12px;color:var(--mut)">${l.device||"—"}</td>
          <td style="padding:8px;font-size:12px;color:var(--mut)">${l.location||"—"}</td>
          <td style="padding:8px;font-size:11px;color:var(--mut)">${fmtDate(l.timestamp)}</td>
        </tr>`).join("")}
        ${!d.alerts.length?`<tr><td colspan="5" style="padding:16px;text-align:center;color:var(--mut)">No high-risk events</td></tr>`:""}
        </tbody></table>`;
    } else if (type === "events") {
      modal.classList.remove("open");
      document.querySelector('[data-s="logs"]').click();
      return;
    }
  } catch(e) { bodyEl.innerHTML=`<p style="color:var(--danger)">${e.message}</p>`; }
};
document.getElementById("drill-modal")?.addEventListener("click", function(e) {
  if (e.target === this) this.classList.remove("open");
});

// ── USERS ──────────────────────────────────────────────────────────────────
let allUsers = [];
async function loadUsers() {
  loadingRow("users-tb", 7);
  try {
    const d = await api("/api/sa/users");
    allUsers = d.users;
    renderUsers(allUsers);
  } catch(e) { toast(e.message, "error"); }
}
function renderUsers(users) {
  const tb  = document.getElementById("users-tb");
  const lbl = document.getElementById("user-count-label");
  if (lbl) lbl.textContent = `${users.length} user${users.length!==1?"s":""}`;
  if (!users.length) {
    tb.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:18px;color:var(--mut)">No users found</td></tr>`;
    return;
  }
  tb.innerHTML = users.map(u => `
    <tr>
      <td style="font-size:11px;font-family:var(--mono);color:var(--mut)">#${u.id}</td>
      <td style="font-size:13px">${u.email}</td>
      <td style="font-size:13px;color:var(--mut)">${u.name || "—"}</td>
      <td>${roleBadge(u.role)}</td>
      <td>${statusBadge(u.status)}</td>
      <td style="font-size:11px;color:var(--mut)">${fmtDate(u.created_at)}</td>
      <td style="white-space:nowrap">
        ${u.email !== "sanjay22522g@gmail.com" ? `
          <select class="rsel" data-uid="${u.id}" style="background:var(--card2);border:1px solid var(--bdr);color:var(--dt);border-radius:6px;padding:4px 7px;font-size:11px;margin-right:4px">
            <option value="">Role...</option>
            <option value="super_admin" ${u.role==="super_admin"?"selected":""}>Super Admin</option>
            <option value="admin"       ${u.role==="admin"?"selected":""}>Admin</option>
            <option value="user"        ${u.role==="user"?"selected":""}>User</option>
          </select>
          <button class="btn ${u.status==="active"?"btn-d":"btn-s"}" onclick="window.togSt(${u.id},'${u.status}')" style="margin-right:4px">
            ${u.status==="active"?"Block":"Unblock"}
          </button>
          <button class="btn btn-o" onclick="window.delUsr(${u.id},'${u.email}')">Delete</button>
        ` : `<span style="font-size:12px;color:var(--warn)">Protected</span>`}
      </td>
    </tr>`).join("");

  document.querySelectorAll(".rsel").forEach(sel => {
    sel.addEventListener("change", async () => {
      if (!sel.value) return;
      try {
        await api(`/api/sa/users/${sel.dataset.uid}/role`, { method:"PUT", body:JSON.stringify({ role:sel.value }) });
        toast("Role updated", "success"); loadUsers();
      } catch(e) { toast(e.message, "error"); sel.value = ""; }
    });
  });
}
window.togSt = async (uid, cur) => {
  const st = cur === "active" ? "blocked" : "active";
  try {
    await api(`/api/sa/users/${uid}/status`, { method:"PUT", body:JSON.stringify({ status:st }) });
    toast(`User ${st}`, "success"); loadUsers();
  } catch(e) { toast(e.message, "error"); }
};
window.delUsr = async (uid, email) => {
  if (!confirm(`Delete ${email}? This action cannot be undone.`)) return;
  try {
    await api(`/api/sa/users/${uid}`, { method:"DELETE" });
    toast("User deleted", "success"); loadUsers();
  } catch(e) { toast(e.message, "error"); }
};
document.getElementById("user-search")?.addEventListener("input",  filterUsers);
document.getElementById("role-filter")?.addEventListener("change", filterUsers);
document.getElementById("status-filter")?.addEventListener("change", filterUsers);
function filterUsers() {
  const q  = (document.getElementById("user-search")?.value||"").toLowerCase();
  const rf = document.getElementById("role-filter")?.value||"";
  const sf = document.getElementById("status-filter")?.value||"";
  renderUsers(allUsers.filter(u =>
    (!q  || u.email.toLowerCase().includes(q) || (u.name||"").toLowerCase().includes(q)) &&
    (!rf || u.role === rf) &&
    (!sf || u.status === sf)
  ));
}

// ── LOGS ───────────────────────────────────────────────────────────────────
let allLogs = [];
async function loadLogs() {
  loadingRow("logs-tb", 8);
  try {
    const d = await api("/api/sa/logs?limit=200");
    allLogs = d.logs;
    renderLogs(allLogs);
  } catch(e) { toast(e.message, "error"); }
}
function renderLogs(logs) {
  const tb  = document.getElementById("logs-tb");
  const lbl = document.getElementById("log-count-label");
  if (lbl) lbl.textContent = `${logs.length} event${logs.length!==1?"s":""}`;
  if (!logs.length) { tb.innerHTML=`<tr><td colspan="8" style="text-align:center;padding:18px;color:var(--mut)">No logs</td></tr>`; return; }
  tb.innerHTML = logs.map(l => `<tr>
    <td style="font-size:11px;font-family:var(--mono);color:var(--mut)">#${l.user_id||"—"}</td>
    <td style="font-size:12px">${l.email||"—"}</td>
    <td style="font-size:12px;color:var(--mut)">${l.action||"—"}</td>
    <td>${riskBadge(l.risk_label||"low")}</td>
    <td>${statusBadge(l.status||"—")}</td>
    <td style="font-size:11px;color:var(--mut)">${l.device||"—"}</td>
    <td style="font-size:11px;color:var(--mut)">${l.location||"—"}</td>
    <td style="font-size:11px;color:var(--mut)">${fmtDate(l.timestamp)}</td>
  </tr>`).join("");
}
document.getElementById("log-search")?.addEventListener("input",        filterLogs);
document.getElementById("log-risk-filter")?.addEventListener("change",   filterLogs);
document.getElementById("log-status-filter")?.addEventListener("change", filterLogs);
function filterLogs() {
  const q  = (document.getElementById("log-search")?.value||"").toLowerCase();
  const rf = document.getElementById("log-risk-filter")?.value||"";
  const sf = document.getElementById("log-status-filter")?.value||"";
  renderLogs(allLogs.filter(l =>
    (!q  || (l.email||"").toLowerCase().includes(q) || (l.action||"").includes(q)) &&
    (!rf || (l.risk_label||"low") === rf) &&
    (!sf || l.status === sf)
  ));
}

// ── SECURITY ───────────────────────────────────────────────────────────────
async function loadSecurity() {
  loadingRow("sec-tb", 5);
  try {
    const d = await api("/api/sa/security");
    document.getElementById("alert-count").textContent = d.alerts.length;
    const tb = document.getElementById("sec-tb");
    if (!d.alerts.length) { tb.innerHTML=`<tr><td colspan="5" style="text-align:center;padding:18px;color:var(--mut)">No high-risk events</td></tr>`; return; }
    tb.innerHTML = d.alerts.map(l => `<tr>
      <td style="font-size:12px">${l.email||"—"}</td>
      <td style="font-size:12px;color:var(--mut)">${l.action||"—"}</td>
      <td style="font-size:12px;color:var(--mut)">${l.device||"—"}</td>
      <td style="font-size:12px;color:var(--mut)">${l.location||"—"}</td>
      <td style="font-size:11px;color:var(--mut)">${fmtDate(l.timestamp)}</td>
    </tr>`).join("");
  } catch(e) { toast(e.message, "error"); }
}

// ── ANALYTICS ──────────────────────────────────────────────────────────────
let charts = {};
async function loadAnalytics() {
  try {
    const [basic, rich] = await Promise.all([
      api("/api/sa/analytics"),
      api("/api/sa/analytics/rich")
    ]);
    const co = { plugins:{legend:{labels:{color:"#e2e8f0",font:{size:11}}}}, responsive:true, maintainAspectRatio:true };
    const sc = { ticks:{color:"#64748b"}, grid:{color:"#232d45"} };
    document.querySelectorAll(".atab").forEach(tab => {
      tab.addEventListener("click", () => {
        document.querySelectorAll(".atab").forEach(t=>t.classList.remove("active"));
        document.querySelectorAll(".asec").forEach(s=>s.classList.remove("active"));
        tab.classList.add("active");
        document.getElementById("at-"+tab.dataset.at)?.classList.add("active");
        renderTabCharts(tab.dataset.at, basic, rich, co, sc);
      });
    });
    renderTabCharts("login", basic, rich, co, sc);
  } catch(e) { toast(e.message, "error"); }
}
function mkChart(id, cfg, chartKey) {
  const ctx = document.getElementById(id)?.getContext("2d");
  if (!ctx) return;
  charts[chartKey]?.destroy();
  charts[chartKey] = new Chart(ctx, cfg);
}
function renderTabCharts(tab, basic, rich, co, sc) {
  if (tab === "login") {
    mkChart("chart-trend7", { type:"line", data:{
      labels: basic.trend.map(t=>t.date.slice(5)),
      datasets:[
        {label:"Success",  data:basic.trend.map(t=>t.success),   borderColor:"#10b981",backgroundColor:"rgba(16,185,129,.1)",tension:.4,fill:true},
        {label:"Failed",   data:basic.trend.map(t=>t.failed),    borderColor:"#f43f5e",backgroundColor:"rgba(244,63,94,.1)",tension:.4,fill:true},
        {label:"High Risk",data:basic.trend.map(t=>t.high_risk), borderColor:"#f59e0b",backgroundColor:"rgba(245,158,11,.1)",tension:.4,fill:true}
      ]}, options:{...co, scales:{x:sc,y:{...sc,beginAtZero:true}}}
    }, "t7");
    const sb = rich.status_breakdown;
    mkChart("chart-status", { type:"pie", data:{
      labels:["Success","Failed","Pending"],
      datasets:[{data:[sb.success||0,sb.failed||0,sb.pending||0],
        backgroundColor:["#10b981","#f43f5e","#f59e0b"],borderColor:"#141926",borderWidth:2}]
    }, options:co }, "ts");
    mkChart("chart-trend30", { type:"bar", data:{
      labels: rich.trend_30days.map(t=>t.date.slice(5)),
      datasets:[{label:"Events",data:rich.trend_30days.map(t=>t.count),backgroundColor:"rgba(79,142,247,.6)",borderRadius:3}]
    }, options:{...co, plugins:{legend:{display:false}}, scales:{x:sc,y:{...sc,beginAtZero:true}}}}, "t30");
  } else if (tab === "user") {
    const rd = rich.role_distribution;
    mkChart("chart-roles", { type:"doughnut", data:{
      labels:["Super Admin","Admin","User"],
      datasets:[{data:[rd.super_admin||0,rd.admin||0,rd.user||0],
        backgroundColor:["#f59e0b","#4f8ef7","#10b981"],borderColor:"#141926",borderWidth:2}]
    }, options:co }, "roles");
    mkChart("chart-ustatus", { type:"doughnut", data:{
      labels:["Active","Blocked"],
      datasets:[{data:[rd.user||0,rd.super_admin||0],
        backgroundColor:["#10b981","#f43f5e"],borderColor:"#141926",borderWidth:2}]
    }, options:co }, "ustatus");
    const locBars = document.getElementById("loc-bars");
    if (locBars && rich.top_locations?.length) {
      const max = rich.top_locations[0][1];
      locBars.innerHTML = rich.top_locations.map(([loc,count]) => `
        <div class="bar-item">
          <div class="bar-label">${loc}</div>
          <div class="bar-track"><div class="bar-fill" style="width:${(count/max*100).toFixed(0)}%;background:var(--acc)"></div></div>
          <div class="bar-count">${count}</div>
        </div>`).join("");
    }
  } else if (tab === "risk") {
    mkChart("chart-risk", { type:"doughnut", data:{
      labels:["Safe","High Risk"],
      datasets:[{data:[basic.risk_distribution.low,basic.risk_distribution.high],
        backgroundColor:["#10b981","#f43f5e"],borderColor:"#141926",borderWidth:2}]
    }, options:co }, "risk");
    const act = rich.action_breakdown;
    mkChart("chart-actions", { type:"bar", data:{
      labels: Object.keys(act),
      datasets:[{label:"Count",data:Object.values(act),backgroundColor:"rgba(124,58,237,.7)",borderRadius:4}]
    }, options:{...co, plugins:{legend:{display:false}}, scales:{x:{...sc,ticks:{...sc.ticks,maxRotation:30}},y:{...sc,beginAtZero:true}}}}, "actions");
    mkChart("chart-highrisk", { type:"line", data:{
      labels: basic.trend.map(t=>t.date.slice(5)),
      datasets:[{label:"High Risk",data:basic.trend.map(t=>t.high_risk),
        borderColor:"#f43f5e",backgroundColor:"rgba(244,63,94,.15)",tension:.4,fill:true}]
    }, options:{...co, plugins:{legend:{display:false}}, scales:{x:sc,y:{...sc,beginAtZero:true}}}}, "highrisk");
  } else if (tab === "device") {
    const dev = rich.device_breakdown;
    mkChart("chart-devices", { type:"doughnut", data:{
      labels: Object.keys(dev).length ? Object.keys(dev) : ["No data"],
      datasets:[{data: Object.keys(dev).length ? Object.values(dev) : [1],
        backgroundColor:["#4f8ef7","#f59e0b","#10b981","#f43f5e"],borderColor:"#141926",borderWidth:2}]
    }, options:co }, "dev");
    const locBars2 = document.getElementById("device-loc-bars");
    if (locBars2 && rich.top_locations?.length) {
      const max = rich.top_locations[0][1];
      locBars2.innerHTML = rich.top_locations.map(([loc,count]) => `
        <div class="bar-item">
          <div class="bar-label">${loc}</div>
          <div class="bar-track"><div class="bar-fill" style="width:${(count/max*100).toFixed(0)}%;background:#f59e0b"></div></div>
          <div class="bar-count">${count}</div>
        </div>`).join("");
    } else if (locBars2) {
      locBars2.innerHTML = `<p style="color:var(--mut);padding:12px">No location data available</p>`;
    }
  } else if (tab === "time") {
    const labels = Array.from({length:24},(_,i)=>`${String(i).padStart(2,"0")}:00`);
    mkChart("chart-hourly", { type:"bar", data:{
      labels,
      datasets:[{label:"Logins",data:rich.hourly_activity,
        backgroundColor: rich.hourly_activity.map((_,i) =>
          (i>=6&&i<=9)||i===12||(i>=17&&i<=20) ? "rgba(16,185,129,.7)" : "rgba(79,142,247,.5)"
        ),borderRadius:4}]
    }, options:{...co, plugins:{legend:{display:false}},
      scales:{x:{...sc,ticks:{...sc.ticks,maxRotation:45}},y:{...sc,beginAtZero:true}}}}, "hourly");
  }
}

// ── CONTROLS ───────────────────────────────────────────────────────────────
async function loadControls() {
  try {
    const [stats, rich] = await Promise.all([
      api("/api/sa/stats"),
      api("/api/sa/analytics/rich")
    ]);
    const dbEl = document.getElementById("ctrl-db-stats");
    if (dbEl) dbEl.textContent = `${rich.total_users} users · ${rich.total_logs} events`;
    const saEl = document.getElementById("ctrl-sa-email");
    if (saEl) {
      const d  = await api("/api/sa/users");
      const sa = d.users.find(u => u.role === "super_admin");
      if (sa) saEl.textContent = sa.email;
    }
    const msEl = document.getElementById("model-status");
    if (msEl) {
      try {
        await api("/api/sa/analytics");
        msEl.innerHTML = `<span class="ctrl-badge cb-ok">Active</span>`;
      } catch {
        msEl.innerHTML = `<span class="ctrl-badge cb-warn">Check logs</span>`;
      }
    }
  } catch(e) { console.warn("Controls load error:", e.message); }
}

// ── FIREWALL ───────────────────────────────────────────────────────────────
async function loadFirewall() {
  await Promise.all([loadFwStats(), loadFwRules()]);

  // Load current IP
  try {
    const ip = await fetch("/api/sa/firewall/myip").then(r => r.json());
    const el = document.getElementById("fw-myip");
    if (el) el.textContent = ip.ip || "Unknown";
  } catch { /* silently fail */ }

  // Load OS status card
  await loadFwOsStatus();

  // Tab switching
  document.querySelectorAll(".fw-tab").forEach(tab => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".fw-tab").forEach(t => t.classList.remove("active"));
      document.querySelectorAll(".fw-pane").forEach(p => p.classList.remove("active"));
      tab.classList.add("active");
      document.getElementById("fwp-" + tab.dataset.fw)?.classList.add("active");
      if (tab.dataset.fw === "logs")      loadFwLogs();
      if (tab.dataset.fw === "rules")     loadFwRules();
      if (tab.dataset.fw === "visitors")  loadFwVisitors();
      if (tab.dataset.fw === "os-rules")  loadFwOsRules();
    });
  });

  // Sync button
  document.getElementById("fw-sync-btn")?.addEventListener("click", async () => {
    const btn = document.getElementById("fw-sync-btn");
    btn.textContent = "Syncing..."; btn.disabled = true;
    try {
      const d = await api("/api/sa/firewall/sync", { method: "POST" });
      toast(d.message, "success");
      loadFwStats(); loadFwOsStatus();
    } catch(e) {
      toast(e.message, "error");
    }
    btn.textContent = "Sync Rules to OS"; btn.disabled = false;
  });

  // Setup guide button
  document.getElementById("fw-guide-btn")?.addEventListener("click", async () => {
    try {
      const d   = await api("/api/sa/firewall/setup-guide");
      const mod = document.getElementById("fw-guide-modal");
      const ttl = document.getElementById("fw-guide-title");
      const cnt = document.getElementById("fw-guide-content");
      ttl.textContent = `${d.os} Firewall Setup Guide`;
      const statusColor = d.privileged ? "#26c281" : "#ffa726";
      cnt.innerHTML = `
        <div style="background:${d.privileged ? "rgba(38,194,129,0.1)" : "rgba(255,167,38,0.1)"};
          border:1px solid ${statusColor};border-radius:8px;padding:12px 16px;margin-bottom:16px">
          <strong style="color:${statusColor}">
            ${d.privileged ? "Running with privileges — OS firewall is active." : "Running WITHOUT privileges — OS firewall is inactive."}
          </strong>
        </div>
        <p style="color:var(--mut);margin-bottom:12px">Follow these steps to run with elevated privileges:</p>
        <ol style="padding-left:20px;color:var(--dt)">
          ${d.steps.map(s => `<li style="margin-bottom:10px;font-size:13px">${s}</li>`).join("")}
        </ol>`;
      mod.classList.add("open");
    } catch(e) { toast(e.message, "error"); }
  });
  document.getElementById("fw-guide-modal")?.addEventListener("click", function(ev) {
    if (ev.target === this) this.classList.remove("open");
  });

  // Add rule
  document.getElementById("fw-add-btn")?.addEventListener("click", async () => {
    const ip     = (document.getElementById("fw-ip-input")?.value || "").trim();
    const type   = document.getElementById("fw-type-select")?.value || "blacklist";
    const reason = (document.getElementById("fw-reason-input")?.value || "").trim();
    if (!ip) { toast("Please enter an IP address", "error"); return; }
    try {
      await api("/api/sa/firewall/rules", {
        method: "POST",
        body: JSON.stringify({ ip, rule_type: type, reason })
      });
      toast(`IP ${ip} added to ${type}`, "success");
      document.getElementById("fw-ip-input").value     = "";
      document.getElementById("fw-reason-input").value = "";
      loadFwStats(); loadFwRules();
    } catch(e) { toast(e.message, "error"); }
  });

  // Clear expired
  document.getElementById("fw-clear-expired")?.addEventListener("click", async () => {
    try {
      const d = await api("/api/sa/firewall/clear-expired", { method: "POST" });
      toast(d.message, "success");
      loadFwStats(); loadFwRules();
    } catch(e) { toast(e.message, "error"); }
  });
}

async function loadFwStats() {
  try {
    const d = await api("/api/sa/firewall/stats");
    Object.entries(d).forEach(([k, v]) => {
      const el = document.getElementById("fw-" + k);
      if (el) el.textContent = typeof v === "number" ? v.toLocaleString() : v;
    });
    // Also refresh OS status badge
    await loadFwOsStatus();
  } catch(e) { console.warn("Firewall stats error:", e.message); }
}

async function loadFwRules() {
  loadingRow("fw-rules-tb", 7);
  try {
    const d  = await api("/api/sa/firewall/rules");
    const tb = document.getElementById("fw-rules-tb");
    if (!d.rules.length) {
      tb.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:18px;color:var(--mut)">No rules configured</td></tr>`;
      return;
    }
    tb.innerHTML = d.rules.map(r => `<tr>
      <td style="font-family:var(--mono);font-size:12px;color:var(--acc2)">${r.ip}</td>
      <td><span class="badge ${r.rule_type==="blacklist"?"b-blocked":"b-active"}">${r.rule_type}</span></td>
      <td style="font-size:12px;color:var(--mut)">${r.reason || "—"}</td>
      <td style="font-size:11px;color:var(--mut)">${r.auto ? "Auto" : "Manual"}</td>
      <td style="font-size:11px;color:var(--mut)">${r.expires_at ? fmtDate(r.expires_at) : "Permanent"}</td>
      <td style="font-size:11px;color:var(--mut)">${fmtDate(r.created_at)}</td>
      <td><button class="btn btn-d" onclick="window.delFwRule(${r.id})">Remove</button></td>
    </tr>`).join("");
  } catch(e) { toast(e.message, "error"); }
}

async function loadFwLogs() {
  loadingRow("fw-logs-tb", 5);
  try {
    const d  = await api("/api/sa/firewall/logs?limit=200");
    const tb = document.getElementById("fw-logs-tb");
    if (!d.logs.length) {
      tb.innerHTML = `<tr><td colspan="5" style="text-align:center;padding:18px;color:var(--mut)">No firewall events</td></tr>`;
      return;
    }
    tb.innerHTML = d.logs.map(l => `<tr>
      <td style="font-family:var(--mono);font-size:12px;color:var(--acc2)">${l.ip||"—"}</td>
      <td><span class="action-badge ab-${l.action}">${l.action||"—"}</span></td>
      <td style="font-size:12px;color:var(--mut)">${l.reason||"—"}</td>
      <td style="font-size:12px;color:var(--mut)">${l.endpoint||"—"}</td>
      <td style="font-size:11px;color:var(--mut)">${fmtDate(l.timestamp)}</td>
    </tr>`).join("");
  } catch(e) { toast(e.message, "error"); }
}

async function loadFwOsStatus() {
  try {
    const d = await api("/api/sa/firewall/stats");
    const nameEl    = document.getElementById("fw-os-name");
    const enabledEl = document.getElementById("fw-os-enabled-badge");
    const privEl    = document.getElementById("fw-priv-badge");
    if (nameEl)    nameEl.textContent = d.os_name || "Unknown OS";
    if (enabledEl) {
      const on = d.privileged;
      enabledEl.innerHTML = `<span class="badge ${on ? "b-active" : "b-blocked"}">
        OS Firewall ${on ? "Active" : "Inactive"}</span>`;
    }
    if (privEl) {
      privEl.innerHTML = d.privileged
        ? `<span class="badge b-active">Privileged</span>`
        : `<span class="badge b-blocked">No Privileges — Run as ${d.os_name === "Windows" ? "Administrator" : "root/sudo"}</span>`;
    }
    // Update os_applied stat
    const osEl = document.getElementById("fw-os_applied");
    if (osEl) osEl.textContent = (d.os_applied || 0).toLocaleString();
  } catch(e) { console.warn("OS status error:", e.message); }
}

async function loadFwOsRules() {
  loadingRow("fw-os-rules-tb", 4);
  try {
    const d  = await api("/api/sa/firewall/os-status");
    const tb = document.getElementById("fw-os-rules-tb");
    const sub = document.getElementById("os-rules-subtitle");
    if (sub) sub.textContent = `OS: ${d.os || "Unknown"} | Privileged: ${d.privileged ? "Yes" : "No"}`;
    const rules = d.os_rules || [];
    if (!rules.length) {
      const msg = d.privileged
        ? "No OS firewall rules found. Add rules above to create them."
        : `No OS access. Run as ${d.os === "Windows" ? "Administrator" : "root/sudo"} to manage OS firewall.`;
      tb.innerHTML = `<tr><td colspan="4" style="text-align:center;padding:18px;color:var(--mut)">${msg}</td></tr>`;
      return;
    }
    tb.innerHTML = rules.map(r => {
      const name  = r.name   || r.source || "—";
      const act   = r.action || "—";
      const dir   = r.direction || "In";
      const en    = r.enabled || "Yes";
      const color = act === "DROP" || act === "Block" ? "b-blocked" : "b-active";
      return `<tr>
        <td style="font-family:var(--mono);font-size:12px;color:var(--acc2)">${name}</td>
        <td><span class="badge ${color}">${act}</span></td>
        <td style="font-size:12px;color:var(--mut)">${dir}</td>
        <td style="font-size:12px;color:var(--mut)">${en}</td>
      </tr>`;
    }).join("");
  } catch(e) { toast(e.message, "error"); }
}

async function loadFwVisitors() {
  loadingRow("fw-visitors-tb", 8);
  try {
    const d  = await api("/api/sa/firewall/visitors?limit=100");
    const tb = document.getElementById("fw-visitors-tb");
    if (!d.visitors.length) {
      tb.innerHTML = `<tr><td colspan="8" style="text-align:center;padding:18px;color:var(--mut)">No visitors recorded yet. Visitors appear as soon as anyone accesses the server.</td></tr>`;
      return;
    }
    tb.innerHTML = d.visitors.map(v => {
      const statusMap = {
        blacklisted: `<span class="badge b-blocked">Blacklisted</span>`,
        whitelisted: `<span class="badge b-active">Whitelisted</span>`,
        allowed:     `<span class="badge b-user">Allowed</span>`
      };
      return `<tr>
        <td style="font-family:var(--mono);font-size:12px;color:var(--acc2)">${v.ip}</td>
        <td>${statusMap[v.fw_status] || v.fw_status}</td>
        <td style="font-size:12px;color:var(--mut)">${v.email || "—"}</td>
        <td style="font-size:11px;color:var(--mut);max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${v.endpoint || "—"}</td>
        <td style="font-family:var(--mono);font-size:12px;text-align:center">${v.req_count}</td>
        <td style="font-size:11px;color:var(--mut)">${fmtDate(v.first_seen)}</td>
        <td style="font-size:11px;color:var(--mut)">${fmtDate(v.last_seen)}</td>
        <td>
          ${v.fw_status !== "blacklisted" ? `<button class="btn btn-d" onclick="window.blockVisitor('${v.ip}')">Block</button>` : `<span style="font-size:11px;color:var(--mut)">Blocked</span>`}
        </td>
      </tr>`;
    }).join("");
  } catch(e) { toast(e.message, "error"); }
}

window.blockVisitor = async (ip) => {
  if (!confirm(`Block IP ${ip}? They will be denied all access.`)) return;
  try {
    await api("/api/sa/firewall/block-visitor", {
      method: "POST",
      body: JSON.stringify({ ip, reason: "Blocked from visitor list by Super Admin" })
    });
    toast(`IP ${ip} blocked`, "success");
    loadFwStats(); loadFwVisitors();
  } catch(e) { toast(e.message, "error"); }
};

window.delFwRule = async (id) => {
  if (!confirm("Remove this firewall rule?")) return;
  try {
    await api(`/api/sa/firewall/rules/${id}`, { method: "DELETE" });
    toast("Rule removed", "success");
    loadFwStats(); loadFwRules();
  } catch(e) { toast(e.message, "error"); }
};

// ── LOGOUT ─────────────────────────────────────────────────────────────────
document.getElementById("logout-btn").addEventListener("click", async () => {
  try { await api("/api/logout", {method:"POST"}); } catch {}
  clrAuth(); window.location.href="/";
});

load("overview");
