import { api, guard, getUsr, clrAuth, toast, fmtDate, riskBadge, roleBadge, statusBadge, loadingRow } from "./utils.js";
if (!guard("admin")) throw 0;
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
  if (name === "overview")  loadStats();
  if (name === "users")     loadUsers();
  if (name === "logs")      loadLogs();
  if (name === "analytics") loadAnalytics();
}

async function loadStats() {
  try {
    const d = await api("/api/admin/stats");
    Object.entries(d).forEach(([k,v]) => { const el=document.getElementById("st-"+k); if(el) el.textContent=v; });
  } catch(e) { toast(e.message,"error"); }
}

let allUsers = [];
async function loadUsers() {
  loadingRow("users-tb", 4);
  try {
    const d = await api("/api/admin/users");
    allUsers = d.users;
    renderUsers(allUsers);
  } catch(e) { toast(e.message,"error"); }
}
function renderUsers(users) {
  const tb = document.getElementById("users-tb");
  if (!users.length) { tb.innerHTML=`<tr><td colspan="4" style="text-align:center;padding:18px;color:var(--mut)">No users</td></tr>`; return; }
  tb.innerHTML = users.map(u => `<tr>
    <td>${u.email}</td>
    <td>${u.name||"—"}</td>
    <td>${roleBadge(u.role)}</td>
    <td>${statusBadge(u.status)}
      <button class="btn ${u.status==="active"?"btn-d":"btn-s"}" style="margin-left:8px"
        onclick="window.togSt(${u.id},'${u.status}')">
        ${u.status==="active"?"Block":"Unblock"}
      </button>
    </td>
  </tr>`).join("");
}
window.togSt = async (uid, cur) => {
  const st = cur==="active" ? "blocked" : "active";
  try {
    await api(`/api/admin/users/${uid}/status`, {method:"PUT", body:JSON.stringify({status:st})});
    toast(`User ${st}`,"success"); loadUsers();
  } catch(e) { toast(e.message,"error"); }
};
document.getElementById("user-search")?.addEventListener("input", e => {
  const q = e.target.value.toLowerCase();
  renderUsers(allUsers.filter(u => u.email.toLowerCase().includes(q)||(u.name||"").toLowerCase().includes(q)));
});

async function loadLogs() {
  loadingRow("logs-tb", 5);
  try {
    const d = await api("/api/admin/logs?limit=200");
    const tb = document.getElementById("logs-tb");
    if (!d.logs.length) { tb.innerHTML=`<tr><td colspan="5" style="text-align:center;padding:18px;color:var(--mut)">No logs</td></tr>`; return; }
    tb.innerHTML = d.logs.map(l => `<tr>
      <td>${l.email||"—"}</td>
      <td>${l.action||"—"}</td>
      <td>${riskBadge(l.risk_label||"low")}</td>
      <td>${statusBadge(l.status||"—")}</td>
      <td style="font-size:11px;color:var(--mut)">${fmtDate(l.timestamp)}</td>
    </tr>`).join("");
  } catch(e) { toast(e.message,"error"); }
}

let charts = {};
async function loadAnalytics() {
  try {
    const d = await api("/api/admin/analytics");
    const co={plugins:{legend:{labels:{color:"#e2e8f0"}}},responsive:true};
    const sc={ticks:{color:"#64748b"},grid:{color:"#232d45"}};
    const tc = document.getElementById("chart-trend")?.getContext("2d");
    if(tc){charts.t?.destroy();charts.t=new Chart(tc,{type:"line",data:{
      labels:d.trend.map(t=>t.date.slice(5)),
      datasets:[
        {label:"Success",data:d.trend.map(t=>t.success),borderColor:"#10b981",backgroundColor:"rgba(16,185,129,.08)",tension:.4},
        {label:"Failed",data:d.trend.map(t=>t.failed),borderColor:"#f43f5e",backgroundColor:"rgba(244,63,94,.08)",tension:.4},
        {label:"High Risk",data:d.trend.map(t=>t.high_risk),borderColor:"#f59e0b",backgroundColor:"rgba(245,158,11,.08)",tension:.4}
      ]},options:{...co,scales:{x:sc,y:{...sc,beginAtZero:true}}}});}
    const rc = document.getElementById("chart-risk")?.getContext("2d");
    if(rc){charts.r?.destroy();charts.r=new Chart(rc,{type:"doughnut",data:{
      labels:["Safe","High Risk"],
      datasets:[{data:[d.risk_distribution.low,d.risk_distribution.high],backgroundColor:["#10b981","#f43f5e"],borderColor:"#141926",borderWidth:3}]
    },options:co});}
  } catch(e) { toast(e.message,"error"); }
}

document.getElementById("logout-btn").addEventListener("click", async () => {
  try { await api("/api/logout",{method:"POST"}); } catch {}
  clrAuth(); window.location.href="/";
});

load("overview");
