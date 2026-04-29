"""
SMS OS Firewall Module — Flask Blueprint
Integrates directly with Windows Firewall (netsh advfirewall) and
Linux Firewall (iptables) for OS-level packet blocking.

How it works:
  - HTTP threat detection (SQLi, XSS, rate limit) still runs in Python
    because the OS firewall cannot inspect HTTP content.
  - When a threat is detected OR an admin adds a rule, Python calls the
    appropriate OS command to create a real firewall rule at kernel level.
  - All rules are mirrored in SQLite so the dashboard can display them
    and so rules can be re-applied after a Linux reboot.
  - On startup, all active SQLite rules are re-applied to the OS
    automatically (handles Linux reboot persistence).

Privilege requirements:
  - Windows: run Python as Administrator
  - Linux:   run Python as root or with sudo

Rule naming convention (so we only manage our own rules):
  Block:   SMS_BLOCK_1_2_3_4
  Allow:   SMS_ALLOW_1_2_3_4
"""

from flask import Blueprint, request, jsonify
import sqlite3, time, datetime, threading, re as _re, os, sys
import subprocess, platform, ipaddress
import jwt as _jwt

fw_bp = Blueprint("os_firewall", __name__)

# ── CONFIG ───────────────────────────────────────────────────────────────────
_JWT_SECRET       = "sms-rbac-secret-key-min32bytes-ok"
DB_PATH           = "sms.db"
RATE_WINDOW       = 60      # seconds per sliding window
RATE_MAX          = 10      # max requests per IP per window (raise to 100 for production)
RATE_BLOCK_SECS   = 120     # 2-min temporary block on rate breach (raise to 900 for production)
THREAT_BLOCK_SECS = 3600    # 1-hour block on detected attack
RULE_PREFIX_BLOCK = "SMS_BLOCK_"
RULE_PREFIX_ALLOW = "SMS_ALLOW_"

# ── OS DETECTION ─────────────────────────────────────────────────────────────
OS_NAME = platform.system()   # "Windows" or "Linux"
IS_WIN  = OS_NAME == "Windows"
IS_LIN  = OS_NAME == "Linux"

# ── PRIVILEGE CHECK ───────────────────────────────────────────────────────────
def _is_privileged():
    try:
        if IS_WIN:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        else:
            return os.geteuid() == 0
    except Exception:
        return False

HAS_PRIV = _is_privileged()

if not HAS_PRIV:
    print("\n" + "="*60)
    print("  SMS OS FIREWALL — PRIVILEGE WARNING")
    if IS_WIN:
        print("  Run 'python app.py' as Administrator for OS firewall.")
    else:
        print("  Run 'sudo python app.py' for OS firewall.")
    print("  App firewall (rate limit + threat scan) still active.")
    print("="*60 + "\n")
else:
    print(f"\n[OS FIREWALL] Running with {'Administrator' if IS_WIN else 'root'} "
          f"privileges on {OS_NAME}. OS firewall active.\n")

# ── ATTACK PATTERNS ───────────────────────────────────────────────────────────
_SQLI = _re.compile(
    r"(union[\s\+]+select|select\s.+\sfrom\s|insert\s+into\s|drop\s+table"
    r"|delete\s+from\s|;\s*drop|;\s*delete|xp_cmdshell|exec\s*\("
    r"|sleep\s*\(\d+\)|benchmark\s*\(|0x[0-9a-f]{6,})",
    _re.IGNORECASE
)
_XSS = _re.compile(
    r"(<\s*script[\s>]|javascript\s*:|on\w+\s*=\s*['\"]"
    r"|<\s*iframe|document\.cookie|eval\s*\(|alert\s*\()",
    _re.IGNORECASE
)
_PATH  = _re.compile(r"\.\.[/\\]|%2e%2e[%2f%5c]", _re.IGNORECASE)
_CMDI  = _re.compile(
    r"(;|\||&&|`)\s*(ls|cat|rm|wget|curl|bash|sh|python|nc|ncat|chmod)",
    _re.IGNORECASE
)
_SSRF  = _re.compile(
    r"(https?://(localhost|127\.|192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.))",
    _re.IGNORECASE
)
_HDRI  = _re.compile(r"[\r\n]%0[aAdD]", _re.IGNORECASE)

# ── IN-MEMORY RATE TRACKER ────────────────────────────────────────────────────
_rate_store = {}
_rate_lock  = threading.Lock()

# ── DB ────────────────────────────────────────────────────────────────────────
def _db():
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    return c

def _init_tables():
    with _db() as c:
        c.executescript("""
            CREATE TABLE IF NOT EXISTS fw_rules (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ip          TEXT    NOT NULL,
                rule_type   TEXT    NOT NULL,
                reason      TEXT    DEFAULT '',
                auto        INTEGER DEFAULT 0,
                os_applied  INTEGER DEFAULT 0,
                expires_at  TEXT,
                created_at  TEXT    DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS fw_logs (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ip        TEXT,
                action    TEXT,
                reason    TEXT,
                endpoint  TEXT,
                timestamp TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS fw_visitors (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                ip         TEXT NOT NULL,
                email      TEXT DEFAULT '',
                endpoint   TEXT DEFAULT '',
                req_count  INTEGER DEFAULT 1,
                first_seen TEXT DEFAULT (datetime('now')),
                last_seen  TEXT DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_fwr_ip  ON fw_rules(ip);
            CREATE INDEX IF NOT EXISTS idx_fwl_ts  ON fw_logs(timestamp);
            CREATE INDEX IF NOT EXISTS idx_fwv_ip  ON fw_visitors(ip);
        """)
        # Migration-safe: add os_applied column if upgrading
        try:
            c.execute("ALTER TABLE fw_rules ADD COLUMN os_applied INTEGER DEFAULT 0")
        except Exception:
            pass

_init_tables()

# ── HELPERS ───────────────────────────────────────────────────────────────────
def _get_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    return xff.split(",")[0].strip() if xff else (request.remote_addr or "127.0.0.1")

def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _rule_name(action, ip):
    """Generate a unique, parseable rule name for this IP."""
    safe_ip = ip.replace(".", "_").replace(":", "_")
    return f"{RULE_PREFIX_BLOCK if action == 'block' else RULE_PREFIX_ALLOW}{safe_ip}"

def _fw_log(ip, action, reason, endpoint):
    with _db() as c:
        c.execute(
            "INSERT INTO fw_logs (ip,action,reason,endpoint,timestamp) VALUES (?,?,?,?,?)",
            (ip, action, reason, endpoint, _now())
        )

def _track_visitor(ip, endpoint, email=""):
    with _db() as c:
        row = c.execute("SELECT id FROM fw_visitors WHERE ip=?", (ip,)).fetchone()
        if row:
            c.execute(
                "UPDATE fw_visitors SET req_count=req_count+1, last_seen=?, "
                "endpoint=?, email=CASE WHEN ?!='' THEN ? ELSE email END WHERE ip=?",
                (_now(), endpoint, email, email, ip)
            )
        else:
            c.execute(
                "INSERT INTO fw_visitors (ip,email,endpoint,req_count,first_seen,last_seen) "
                "VALUES (?,?,?,1,?,?)",
                (ip, email, endpoint, _now(), _now())
            )

# ═══════════════════════════════════════════════════════════════════════════════
#  OS FIREWALL COMMANDS
# ═══════════════════════════════════════════════════════════════════════════════

def _run_cmd(cmd, timeout=8):
    """Run a shell command. Returns (success, output, error)."""
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True,
            text=True, timeout=timeout
        )
        return r.returncode == 0, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)

# ── WINDOWS COMMANDS (netsh advfirewall) ──────────────────────────────────────
def _win_block(ip):
    name = _rule_name("block", ip)
    ok, out, err = _run_cmd(
        f'netsh advfirewall firewall add rule name="{name}" '
        f'dir=in action=block remoteip={ip} protocol=any'
    )
    if ok:
        print(f"[WIN FW] Blocked {ip}")
    else:
        print(f"[WIN FW] Block {ip} failed: {err}")
    return ok

def _win_allow(ip):
    name = _rule_name("allow", ip)
    ok, out, err = _run_cmd(
        f'netsh advfirewall firewall add rule name="{name}" '
        f'dir=in action=allow remoteip={ip} protocol=any'
    )
    if ok:
        print(f"[WIN FW] Whitelisted {ip}")
    else:
        print(f"[WIN FW] Whitelist {ip} failed: {err}")
    return ok

def _win_remove(ip, rule_type):
    name = _rule_name("block" if rule_type == "blacklist" else "allow", ip)
    ok, out, err = _run_cmd(
        f'netsh advfirewall firewall delete rule name="{name}"'
    )
    print(f"[WIN FW] Removed rule '{name}': {'ok' if ok else err}")
    return ok

def _win_status():
    ok, out, err = _run_cmd(
        "netsh advfirewall show allprofiles state"
    )
    if not ok:
        return {"enabled": False, "profiles": {}, "error": err}
    profiles = {}
    for line in out.splitlines():
        line = line.strip()
        if "State" in line:
            parts = line.split()
            state = parts[-1].upper()
            profiles[line] = state == "ON"
    enabled = any(profiles.values())
    return {"enabled": enabled, "profiles": profiles, "error": None}

def _win_list_sms_rules():
    """List all rules created by SMS."""
    ok, out, err = _run_cmd(
        f'netsh advfirewall firewall show rule name=all'
    )
    if not ok:
        return []
    rules = []
    current = {}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Rule Name:"):
            if current.get("name", "").startswith(("SMS_BLOCK_", "SMS_ALLOW_")):
                rules.append(current)
            current = {"name": line.split(":", 1)[1].strip()}
        elif line.startswith("Direction:"):
            current["direction"] = line.split(":", 1)[1].strip()
        elif line.startswith("Action:"):
            current["action"] = line.split(":", 1)[1].strip()
        elif line.startswith("RemoteIP:"):
            current["remoteip"] = line.split(":", 1)[1].strip()
        elif line.startswith("Enabled:"):
            current["enabled"] = line.split(":", 1)[1].strip()
    if current.get("name", "").startswith(("SMS_BLOCK_", "SMS_ALLOW_")):
        rules.append(current)
    return rules

# ── LINUX COMMANDS (iptables) ─────────────────────────────────────────────────
def _lin_block(ip):
    # Remove any existing ACCEPT rule first to avoid conflicts
    _run_cmd(f"iptables -D INPUT -s {ip} -j ACCEPT 2>/dev/null")
    ok, out, err = _run_cmd(f"iptables -I INPUT 1 -s {ip} -j DROP")
    if ok:
        _lin_save()
        print(f"[LIN FW] Blocked {ip}")
    else:
        print(f"[LIN FW] Block {ip} failed: {err}")
    return ok

def _lin_allow(ip):
    # Remove any existing DROP rule first to avoid conflicts
    _run_cmd(f"iptables -D INPUT -s {ip} -j DROP 2>/dev/null")
    ok, out, err = _run_cmd(f"iptables -I INPUT 1 -s {ip} -j ACCEPT")
    if ok:
        _lin_save()
        print(f"[LIN FW] Whitelisted {ip}")
    else:
        print(f"[LIN FW] Whitelist {ip} failed: {err}")
    return ok

def _lin_remove(ip, rule_type):
    action = "DROP" if rule_type == "blacklist" else "ACCEPT"
    ok, out, err = _run_cmd(f"iptables -D INPUT -s {ip} -j {action}")
    if ok:
        _lin_save()
        print(f"[LIN FW] Removed {action} rule for {ip}")
    else:
        print(f"[LIN FW] Remove {ip} failed: {err}")
    return ok

def _lin_save():
    """Persist iptables rules across reboots."""
    # Try iptables-save first, then ufw if available
    ok, _, _ = _run_cmd("iptables-save > /etc/iptables/rules.v4 2>/dev/null || "
                         "iptables-save > /etc/iptables.rules 2>/dev/null")
    return ok

def _lin_status():
    ok, out, err = _run_cmd("iptables -L INPUT -n --line-numbers")
    if not ok:
        return {"enabled": False, "rule_count": 0, "error": err, "rules_preview": ""}
    lines = [l for l in out.splitlines() if l.strip()]
    rule_count = max(0, len(lines) - 2)  # subtract header lines
    return {
        "enabled": True,
        "rule_count": rule_count,
        "error": None,
        "rules_preview": out[:800]
    }

def _lin_list_sms_rules():
    """List iptables INPUT rules that belong to SMS (DROP or ACCEPT rules)."""
    ok, out, err = _run_cmd("iptables -L INPUT -n --line-numbers")
    if not ok:
        return []
    rules = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[1] in ("DROP", "ACCEPT") and parts[3] != "0.0.0.0/0":
            rules.append({
                "line_num": parts[0],
                "action":   parts[1],
                "source":   parts[3],
                "enabled":  "Yes"
            })
    return rules

# ── UNIFIED OS INTERFACE ──────────────────────────────────────────────────────
def os_block(ip):
    if not HAS_PRIV:
        print(f"[OS FW] No privileges — skipping OS block for {ip}")
        return False
    return _win_block(ip) if IS_WIN else _lin_block(ip)

def os_allow(ip):
    if not HAS_PRIV:
        return False
    return _win_allow(ip) if IS_WIN else _lin_allow(ip)

def os_remove(ip, rule_type):
    if not HAS_PRIV:
        return False
    return _win_remove(ip, rule_type) if IS_WIN else _lin_remove(ip, rule_type)

def os_status():
    if not HAS_PRIV:
        return {"enabled": False, "error": "No admin/root privileges",
                "os": OS_NAME, "privileged": False}
    status = _win_status() if IS_WIN else _lin_status()
    status["os"]         = OS_NAME
    status["privileged"] = True
    return status

def os_list_rules():
    if not HAS_PRIV:
        return []
    return _win_list_sms_rules() if IS_WIN else _lin_list_sms_rules()

# ── DB RULE HELPERS ───────────────────────────────────────────────────────────
def _is_whitelisted(ip):
    with _db() as c:
        return c.execute(
            "SELECT id FROM fw_rules WHERE ip=? AND rule_type='whitelist' "
            "AND (expires_at IS NULL OR expires_at > datetime('now'))", (ip,)
        ).fetchone() is not None

def _is_blacklisted(ip):
    with _db() as c:
        return c.execute(
            "SELECT id FROM fw_rules WHERE ip=? AND rule_type='blacklist' "
            "AND (expires_at IS NULL OR expires_at > datetime('now'))", (ip,)
        ).fetchone() is not None

def _add_rule_db(ip, rule_type, reason, auto=0, expires_at=None, os_applied=0):
    with _db() as c:
        existing = c.execute(
            "SELECT id FROM fw_rules WHERE ip=? AND rule_type=?", (ip, rule_type)
        ).fetchone()
        if existing:
            return False
        c.execute(
            "INSERT INTO fw_rules (ip,rule_type,reason,auto,os_applied,expires_at) "
            "VALUES (?,?,?,?,?,?)",
            (ip, rule_type, reason, auto, os_applied, expires_at)
        )
        return True

def _auto_block(ip, reason, secs):
    expires = (
        datetime.datetime.now(datetime.timezone.utc) +
        datetime.timedelta(seconds=secs)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    with _db() as c:
        already = c.execute(
            "SELECT id FROM fw_rules WHERE ip=? AND rule_type='blacklist' "
            "AND (expires_at IS NULL OR expires_at > datetime('now'))", (ip,)
        ).fetchone()
        if already:
            return
        applied = 1 if os_block(ip) else 0
        c.execute(
            "INSERT INTO fw_rules (ip,rule_type,reason,auto,os_applied,expires_at) "
            "VALUES (?,?,?,1,?,?)",
            (ip, "blacklist", reason, applied, expires)
        )
    _fw_log(ip, "auto_blocked", reason, request.path if request else "system")

# ── RATE LIMITER ──────────────────────────────────────────────────────────────
def _check_rate(ip):
    now = time.time()
    with _rate_lock:
        ts = [t for t in _rate_store.get(ip, []) if now - t < RATE_WINDOW]
        ts.append(now)
        _rate_store[ip] = ts
        return len(ts) > RATE_MAX

# ── THREAT SCANNER ────────────────────────────────────────────────────────────
def _detect_threat(req):
    parts = [req.path, req.query_string.decode("utf-8", errors="ignore")]
    if req.method in ("POST", "PUT", "PATCH"):
        try:
            parts.append(req.get_data(as_text=True))
        except Exception:
            pass
    payload = " ".join(parts)
    if _SQLI.search(payload): return "SQL Injection"
    if _XSS.search(payload):  return "XSS Attempt"
    if _PATH.search(payload):  return "Path Traversal"
    if _CMDI.search(payload):  return "Command Injection"
    if _SSRF.search(payload):  return "SSRF Attempt"
    if _HDRI.search(payload):  return "HTTP Header Injection"
    return None

# ── JWT AUTH ──────────────────────────────────────────────────────────────────
def _need_sa():
    auth = request.headers.get("Authorization", "")
    tok  = auth[7:] if auth.startswith("Bearer ") else request.cookies.get("token")
    if not tok:
        return None, (jsonify({"error": "Unauthorized"}), 401)
    try:
        p = _jwt.decode(tok, _JWT_SECRET, algorithms=["HS256"])
    except _jwt.ExpiredSignatureError:
        return None, (jsonify({"error": "Token expired"}), 401)
    except _jwt.InvalidTokenError:
        return None, (jsonify({"error": "Invalid token"}), 401)
    if p.get("role") != "super_admin":
        return None, (jsonify({"error": "Super Admin only"}), 403)
    return p, None

# ── STARTUP SYNC (re-apply all active rules to OS after reboot) ───────────────
def _startup_sync():
    """On startup, re-apply all non-expired SQLite rules to the OS firewall.
    This is critical on Linux where iptables rules don't persist after reboot."""
    if not HAS_PRIV:
        return
    try:
        with _db() as c:
            rules = c.execute(
                "SELECT ip, rule_type FROM fw_rules "
                "WHERE (expires_at IS NULL OR expires_at > datetime('now'))"
            ).fetchall()
        count = 0
        for r in rules:
            ip, rt = r["ip"], r["rule_type"]
            if rt == "blacklist":
                ok = os_block(ip)
            else:
                ok = os_allow(ip)
            if ok:
                count += 1
                with _db() as c:
                    c.execute(
                        "UPDATE fw_rules SET os_applied=1 WHERE ip=? AND rule_type=?",
                        (ip, rt)
                    )
        print(f"[OS FW] Startup sync: applied {count}/{len(rules)} rules to {OS_NAME} firewall.")
    except Exception as e:
        print(f"[OS FW] Startup sync error: {e}")

# Run startup sync in a background thread so it doesn't delay app startup
threading.Thread(target=_startup_sync, daemon=True).start()

# ═══════════════════════════════════════════════════════════════════════════════
#  FIREWALL MIDDLEWARE
# ═══════════════════════════════════════════════════════════════════════════════
@fw_bp.before_app_request
def firewall_middleware():
    if request.path.startswith("/static/"):
        return

    ip = _get_ip()

    # Track visitors (background thread — non-blocking)
    threading.Thread(target=_track_visitor, args=(ip, request.path), daemon=True).start()

    # 1. Whitelist — always allow (OS already allows, this is a fast-path)
    if _is_whitelisted(ip):
        return

    # 2. Blacklist check in SQLite (OS already blocked most packets,
    #    but loopback/proxy might still reach Flask)
    if _is_blacklisted(ip):
        _fw_log(ip, "blocked", "IP is blacklisted", request.path)
        return jsonify({
            "error": "Access denied. Your IP has been blocked by the firewall."
        }), 403

    # 3. Rate limiting (OS cannot do this — HTTP-level only)
    if _check_rate(ip):
        _fw_log(ip, "rate_limited", "Rate limit exceeded (100 req/60s)", request.path)
        threading.Thread(
            target=_auto_block,
            args=(ip, "Auto-blocked: Rate limit exceeded", RATE_BLOCK_SECS),
            daemon=True
        ).start()
        return jsonify({
            "error": "Too many requests. Your IP has been temporarily blocked."
        }), 429

    # 4. Threat detection (OS cannot read HTTP body — Python-level only)
    threat = _detect_threat(request)
    if threat:
        _fw_log(ip, "threat", threat, request.path)
        threading.Thread(
            target=_auto_block,
            args=(ip, f"Auto-blocked: {threat}", THREAT_BLOCK_SECS),
            daemon=True
        ).start()
        return jsonify({
            "error": "Request blocked by the security firewall."
        }), 403

# ═══════════════════════════════════════════════════════════════════════════════
#  SECURITY RESPONSE HEADERS
# ═══════════════════════════════════════════════════════════════════════════════
@fw_bp.after_app_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"]  = "nosniff"
    response.headers["X-Frame-Options"]         = "DENY"
    response.headers["X-XSS-Protection"]        = "1; mode=block"
    response.headers["Referrer-Policy"]         = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]      = "geolocation=(), microphone=(), camera=()"
    return response

# ═══════════════════════════════════════════════════════════════════════════════
#  API ROUTES — Super Admin only
# ═══════════════════════════════════════════════════════════════════════════════

@fw_bp.route("/api/sa/firewall/myip")
def fw_myip():
    return jsonify({"ip": _get_ip()})


@fw_bp.route("/api/sa/firewall/os-status")
def fw_os_status():
    p, e = _need_sa()
    if e: return e
    status = os_status()
    status["os_rules"] = os_list_rules()
    return jsonify(status)


@fw_bp.route("/api/sa/firewall/stats")
def fw_stats():
    p, e = _need_sa()
    if e: return e
    with _db() as c:
        blacklisted     = c.execute(
            "SELECT COUNT(*) FROM fw_rules WHERE rule_type='blacklist' "
            "AND (expires_at IS NULL OR expires_at > datetime('now'))"
        ).fetchone()[0]
        whitelisted     = c.execute(
            "SELECT COUNT(*) FROM fw_rules WHERE rule_type='whitelist'"
        ).fetchone()[0]
        total_blocked   = c.execute(
            "SELECT COUNT(*) FROM fw_logs WHERE action IN ('blocked','rate_limited','threat','auto_blocked')"
        ).fetchone()[0]
        threats_24h     = c.execute(
            "SELECT COUNT(*) FROM fw_logs WHERE action='threat' "
            "AND timestamp > datetime('now','-24 hours')"
        ).fetchone()[0]
        rate_events     = c.execute(
            "SELECT COUNT(*) FROM fw_logs WHERE action='rate_limited'"
        ).fetchone()[0]
        unique_visitors = c.execute("SELECT COUNT(*) FROM fw_visitors").fetchone()[0]
        total_requests  = c.execute(
            "SELECT COALESCE(SUM(req_count),0) FROM fw_visitors"
        ).fetchone()[0]
        os_applied_count= c.execute(
            "SELECT COUNT(*) FROM fw_rules WHERE os_applied=1 "
            "AND (expires_at IS NULL OR expires_at > datetime('now'))"
        ).fetchone()[0]
    return jsonify({
        "blacklisted":      blacklisted,
        "whitelisted":      whitelisted,
        "total_blocked":    total_blocked,
        "threats_24h":      threats_24h,
        "rate_events":      rate_events,
        "unique_visitors":  unique_visitors,
        "total_requests":   total_requests,
        "os_applied":       os_applied_count,
        "os_name":          OS_NAME,
        "privileged":       HAS_PRIV
    })


@fw_bp.route("/api/sa/firewall/rules")
def fw_rules_get():
    p, e = _need_sa()
    if e: return e
    with _db() as c:
        rules = [dict(r) for r in c.execute(
            "SELECT * FROM fw_rules ORDER BY created_at DESC"
        ).fetchall()]
    return jsonify({"rules": rules})


@fw_bp.route("/api/sa/firewall/rules", methods=["POST"])
def fw_rules_add():
    p, e = _need_sa()
    if e: return e
    d         = request.get_json() or {}
    ip        = d.get("ip", "").strip()
    rule_type = d.get("rule_type", "")
    reason    = (d.get("reason") or "Manual rule").strip()

    if not ip or rule_type not in ("blacklist", "whitelist"):
        return jsonify({"error": "Valid IP and rule type (blacklist/whitelist) required"}), 400

    # Validate IP format
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"error": "Invalid IP address format"}), 400

    with _db() as c:
        if c.execute(
            "SELECT id FROM fw_rules WHERE ip=? AND rule_type=?", (ip, rule_type)
        ).fetchone():
            return jsonify({"error": "A rule for this IP already exists"}), 409

    # Apply to OS firewall
    if rule_type == "blacklist":
        applied = os_block(ip)
    else:
        applied = os_allow(ip)

    _add_rule_db(ip, rule_type, reason, auto=0, os_applied=1 if applied else 0)
    _fw_log(ip, "manual_" + rule_type, reason, "dashboard")

    return jsonify({
        "message":    f"IP {ip} added to {rule_type}",
        "os_applied": applied,
        "os_name":    OS_NAME,
        "warning":    None if applied else (
            f"Saved to database but OS firewall command failed. "
            f"{'Run as Administrator.' if IS_WIN else 'Run as root/sudo.'}"
        )
    }), 201


@fw_bp.route("/api/sa/firewall/rules/<int:rid>", methods=["DELETE"])
def fw_rules_delete(rid):
    p, e = _need_sa()
    if e: return e
    with _db() as c:
        rule = c.execute("SELECT * FROM fw_rules WHERE id=?", (rid,)).fetchone()
        if not rule:
            return jsonify({"error": "Rule not found"}), 404
        rule = dict(rule)
        c.execute("DELETE FROM fw_rules WHERE id=?", (rid,))

    # Remove from OS
    os_remove(rule["ip"], rule["rule_type"])
    _fw_log(rule["ip"], "rule_removed", f"Admin removed {rule['rule_type']} rule", "dashboard")
    return jsonify({"message": f"Rule removed for {rule['ip']}"})


@fw_bp.route("/api/sa/firewall/logs")
def fw_logs_get():
    p, e = _need_sa()
    if e: return e
    limit = min(int(request.args.get("limit", 200)), 1000)
    with _db() as c:
        logs = [dict(r) for r in c.execute(
            "SELECT * FROM fw_logs ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()]
    return jsonify({"logs": logs})


@fw_bp.route("/api/sa/firewall/visitors")
def fw_visitors():
    p, e = _need_sa()
    if e: return e
    limit = min(int(request.args.get("limit", 100)), 500)
    with _db() as c:
        rows = [dict(r) for r in c.execute(
            "SELECT v.*, "
            "  CASE WHEN b.id IS NOT NULL THEN 'blacklisted' "
            "       WHEN w.id IS NOT NULL THEN 'whitelisted' "
            "       ELSE 'allowed' END AS fw_status "
            "FROM fw_visitors v "
            "LEFT JOIN fw_rules b ON v.ip=b.ip AND b.rule_type='blacklist' "
            "  AND (b.expires_at IS NULL OR b.expires_at > datetime('now')) "
            "LEFT JOIN fw_rules w ON v.ip=w.ip AND w.rule_type='whitelist' "
            "ORDER BY v.last_seen DESC LIMIT ?",
            (limit,)
        ).fetchall()]
    return jsonify({"visitors": rows})


@fw_bp.route("/api/sa/firewall/block-visitor", methods=["POST"])
def fw_block_visitor():
    p, e = _need_sa()
    if e: return e
    d      = request.get_json() or {}
    ip     = d.get("ip", "").strip()
    reason = d.get("reason") or "Blocked from visitor list"
    if not ip:
        return jsonify({"error": "IP required"}), 400
    with _db() as c:
        if c.execute(
            "SELECT id FROM fw_rules WHERE ip=? AND rule_type='blacklist' "
            "AND (expires_at IS NULL OR expires_at > datetime('now'))", (ip,)
        ).fetchone():
            return jsonify({"error": "IP is already blacklisted"}), 409
    applied = os_block(ip)
    _add_rule_db(ip, "blacklist", reason, auto=0, os_applied=1 if applied else 0)
    _fw_log(ip, "manual_blacklist", reason, "visitor_dashboard")
    return jsonify({
        "message":    f"IP {ip} blocked",
        "os_applied": applied,
        "warning":    None if applied else "Saved to DB but OS command failed — check privileges."
    })


@fw_bp.route("/api/sa/firewall/sync", methods=["POST"])
def fw_sync():
    """Re-apply all active DB rules to the OS firewall (e.g. after a reboot)."""
    p, e = _need_sa()
    if e: return e
    if not HAS_PRIV:
        return jsonify({
            "error": f"No privileges. {'Run as Administrator.' if IS_WIN else 'Run as root/sudo.'}"
        }), 403
    with _db() as c:
        rules = c.execute(
            "SELECT ip, rule_type FROM fw_rules "
            "WHERE (expires_at IS NULL OR expires_at > datetime('now'))"
        ).fetchall()
    applied = 0
    failed  = 0
    for r in rules:
        ok = os_block(r["ip"]) if r["rule_type"] == "blacklist" else os_allow(r["ip"])
        if ok:
            applied += 1
            with _db() as c:
                c.execute(
                    "UPDATE fw_rules SET os_applied=1 WHERE ip=? AND rule_type=?",
                    (r["ip"], r["rule_type"])
                )
        else:
            failed += 1
    return jsonify({
        "message":  f"Sync complete: {applied} applied, {failed} failed",
        "applied":  applied,
        "failed":   failed,
        "os_name":  OS_NAME
    })


@fw_bp.route("/api/sa/firewall/clear-expired", methods=["POST"])
def fw_clear_expired():
    p, e = _need_sa()
    if e: return e
    with _db() as c:
        expired = c.execute(
            "SELECT ip, rule_type FROM fw_rules "
            "WHERE expires_at IS NOT NULL AND expires_at <= datetime('now')"
        ).fetchall()
        count = 0
        for r in expired:
            os_remove(r["ip"], r["rule_type"])
            count += 1
        c.execute(
            "DELETE FROM fw_rules "
            "WHERE expires_at IS NOT NULL AND expires_at <= datetime('now')"
        )
    return jsonify({"message": f"Cleared {count} expired rule(s) from DB and OS firewall"})


@fw_bp.route("/api/sa/firewall/setup-guide")
def fw_setup_guide():
    """Returns OS-specific setup instructions for running with privileges."""
    p, e = _need_sa()
    if e: return e
    if IS_WIN:
        steps = [
            "Right-click Command Prompt or PowerShell → Run as Administrator",
            "Navigate to your project folder: cd path\\to\\sms_final",
            "Run: python app.py",
            "Windows Defender Firewall will now be controlled by SMS."
        ]
    else:
        steps = [
            "Open a terminal in your project folder",
            "Run: sudo python app.py",
            "Or: sudo python3 app.py",
            "iptables rules will be created and saved automatically.",
            "Rules persist via /etc/iptables/rules.v4 or /etc/iptables.rules"
        ]
    return jsonify({
        "os":        OS_NAME,
        "steps":     steps,
        "privileged": HAS_PRIV,
        "current_status": "Running with privileges — OS firewall active." if HAS_PRIV
                          else "Running WITHOUT privileges — OS firewall inactive. Follow steps above."
    })
