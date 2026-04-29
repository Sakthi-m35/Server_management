# SMS — Server Management System
Smart AI MFA + RBAC + Application Firewall | Flask + SQLite

## Quick Start

```bash
pip install -r requirements.txt
python app.py
```
Visit: http://localhost:5000

## Super Admin Credentials
- Email: sanjay22522g@gmail.com
- Password: rbac@2006

## What's New in This Version

### Firewall Module (`firewall.py`)
A Flask Blueprint that plugs into app.py with zero disruption to existing code.

**Features:**
- IP Blacklist — permanently or temporarily deny specific IPs
- IP Whitelist — trust specific IPs, bypassing all checks
- Rate Limiting — 100 requests per IP per 60 seconds; auto-blocks for 15 min
- SQL Injection detection — auto-blocks for 1 hour
- XSS detection — auto-blocks for 1 hour
- Path Traversal detection — auto-blocks for 1 hour
- Firewall Logs — separate `fw_logs` table, not mixed with app logs
- Auto-expiry — temporary blocks expire automatically
- Super Admin UI — Firewall section in the Super Admin dashboard (below Controls)

**Accessible at:** Super Admin Dashboard → Firewall (sidebar)

### Blocked / Deleted Account Pages
- Blocked users are redirected to `/blocked` showing who suspended them
- Deleted users are redirected to `/account-deleted` showing who removed them and when
- Both pages show the responsible administrator's email

### Professional UI
- All emoji icons removed from dashboards and navigation
- Clean monospace abbreviation indicators in sidebar
- Consistent corporate styling across all pages

## File Structure
```
sms_final/
├── app.py              # Main Flask app (2 lines added for firewall)
├── firewall.py         # Firewall Blueprint — new module
├── requirements.txt
├── render.yaml
├── templates/
│   ├── index.html          # Login
│   ├── signup.html         # Register
│   ├── otp.html            # OTP verification
│   ├── home.html           # Role redirect
│   ├── super_admin.html    # Super Admin dashboard (with Firewall section)
│   ├── admin.html          # Admin dashboard
│   ├── user.html           # User dashboard
│   ├── blocked.html        # NEW — account suspended page
│   └── account_deleted.html# NEW — account removed page
└── static/
    ├── css/style.css
    └── js/
        ├── auth.js         # Updated — handles blocked/deleted redirects
        ├── utils.js        # Updated — no emojis in badges
        ├── otp.js
        ├── user.js
        ├── admin.js
        └── super_admin.js  # Updated — Firewall section added
```

## Firewall DB Tables
Both tables are created automatically on first run inside `sms.db`:
- `fw_rules` — IP rules (blacklist/whitelist, manual/auto, expiry)
- `fw_logs`  — All firewall events (blocked, threat, rate_limited)
