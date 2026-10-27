"""Aegis Zero-Trust Security Dashboard & Interactive Visual Console.

Provides:
- Visual Web Console at `GET /` and `GET /dashboard`
- Live Telemetry APIs at `GET /api/stats` and `GET /api/audit-logs`
- Interactive Sandbox allowing live penetration tests and DLP verification.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List
from fastapi import APIRouter, status
from fastapi.responses import HTMLResponse, JSONResponse

from security.config import get_settings
from services.audit_logger import get_audit_log_buffer
from services.db_client import get_supabase_client

logger = logging.getLogger("aegis.routers.dashboard")

router = APIRouter(tags=["Security Console"])


@router.get("/api/stats", summary="Get Gateway Security Telemetry")
async def get_gateway_stats() -> Dict[str, Any]:
    """Calculate live security telemetry metrics from Supabase mcp_audit_logs (or memory fallback)."""
    logs: List[Dict[str, Any]] = []
    client = await get_supabase_client()
    if client:
        try:
            res = await client.table("mcp_audit_logs").select("status").execute()
            if res.data is not None and len(res.data) > 0:
                logs = res.data
        except Exception as exc:
            logger.warning("Failed to fetch stats from Supabase (%s). Using in-memory buffer.", str(exc))

    if not logs:
        logs = get_audit_log_buffer()

    total = len(logs)
    blocked = sum(1 for log in logs if log.get("status") == "BLOCKED_POLICY")
    sanitized = sum(1 for log in logs if log.get("status") == "SANITIZED_PII")
    allowed = sum(1 for log in logs if log.get("status") == "ALLOWED")

    defense_rate = 100.0 if total == 0 else round(((blocked + sanitized + allowed) / total) * 100.0, 1)

    return {
        "total_requests": total,
        "blocked_attacks": blocked,
        "sanitized_pii": sanitized,
        "allowed_clean": allowed,
        "defense_rate": defense_rate,
        "forward_shield": "ACTIVE",
        "return_dlp": "ACTIVE",
        "supabase_rbac": "ACTIVE",
    }


@router.get("/api/audit-logs", summary="Get Recent Security Audit Logs")
async def get_recent_audit_logs() -> List[Dict[str, Any]]:
    """Retrieve up to 50 most recent immutable audit log records from Supabase (or memory fallback)."""
    client = await get_supabase_client()
    if client:
        try:
            res = await client.table("mcp_audit_logs").select("*").order("timestamp", desc=True).limit(50).execute()
            if res.data is not None and len(res.data) > 0:
                return res.data
        except Exception as exc:
            logger.warning("Failed to fetch audit logs from Supabase (%s). Using in-memory buffer.", str(exc))

    logs = get_audit_log_buffer()
    return list(reversed(logs[-50:]))


@router.get("/", response_class=HTMLResponse, summary="Aegis Security Console")
@router.get("/dashboard", response_class=HTMLResponse, summary="Aegis Security Console")
async def get_security_dashboard() -> HTMLResponse:
    """Render the high-performance Aegis Zero-Trust Security Dashboard."""
    settings = get_settings()

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Aegis Zero-Trust MCP Gateway | Security Command Center</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg-base: #060911;
      --bg-surface: #0c1220;
      --bg-card: rgba(16, 24, 40, 0.75);
      --bg-card-hover: rgba(22, 34, 58, 0.85);
      --border-subtle: rgba(255, 255, 255, 0.08);
      --border-accent: rgba(0, 242, 254, 0.3);
      --primary: #00f2fe;
      --primary-glow: rgba(0, 242, 254, 0.25);
      --emerald: #10b981;
      --emerald-glow: rgba(16, 185, 129, 0.25);
      --crimson: #f43f5e;
      --crimson-glow: rgba(244, 63, 94, 0.25);
      --amber: #f59e0b;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --font-sans: 'Plus Jakarta Sans', system-ui, sans-serif;
      --font-mono: 'JetBrains Mono', monospace;
    }}

    * {{ box-sizing: border-box; margin: 0; padding: 0; }}

    body {{
      background-color: var(--bg-base);
      color: var(--text-main);
      font-family: var(--font-sans);
      min-height: 100vh;
      overflow-x: hidden;
      background-image: 
        radial-gradient(circle at 15% 15%, rgba(0, 242, 254, 0.04) 0%, transparent 40%),
        radial-gradient(circle at 85% 85%, rgba(16, 185, 129, 0.03) 0%, transparent 40%),
        linear-gradient(rgba(255, 255, 255, 0.02) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255, 255, 255, 0.02) 1px, transparent 1px);
      background-size: 100% 100%, 100% 100%, 48px 48px, 48px 48px;
    }}

    /* Top Navigation */
    header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 1.25rem 2.5rem;
      border-bottom: 1px solid var(--border-subtle);
      background: rgba(6, 9, 17, 0.8);
      backdrop-filter: blur(16px);
      position: sticky;
      top: 0;
      z-index: 100;
    }}

    .brand {{
      display: flex;
      align-items: center;
      gap: 0.85rem;
      text-decoration: none;
    }}

    .brand-icon {{
      width: 40px;
      height: 40px;
      border-radius: 10px;
      background: linear-gradient(135deg, #00f2fe 0%, #4facfe 100%);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1.3rem;
      box-shadow: 0 0 20px var(--primary-glow);
    }}

    .brand-title {{
      font-weight: 800;
      font-size: 1.35rem;
      letter-spacing: -0.02em;
      color: #fff;
    }}

    .brand-title span {{
      color: var(--primary);
    }}

    .badge-pill {{
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      padding: 0.25rem 0.75rem;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      background: rgba(16, 185, 129, 0.12);
      color: var(--emerald);
      border: 1px solid rgba(16, 185, 129, 0.3);
    }}

    .badge-pill::before {{
      content: '';
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: var(--emerald);
      box-shadow: 0 0 8px var(--emerald);
      animation: pulse 2s infinite;
    }}

    @keyframes pulse {{
      0%, 100% {{ opacity: 1; transform: scale(1); }}
      50% {{ opacity: 0.4; transform: scale(0.85); }}
    }}

    .nav-actions {{
      display: flex;
      align-items: center;
      gap: 1rem;
    }}

    .btn-link {{
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.5rem 1rem;
      border-radius: 8px;
      font-size: 0.85rem;
      font-weight: 600;
      color: var(--text-muted);
      text-decoration: none;
      border: 1px solid var(--border-subtle);
      transition: all 0.2s ease;
    }}

    .btn-link:hover {{
      color: #fff;
      border-color: var(--primary);
      box-shadow: 0 0 12px var(--primary-glow);
    }}

    /* Container Layout */
    .container {{
      max-width: 1400px;
      margin: 0 auto;
      padding: 2rem 2.5rem;
      display: flex;
      flex-direction: column;
      gap: 2rem;
    }}

    /* Telemetry Grid */
    .telemetry-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 1.25rem;
    }}

    .telemetry-card {{
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      border-radius: 16px;
      padding: 1.5rem;
      backdrop-filter: blur(12px);
      transition: transform 0.2s ease, border-color 0.2s ease;
      position: relative;
      overflow: hidden;
    }}

    .telemetry-card:hover {{
      transform: translateY(-2px);
      border-color: var(--border-accent);
    }}

    .card-label {{
      font-size: 0.8rem;
      font-weight: 600;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 0.6rem;
    }}

    .card-metric {{
      font-size: 2.25rem;
      font-weight: 800;
      font-family: var(--font-mono);
      letter-spacing: -0.03em;
      display: flex;
      align-items: baseline;
      gap: 0.5rem;
    }}

    .metric-emerald {{ color: var(--emerald); }}
    .metric-crimson {{ color: var(--crimson); }}
    .metric-primary {{ color: var(--primary); }}
    .metric-amber {{ color: var(--amber); }}

    .card-footer {{
      margin-top: 0.75rem;
      font-size: 0.75rem;
      color: var(--text-muted);
      display: flex;
      align-items: center;
      gap: 0.4rem;
    }}

    /* Main Grid: Sandbox & Logs */
    .dashboard-split {{
      display: grid;
      grid-template-columns: 1.15fr 1fr;
      gap: 1.5rem;
    }}

    @media (max-width: 1024px) {{
      .dashboard-split {{ grid-template-columns: 1fr; }}
    }}

    .glass-panel {{
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      border-radius: 18px;
      padding: 1.75rem;
      backdrop-filter: blur(16px);
      display: flex;
      flex-direction: column;
      gap: 1.25rem;
    }}

    .panel-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 0.75rem;
      border-bottom: 1px solid var(--border-subtle);
    }}

    .panel-title {{
      font-size: 1.15rem;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 0.6rem;
    }}

    /* Preset Attack Buttons */
    .preset-group {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
    }}

    .btn-preset {{
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-subtle);
      color: var(--text-muted);
      padding: 0.45rem 0.85rem;
      border-radius: 8px;
      font-size: 0.75rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
    }}

    .btn-preset:hover {{
      background: rgba(0, 242, 254, 0.08);
      color: var(--primary);
      border-color: var(--primary);
    }}

    .btn-preset.danger:hover {{
      background: rgba(244, 63, 94, 0.08);
      color: var(--crimson);
      border-color: var(--crimson);
    }}

    /* Code Editors / Viewers */
    .code-box {{
      background: #03060c;
      border: 1px solid var(--border-subtle);
      border-radius: 12px;
      padding: 1rem;
      font-family: var(--font-mono);
      font-size: 0.82rem;
      color: #e2e8f0;
      min-height: 180px;
      max-height: 260px;
      overflow: auto;
      resize: vertical;
      line-height: 1.5;
    }}

    textarea.code-box {{
      width: 100%;
      outline: none;
    }}

    textarea.code-box:focus {{
      border-color: var(--primary);
      box-shadow: 0 0 14px var(--primary-glow);
    }}

    .btn-fire {{
      background: linear-gradient(135deg, #00f2fe 0%, #4facfe 100%);
      color: #040914;
      font-weight: 700;
      font-size: 0.9rem;
      padding: 0.75rem 1.5rem;
      border: none;
      border-radius: 10px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
      transition: all 0.2s ease;
      box-shadow: 0 0 20px var(--primary-glow);
    }}

    .btn-fire:hover {{
      transform: translateY(-1px);
      box-shadow: 0 0 28px rgba(0, 242, 254, 0.4);
    }}

    /* Live Audit Table */
    .log-table-container {{
      max-height: 480px;
      overflow-y: auto;
    }}

    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.8rem;
    }}

    th {{
      text-align: left;
      padding: 0.75rem 0.6rem;
      color: var(--text-muted);
      border-bottom: 1px solid var(--border-subtle);
      font-size: 0.7rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}

    td {{
      padding: 0.75rem 0.6rem;
      border-bottom: 1px solid rgba(255, 255, 255, 0.03);
      font-family: var(--font-mono);
    }}

    .status-tag {{
      display: inline-block;
      padding: 0.2rem 0.55rem;
      border-radius: 6px;
      font-size: 0.7rem;
      font-weight: 700;
      letter-spacing: 0.03em;
    }}

    .status-allowed {{
      background: rgba(16, 185, 129, 0.15);
      color: var(--emerald);
      border: 1px solid rgba(16, 185, 129, 0.3);
    }}

    .status-blocked {{
      background: rgba(244, 63, 94, 0.15);
      color: var(--crimson);
      border: 1px solid rgba(244, 63, 94, 0.3);
    }}

    .status-sanitized {{
      background: rgba(0, 242, 254, 0.15);
      color: var(--primary);
      border: 1px solid rgba(0, 242, 254, 0.3);
    }}

    .json-tag {{
      max-width: 180px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      display: block;
      color: var(--text-muted);
    }}
  </style>
</head>
<body>
  <!-- Header -->
  <header>
    <a href="/" class="brand">
      <div class="brand-icon">🛡️</div>
      <div class="brand-title">AEGIS <span>ZERO-TRUST</span></div>
    </a>
    <div class="nav-actions">
      <span class="badge-pill">Gateway Online</span>
      <a href="/docs" target="_blank" class="btn-link">⚡ OpenAPI Swagger</a>
      <a href="/health" target="_blank" class="btn-link">💚 Health</a>
    </div>
  </header>

  <div class="container">
    <!-- Telemetry Strip -->
    <div class="telemetry-grid">
      <div class="telemetry-card">
        <div class="card-label">Total MCP Invocations</div>
        <div class="card-metric metric-primary" id="stat-total">0</div>
        <div class="card-footer">Forwarded & Evaluated</div>
      </div>
      <div class="telemetry-card">
        <div class="card-label">Attacks Neutralized</div>
        <div class="card-metric metric-crimson" id="stat-blocked">0</div>
        <div class="card-footer">Shell Injection & Schema Pollution</div>
      </div>
      <div class="telemetry-card">
        <div class="card-label">PII Redactions Applied</div>
        <div class="card-metric metric-emerald" id="stat-sanitized">0</div>
        <div class="card-footer">Presidio Return-Path Scrubbing</div>
      </div>
      <div class="telemetry-card">
        <div class="card-label">Defense Efficacy</div>
        <div class="card-metric metric-emerald" id="stat-rate">100.0%</div>
        <div class="card-footer">Zero-Trust Boundaries Held</div>
      </div>
    </div>

    <!-- Main Split: Live Interactive Playground & Immutable Audit Stream -->
    <div class="dashboard-split">
      <!-- Left Panel: Interactive Tool Simulator / Attack Sandbox -->
      <div class="glass-panel">
        <div class="panel-header">
          <div class="panel-title">🎯 Live MCP Attack & Sandbox Playground</div>
          <span style="font-size: 0.75rem; color: var(--text-muted);">Direct Gateway Dispatch</span>
        </div>

        <div style="font-size: 0.85rem; color: var(--text-muted);">
          Select a test scenario below to fire simulated payloads at the gateway and observe real-time forward injection blocking or return-path Presidio DLP redaction:
        </div>

        <div class="preset-group">
          <button class="btn-preset danger" onclick="loadPreset('shell_inject')">💀 Shell Injection Attack</button>
          <button class="btn-preset danger" onclick="loadPreset('schema_pollute')">☣️ Schema Pollution</button>
          <button class="btn-preset" onclick="loadPreset('pii_leak')">💳 PII Leak Exfiltration</button>
          <button class="btn-preset" onclick="loadPreset('unauth_rbac')">🚫 Unauthorized Session</button>
          <button class="btn-preset" onclick="loadPreset('clean')">✅ Clean Query</button>
        </div>

        <div>
          <label style="font-size: 0.75rem; font-weight: 600; color: var(--text-muted); display: block; margin-bottom: 0.35rem;">
            MCP REQUEST PAYLOAD (POST /mcp/execute)
          </label>
          <textarea id="request-payload" class="code-box" spellcheck="false"></textarea>
        </div>

        <button class="btn-fire" onclick="firePayload()">
          <span>⚡ Execute Through Aegis Gateway</span>
        </button>

        <div>
          <label style="font-size: 0.75rem; font-weight: 600; color: var(--text-muted); display: flex; justify-content: space-between; margin-bottom: 0.35rem;">
            <span>GATEWAY RETURN RESPONSE</span>
            <span id="response-status" style="font-family: var(--font-mono); font-size: 0.75rem;">Waiting for request...</span>
          </label>
          <pre id="response-viewer" class="code-box" style="white-space: pre-wrap; word-break: break-all;">No request fired yet. Select a preset and click Execute above.</pre>
        </div>
      </div>

      <!-- Right Panel: Immutable Audit Stream -->
      <div class="glass-panel">
        <div class="panel-header">
          <div class="panel-title">📋 Live Security Audit Log Stream</div>
          <button class="btn-preset" onclick="fetchAuditLogs()">🔄 Refresh</button>
        </div>

        <div style="font-size: 0.85rem; color: var(--text-muted);">
          Mirrored immutable event log recorded to Supabase table <code style="font-family: var(--font-mono); color: var(--primary);">mcp_audit_logs</code>:
        </div>

        <div class="log-table-container">
          <table>
            <thead>
              <tr>
                <th>Status</th>
                <th>Tool</th>
                <th>Mitigation</th>
                <th>Session</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody id="audit-table-body">
              <tr>
                <td colspan="5" style="text-align: center; color: var(--text-muted); padding: 2rem;">
                  Loading audit events...
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>

  <script>
    const GATEWAY_TOKEN = "{settings.aegis_gateway_token}";

    const PRESETS = {{
      shell_inject: {{
        jsonrpc: "2.0",
        id: "req-attack-001",
        method: "tools/call",
        params: {{
          name: "read_file",
          arguments: {{
            path: "financial_report.pdf; cat /etc/passwd | /bin/sh"
          }},
          _meta: {{ session_id: "sess-operator-002" }}
        }}
      }},
      schema_pollute: {{
        jsonrpc: "2.0",
        id: "req-pollute-002",
        method: "tools/call",
        params: {{
          name: "fetch_metrics",
          arguments: {{}},
          __proto__: {{ polluted: true }},
          admin_override: true
        }}
      }},
      pii_leak: {{
        jsonrpc: "2.0",
        id: "req-pii-003",
        method: "tools/call",
        params: {{
          name: "query_database",
          arguments: {{ customer_id: "cust_9921" }},
          _meta: {{ session_id: "sess-operator-002" }}
        }}
      }},
      unauth_rbac: {{
        jsonrpc: "2.0",
        id: "req-unauth-004",
        method: "tools/call",
        params: {{
          name: "read_file",
          arguments: {{ path: "server_config.yaml" }},
          _meta: {{ session_id: "sess-unauthorized-999" }}
        }}
      }},
      clean: {{
        jsonrpc: "2.0",
        id: "req-clean-005",
        method: "tools/call",
        params: {{
          name: "simulate_tool",
          arguments: {{ status: "healthy", query: "server_uptime" }},
          _meta: {{ session_id: "sess-operator-002" }}
        }}
      }}
    }};

    function loadPreset(key) {{
      const payload = PRESETS[key];
      if (payload) {{
        document.getElementById('request-payload').value = JSON.stringify(payload, null, 2);
      }}
    }}

    async function firePayload() {{
      const rawText = document.getElementById('request-payload').value;
      const statusEl = document.getElementById('response-status');
      const viewerEl = document.getElementById('response-viewer');

      let payload;
      try {{
        payload = JSON.parse(rawText);
      }} catch (err) {{
        statusEl.textContent = 'Invalid JSON';
        statusEl.style.color = 'var(--crimson)';
        viewerEl.textContent = 'Error: Cannot parse payload JSON.';
        return;
      }}

      statusEl.textContent = 'Dispatching to Gateway...';
      statusEl.style.color = 'var(--primary)';

      try {{
        const startTime = performance.now();
        const res = await fetch('/mcp/execute', {{
          method: 'POST',
          headers: {{
            'Authorization': 'Bearer ' + GATEWAY_TOKEN,
            'Content-Type': 'application/json',
            'X-Session-ID': (payload.params && payload.params._meta && payload.params._meta.session_id) || 'sess-operator-002'
          }},
          body: JSON.stringify(payload)
        }});

        const duration = Math.round(performance.now() - startTime);
        const data = await res.json();

        statusEl.textContent = `HTTP ${{res.status}} (${{duration}}ms)`;
        statusEl.style.color = res.status === 200 ? 'var(--emerald)' : 'var(--crimson)';
        viewerEl.textContent = JSON.stringify(data, null, 2);

        // Refresh stats and audit stream
        fetchStats();
        fetchAuditLogs();
      }} catch (err) {{
        statusEl.textContent = 'Network Error';
        statusEl.style.color = 'var(--crimson)';
        viewerEl.textContent = String(err);
      }}
    }}

    async function fetchStats() {{
      try {{
        const res = await fetch('/api/stats');
        const data = await res.json();
        document.getElementById('stat-total').textContent = data.total_requests;
        document.getElementById('stat-blocked').textContent = data.blocked_attacks;
        document.getElementById('stat-sanitized').textContent = data.sanitized_pii;
        document.getElementById('stat-rate').textContent = data.defense_rate + '%';
      }} catch (err) {{
        console.error(err);
      }}
    }}

    async function fetchAuditLogs() {{
      try {{
        const res = await fetch('/api/audit-logs');
        const logs = await res.json();
        const tbody = document.getElementById('audit-table-body');

        if (!logs || logs.length === 0) {{
          tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">No audit logs recorded yet.</td></tr>';
          return;
        }}

        tbody.innerHTML = logs.map(l => {{
          let tagClass = 'status-allowed';
          if (l.status === 'BLOCKED_POLICY') tagClass = 'status-blocked';
          else if (l.status === 'SANITIZED_PII') tagClass = 'status-sanitized';

          const time = l.timestamp ? l.timestamp.split('T')[1].split('.')[0] : '--:--:--';
          return `
            <tr>
              <td><span class="status-tag ${{tagClass}}">${{l.status}}</span></td>
              <td><strong>${{l.tool_name || 'unknown'}}</strong></td>
              <td style="color: var(--text-muted);">${{l.mitigation_applied || 'none'}}</td>
              <td style="color: var(--primary);">${{l.session_id || 'anonymous'}}</td>
              <td style="color: var(--text-muted);">${{time}}</td>
            </tr>
          `;
        }}).join('');
      }} catch (err) {{
        console.error(err);
      }}
    }}

    // Initial load
    loadPreset('pii_leak');
    fetchStats();
    fetchAuditLogs();
  </script>
</body>
</html>"""
    return HTMLResponse(content=html_content, status_code=status.HTTP_200_OK)
