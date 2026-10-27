# 🛡️ Aegis Zero-Trust MCP Gateway

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.11+" />
  <img src="https://img.shields.io/badge/FastAPI-0.110%2B-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/MCP-2024--11--05-7928CA?style=for-the-badge&logo=anthropic&logoColor=white" alt="Model Context Protocol" />
  <img src="https://img.shields.io/badge/Presidio-DLP%20Engine-0078D4?style=for-the-badge&logo=microsoft&logoColor=white" alt="Microsoft Presidio" />
  <img src="https://img.shields.io/badge/Supabase-PostgreSQL%20RBAC-3ECF8E?style=for-the-badge&logo=supabase&logoColor=white" alt="Supabase" />
  <img src="https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?style=for-the-badge&logo=githubactions&logoColor=white" alt="GitHub Actions" />
  <img src="https://img.shields.io/badge/Security-Zero--Trust-FF0055?style=for-the-badge&logo=securityscorecard&logoColor=white" alt="Zero-Trust" />
  <img src="https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge" alt="License" />
</p>

---

## 📑 Table of Contents

- [Overview](#-overview)
- [The MCP Security Threat Model](#-the-mcp-security-threat-model)
- [High-Level Architecture](#-high-level-architecture)
  - [Forward Path vs. Return Path](#forward-path-vs-return-path)
  - [End-to-End Sequence Diagram](#end-to-end-sequence-diagram)
- [Zero-Trust Reverse Proxy & Upstream Forwarding](#-zero-trust-reverse-proxy--upstream-forwarding)
- [Defense-in-Depth Security Layers](#-defense-in-depth-security-layers)
  - [1. Constant-Time Authentication](#1-constant-time-authentication)
  - [2. Strict Schema Validation](#2-strict-schema-validation-pydantic-v2)
  - [3. Heuristic Shell Injection Shield](#3-heuristic-shell-injection-shield)
  - [4. Supabase PostgreSQL RBAC & Tool Filtering](#4-supabase-postgresql-rbac--tool-filtering)
  - [5. Microsoft Presidio Return-Path DLP (PII + Secrets)](#5-microsoft-presidio-return-path-dlp-pii--secrets)
  - [6. Sliding-Window Rate Limiting & DoS Shield](#6-sliding-window-rate-limiting--dos-shield)
  - [7. Immutable Forensics & Audit Logging](#7-immutable-forensics--audit-logging)
  - [8. Zero-Information Leakage](#8-zero-information-leakage)
- [Interactive Security Command Center](#-interactive-security-command-center)
- [Quickstart & Installation](#-quickstart--installation)
  - [1. Clone & Dependencies](#1-clone--dependencies)
  - [2. Supabase Database Migration](#2-supabase-database-migration)
  - [3. Environment Configuration](#3-environment-configuration)
  - [4. Verify Connection](#4-verify-connection)
  - [5. Run the Gateway](#5-run-the-gateway)
- [Testing & Security Auditing](#-testing--security-auditing)
  - [Pytest Suite](#1-pytest-integration-suite)
  - [Adversarial Fuzzing Engine](#2-adversarial-fuzzing-engine)
- [API Usage Examples](#-api-usage-examples)
- [Repository Structure](#-repository-structure)
- [License](#-license)

---

## 🌐 Overview

**Aegis** is an asynchronous, production-grade **Zero-Trust Security Gateway & Reverse Proxy** engineered in Python 3.11+ (FastAPI) specifically designed for the **Model Context Protocol (MCP)** specification. 

When Large Language Models (LLMs) interact with external APIs, databases, and filesystem tools via MCP, traditional perimeter defenses collapse. Aegis acts as a zero-trust intermediary that inspects, authorizes, and sanitizes bidirectional JSON-RPC payloads in real time:

1. **Forward Path Inspection:** Blocks shell injections, command chaining, prototype pollution, and unauthorized tool calls before they ever reach your tools.
2. **Return Path Sanitization:** Scans tool responses using **Microsoft Presidio** to mask sensitive PII (credit cards, emails, phone numbers) before returning them to the LLM context window.
3. **Immutable Auditing:** Asynchronously records every interaction to **Supabase PostgreSQL** for forensics and compliance.

---

## ⚡ The MCP Security Threat Model

```
   [ Untrusted User Input ] 
             │
             ▼
      [ LLM Agent ] ───────────► [ Attacker Prompt Injection ]
             │
             ▼
   ══════════════════════════════════════════════════════════════════════
   WITHOUT AEGIS: Tool Execution & Exfiltration Vulnerabilities
   ══════════════════════════════════════════════════════════════════════
   ❌ Tool Privilege Escalation (e.g. standard agent invokes root exec tools)
   ❌ Command Injection Vectors (`path: "file.txt; /bin/sh -c whoami"`)
   ❌ Shadow Schema Pollution (`__proto__`, unauthorized kwargs injection)
   ❌ PII Leakage from Tools (Raw customer cards/emails dumped to LLM)
   ❌ Zero Audit Trail (No forensic record of tool execution decisions)

   ══════════════════════════════════════════════════════════════════════
   WITH AEGIS: Zero-Trust Defense Boundary
   ══════════════════════════════════════════════════════════════════════
   ✅ Constant-Time Bearer Authentication
   ✅ Pydantic V2 Extra-Field Rejection (`extra="forbid"`)
   ✅ Recursive Regex Shell Injection Blocker
   ✅ Supabase PostgreSQL RBAC Least-Privilege Verification
   ✅ Microsoft Presidio DLP Redaction (`<REDACTED_PII>`)
   ✅ Immutable Audit Logs (`ALLOWED`, `BLOCKED_POLICY`, `SANITIZED_PII`)
   ✅ Information Leakage Masking (Uniform generic 403 Forbidden)
```

---

## 🏛️ High-Level Architecture

### Forward Path vs. Return Path

```mermaid
flowchart TD
    subgraph Client["🤖 LLM Agent / MCP Client"]
        Agent[LLM Agent]
    end

    subgraph ForwardPath["🛡️ Aegis Forward-Path Pipeline"]
        Auth["1. Bearer Token Auth<br/>(secrets.compare_digest)"]
        Schema["2. Strict Schema Check<br/>(extra='forbid')"]
        InjectShield["3. Shell Injection Shield<br/>(Heuristic Regex Filter)"]
        RBAC["4. Supabase RBAC Check<br/>(user_roles & role_permissions)"]
    end

    subgraph ToolExec["⚙️ MCP Tool Layer"]
        SimTool["External Tool / MCP Server<br/>(Database, File System, API)"]
    end

    subgraph ReturnPath["🧼 Aegis Return-Path Pipeline"]
        Presidio["5. Microsoft Presidio DLP<br/>(Analyzer & Anonymizer Engine)"]
        Scrubber["6. PII Masking<br/>(Cards, Emails, Phones ➔ REDACTED_PII)"]
    end

    subgraph Storage["🗄️ Supabase PostgreSQL"]
        AuditLog[("mcp_audit_logs<br/>Immutable Forensics")]
        RoleDB[("user_roles &<br/>role_permissions")]
    end

    Agent -->|"POST /mcp/execute (JSON-RPC 2.0)"| Auth
    Auth -->|"Valid Secret"| Schema
    Auth -.->|"Invalid Token"| Block403["403 Forbidden"]
    Schema -->|"Valid Structure"| InjectShield
    Schema -.->|"Extra Fields"| Block403
    InjectShield -->|"Clean Arguments"| RBAC
    InjectShield -.->|"Injection Vector Detected"| Block403
    RBAC -->|"Allowed in Matrix"| SimTool
    RBAC -.->|"Role Not Authorized"| Block403

    RBAC <-->|"Query Permissions"| RoleDB
    Block403 -.->|"Log BLOCKED_POLICY"| AuditLog

    SimTool -->|"Raw Tool Output"| Presidio
    Presidio --> Scrubber
    Scrubber -->|"Sanitized JSON-RPC Result"| Agent
    Scrubber -.->|"Log SANITIZED_PII / ALLOWED"| AuditLog
```

---

### End-to-End Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    actor LLM as LLM Agent
    participant Gateway as Aegis Gateway (Middleware)
    participant Supabase as Supabase PostgreSQL
    participant Tool as Target MCP Tool
    participant Presidio as Microsoft Presidio DLP

    LLM->>Gateway: POST /mcp/execute (Bearer Token + JSON-RPC)
    Note over Gateway: Step 1: Verify Bearer Token (Constant-Time)
    Note over Gateway: Step 2: Validate Schema (extra="forbid")
    Note over Gateway: Step 3: Scan Arguments for Command Injections

    alt Shell Injection or Schema Pollution Detected
        Gateway-->>LLM: HTTP 403 Forbidden {"error": "Forbidden: Request blocked..."}
        Gateway-)Supabase: Asynchronously write BLOCKED_POLICY to mcp_audit_logs
    else Forward Path Clean
        Gateway->>Supabase: Query user_roles & role_permissions for Session ID
        Supabase-->>Gateway: Return authorized tools list

        alt Session lacks Tool Permission
            Gateway-->>LLM: HTTP 403 Forbidden
            Gateway-)Supabase: Asynchronously write BLOCKED_POLICY to mcp_audit_logs
        else Tool Execution Authorized
            Gateway->>Tool: Forward JSON-RPC params
            Tool-->>Gateway: Return raw tool output
            
            Gateway->>Presidio: Scan response payload for PII entities
            Presidio-->>Gateway: Replace Credit Cards, Emails, Phones with <REDACTED_PII>

            Gateway-->>LLM: HTTP 200 OK (Sanitized JSON-RPC Result)
            Gateway-)Supabase: Asynchronously write SANITIZED_PII / ALLOWED to mcp_audit_logs
        end
    end
```

---

## 🔒 Defense-in-Depth Security Layers

| Layer | Component | Mechanism | Mitigation Type |
|---|---|---|---|
| **Layer 1** | Bearer Authentication | `secrets.compare_digest` constant-time verification | Thwarts timing & spoofing attacks |
| **Layer 2** | Schema Enforcement | Pydantic V2 `model_config = ConfigDict(extra="forbid")` | Blocks shadow arguments & prototype pollution |
| **Layer 3** | Injection Shield | Recursive regex inspection (`&&`, `\|`, `;`, `/bin/sh`, backticks, subshells) | Blocks remote code execution (RCE) |
| **Layer 4** | Authorization (RBAC) | Supabase PostgREST async session-to-role matrix | Prevents privilege escalation |
| **Layer 5** | Data Loss Prevention (DLP) | Microsoft Presidio `AnalyzerEngine` + `AnonymizerEngine` | Redacts sensitive PII in return path |
| **Layer 6** | Audit Forensics | Supabase `mcp_audit_logs` immutable table | Regulatory compliance & incident forensics |
| **Layer 7** | Topology Obfuscation | Global exception handler normalizes to generic 403 | Eliminates reconnaissance & enumeration |

---

### 1. Constant-Time Authentication
All requests must provide an `Authorization: Bearer <TOKEN>` header. Tokens are verified using `secrets.compare_digest` to prevent statistical side-channel timing analysis:
```python
if not secrets.compare_digest(provided_token, expected_token):
    return JSONResponse(status_code=403, content=GENERIC_FORBIDDEN_RESPONSE)
```

### 2. Strict Schema Validation (Pydantic V2)
All MCP request and response structures inherit from `StrictMCPBaseModel`:
```python
class StrictMCPBaseModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",            # Strict rejection of undeclared parameters
        populate_by_name=True,
        validate_assignment=True,
    )
```
Any attempt by a prompt injection to smuggle parameters like `__proto__`, `bypass_rbac`, or unmapped arguments is rejected at the serialization boundary.

### 3. Heuristic Shell Injection Shield
Tool arguments are recursively analyzed for shell metacharacters and execution patterns:
- Command chainers: `;`, `&&`, `||`, `|`, `&`
- Unix shell binaries: `/bin/sh`, `/bin/bash`, `/usr/bin/zsh`
- Command substitution: `` `command` ``, `$(command)`
- Windows shells: `powershell.exe`, `cmd.exe`, `pwsh`
- System primitives: `rm -rf`, `cat /etc/passwd`, `chmod`, `whoami`

### 4. Supabase PostgreSQL RBAC
Sessions are correlated to roles defined in PostgreSQL with least-privilege scoping:

```mermaid
classDiagram
    class UserRole {
        +TEXT session_id (PK)
        +TEXT user_id
        +TEXT role (admin | operator | standard | read_only)
    }
    class RolePermission {
        +TEXT role
        +TEXT tool_name
    }
    class AuditLog {
        +BIGINT id (PK)
        +TEXT session_id
        +TEXT tool_name
        +TEXT status (ALLOWED | BLOCKED_POLICY | SANITIZED_PII)
        +JSONB payload_summary
        +TEXT mitigation_applied
        +TIMESTAMPTZ timestamp
    }
    UserRole --> RolePermission : Resolves tool matrix
    UserRole --> AuditLog : Records forensics
```

### 5. Microsoft Presidio Return-Path DLP
Tool responses containing sensitive data are scanned before reaching the model:
- `CREDIT_CARD` (Visa, MasterCard, Amex, regex + Luhn checksum validation)
- `EMAIL_ADDRESS` (RFC 5322 compliance pattern)
- `PHONE_NUMBER` (International & local format detection)

Matched entities are replaced with `<REDACTED_PII>` while preserving valid JSON document hierarchy.

### 6. Immutable Forensics & Audit Logging
Every interaction generates an immutable audit record in Supabase:
```json
{
  "session_id": "sess-operator-002",
  "tool_name": "query_database",
  "status": "SANITIZED_PII",
  "mitigation_applied": "PRESIDIO_PII_REDACTION",
  "payload_summary": {
    "redacted_entities_count": 3,
    "entities": ["EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD"]
  },
  "timestamp": "2026-10-27T10:15:34.413726Z"
}
```

### 7. Zero-Information Leakage
Regardless of whether a request failed due to bad token, missing role, shell injection, or schema mismatch, the gateway returns an identical response:
```json
{
  "error": "Forbidden: Request blocked by security policy"
}
```
This denies adversaries knowledge of whether an injection succeeded or which filter caught the payload.

---

## 🖥️ Interactive Security Command Center

Aegis includes a built-in interactive dashboard served directly at `http://localhost:8000/dashboard`:

- 📊 **Real-Time Defense Telemetry:** Live counters for Allowed Clean Requests, Sanitized PII, Blocked Attacks, and System Defense Rate.
- 🧪 **Interactive Attack Sandbox:** Pre-loaded attack payloads to simulate command injections, schema pollution, and RBAC privilege escalations.
- 📜 **Live Forensics Audit Feed:** View incoming audit logs and mitigation actions with zero page reloads.

---

## 🚀 Quickstart & Installation

### 1. Clone & Dependencies

```bash
git clone https://github.com/Charan291005/Aegis-AI-Proxy.git
cd Aegis-AI-Proxy

python -m venv venv
# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
```

### 2. Supabase Database Migration

1. Go to your [Supabase Dashboard](https://supabase.com/dashboard) $\rightarrow$ Select Project.
2. Open **SQL Editor** $\rightarrow$ Click **New Query**.
3. Copy the contents of [`scripts/schema.sql`](scripts/schema.sql) and click **Run**.
   *This provisions `user_roles`, `role_permissions`, and `mcp_audit_logs` with baseline seed roles.*

### 3. Environment Configuration

Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

Populate your credentials in `.env`:
```env
# Gateway Bearer Secret
AEGIS_GATEWAY_TOKEN=aegis_super_secret_bearer_token_2026_demo

# Server Bindings
AEGIS_HOST=0.0.0.0
AEGIS_PORT=8000
AEGIS_ENV=development

# Supabase PostgreSQL Configuration
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your_supabase_anon_or_publishable_key
SUPABASE_SERVICE_ROLE_KEY=your_supabase_service_role_secret_key

# Security Engine Toggles
ENABLE_PII_REDACTION=true
ENABLE_INJECTION_SHIELD=true
```

### 4. Verify Connection

Run the built-in Supabase diagnostic utility:
```bash
python scripts/test_supabase.py
```
*Expected output:*
```
[+] Successfully connected to Supabase!
[+] Found 5 active user roles in 'user_roles' table.
[+] Found 16 permission entries in 'role_permissions' table.
[+] Live Supabase RBAC Check: Admin Allowed=True, Unauthorized Denied=True
[+] Supabase integration is 100% operational!
```

### 5. Run the Gateway

```bash
python main.py
# Or with live reload:
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```
Navigate to:
- 🛡️ **Security Console:** `http://localhost:8000/dashboard`
- 📖 **OpenAPI Swagger UI:** `http://localhost:8000/docs`
- 💓 **Health Check Probe:** `http://localhost:8000/health`

---

## 🧪 Testing & Security Auditing

### 1. Pytest Integration Suite
Runs 16 comprehensive unit and integration tests:
```bash
python -m pytest -v tests/test_gateway.py
```

### 2. Adversarial Fuzzing Engine
Fires 70+ dynamic mutation payloads and penetration probes:
```bash
# In-process ASGI penetration testing (zero server setup required):
python tests/adversarial/fuzz_gateway.py

# Against a live running deployment:
python tests/adversarial/fuzz_gateway.py --target http://localhost:8000
```

```
================================================================================
   AEGIS ZERO-TRUST MCP GATEWAY - ADVERSARIAL FUZZING REPORT
================================================================================
 Execution Time : 1.06 seconds
 Total Probes   : 73
 Defenses Held  : 73
 Breaches / Fail: 0
 Defense Rate   : 100.0%
--------------------------------------------------------------------------------
 ATTACK CATEGORY                  | FIRED  | BLOCKED  | BREACH  | SUCCESS
--------------------------------------------------------------------------------
 Command Injection Shield         | 30     | 30       | 0       | 100.0% [PASS]
 Schema Pollution Defense         | 25     | 25       | 0       | 100.0% [PASS]
 PII Redaction (DLP)              | 3      | 3        | 0       | 100.0% [PASS]
 Hypothesis Mutation Fuzzing      | 15     | 15       | 0       | 100.0% [PASS]
--------------------------------------------------------------------------------
 [+] POSTURE EVALUATION: HARDENED (ZERO BREACHES)
================================================================================
```

---

## 📡 API Usage Examples

### 1. Legitimate Tool Call (PII Redacted)

```bash
curl -X POST "http://localhost:8000/mcp/execute" \
  -H "Authorization: Bearer aegis_super_secret_bearer_token_2026_demo" \
  -H "X-Session-ID: sess-operator-002" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "req-101",
    "method": "tools/call",
    "params": {
      "name": "query_database",
      "arguments": {
        "customer_id": "cust_9921"
      }
    }
  }'
```

**Response (`200 OK` with sensitive PII automatically scrubbed):**
```json
{
  "jsonrpc": "2.0",
  "id": "req-101",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Database query successful for args: {'customer_id': 'cust_9921'}. Found record: Customer Jane Doe, Email: <REDACTED_PII>, Phone: <REDACTED_PII>, Billing Card: <REDACTED_PII>."
      }
    ],
    "isError": false,
    "_meta": null
  },
  "error": null
}
```

---

### 2. Command Injection Attempt (Blocked)

```bash
curl -X POST "http://localhost:8000/mcp/execute" \
  -H "Authorization: Bearer aegis_super_secret_bearer_token_2026_demo" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "req-102",
    "method": "tools/call",
    "params": {
      "name": "read_file",
      "arguments": {
        "path": "file.txt; /bin/sh -c whoami"
      }
    }
  }'
```

**Response (`403 Forbidden`):**
```json
{
  "error": "Forbidden: Request blocked by security policy"
}
```

---

### 3. Unauthorized Session Attempt (RBAC Blocked)

```bash
curl -X POST "http://localhost:8000/mcp/execute" \
  -H "Authorization: Bearer aegis_super_secret_bearer_token_2026_demo" \
  -H "X-Session-ID: sess-unauthorized-999" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "req-103",
    "method": "tools/call",
    "params": {
      "name": "read_file",
      "arguments": {
        "path": "docs.txt"
      }
    }
  }'
```

**Response (`403 Forbidden`):**
```json
{
  "error": "Forbidden: Request blocked by security policy"
}
```

---

## 📂 Repository Structure

```
Aegis-AI-Proxy/
├── .env.example                 # Environment variables template
├── .gitignore                   # Git exclusion rules
├── requirements.txt             # Python project dependencies
├── Dockerfile                   # Production container definition
├── docker-compose.yml           # Multi-container orchestration
├── main.py                      # Application entrypoint & ASGI lifespan
│
├── middleware/                  # Zero-Trust Interceptor
│   ├── __init__.py
│   └── interceptor.py           # Forward auth, regex shield, RBAC hook & return DLP
│
├── models/                      # Strict Data Contracts
│   ├── __init__.py
│   └── mcp_schemas.py           # MCP 2024-11-05 JSON-RPC models (extra="forbid")
│
├── routers/                     # Endpoint Controllers
│   ├── __init__.py
│   ├── dashboard_router.py      # Interactive visual console & telemetry APIs
│   └── mcp_router.py            # /mcp/execute endpoint simulation
│
├── security/                    # Configuration & Policies
│   ├── __init__.py
│   └── config.py                # Pydantic-settings centralized environment loader
│
├── services/                    # Core Security Subsystems
│   ├── __init__.py
│   ├── audit_logger.py          # Asynchronous immutable Supabase audit recorder
│   ├── db_client.py             # Supabase AsyncClient & RBAC query engine
│   ├── dlp_engine.py            # Microsoft Presidio Analyzer & Anonymizer
│   └── rbac_service.py          # Role definitions & in-memory matrix fallback
│
├── scripts/                     # Database & Diagnostic Scripts
│   ├── schema.sql               # Supabase PostgreSQL DDL migration & seed data
│   └── test_supabase.py         # Direct connection & RBAC verification tool
│
└── tests/                       # Security & Quality Assurance
    ├── __init__.py
    ├── test_gateway.py          # End-to-end Pytest integration suite
    └── adversarial/
        ├── __init__.py
        └── fuzz_gateway.py      # Hypothesis mutation & OWASP adversarial fuzzer
```

---

## 📜 License

Distributed under the **MIT License**. See `LICENSE` for more information.
