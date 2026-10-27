-- ==============================================================================
-- Aegis Zero-Trust MCP Gateway - Supabase PostgreSQL Schema & Seed Migration
-- ==============================================================================
-- Run this script in your Supabase SQL Editor:
-- Dashboard -> SQL Editor -> New Query -> Run

-- 1. Table: user_roles
-- Maps active sessions/principals to designated authorization roles
CREATE TABLE IF NOT EXISTS public.user_roles (
    session_id TEXT PRIMARY KEY,
    user_id TEXT,
    role TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'standard', 'read_only', 'unauthorized')),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Table: role_permissions
-- Defines which MCP tools each role is permitted to invoke (least privilege)
CREATE TABLE IF NOT EXISTS public.role_permissions (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    role TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(role, tool_name)
);

-- 3. Table: mcp_audit_logs
-- Immutable compliance and forensics log for every forward/return interaction
CREATE TABLE IF NOT EXISTS public.mcp_audit_logs (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    session_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('ALLOWED', 'BLOCKED_POLICY', 'SANITIZED_PII')),
    payload_summary JSONB NOT NULL,
    mitigation_applied TEXT,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indices for rapid query lookup under high load
CREATE INDEX IF NOT EXISTS idx_user_roles_session ON public.user_roles(session_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_role ON public.role_permissions(role);
CREATE INDEX IF NOT EXISTS idx_mcp_audit_logs_timestamp ON public.mcp_audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_mcp_audit_logs_status ON public.mcp_audit_logs(status);

-- ------------------------------------------------------------------------------
-- Seed Data: Baseline Roles & Permissions
-- ------------------------------------------------------------------------------

-- Seed User Sessions
INSERT INTO public.user_roles (session_id, user_id, role)
VALUES 
    ('sess-admin-001', 'usr_admin_master', 'admin'),
    ('sess-operator-002', 'usr_ops_lead', 'operator'),
    ('sess-standard-003', 'usr_dev_alice', 'standard'),
    ('sess-unauthorized-999', 'usr_rogue_agent', 'unauthorized'),
    ('default-session', 'usr_default_agent', 'standard')
ON CONFLICT (session_id) DO NOTHING;

-- Seed Role Permissions
-- 'admin' holds wildcard access to all tools
INSERT INTO public.role_permissions (role, tool_name)
VALUES
    ('admin', '*'),
    ('operator', 'read_file'),
    ('operator', 'query_database'),
    ('operator', 'fetch_metrics'),
    ('operator', 'simulate_tool'),
    ('operator', 'ping'),
    ('operator', 'echo'),
    ('standard', 'read_file'),
    ('standard', 'query_database'),
    ('standard', 'fetch_metrics'),
    ('standard', 'simulate_tool'),
    ('standard', 'ping'),
    ('standard', 'echo'),
    ('read_only', 'simulate_tool'),
    ('read_only', 'ping'),
    ('read_only', 'echo')
ON CONFLICT (role, tool_name) DO NOTHING;
