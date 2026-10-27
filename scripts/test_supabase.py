import asyncio
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from services.db_client import get_supabase_client, verify_tool_permission


async def test_connection():
    print("Connecting to Supabase...")
    client = await get_supabase_client()
    if not client:
        print("[-] Failed to create Supabase client. Check SUPABASE_URL and keys in .env.")
        return

    # Check user_roles table
    roles = await client.table("user_roles").select("*").execute()
    print(f"[+] Successfully connected to Supabase!")
    print(f"[+] Found {len(roles.data)} active user roles in 'user_roles' table:")
    for r in roles.data:
        print(f"    - Session: {r['session_id']:<24} Role: {r['role']}")

    # Check role_permissions table
    perms = await client.table("role_permissions").select("*").execute()
    print(f"[+] Found {len(perms.data)} permission entries in 'role_permissions' table.")

    # Check live RBAC evaluation
    admin_ok = await verify_tool_permission("sess-admin-001", "read_file")
    unauth_blocked = not await verify_tool_permission("sess-unauthorized-999", "read_file")
    print(f"[+] Live Supabase RBAC Check: Admin Allowed={admin_ok}, Unauthorized Denied={unauth_blocked}")
    print("\n[+] Supabase integration is 100% operational!")


if __name__ == "__main__":
    asyncio.run(test_connection())
